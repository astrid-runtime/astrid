//! Legacy MCP/extension manifest converter — transforms `mcp.json` or
//! `gemini-extension.json` into a `Capsule.toml` and packages it.

use crate::archiver::{discover_opaque_assets, pack_capsule_archive};
use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

/// Convert a legacy MCP or Gemini extension manifest into a `.capsule` archive.
pub(crate) fn convert(dir: &Path, json_filename: &str, output: Option<&str>) -> Result<()> {
    let json_path = dir.join(json_filename);
    info!("Converting {} into a capsule...", json_path.display());

    let content = fs::read_to_string(&json_path)
        .with_context(|| format!("Failed to read {}", json_path.display()))?;

    let parsed: Value = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse JSON in {}", json_path.display()))?;

    // 1. Extract package metadata
    let name = parsed
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("legacy-mcp")
        .to_string();
    let version = parsed
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("1.0.0")
        .to_string();
    let description = parsed
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("Converted MCP capsule")
        .to_string();

    let mut toml_doc = toml_edit::DocumentMut::new();

    let mut package = toml_edit::Table::new();
    package.insert("name", toml_edit::value(name.clone()));
    package.insert("version", toml_edit::value(version));
    package.insert("description", toml_edit::value(description));
    let mut authors = toml_edit::Array::new();
    authors.push("Auto-Converter");
    package.insert("authors", toml_edit::value(authors));
    toml_doc.insert("package", toml_edit::Item::Table(package));

    let mut additional_files = Vec::new();

    // 2. Extract settings → `[env]` block
    let mut env_table = toml_edit::Table::new();
    extract_settings_env(&parsed, &mut env_table);
    extract_server_env(&parsed, &mut env_table);

    // 3. Extract capabilities
    let capabilities = extract_capabilities(&parsed);
    if !capabilities.is_empty() {
        let mut caps_table = toml_edit::Table::new();
        let mut host_arr = toml_edit::Array::new();
        for cap in capabilities {
            host_arr.push(cap);
        }
        caps_table.insert("host_process", toml_edit::value(host_arr));
        toml_doc.insert("capabilities", toml_edit::Item::Table(caps_table));
    }

    if !env_table.is_empty() {
        toml_doc.insert("env", toml_edit::Item::Table(env_table));
    }

    // 4. Extract MCP servers
    extract_mcp_servers(&parsed, &mut toml_doc);

    // 5. Inject context files (AGENTS.md)
    inject_context_files(dir, &parsed, &mut toml_doc, &mut additional_files);

    // 6. Inject commands
    inject_commands(dir, &mut toml_doc, &mut additional_files);

    // 7. Preserve user-space assets as opaque archive data. No manifest
    // metadata is synthesized and Astrid assigns these files no semantics.
    additional_files.extend(discover_opaque_assets(dir)?);

    let toml = toml_doc.to_string();

    // 8. Pack the archive
    let out_dir = match output {
        Some(p) => PathBuf::from(p),
        None => std::env::current_dir()?.join("dist"),
    };

    if !out_dir.exists() {
        fs::create_dir_all(&out_dir)?;
    }

    let out_file = out_dir.join(format!("{name}.capsule"));
    let refs: Vec<&Path> = additional_files
        .iter()
        .map(std::path::PathBuf::as_path)
        .collect();

    pack_capsule_archive(&out_file, &toml, None, dir, &refs, None)?;

    info!("Successfully converted to capsule: {}", out_file.display());
    Ok(())
}

/// Extract `settings` array entries into env definitions (gemini-extension.json format).
fn extract_settings_env(parsed: &Value, env_table: &mut toml_edit::Table) {
    let Some(settings) = parsed.get("settings").and_then(Value::as_array) else {
        return;
    };
    for setting in settings {
        if let Some(env_var) = setting.get("envVar").and_then(Value::as_str) {
            let req_name = setting
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(env_var);
            let desc = setting
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("");

            let mut env_def = toml_edit::InlineTable::new();
            env_def.insert("type", "secret".into());
            env_def.insert("request", req_name.into());
            env_def.insert("description", desc.into());
            env_table.insert(env_var, toml_edit::value(env_def));
        }
    }
}

/// Fallback: extract env vars from `mcpServers[*].env` when no `settings` block exists.
fn extract_server_env(parsed: &Value, env_table: &mut toml_edit::Table) {
    if !env_table.is_empty() {
        return;
    }
    let Some(servers) = parsed.get("mcpServers").and_then(Value::as_object) else {
        return;
    };
    for (_, server_config) in servers {
        if let Some(env_map) = server_config.get("env").and_then(Value::as_object) {
            for (env_key, _) in env_map {
                let mut env_def = toml_edit::InlineTable::new();
                env_def.insert("type", "secret".into());
                env_def.insert(
                    "request",
                    format!("Please provide a value for {env_key}").into(),
                );
                env_table.insert(env_key, toml_edit::value(env_def));
            }
        }
    }
}

/// Extract unique command names from MCP server definitions.
fn extract_capabilities(parsed: &Value) -> Vec<String> {
    let mut capabilities = Vec::new();
    let Some(servers) = parsed.get("mcpServers").and_then(Value::as_object) else {
        return capabilities;
    };
    for (_, server_config) in servers {
        if let Some(cmd) = server_config.get("command").and_then(Value::as_str)
            && !capabilities.contains(&cmd.to_string())
        {
            capabilities.push(cmd.to_string());
        }
    }
    capabilities
}

/// Extract MCP server definitions into `[[mcp_server]]` entries.
fn extract_mcp_servers(parsed: &Value, toml_doc: &mut toml_edit::DocumentMut) {
    let Some(servers) = parsed.get("mcpServers").and_then(Value::as_object) else {
        return;
    };

    let mut mcp_servers_array = toml_edit::ArrayOfTables::new();
    for (server_id, server_config) in servers {
        let mut server_table = toml_edit::Table::new();
        server_table.insert("id", toml_edit::value(server_id));

        if let Some(desc) = server_config.get("description").and_then(Value::as_str) {
            server_table.insert("description", toml_edit::value(desc));
        }

        if let Some(cmd) = server_config.get("command").and_then(Value::as_str) {
            server_table.insert("type", toml_edit::value("stdio"));
            server_table.insert("command", toml_edit::value(cmd));

            if let Some(args) = server_config.get("args").and_then(Value::as_array) {
                let mut args_arr = toml_edit::Array::new();
                for a in args.iter().filter_map(Value::as_str) {
                    args_arr.push(a);
                }
                if !args_arr.is_empty() {
                    server_table.insert("args", toml_edit::value(args_arr));
                }
            }
        } else if let Some(http_url) = server_config.get("httpUrl").and_then(Value::as_str) {
            server_table.insert("type", toml_edit::value("sse"));
            server_table.insert("url", toml_edit::value(http_url));
        }
        mcp_servers_array.push(server_table);
    }

    if !mcp_servers_array.is_empty() {
        toml_doc.insert(
            "mcp_server",
            toml_edit::Item::ArrayOfTables(mcp_servers_array),
        );
    }
}

/// Inject context files (e.g. `AGENTS.md`) into `[[context_file]]`.
fn inject_context_files(
    dir: &Path,
    parsed: &Value,
    toml_doc: &mut toml_edit::DocumentMut,
    additional_files: &mut Vec<PathBuf>,
) {
    let context_file_name = parsed
        .get("contextFileName")
        .and_then(Value::as_str)
        .unwrap_or("AGENTS.md");
    let sanitized_context_name = Path::new(context_file_name)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let context_path = dir.join(sanitized_context_name.as_ref());

    if !context_path.exists() {
        return;
    }

    let mut context_files_array = toml_edit::ArrayOfTables::new();
    let mut ctx_table = toml_edit::Table::new();
    ctx_table.insert("name", toml_edit::value("workspace-context"));
    ctx_table.insert("file", toml_edit::value(sanitized_context_name.as_ref()));
    context_files_array.push(ctx_table);
    additional_files.push(context_path);

    toml_doc.insert(
        "context_file",
        toml_edit::Item::ArrayOfTables(context_files_array),
    );
}

/// Inject `commands/*.toml` files into `[[command]]`.
fn inject_commands(
    dir: &Path,
    toml_doc: &mut toml_edit::DocumentMut,
    additional_files: &mut Vec<PathBuf>,
) {
    let commands_dir = dir.join("commands");
    if !commands_dir.exists() || !commands_dir.is_dir() {
        return;
    }
    let Ok(entries) = fs::read_dir(&commands_dir) else {
        return;
    };

    let mut commands_array = toml_edit::ArrayOfTables::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("toml") {
            let file_name = path.file_name().unwrap_or_default().to_string_lossy();
            let cmd_name = format!(
                "/{}",
                path.file_stem().unwrap_or_default().to_string_lossy()
            );

            let mut cmd_table = toml_edit::Table::new();
            cmd_table.insert("name", toml_edit::value(cmd_name));
            cmd_table.insert("file", toml_edit::value(format!("commands/{file_name}")));
            commands_array.push(cmd_table);
        }
    }

    if !commands_array.is_empty() {
        additional_files.push(commands_dir);
        toml_doc.insert("command", toml_edit::Item::ArrayOfTables(commands_array));
    }
}
