//! `astrid capsule show <name>` — manifest, interfaces, source.
//!
//! Reads the installed capsule's `Capsule.toml` and `meta.json` from
//! `<principal_home>/.local/capsules/<name>/`. No daemon round-trip is
//! needed — the manifest is on disk, identical for every connected
//! client.

use std::process::ExitCode;

use anyhow::{Context, Result};
use astrid_core::dirs::AstridHome;
use clap::Args;
use colored::Colorize;
use serde::Serialize;

use crate::context;
use crate::theme::Theme;
use crate::value_formatter::{ValueFormat, emit_structured};

#[derive(Args, Debug, Clone)]
pub(crate) struct ShowArgs {
    /// Capsule name.
    pub name: String,
    /// Agent name (defaults to the active context).
    #[arg(short, long)]
    pub agent: Option<String>,
    /// Output format.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

/// JSON/YAML/TOML emission shape — captures what's surfaced in pretty
/// mode plus the on-disk manifest body for scripting.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CapsuleShow {
    /// Capsule name.
    pub name: String,
    /// On-disk version recorded in `meta.json`.
    pub version: String,
    /// Where the capsule was installed from (registry id, local path).
    pub source: String,
    /// `BLAKE3` content hash of the WASM blob.
    pub wasm_hash: String,
    /// ISO 8601 install timestamp.
    pub installed_at: String,
    /// ISO 8601 last-update timestamp.
    pub updated_at: String,
    /// Build-captured tool descriptors (name + description), baked into
    /// `meta.json` at build time. Empty for capsules with no tools.
    pub tools: Vec<ToolSummary>,
    /// Verbatim `Capsule.toml` body.
    pub manifest: String,
}

/// A tool's name + description, surfaced from the baked `meta.json`
/// `tools` array. The full `input_schema` lives in `meta.json`; `show`
/// lists the surface, not the schemas.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ToolSummary {
    /// Tool name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
}

/// Entry point for `astrid capsule show`.
pub(crate) fn run(args: &ShowArgs) -> Result<ExitCode> {
    let principal = context::resolve_agent(args.agent.as_deref())?;
    let format = ValueFormat::parse(&args.format);
    let home = AstridHome::resolve().context("Failed to resolve Astrid home directory")?;
    let capsule_dir = home
        .principal_home(&principal)
        .root()
        .join(".local")
        .join("capsules")
        .join(&args.name);
    if !capsule_dir.exists() {
        eprintln!(
            "{}",
            Theme::error(&format!(
                "capsule '{}' is not installed for agent '{principal}'",
                args.name
            ))
        );
        return Ok(ExitCode::from(1));
    }
    let manifest_path = capsule_dir.join("Capsule.toml");
    let meta_path = capsule_dir.join("meta.json");
    let manifest = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("Failed to read {}", manifest_path.display()))?;
    let meta_raw = std::fs::read_to_string(&meta_path)
        .with_context(|| format!("Failed to read {}", meta_path.display()))?;
    let meta: serde_json::Value = serde_json::from_str(&meta_raw)
        .with_context(|| format!("{} is not valid JSON", meta_path.display()))?;

    let record = CapsuleShow {
        name: args.name.clone(),
        version: meta
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        source: meta
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        wasm_hash: meta
            .get("wasm_hash")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        installed_at: meta
            .get("installed_at")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        updated_at: meta
            .get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        tools: extract_tool_summaries(&meta),
        manifest: manifest.clone(),
    };

    if !format.is_pretty() {
        emit_structured(&record, format)?;
        return Ok(ExitCode::SUCCESS);
    }

    println!("{} {}", "Capsule".bold(), args.name.cyan());
    println!("  Version:      {}", record.version);
    println!("  Source:       {}", record.source);
    println!("  Hash:         {}", record.wasm_hash);
    println!("  Installed:    {}", record.installed_at);
    println!("  Updated:      {}", record.updated_at);
    println!("  Agent:        {principal}");
    println!();
    if record.tools.is_empty() {
        println!("{} (none captured at build)", "Tools".bold());
    } else {
        println!("{} ({})", "Tools".bold(), record.tools.len());
        for tool in &record.tools {
            // Tool descriptions are doc comments and can span lines; show
            // only the first line here so the listing stays scannable. The
            // full description + input schema live in `meta.json`.
            let summary = tool.description.lines().next().unwrap_or_default();
            if summary.is_empty() {
                println!("  {}", tool.name.cyan());
            } else {
                println!("  {}  {}", tool.name.cyan(), summary.dimmed());
            }
        }
    }
    println!();
    println!("{}", "Manifest".bold());
    for line in manifest.lines() {
        println!("  {line}");
    }
    Ok(ExitCode::SUCCESS)
}

/// Pull `name` + `description` out of the baked `meta.json` `tools`
/// array. Tolerant of a missing / malformed array (yields empty) — a
/// capsule built before tool-baking, or a non-tool capsule, simply has
/// no tools to show.
fn extract_tool_summaries(meta: &serde_json::Value) -> Vec<ToolSummary> {
    let Some(tools) = meta.get("tools").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    tools
        .iter()
        .filter_map(|t| {
            let name = t.get("name")?.as_str()?.to_string();
            let description = t
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            Some(ToolSummary { name, description })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trips_to_json() {
        let rec = CapsuleShow {
            name: "x".into(),
            version: "0.1.0".into(),
            source: "local".into(),
            wasm_hash: "abc".into(),
            installed_at: "2026-04-28T00:00:00Z".into(),
            updated_at: "2026-04-28T00:00:00Z".into(),
            tools: vec![ToolSummary {
                name: "do_thing".into(),
                description: "Does the thing".into(),
            }],
            manifest: "[package]\nname = \"x\"\n".into(),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["name"], "x");
        assert_eq!(parsed["version"], "0.1.0");
        assert_eq!(parsed["tools"][0]["name"], "do_thing");
    }

    #[test]
    fn extract_tool_summaries_reads_baked_tools() {
        let meta = serde_json::json!({
            "version": "0.1.0",
            "tools": [
                { "name": "read_file", "description": "Read a file", "input_schema": {} },
                { "name": "write_file", "input_schema": {} },
            ]
        });
        let tools = extract_tool_summaries(&meta);
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "read_file");
        assert_eq!(tools[0].description, "Read a file");
        assert_eq!(tools[1].name, "write_file");
        assert_eq!(tools[1].description, "");
    }

    #[test]
    fn extract_tool_summaries_tolerates_missing_array() {
        let meta = serde_json::json!({ "version": "0.1.0" });
        assert!(extract_tool_summaries(&meta).is_empty());
    }
}
