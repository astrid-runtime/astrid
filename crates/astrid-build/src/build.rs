//! Capsule build dispatch — routes to the appropriate builder by project type.

use anyhow::{Result, bail};
use std::path::Path;
use tracing::info;

/// Main entrypoint for the `astrid build` Universal Packager command.
pub(crate) fn run_build(
    path: Option<&str>,
    output: Option<&str>,
    project_type: Option<&str>,
    from_mcp_json: Option<&str>,
) -> Result<()> {
    let target_dir = match path {
        Some(p) => Path::new(p).to_path_buf(),
        None => std::env::current_dir()?,
    };

    if !target_dir.exists() {
        bail!("Directory does not exist: {}", target_dir.display());
    }

    // Early exit for legacy `mcp.json` or `gemini-extension.json` quick convert
    if let Some(json_path_str) = from_mcp_json {
        let json_path = Path::new(json_path_str);
        let dir = json_path.parent().unwrap_or(Path::new(""));
        let file_name = json_path.file_name().unwrap_or_default().to_string_lossy();
        return crate::mcp::convert(dir, &file_name, output);
    }

    // Detect the project type if not explicitly provided
    let detected_type = if let Some(explicit) = project_type {
        explicit.to_string()
    } else {
        detect_project_type(&target_dir)?
    };

    info!("Detected project type: {detected_type}");

    // Route to the appropriate builder
    match detected_type.as_str() {
        "rust" => crate::rust::build(&target_dir, output)?,
        "mcp" => crate::mcp::convert(&target_dir, "mcp.json", output)?,
        "extension" => crate::mcp::convert(&target_dir, "gemini-extension.json", output)?,
        "openclaw" => crate::openclaw::build(&target_dir, output)?,
        "js" | "ts" => crate::js::build(&target_dir, output)?,
        "node" => {
            bail!(
                "Project type 'node' is ambiguous. For native Astrid JS/TS capsules use --type js or --type ts. \
                 For OpenClaw plugins, use --type openclaw or ensure openclaw.plugin.json exists."
            );
        },
        "static" => {
            bail!("Static No-Code building is not yet implemented in the CLI.");
        },
        unknown => {
            bail!(
                "Unknown project type: {unknown}. \
                 Supported types: rust, openclaw, mcp, extension"
            );
        },
    }

    Ok(())
}

fn detect_project_type(dir: &Path) -> Result<String> {
    if dir.join("Cargo.toml").exists() {
        return Ok("rust".to_string());
    }

    if dir.join("gemini-extension.json").exists() {
        return Ok("extension".to_string());
    }

    // OpenClaw plugins are identified by their manifest file, distinct from
    // a future native Astrid JS/TS SDK which would use Capsule.toml directly.
    if dir.join("openclaw.plugin.json").exists() {
        return Ok("openclaw".to_string());
    }

    if dir.join("package.json").exists() {
        // Disambiguate: native Astrid JS/TS capsules also carry a Capsule.toml.
        // Without one, it's almost certainly an OpenClaw plugin or unrelated
        // project — fall through and let the next checks (or a manual --type)
        // decide.
        if dir.join("Capsule.toml").exists() {
            if dir.join("tsconfig.json").exists() {
                return Ok("ts".to_string());
            }
            return Ok("js".to_string());
        }
    }

    if dir.join("mcp.json").exists() {
        return Ok("mcp".to_string());
    }

    if dir.join("Capsule.toml").exists() {
        return Ok("static".to_string());
    }

    bail!(
        "Could not automatically detect the project type. \
         Please ensure a Cargo.toml, openclaw.plugin.json, gemini-extension.json, \
         package.json, or Capsule.toml exists in the directory, or use the --type flag."
    );
}

#[cfg(test)]
mod tests {
    use crate::archiver::pack_capsule_archive;
    use astrid_capsule::discovery::load_manifest;
    use astrid_openclaw::pipeline::{self, CompileOptions};
    use astrid_openclaw::tier::PluginTier;
    use std::fs;
    use std::path::{Path, PathBuf};

    /// Create a minimal Tier 2 `OpenClaw` plugin (`Node.js` — no `QuickJS` kernel needed).
    fn create_tier2_plugin(dir: &Path) {
        let manifest = r#"{
            "id": "lifecycle-test",
            "name": "Lifecycle Test Plugin",
            "version": "1.0.0",
            "description": "Tests the full compile-archive-unpack-load cycle",
            "kind": "tool",
            "skills": ["testing"],
            "configSchema": {
                "type": "object",
                "properties": {
                    "apiKey": {"type": "string"},
                    "endpoint": {"type": "string"}
                }
            }
        }"#;
        fs::write(dir.join("openclaw.plugin.json"), manifest).unwrap();

        let pkg = r#"{"name": "lifecycle-test", "dependencies": {"got": "^1.0"}}"#;
        fs::write(dir.join("package.json"), pkg).unwrap();

        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("src/index.js"),
            "const got = require('got');\nmodule.exports.activate = function(ctx) {\n  ctx.registerTool('test', { description: 'test' }, () => 'ok');\n};",
        ).unwrap();
    }

    /// Unpack a .capsule archive into a directory (mirrors install.rs logic).
    fn unpack_capsule(archive_path: &Path, dest: &Path) {
        let tar_gz = fs::File::open(archive_path).unwrap();
        let decoder = flate2::read::GzDecoder::new(tar_gz);
        let mut archive = tar::Archive::new(decoder);

        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_path_buf();

            assert!(
                !path.is_absolute(),
                "archive contains absolute path: {}",
                path.display()
            );
            assert!(
                !path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)),
                "archive contains path traversal: {}",
                path.display()
            );
            assert!(
                !entry.header().entry_type().is_symlink()
                    && !entry.header().entry_type().is_hard_link(),
                "archive contains symlink: {}",
                path.display()
            );

            let out_path = dest.join(&path);
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            entry.unpack(&out_path).unwrap();
        }
    }

    #[test]
    fn full_lifecycle_tier2_compile_archive_unpack_load() {
        let plugin_dir = tempfile::tempdir().unwrap();
        create_tier2_plugin(plugin_dir.path());

        let build_dir = tempfile::tempdir().unwrap();
        let config = std::collections::HashMap::new();
        let result = pipeline::compile_plugin(&CompileOptions {
            plugin_dir: plugin_dir.path(),
            output_dir: build_dir.path(),
            config: &config,
            cache_dir: None,
            js_only: false,
            no_cache: true,
        })
        .expect("compilation should succeed");

        assert_eq!(result.astrid_id, "lifecycle-test");
        assert_eq!(result.tier, PluginTier::Node);

        let toml_content = fs::read_to_string(build_dir.path().join("Capsule.toml"))
            .expect("Capsule.toml should exist after compilation");

        let archive_dir = tempfile::tempdir().unwrap();
        let capsule_path = archive_dir.path().join("lifecycle-test.capsule");

        let mut additional: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(build_dir.path()).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() == "Capsule.toml" {
                continue;
            }
            additional.push(entry.path());
        }
        let refs: Vec<&Path> = additional.iter().map(PathBuf::as_path).collect();

        pack_capsule_archive(
            &capsule_path,
            &toml_content,
            None,
            build_dir.path(),
            &refs,
            None,
        )
        .expect("archiving should succeed");

        assert!(capsule_path.exists(), ".capsule file should exist");
        assert!(
            fs::metadata(&capsule_path).unwrap().len() > 0,
            ".capsule should not be empty"
        );

        // Verify exactly one Capsule.toml in the archive
        {
            let tar_gz = fs::File::open(&capsule_path).unwrap();
            let decoder = flate2::read::GzDecoder::new(tar_gz);
            let mut archive = tar::Archive::new(decoder);
            let toml_count = archive
                .entries()
                .unwrap()
                .map(|e| e.expect("archive entry must be readable"))
                .filter(|e| {
                    e.path().expect("archive entry path must be valid").as_ref()
                        == Path::new("Capsule.toml")
                })
                .count();
            assert_eq!(
                toml_count, 1,
                "archive must contain exactly one Capsule.toml, found {toml_count}"
            );
        }

        let unpack_dir = tempfile::tempdir().unwrap();
        unpack_capsule(&capsule_path, unpack_dir.path());

        assert!(unpack_dir.path().join("Capsule.toml").exists());
        assert!(unpack_dir.path().join("astrid_bridge.mjs").exists());
        assert!(unpack_dir.path().join("src").exists());
        assert!(unpack_dir.path().join("package.json").exists());

        let npm_available = build_dir.path().join("node_modules").exists();
        if npm_available {
            assert!(unpack_dir.path().join("node_modules").exists());
        }

        let manifest = load_manifest(&unpack_dir.path().join("Capsule.toml"))
            .expect("unpacked Capsule.toml must be loadable");

        assert_eq!(manifest.package.name, "lifecycle-test");
        assert_eq!(manifest.package.version, "1.0.0");
        assert!(!manifest.mcp_servers.is_empty());
    }

    #[test]
    fn full_lifecycle_tier1_js_only_compile_archive_unpack_load() {
        let plugin_dir = tempfile::tempdir().unwrap();
        let manifest = r#"{
            "id": "tier1-lifecycle",
            "name": "Tier 1 Lifecycle",
            "version": "2.0.0",
            "description": "Tier 1 lifecycle test",
            "configSchema": {
                "type": "object",
                "properties": {
                    "token": {"type": "string"}
                }
            }
        }"#;
        fs::write(plugin_dir.path().join("openclaw.plugin.json"), manifest).unwrap();
        fs::create_dir_all(plugin_dir.path().join("src")).unwrap();
        fs::write(
            plugin_dir.path().join("src/index.js"),
            "module.exports.activate = function(ctx) {};",
        )
        .unwrap();

        let build_dir = tempfile::tempdir().unwrap();
        let config = std::collections::HashMap::new();
        let result = pipeline::compile_plugin(&CompileOptions {
            plugin_dir: plugin_dir.path(),
            output_dir: build_dir.path(),
            config: &config,
            cache_dir: None,
            js_only: true,
            no_cache: true,
        })
        .expect("js_only compilation should succeed");

        assert_eq!(result.tier, PluginTier::Wasm);

        let shim_path = build_dir.path().join("shim.js");
        assert!(shim_path.exists());

        let shim = fs::read_to_string(&shim_path).unwrap();
        assert!(shim.contains("_ensureActivated"));
        assert!(shim.contains("astrid_deactivate"));
        assert!(shim.contains("_Buffer.from"));
    }

    #[test]
    fn full_lifecycle_config_validation_rejects_bad_config() {
        let plugin_dir = tempfile::tempdir().unwrap();
        let manifest = r#"{
            "id": "config-test",
            "configSchema": {
                "type": "object",
                "properties": {
                    "apiKey": {"type": "string"}
                },
                "required": ["apiKey"]
            }
        }"#;
        fs::write(plugin_dir.path().join("openclaw.plugin.json"), manifest).unwrap();
        fs::create_dir_all(plugin_dir.path().join("src")).unwrap();
        fs::write(
            plugin_dir.path().join("src/index.js"),
            "module.exports = {};",
        )
        .unwrap();

        let build_dir = tempfile::tempdir().unwrap();
        let mut config = std::collections::HashMap::new();
        config.insert("bogusKey".into(), serde_json::json!("val"));

        let err = pipeline::compile_plugin(&CompileOptions {
            plugin_dir: plugin_dir.path(),
            output_dir: build_dir.path(),
            config: &config,
            cache_dir: None,
            js_only: true,
            no_cache: true,
        });

        assert!(err.is_err(), "should reject unknown config key");
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("bogusKey"),
            "error should mention the bad key, got: {msg}"
        );
    }

    fn assert_symlinks_dereferenced(symlink_fn: impl FnOnce(&Path, &Path)) {
        let build_dir = tempfile::tempdir().unwrap();
        let base = build_dir.path();

        let bin_dir = base.join("node_modules/.bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let real_script = base.join("node_modules/somepkg/cli.js");
        fs::create_dir_all(real_script.parent().unwrap()).unwrap();
        fs::write(&real_script, "#!/usr/bin/env node\nconsole.log('hello');").unwrap();

        symlink_fn(&real_script, &bin_dir.join("somepkg"));

        let archive_path = base.join("test.capsule");
        pack_capsule_archive(
            &archive_path,
            "[package]\nname = \"test\"\nversion = \"0.1.0\"\n",
            None,
            base,
            &[&base.join("node_modules")],
            None,
        )
        .expect("archiving should succeed");

        let tar_gz = fs::File::open(&archive_path).unwrap();
        let decoder = flate2::read::GzDecoder::new(tar_gz);
        let mut archive = tar::Archive::new(decoder);

        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            assert!(
                !entry.header().entry_type().is_symlink()
                    && !entry.header().entry_type().is_hard_link(),
                "archive must not contain symlinks, found: {}",
                entry.path().unwrap().display()
            );
        }

        let unpack_dir = tempfile::tempdir().unwrap();
        unpack_capsule(&archive_path, unpack_dir.path());

        let dereferenced = unpack_dir.path().join("node_modules/.bin/somepkg");
        assert!(dereferenced.exists());
        let content = fs::read_to_string(&dereferenced).unwrap();
        assert!(content.contains("hello"));
    }

    #[test]
    #[cfg_attr(windows, ignore = "symlinks require elevated privileges on Windows")]
    fn archive_dereferences_absolute_symlinks() {
        assert_symlinks_dereferenced(|target, link| {
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, link).unwrap();
            #[cfg(windows)]
            std::os::windows::fs::symlink_file(target, link).unwrap();
        });
    }

    #[test]
    #[cfg_attr(windows, ignore = "symlinks require elevated privileges on Windows")]
    fn archive_dereferences_relative_symlinks() {
        assert_symlinks_dereferenced(|_target, link| {
            let relative = Path::new("../somepkg/cli.js");
            #[cfg(unix)]
            std::os::unix::fs::symlink(relative, link).unwrap();
            #[cfg(windows)]
            std::os::windows::fs::symlink_file(relative, link).unwrap();
        });
    }

    #[test]
    #[cfg_attr(windows, ignore = "symlinks require elevated privileges on Windows")]
    fn archive_detects_symlink_cycle_without_hanging() {
        let build_dir = tempfile::tempdir().unwrap();
        let base = build_dir.path();

        let evil_dir = base.join("node_modules/evil");
        fs::create_dir_all(&evil_dir).unwrap();
        fs::write(evil_dir.join("legit.js"), "// not malicious").unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(Path::new("../../"), evil_dir.join("loop")).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(Path::new("../../"), evil_dir.join("loop")).unwrap();

        let archive_path = base.join("cycle-test.capsule");
        pack_capsule_archive(
            &archive_path,
            "[package]\nname = \"cycle-test\"\nversion = \"0.1.0\"\n",
            None,
            base,
            &[&base.join("node_modules")],
            None,
        )
        .expect("archiving must not hang on symlink cycles");

        let tar_gz = fs::File::open(&archive_path).unwrap();
        let decoder = flate2::read::GzDecoder::new(tar_gz);
        let mut archive = tar::Archive::new(decoder);

        let entries: Vec<_> = archive
            .entries()
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path().unwrap().to_path_buf())
            .collect();

        assert!(entries.iter().any(|p| p.ends_with("legit.js")));
        assert!(
            entries.len() < 50,
            "archive has {} entries — cycle detection may have failed",
            entries.len()
        );
    }
}
