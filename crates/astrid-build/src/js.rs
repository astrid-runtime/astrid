//! `JavaScript` / `TypeScript` capsule builder. Shells out to the
//! `Node`-based `@astrid-os/build` orchestrator which runs `tsc`, bundles
//! with esbuild, and componentizes via `ComponentizeJS`. Packs the resulting
//! `wasip2` component into a `.capsule` archive using the shared archiver.

use crate::archiver::pack_capsule_archive;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Build a JS/TS capsule from a project directory.
///
/// Pipeline:
/// 1. Verify `node` is available.
/// 2. Locate the `@astrid-os/build` orchestrator (project's `node_modules`,
///    workspace fallback, or `ASTRID_JS_BUILD` env var override).
/// 3. Shell out: `node <orchestrator> <project-dir> --out <wasm-path>`.
/// 4. Parse the orchestrator's JSON result line to confirm wasm location.
/// 5. Merge `Capsule.toml` (defaulting if absent).
/// 6. Stage the `wit/` directory if present.
/// 7. Pack the `.capsule` archive.
pub(crate) fn build(dir: &Path, output: Option<&str>) -> Result<()> {
    info!("Building JS/TS WASM capsule from {}", dir.display());

    // Canonicalize to absolute. Without this, the walk-up orchestrator lookup
    // produces a relative path that gets reinterpreted against the spawned
    // node process's CWD, leading to garbage path resolution.
    let dir = dir
        .canonicalize()
        .with_context(|| format!("failed to canonicalize project dir: {}", dir.display()))?;
    let dir = dir.as_path();

    verify_node_available()?;

    let (pkg_name, pkg_version) = resolve_package_metadata(dir)?;
    let orchestrator = locate_orchestrator(dir)?;
    let target_dir = dir.join("target");
    fs::create_dir_all(&target_dir)
        .with_context(|| format!("failed to create target dir: {}", target_dir.display()))?;
    let wasm_path = target_dir.join(format!("{pkg_name}.wasm"));

    run_orchestrator(&orchestrator, dir, &wasm_path)?;

    if !wasm_path.exists() {
        bail!(
            "JS builder reported success but produced no wasm at {}",
            wasm_path.display()
        );
    }

    let toml_content = build_manifest_content(dir, &pkg_name, &pkg_version, &wasm_path)?;

    let out_dir = resolve_output_dir(output, dir)?;
    let out_file = out_dir.join(format!("{pkg_name}.capsule"));

    let wit_staging = stage_wit_directory(dir);

    pack_capsule_archive(
        &out_file,
        &toml_content,
        Some(&wasm_path),
        dir,
        &[],
        wit_staging.as_deref(),
    )?;

    info!("Successfully built JS/TS capsule: {}", out_file.display());
    Ok(())
}

fn verify_node_available() -> Result<()> {
    let output = std::process::Command::new("node").arg("--version").output();
    match output {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => bail!(
            "`node --version` failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(_) => bail!(
            "`node` is not installed or not in PATH. JS/TS capsule builds require Node.js 20 or newer."
        ),
    }
}

#[derive(Deserialize)]
struct PackageJson {
    name: String,
    #[serde(default = "default_version")]
    version: String,
}

fn default_version() -> String {
    "0.0.0".to_string()
}

fn resolve_package_metadata(dir: &Path) -> Result<(String, String)> {
    let pkg_path = dir.join("package.json");
    if !pkg_path.exists() {
        bail!(
            "missing package.json at {}. JS/TS capsules require a package.json.",
            pkg_path.display()
        );
    }
    let raw = fs::read_to_string(&pkg_path)
        .with_context(|| format!("failed to read {}", pkg_path.display()))?;
    let parsed: PackageJson = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", pkg_path.display()))?;
    if parsed.name.is_empty() {
        bail!("package.json must have a non-empty `name` field");
    }
    Ok((parsed.name, parsed.version))
}

/// Locate the `@astrid-os/build` orchestrator script.
///
/// Search order:
/// 1. `$ASTRID_JS_BUILD` env var (absolute path override, dev-only).
/// 2. `<project>/node_modules/@astrid-os/build/src/index.mjs` (the
///    production path — user `npm install`'d the orchestrator).
fn locate_orchestrator(project_dir: &Path) -> Result<PathBuf> {
    if let Ok(env_path) = std::env::var("ASTRID_JS_BUILD") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Ok(p);
        }
        warn!(
            "ASTRID_JS_BUILD points to {} but file does not exist; falling back to node_modules",
            p.display()
        );
    }

    // Walk up the directory tree looking for node_modules/@astrid-os/build,
    // matching Node's own module resolution. Important for npm workspaces
    // where the orchestrator is hoisted to the workspace root.
    let mut cursor = Some(project_dir.to_path_buf());
    while let Some(dir) = cursor {
        let candidate = dir
            .join("node_modules")
            .join("@astrid-os")
            .join("build")
            .join("src")
            .join("index.mjs");
        if candidate.is_file() {
            return Ok(candidate);
        }
        cursor = dir.parent().map(Path::to_path_buf);
    }

    bail!(
        "Could not locate the @astrid-os/build orchestrator. \
         Run `npm install @astrid-os/build` in the project directory, \
         or set ASTRID_JS_BUILD to point at the orchestrator script."
    );
}

fn run_orchestrator(orchestrator: &Path, project_dir: &Path, wasm_path: &Path) -> Result<()> {
    info!("   Running {} ...", orchestrator.display());
    // CWD must be the project dir: componentize-js's source-path rewrite
    // only kicks in when the source (our generated bundle) lives inside CWD.
    // Without that, Wizer mounts only the `gen/` subdir at `/` and the
    // pre-init script can't load the source by its original absolute path.
    let status = std::process::Command::new("node")
        .current_dir(project_dir)
        .arg(orchestrator)
        .arg(project_dir)
        .arg("--out")
        .arg(wasm_path)
        .status()
        .context("failed to spawn node orchestrator")?;
    if !status.success() {
        bail!("@astrid-os/build orchestrator exited with status {status}");
    }
    Ok(())
}

fn build_manifest_content(
    dir: &Path,
    pkg_name: &str,
    pkg_version: &str,
    wasm_path: &Path,
) -> Result<String> {
    let base_toml_path = dir.join("Capsule.toml");
    if base_toml_path.exists() {
        let content = fs::read_to_string(&base_toml_path).context("failed to read Capsule.toml")?;
        // Parse to validate; the existing rust.rs builder also runs a parse
        // here. We don't currently rewrite the [[component]] file path even
        // if it mismatches — the JS orchestrator emits `<name>.wasm` and
        // the manifest's [[component]].file must match.
        content
            .parse::<toml_edit::DocumentMut>()
            .context("failed to parse Capsule.toml")?;
        return Ok(content);
    }

    let wasm_file = wasm_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("capsule.wasm");

    let default = format!(
        r#"[package]
name = "{pkg_name}"
version = "{pkg_version}"
description = ""

[[component]]
id = "{pkg_name}"
file = "{wasm_file}"
type = "executable"
"#
    );
    Ok(default)
}

fn resolve_output_dir(output: Option<&str>, project_dir: &Path) -> Result<PathBuf> {
    let out_dir = match output {
        Some(p) => PathBuf::from(p),
        None => project_dir.join("dist"),
    };
    if !out_dir.exists() {
        fs::create_dir_all(&out_dir)?;
    }
    Ok(out_dir)
}

/// Stage the capsule's `wit/` directory if present. Phase 1 omits the
/// shared SDK-contracts merge that the Rust builder does; that lands in
/// Phase 2 when the JS SDK exposes shared contract types.
fn stage_wit_directory(project_dir: &Path) -> Option<PathBuf> {
    let wit_dir = project_dir.join("wit");
    if !wit_dir.is_dir() {
        return None;
    }
    Some(wit_dir)
}
