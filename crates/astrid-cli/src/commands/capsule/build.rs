//! `astrid capsule build` — compile + package, then bake the tool surface.
//!
//! The heavy lifting (cargo compile → component wrap → `.capsule` pack)
//! runs in the standalone `astrid-build` companion binary, which is kept
//! lean (no wasmtime). After it produces the archive, this layer — which
//! already links the capsule engine — instantiates the freshly-built
//! component and captures its `#[astrid::tool]` descriptors, baking them
//! into the archive as `tools.json`. Install reads that file into
//! `meta.json` so the tool surface is a static, offline-inspectable
//! artifact (see `astrid capsule show`).
//!
//! Capture is **best-effort and non-fatal**: a build that compiles and
//! packs is a success even if descriptor capture fails — the tools just
//! won't be pre-baked (the runtime describe fan-out still works). We warn
//! loudly so the omission is visible.

use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use astrid_capsule::describe_capsule_tools;

use crate::bootstrap;
use crate::theme::Theme;

/// Run `astrid capsule build`, then bake captured tool descriptors into
/// the produced `.capsule` archive.
pub(crate) async fn run(
    path: Option<&str>,
    output: Option<&str>,
    project_type: Option<&str>,
    from_mcp_json: Option<&str>,
) -> Result<ExitCode> {
    // Resolve the output dir BEFORE the build so we can tell which
    // `.capsule` the build produced (newest archive after vs before).
    let out_dir = resolve_output_dir(output)?;
    let before = newest_capsule_mtime(&out_dir);

    let status = bootstrap::run_build_companion(path, output, project_type, from_mcp_json)?;
    if status != ExitCode::SUCCESS {
        return Ok(status);
    }

    // MCP-import builds (`--from-mcp-json`) and explicit non-rust types
    // don't produce a WASM tool surface — nothing to capture.
    if from_mcp_json.is_some() || project_type.is_some_and(|t| t != "rust") {
        return Ok(ExitCode::SUCCESS);
    }

    // Resolve the package name from the source manifest so we can locate the
    // produced archive deterministically by name (`<name>.capsule`) rather
    // than by mtime alone — robust against a stale archive or a concurrent
    // build in the same output dir.
    let source = path.unwrap_or(".");
    let package_name =
        astrid_capsule::discovery::load_manifest(&Path::new(source).join("Capsule.toml"))
            .map(|m| m.package.name)
            .ok();

    if let Err(e) = bake_tools_into_latest(&out_dir, package_name.as_deref(), before).await {
        eprintln!(
            "{}",
            Theme::warning(&format!(
                "tool descriptors not baked into the capsule ({e:#}); the runtime describe \
                 fan-out still works, but `astrid capsule show` won't pre-list this capsule's tools"
            ))
        );
    }

    Ok(ExitCode::SUCCESS)
}

/// Capture tools from the just-built archive and inject `tools.json`.
async fn bake_tools_into_latest(
    out_dir: &Path,
    package_name: Option<&str>,
    before: Option<std::time::SystemTime>,
) -> Result<()> {
    let archive = locate_built_capsule(out_dir, package_name, before)
        .context("could not locate the built .capsule archive")?;

    // Unpack into a temp dir so we get the canonical install-staging
    // layout (`Capsule.toml` + `<crate>.wasm` co-located), which is what
    // `describe_capsule_tools` needs to instantiate the component.
    let staging = tempfile::tempdir().context("failed to create staging dir for capture")?;
    unpack_capsule(&archive, staging.path())?;

    // The WASM engine drives itself on the ambient (multi-thread) tokio
    // runtime via `block_in_place`, so capture is awaited inline, not run
    // on a nested runtime (which would panic "runtime within a runtime").
    // A capsule that embeds an MCP server surfaces tools through the MCP
    // engine, not `#[astrid::tool]` — so the WASM `tool_describe` capture is
    // *incomplete* for it. Leave such a capsule unmarked (no `tools.json`) so
    // the installed `meta.json` records `tools: None` and a consumer discovers
    // its full surface at runtime instead of trusting a partial static set.
    if manifest_declares_mcp_server(staging.path()) {
        return Ok(());
    }

    let tools = describe_capsule_tools(staging.path())
        .await
        .context("failed to capture tool descriptors")?;

    // Always write `tools.json` when the capture succeeds — even for a
    // zero-tool capsule. The file's presence is the "surface captured" marker
    // that lets a consumer trust an empty set as authoritative ("no tools")
    // rather than "not yet baked"; an empty array is `Some(vec![])` on install.
    let json = serde_json::to_vec_pretty(&tools).context("failed to serialize tool descriptors")?;
    append_file_to_capsule(&archive, "tools.json", &json)
        .context("failed to inject tools.json into the capsule archive")?;

    println!(
        "{}",
        Theme::success(&format!(
            "captured {} tool descriptor(s) into {}",
            tools.len(),
            archive.display()
        ))
    );
    Ok(())
}

/// Whether the capsule unpacked at `dir` declares an `[[mcp_server]]` — its
/// WASM `tool_describe` capture would be incomplete, so it must be left
/// unmarked. A manifest that fails to load is treated as "no MCP server"
/// (capture proceeds); the describe step surfaces any real load problem.
fn manifest_declares_mcp_server(dir: &Path) -> bool {
    astrid_capsule::discovery::load_manifest(&dir.join("Capsule.toml"))
        .is_ok_and(|m| !m.mcp_servers.is_empty())
}

/// Resolve the build output directory, mirroring `astrid-build`'s default
/// (`<cwd>/dist` when `--output` is absent). We do not create it — the
/// build did.
fn resolve_output_dir(output: Option<&str>) -> Result<PathBuf> {
    match output {
        Some(p) => Ok(PathBuf::from(p)),
        None => Ok(std::env::current_dir()
            .context("failed to resolve current directory")?
            .join("dist")),
    }
}

/// The newest `*.capsule` modification time in `dir`, if any. Used to
/// disambiguate the archive the build just wrote.
fn newest_capsule_mtime(dir: &Path) -> Option<std::time::SystemTime> {
    capsule_archives(dir)
        .into_iter()
        .filter_map(|p| std::fs::metadata(&p).and_then(|m| m.modified()).ok())
        .max()
}

/// The `.capsule` the build just produced. Prefers a deterministic match on
/// the package name (`<name>.capsule`, with the underscore variant as a
/// safety net), and only falls back to the mtime heuristic — the newest
/// archive at or after the pre-build high-water mark — when the name is
/// unknown or no name-matched file exists.
fn locate_built_capsule(
    dir: &Path,
    package_name: Option<&str>,
    before: Option<std::time::SystemTime>,
) -> Result<PathBuf> {
    if let Some(name) = package_name {
        for candidate in [
            dir.join(format!("{name}.capsule")),
            dir.join(format!("{}.capsule", name.replace('-', "_"))),
        ] {
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for path in capsule_archives(dir) {
        let Ok(mtime) = std::fs::metadata(&path).and_then(|m| m.modified()) else {
            continue;
        };
        if before.is_some_and(|b| mtime < b) {
            continue;
        }
        if newest.as_ref().is_none_or(|(t, _)| mtime >= *t) {
            newest = Some((mtime, path));
        }
    }
    newest
        .map(|(_, p)| p)
        .with_context(|| format!("no .capsule archive found in {}", dir.display()))
}

/// All `*.capsule` files directly under `dir`.
fn capsule_archives(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "capsule"))
        .collect()
}

/// Unpack a `.capsule` (tar.gz) into `dest`, with the same path-traversal
/// and symlink defenses the install path enforces.
fn unpack_capsule(archive: &Path, dest: &Path) -> Result<()> {
    let file = std::fs::File::open(archive)
        .with_context(|| format!("failed to open {}", archive.display()))?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    for entry in tar.entries().context("failed to read archive entries")? {
        let mut entry = entry.context("failed to read archive entry")?;
        let entry_path = entry.path().context("invalid path in archive")?;
        if entry_path.is_absolute()
            || entry_path
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            bail!("malicious archive: invalid path '{}'", entry_path.display());
        }
        if entry.header().entry_type().is_symlink() || entry.header().entry_type().is_hard_link() {
            bail!(
                "malicious archive: links not allowed ('{}')",
                entry_path.display()
            );
        }
        let out_path = dest.join(&entry_path);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        entry
            .unpack(&out_path)
            .with_context(|| format!("failed to unpack {}", out_path.display()))?;
    }
    Ok(())
}

/// Append a single in-memory file at the archive root by repacking the
/// `.capsule` (tar.gz). A streaming append isn't possible on a gzip
/// stream, so we re-unpack to a temp tree, add the file, and re-pack —
/// preserving every existing entry.
fn append_file_to_capsule(archive: &Path, name: &str, contents: &[u8]) -> Result<()> {
    let staging = tempfile::tempdir().context("failed to create repack staging dir")?;
    unpack_capsule(archive, staging.path())?;
    std::fs::write(staging.path().join(name), contents)
        .with_context(|| format!("failed to write {name} into repack staging"))?;

    let tmp_out = archive.with_extension("capsule.tmp");
    {
        let file = std::fs::File::create(&tmp_out)
            .with_context(|| format!("failed to create {}", tmp_out.display()))?;
        let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(enc);
        builder.follow_symlinks(true);
        builder
            .append_dir_all(".", staging.path())
            .context("failed to repack capsule contents")?;
        builder
            .into_inner()
            .context("failed to finish tar stream")?
            .finish()
            .context("failed to finish gzip stream")?;
    }
    std::fs::rename(&tmp_out, archive)
        .with_context(|| format!("failed to replace {}", archive.display()))?;
    Ok(())
}
