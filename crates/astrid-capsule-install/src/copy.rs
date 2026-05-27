//! Per-capsule directory copy.
//!
//! The destination ends up holding only what the runtime actually
//! reads per-capsule: `Capsule.toml`, `meta.json`, `.env.json`, plus
//! tier-2 resources (`dist/`, `node_modules/`, MCP command scripts).
//! The capsule's `.wasm` binary and `wit/` directory are
//! deliberately excluded — those live in the shared content-addressed
//! stores under `home.bin_dir()` / `home.wit_dir()` and are
//! referenced from `meta.json` by hash.
//!
//! Symlinks are dereferenced (`cp -rL`) because `npm install` creates
//! symlinks in `node_modules/.bin/` and the archiver also
//! dereferences them via `follow_symlinks(true)`.

use std::path::Path;

use anyhow::Context;

/// Recursively copy a capsule source tree to its install target.
///
/// Excludes:
/// * `*.wasm` files at any depth (the binary lives in `bin/`,
///   content-addressed).
/// * The top-level `wit/` directory (content-addressed in `wit/`).
/// * `.git`, `target`, and the top-level `dist/` directory
///   (build/source-control artefacts the runtime never reads).
pub fn copy_capsule_dir(src: &Path, dst: &Path) -> anyhow::Result<()> {
    copy_capsule_dir_inner(src, dst, true)
}

fn copy_capsule_dir_inner(src: &Path, dst: &Path, is_root: bool) -> anyhow::Result<()> {
    std::fs::create_dir_all(dst).with_context(|| format!("failed to create {}", dst.display()))?;

    for entry in
        std::fs::read_dir(src).with_context(|| format!("failed to read {}", src.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let name = entry.file_name();
        let dst_path = dst.join(&name);

        if file_type.is_dir() {
            // Always skip .git and target. Skip dist at the top level only —
            // inside node_modules, dist/ contains compiled library code that
            // Tier 2 capsules need at runtime.
            // Skip top-level wit/ — content-addressed into home.wit_dir() instead.
            if name == ".git" || name == "target" || (is_root && (name == "dist" || name == "wit"))
            {
                continue;
            }
            copy_capsule_dir_inner(&src_path, &dst_path, false)?;
        } else if file_type.is_symlink() {
            // Dereference symlinks: resolve to the target's content and copy
            // as a regular file. Handles npm's node_modules/.bin/ symlinks.
            // fs::copy follows symlinks by default (reads the target, not the link).
            let metadata = std::fs::metadata(&src_path)
                .with_context(|| format!("symlink target not found for {}", src_path.display()))?;
            if metadata.is_dir() {
                copy_capsule_dir_inner(&src_path, &dst_path, false)?;
            } else if !is_wasm(&src_path) {
                std::fs::copy(&src_path, &dst_path)
                    .with_context(|| format!("failed to copy {}", src_path.display()))?;
            }
        } else if !is_wasm(&src_path) {
            std::fs::copy(&src_path, &dst_path)
                .with_context(|| format!("failed to copy {}", src_path.display()))?;
        }
    }
    Ok(())
}

fn is_wasm(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some("wasm")
}
