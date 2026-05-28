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
//! ## Symlink posture
//!
//! `npm install` populates `node_modules/.bin/` with **file**
//! symlinks pointing to executables elsewhere under
//! `node_modules/`. We dereference those into regular files (`cp -rL`
//! behaviour) so the runtime sees real bytes regardless of how the
//! source tree was provisioned.
//!
//! Two threat scenarios that the naive `metadata().is_dir() →
//! recurse` shape opens up:
//!
//! 1. **Sandbox escape**: a malicious capsule directory ships
//!    `secrets -> /etc/shadow` or `creds -> ~/.ssh`. Following the
//!    symlink during install copies the host's sensitive file into
//!    the per-capsule directory, where the capsule's WASM
//!    sandbox can read it via `home://` VFS or a `[[mcp_server]]`
//!    local-command script.
//!
//! 2. **Disk / stack exhaustion**: a symlink pointing to the source
//!    root (or an ancestor) loops the recursion infinitely.
//!
//! Defense:
//!
//! * **Directory symlinks are refused outright.** `node_modules/.bin/`
//!   are file symlinks, never directory symlinks; we have no legit
//!   use case for the directory case.
//! * **File symlinks must resolve inside the source root.** Canonical
//!   target compared with `Path::starts_with` against the canonical
//!   source root. Defends against `lib.so -> /etc/shadow` plus any
//!   path containing `..` that escapes the tree.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

/// Recursively copy a capsule source tree to its install target.
///
/// Excludes:
/// * `*.wasm` files at any depth (the binary lives in `bin/`,
///   content-addressed).
/// * The top-level `wit/` directory (content-addressed in `wit/`).
/// * `.git`, `target`, and the top-level `dist/` directory
///   (build/source-control artefacts the runtime never reads).
///
/// Refuses to follow directory symlinks (sandbox-escape /
/// stack-exhaustion vector). File symlinks are dereferenced only when
/// their canonical target stays within the source root.
///
/// # Errors
///
/// Returns an error on filesystem failures, refused directory
/// symlinks, file symlinks pointing outside the source root, or any
/// path that fails to canonicalise.
pub fn copy_capsule_dir(src: &Path, dst: &Path) -> anyhow::Result<()> {
    let canonical_root = std::fs::canonicalize(src)
        .with_context(|| format!("failed to canonicalize source root {}", src.display()))?;
    copy_capsule_dir_inner(src, dst, true, &canonical_root)
}

fn copy_capsule_dir_inner(
    src: &Path,
    dst: &Path,
    is_root: bool,
    canonical_root: &Path,
) -> anyhow::Result<()> {
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
            copy_capsule_dir_inner(&src_path, &dst_path, false, canonical_root)?;
        } else if file_type.is_symlink() {
            handle_symlink(&src_path, &dst_path, canonical_root)?;
        } else if !is_wasm(&src_path) {
            std::fs::copy(&src_path, &dst_path)
                .with_context(|| format!("failed to copy {}", src_path.display()))?;
        }
    }
    Ok(())
}

/// Resolve a symlink and decide whether to copy it. Returns Ok(())
/// on safe file symlinks (copied) and silently on refused cases that
/// shouldn't break the install (a dangling symlink, for instance);
/// returns Err on outright security failures.
fn handle_symlink(src_path: &Path, dst_path: &Path, canonical_root: &Path) -> anyhow::Result<()> {
    // Canonicalize first — resolves the symlink chain to a real path
    // we can reason about. A dangling symlink errors here; we treat
    // that as a hard install failure because a capsule tree with
    // broken symlinks isn't trustworthy.
    let resolved: PathBuf = std::fs::canonicalize(src_path).with_context(|| {
        format!(
            "symlink {} could not be canonicalized (dangling or denied)",
            src_path.display()
        )
    })?;

    // Hard-refuse anything that resolves outside the source tree.
    // `Path::starts_with` on canonical paths is sound: canonicalize
    // has already collapsed every `..` and resolved every symlink in
    // both the resolved target and the root, so there's no path-
    // traversal escape hatch left.
    if !resolved.starts_with(canonical_root) {
        bail!(
            "symlink {} resolves outside the capsule source root ({}); \
             refusing to copy (sandbox-escape vector)",
            src_path.display(),
            resolved.display()
        );
    }

    let resolved_meta = std::fs::metadata(&resolved)
        .with_context(|| format!("stat resolved symlink target {}", resolved.display()))?;

    if resolved_meta.is_dir() {
        // Directory symlinks open the door to (a) infinite recursion
        // when the link points to an ancestor and (b) ballooning
        // copies of legitimately-shared trees. `npm install` only
        // produces FILE symlinks for `.bin/` entries; we don't need
        // directory symlinks for any current capsule layout. Refuse
        // them outright.
        bail!(
            "directory symlink {} not allowed in capsule source tree \
             (refusing to recurse — risk of cycles / cross-tree copies)",
            src_path.display()
        );
    }

    if is_wasm(src_path) {
        // Same filter as the regular-file branch — `.wasm` lives in
        // `bin/<hash>.wasm`, not in the per-capsule dir.
        return Ok(());
    }

    // File symlink, target inside the root: copy the resolved
    // bytes. `std::fs::copy` follows the link by default.
    std::fs::copy(src_path, dst_path)
        .with_context(|| format!("failed to copy {}", src_path.display()))?;
    Ok(())
}

fn is_wasm(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some("wasm")
}
