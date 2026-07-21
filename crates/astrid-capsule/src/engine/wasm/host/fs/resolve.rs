//! Path resolution for the `astrid:fs@1.0.0` host: turn a raw guest
//! path (with possible `cwd://`, `home://`, `/tmp/`, or implicit
//! workspace scheme) into a `(physical, relative, target VFS)` triple
//! that the security gate and the VFS layer can use.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::engine::wasm::host_state::HostState;

/// URI scheme prefix for the principal's home directory.
pub(super) const HOME_SCHEME: &str = "home://";

/// URI scheme prefix for the daemon's current working directory.
pub(super) const CWD_SCHEME: &str = "cwd://";

/// Path prefix that maps to the principal's tmp directory.
pub(super) const TMP_PREFIX: &str = "/tmp/";

/// Strip leading absolute slashes or prefixes (e.g. `C:\`) so the path
/// can be joined to a confined root.
fn make_relative(requested: &str) -> &Path {
    let path = Path::new(requested);
    let mut components = path.components();
    while let Some(c) = components.clone().next() {
        if matches!(c, Component::RootDir | Component::Prefix(_)) {
            components.next();
        } else {
            break;
        }
    }
    components.as_path()
}

/// Result of resolving a path to a physical absolute location on disk.
pub(super) struct ResolvedPhysical {
    pub(super) physical: PathBuf,
    pub(super) canonical_root: PathBuf,
}

/// Compute the true physical absolute path for the security gate by
/// canonicalizing on the host filesystem. This prevents symlink bypass
/// attacks where a lexical path passes the gate but cap-std follows a
/// symlink at a later resolution step.
pub(super) fn resolve_physical_absolute(
    root: &Path,
    requested: &str,
) -> Result<ResolvedPhysical, String> {
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());

    let relative_requested = make_relative(requested);
    let joined = canonical_root.join(relative_requested);

    let mut current_check = joined.clone();
    let mut unexisting_components = Vec::new();

    loop {
        if std::fs::symlink_metadata(&current_check).is_ok() {
            let canonical =
                std::fs::canonicalize(&current_check).unwrap_or_else(|_| current_check.clone());
            let mut final_path = canonical;
            for comp in unexisting_components.into_iter().rev() {
                final_path.push(comp);
            }
            if !final_path.starts_with(&canonical_root) {
                return Err(format!(
                    "path escapes root boundary: {requested} resolves to {}",
                    final_path.display()
                ));
            }
            return Ok(ResolvedPhysical {
                physical: final_path,
                canonical_root,
            });
        }
        if let Some(parent) = current_check.parent() {
            if let Some(file_name) = current_check.file_name() {
                unexisting_components.push(file_name.to_os_string());
            }
            current_check = parent.to_path_buf();
        } else {
            break;
        }
    }

    if !joined.starts_with(&canonical_root) {
        return Err(format!(
            "path escapes root boundary: {requested} resolves to {}",
            joined.display()
        ));
    }

    Ok(ResolvedPhysical {
        physical: joined,
        canonical_root,
    })
}

/// Resolve a path while preserving its final directory entry instead of
/// following a final symbolic link. Every parent is still canonicalized and
/// confined beneath `root`, so callers can safely implement lstat semantics
/// without turning the final link target into authority.
fn resolve_physical_symlink(root: &Path, requested: &str) -> Result<ResolvedPhysical, String> {
    let relative = make_relative(requested);
    if relative.as_os_str().is_empty() || relative == Path::new(".") {
        return resolve_physical_absolute(root, "");
    }
    let leaf = relative
        .file_name()
        .ok_or_else(|| format!("invalid non-following path: {requested}"))?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let parent = resolve_physical_absolute(root, parent.to_string_lossy().as_ref())?;
    let physical = parent.physical.join(leaf);
    if !physical.starts_with(&parent.canonical_root) {
        return Err(format!(
            "path escapes root boundary: {requested} resolves to {}",
            physical.display()
        ));
    }
    Ok(ResolvedPhysical {
        physical,
        canonical_root: parent.canonical_root,
    })
}

/// Which VFS target a resolved path points at.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum VfsTarget {
    Workspace,
    Home,
    Tmp,
}

/// Phase-1 resolution: physical path for the security gate + VFS-relative
/// path + which VFS bundle to use.
pub(super) struct ResolvedPath {
    pub(super) physical: PathBuf,
    pub(super) relative: PathBuf,
    pub(super) target: VfsTarget,
}

/// Phase-2 resolution: the VFS instance and capability handle to use
/// for the actual filesystem operation.
pub(super) struct ResolvedVfsPath {
    pub(super) relative: PathBuf,
    pub(super) vfs: Arc<dyn astrid_vfs::Vfs>,
    pub(super) handle: astrid_capabilities::DirHandle,
}

/// Phase 1: resolve a raw guest path to a physical path and determine
/// whether it targets the workspace / home / tmp VFS. Uses the effective
/// mounts (per-invocation > load-time) so cross-principal calls land in
/// the right tree.
pub(super) fn resolve_path(state: &HostState, raw_path: &str) -> Result<ResolvedPath, String> {
    resolve_path_with(state, raw_path, true)
}

/// Resolve a path without following its final symbolic link.
pub(super) fn resolve_path_symlink(
    state: &HostState,
    raw_path: &str,
) -> Result<ResolvedPath, String> {
    resolve_path_with(state, raw_path, false)
}

fn resolve_path_with(
    state: &HostState,
    raw_path: &str,
    follow_final: bool,
) -> Result<ResolvedPath, String> {
    let resolve = |root: &Path, requested: &str| {
        if follow_final {
            resolve_physical_absolute(root, requested)
        } else {
            resolve_physical_symlink(root, requested)
        }
    };
    if let Some(stripped) = raw_path.strip_prefix(CWD_SCHEME) {
        let resolved = resolve(&state.workspace_root, stripped)?;
        let relative = resolved
            .physical
            .strip_prefix(&resolved.canonical_root)
            .map_err(|_| "resolved cwd path escaped canonical root".to_string())?
            .to_path_buf();
        Ok(ResolvedPath {
            physical: resolved.physical,
            relative,
            target: VfsTarget::Workspace,
        })
    } else if let Some(stripped) = raw_path.strip_prefix(HOME_SCHEME) {
        let home = state
            .effective_home()
            .ok_or_else(|| "home:// scheme is not available for this principal".to_string())?;
        let resolved = resolve(&home.root, stripped)?;
        let relative = resolved
            .physical
            .strip_prefix(&resolved.canonical_root)
            .map_err(|_| "resolved home path escaped canonical root".to_string())?
            .to_path_buf();
        Ok(ResolvedPath {
            physical: resolved.physical,
            relative,
            target: VfsTarget::Home,
        })
    } else if raw_path.starts_with(TMP_PREFIX) || raw_path == "/tmp" {
        let tmp_mount = state
            .effective_tmp()
            .ok_or_else(|| "/tmp is not available for this principal".to_string())?;
        let stripped = raw_path
            .strip_prefix(TMP_PREFIX)
            .or_else(|| raw_path.strip_prefix("/tmp"))
            .unwrap_or("");
        let resolved = resolve(&tmp_mount.root, stripped)?;
        let relative = resolved
            .physical
            .strip_prefix(&resolved.canonical_root)
            .map_err(|_| "resolved /tmp path escaped canonical root".to_string())?
            .to_path_buf();
        Ok(ResolvedPath {
            physical: resolved.physical,
            relative,
            target: VfsTarget::Tmp,
        })
    } else {
        let resolved = resolve(&state.workspace_root, raw_path)?;
        let relative = resolved
            .physical
            .strip_prefix(&resolved.canonical_root)
            .map_err(|_| "resolved path escaped canonical root".to_string())?
            .to_path_buf();
        Ok(ResolvedPath {
            physical: resolved.physical,
            relative,
            target: VfsTarget::Workspace,
        })
    }
}

/// Phase 2: pick the VFS instance + capability handle for `resolved`.
pub(super) fn resolve_vfs(
    state: &HostState,
    resolved: &ResolvedPath,
) -> Result<ResolvedVfsPath, String> {
    let (vfs, handle) = match resolved.target {
        VfsTarget::Home => {
            let m = state
                .effective_home()
                .ok_or_else(|| "home:// VFS is not mounted".to_string())?;
            (m.vfs.clone(), m.handle.clone())
        },
        VfsTarget::Tmp => {
            let m = state
                .effective_tmp()
                .ok_or_else(|| "/tmp VFS is not mounted".to_string())?;
            (m.vfs.clone(), m.handle.clone())
        },
        VfsTarget::Workspace => (state.vfs.clone(), state.vfs_root_handle.clone()),
    };
    Ok(ResolvedVfsPath {
        relative: resolved.relative.clone(),
        vfs,
        handle,
    })
}
