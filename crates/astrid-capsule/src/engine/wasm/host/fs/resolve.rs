//! Path resolution for the `astrid:fs@1.0.0` host: turn a raw guest
//! path (with possible `cwd://`, `home://`, `/tmp/`, or implicit
//! workspace scheme) into a gate spelling, optional physical path, relative
//! VFS path, and target.  Workspace/tmp retain physical canonicalization;
//! storage-backed `home://` is a logical namespace and never touches host
//! paths.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::engine::wasm::host_state::HostState;

/// URI scheme prefix for the principal's home directory.
pub(super) const HOME_SCHEME: &str = "home://";

/// URI scheme prefix for the daemon's current working directory.
pub(super) const CWD_SCHEME: &str = "cwd://";
/// Logical scheme used for the path-free canonical Astrid workspace.
pub(super) const WORKSPACE_SCHEME: &str = "workspace://";

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
/// canonicalizing the existing prefix and appending only absent children.
pub(super) fn resolve_physical_absolute(
    root: &Path,
    requested: &str,
) -> Result<ResolvedPhysical, String> {
    let canonical_root = root
        .canonicalize()
        .map_err(|error| format!("cannot resolve filesystem root {}: {error}", root.display()))?;
    let joined = canonical_root.join(make_relative(requested));
    let mut existing = joined.as_path();
    let mut missing = Vec::new();
    let mut physical = loop {
        match std::fs::symlink_metadata(existing) {
            Ok(_) => {
                break existing.canonicalize().map_err(|error| {
                    format!(
                        "cannot resolve existing path {}: {error}",
                        existing.display()
                    )
                })?;
            },
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && existing != canonical_root =>
            {
                let name = existing.file_name().ok_or_else(|| {
                    format!("cannot resolve missing path component in {requested}")
                })?;
                missing.push(name);
                existing = existing
                    .parent()
                    .ok_or_else(|| format!("path escapes root boundary: {requested}"))?;
            },
            Err(error) => return Err(format!("cannot inspect {}: {error}", existing.display())),
        }
    };
    for name in missing.into_iter().rev() {
        physical.push(name);
    }
    if !physical.starts_with(&canonical_root) {
        return Err(format!(
            "path escapes root boundary: {requested} resolves to {}",
            physical.display()
        ));
    }
    Ok(ResolvedPhysical {
        physical,
        canonical_root,
    })
}

/// Phase-1 resolution: physical path for the security gate + VFS-relative
/// path + which VFS bundle to use.
pub(super) struct ResolvedPath {
    /// Stable spelling passed to the manifest gate and audit sink.
    pub(super) gate_path: String,
    /// Host path for workspace/tmp and legacy physical home mounts. `None`
    /// for AstridFilesystem-backed home namespaces.
    pub(super) physical: Option<PathBuf>,
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
    if let Some(stripped) = raw_path.strip_prefix(CWD_SCHEME) {
        if state.effective_workspace().is_some_and(|mount| {
            matches!(
                &mount.location,
                crate::engine::wasm::host_state::PrincipalMountLocation::AstridFilesystem
            )
        }) {
            return resolve_logical_workspace(stripped);
        }
        let resolved = resolve_physical_absolute(&state.workspace_root, stripped)?;
        let relative = resolved
            .physical
            .strip_prefix(&resolved.canonical_root)
            .map_err(|_| "resolved cwd path escaped canonical root".to_string())?
            .to_path_buf();
        Ok(ResolvedPath {
            gate_path: resolved.physical.to_string_lossy().into_owned(),
            physical: Some(resolved.physical),
            relative,
            target: VfsTarget::Workspace,
        })
    } else if let Some(stripped) = raw_path.strip_prefix(HOME_SCHEME) {
        let home = state
            .effective_home()
            .ok_or_else(|| "home:// scheme is not available for this principal".to_string())?;
        if matches!(
            &home.location,
            crate::engine::wasm::host_state::PrincipalMountLocation::AstridFilesystem
        ) {
            let path = astrid_storage::FilesystemPath::new(stripped.to_owned())
                .map_err(|error| error.to_string())?;
            let gate_path = if path.as_str().is_empty() {
                HOME_SCHEME.to_owned()
            } else {
                format!("{HOME_SCHEME}{}", path.as_str())
            };
            return Ok(ResolvedPath {
                gate_path,
                physical: None,
                relative: PathBuf::from(path.as_str()),
                target: VfsTarget::Home,
            });
        }
        let crate::engine::wasm::host_state::PrincipalMountLocation::Native(root) = &home.location
        else {
            return Err("home:// storage mount did not resolve logically".to_owned());
        };
        let resolved = resolve_physical_absolute(root, stripped)?;
        let relative = resolved
            .physical
            .strip_prefix(&resolved.canonical_root)
            .map_err(|_| "resolved home path escaped canonical root".to_string())?
            .to_path_buf();
        Ok(ResolvedPath {
            gate_path: resolved.physical.to_string_lossy().into_owned(),
            physical: Some(resolved.physical),
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
        let crate::engine::wasm::host_state::PrincipalMountLocation::Native(root) =
            &tmp_mount.location
        else {
            return Err("/tmp mount is not a native scratch directory".to_owned());
        };
        let resolved = resolve_physical_absolute(root, stripped)?;
        let relative = resolved
            .physical
            .strip_prefix(&resolved.canonical_root)
            .map_err(|_| "resolved /tmp path escaped canonical root".to_string())?
            .to_path_buf();
        Ok(ResolvedPath {
            gate_path: resolved.physical.to_string_lossy().into_owned(),
            physical: Some(resolved.physical),
            relative,
            target: VfsTarget::Tmp,
        })
    } else {
        if state.effective_workspace().is_some_and(|mount| {
            matches!(
                &mount.location,
                crate::engine::wasm::host_state::PrincipalMountLocation::AstridFilesystem
            )
        }) {
            return resolve_logical_workspace(raw_path);
        }
        let resolved = resolve_physical_absolute(&state.workspace_root, raw_path)?;
        let relative = resolved
            .physical
            .strip_prefix(&resolved.canonical_root)
            .map_err(|_| "resolved path escaped canonical root".to_string())?
            .to_path_buf();
        Ok(ResolvedPath {
            gate_path: resolved.physical.to_string_lossy().into_owned(),
            physical: Some(resolved.physical),
            relative,
            target: VfsTarget::Workspace,
        })
    }
}

fn resolve_logical_workspace(raw_path: &str) -> Result<ResolvedPath, String> {
    // Guest paths use ordinary current-directory spelling; storage names
    // remain canonical. Do not collapse parent traversal or empty components.
    let relative = raw_path
        .trim_start_matches('/')
        .split('/')
        .filter(|component| *component != ".")
        .collect::<Vec<_>>()
        .join("/");
    let path = astrid_storage::FilesystemPath::new(relative).map_err(|error| error.to_string())?;
    let gate_path = if path.as_str().is_empty() {
        WORKSPACE_SCHEME.to_owned()
    } else {
        format!("{WORKSPACE_SCHEME}{}", path.as_str())
    };
    Ok(ResolvedPath {
        gate_path,
        physical: None,
        relative: PathBuf::from(path.as_str()),
        target: VfsTarget::Workspace,
    })
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
        VfsTarget::Workspace => {
            let mount = state
                .effective_workspace()
                .ok_or_else(|| "workspace VFS is not mounted".to_owned())?;
            (mount.vfs.clone(), mount.handle.clone())
        },
    };
    Ok(ResolvedVfsPath {
        relative: resolved.relative.clone(),
        vfs,
        handle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_paths_require_a_resolved_root_and_allow_new_children() {
        let root = tempfile::tempdir().unwrap();
        let absent = root.path().join("absent");
        assert!(resolve_physical_absolute(&absent, "child").is_err());
        let result = resolve_physical_absolute(root.path(), "absent/child").unwrap();
        assert_eq!(
            result.physical,
            root.path().canonicalize().unwrap().join("absent/child")
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_unresolvable_link_is_not_an_absent_child() {
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("absent", root.path().join("link")).unwrap();
        assert!(resolve_physical_absolute(root.path(), "link").is_err());
        assert!(resolve_physical_absolute(root.path(), "link/child").is_err());
    }

    #[test]
    fn logical_workspace_accepts_current_directory_spellings() {
        for raw in ["", "/", ".", "./", "/.", "././"] {
            let resolved = resolve_logical_workspace(raw).expect("workspace root resolves");
            assert_eq!(resolved.gate_path, WORKSPACE_SCHEME, "{raw:?}");
            assert_eq!(resolved.relative, PathBuf::new(), "{raw:?}");
            assert!(resolved.physical.is_none());
            assert!(matches!(resolved.target, VfsTarget::Workspace));
        }
        for raw in ["file", "./file", "././file", "/./file"] {
            let resolved = resolve_logical_workspace(raw).expect("workspace file resolves");
            assert_eq!(resolved.gate_path, "workspace://file", "{raw:?}");
            assert_eq!(resolved.relative, PathBuf::from("file"), "{raw:?}");
        }
        let nested = resolve_logical_workspace("dir/./file").expect("nested current directory");
        assert_eq!(nested.gate_path, "workspace://dir/file");
        assert_eq!(nested.relative, PathBuf::from("dir/file"));
    }

    #[test]
    fn logical_workspace_rejects_noncanonical_or_parent_paths() {
        for raw in [
            "..",
            "../file",
            "./../file",
            "dir/../file",
            "dir//file",
            "file\0",
        ] {
            assert!(resolve_logical_workspace(raw).is_err(), "{raw:?}");
        }
    }
}
