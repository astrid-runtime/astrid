//! Path resolution for capsule install destinations.

use std::path::{Path, PathBuf};

use anyhow::Context;
use astrid_core::dirs::{AstridHome, WorkspaceLayout};
use astrid_core::{PrincipalId, PrincipalUid};

/// The principal a non-workspace install targets.
///
/// Non-workspace installs currently land in the local bootstrap principal's
/// home. That does not make `default` shared: visibility and execution are
/// still controlled by each caller's principal profile, and env/secrets are
/// stored under the caller principal. Future caller-scoped installs should
/// thread an explicit principal through `InstallOptions` instead of reusing
/// this legacy resolver.
#[must_use]
pub fn install_principal() -> astrid_core::PrincipalId {
    astrid_core::PrincipalId::default()
}

/// Resolve the directory a capsule should be installed into.
///
/// This legacy resolver is retained for explicit workspace/external-cache
/// callers. Authoritative non-workspace installs must use the
/// owner/digest-scoped cache resolver; the durable package and metadata
/// authority lives in Astrid storage.
pub fn resolve_target_dir(home: &AstridHome, id: &str, workspace: bool) -> anyhow::Result<PathBuf> {
    resolve_target_dir_with_layout(home, id, workspace, &WorkspaceLayout::default())
}

/// Resolve a capsule target using an explicit workspace layout.
pub fn resolve_target_dir_with_layout(
    home: &AstridHome,
    id: &str,
    workspace: bool,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<PathBuf> {
    resolve_target_dir_for_with_layout(home, &install_principal(), id, workspace, workspace_layout)
}

/// Resolve the directory a capsule should be installed into for `principal`.
pub fn resolve_target_dir_for(
    home: &AstridHome,
    principal: &PrincipalId,
    id: &str,
    workspace: bool,
) -> anyhow::Result<PathBuf> {
    resolve_target_dir_for_with_layout(home, principal, id, workspace, &WorkspaceLayout::default())
}

/// Resolve a capsule target for `principal` using an explicit workspace layout.
pub fn resolve_target_dir_for_with_layout(
    home: &AstridHome,
    principal: &PrincipalId,
    id: &str,
    workspace: bool,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<PathBuf> {
    let workspace_root = if workspace {
        Some(std::env::current_dir().context("could not determine current directory")?)
    } else {
        None
    };
    resolve_target_dir_for_in_workspace(
        home,
        principal,
        id,
        workspace,
        workspace_root.as_deref(),
        workspace_layout,
    )
}

/// Resolve a capsule target using an explicit workspace root and layout.
pub fn resolve_target_dir_for_in_workspace(
    home: &AstridHome,
    principal: &PrincipalId,
    id: &str,
    workspace: bool,
    workspace_root: Option<&Path>,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<PathBuf> {
    if workspace {
        let root = workspace_root.context("workspace install requires a workspace root")?;
        let selection = workspace_layout
            .resolve(root)
            .context("selected workspace state path is unsafe")?;
        selection
            .resolve_directory(Path::new("capsules").join(id))
            .context("workspace capsule target is unsafe")
    } else {
        let _ = principal;
        Ok(home.run_dir().join("capsules").join(id))
    }
}

/// Resolve the disposable materialization directory for an authoritative
/// package generation.
///
/// A cache path is scoped by the immutable owner UID, capsule ID, and exact
/// archive digest. The durable registry remains the authority: this path is
/// only a private host cache for APIs that still require a directory. The
/// owner and digest components are deliberately part of the path so two
/// principals installing the same ID, or two generations of one capsule,
/// cannot reuse each other's residue.
pub fn resolve_cache_target_dir(
    home: &AstridHome,
    owner_uid: PrincipalUid,
    id: &str,
    archive_digest: &str,
    workspace: bool,
    workspace_root: Option<&Path>,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<PathBuf> {
    validate_cache_component("capsule id", id, false)?;
    validate_cache_component("archive digest", archive_digest, true)?;
    let uid = owner_uid.to_string();
    if workspace {
        let root = workspace_root.context("workspace install requires a workspace root")?;
        let selection = workspace_layout
            .resolve(root)
            .context("selected workspace state path is unsafe")?;
        selection
            .resolve_directory(
                Path::new("capsules")
                    .join(uid)
                    .join(id)
                    .join(archive_digest),
            )
            .context("workspace capsule cache target is unsafe")
    } else {
        let target = home
            .run_dir()
            .join("capsules")
            .join(uid)
            .join(id)
            .join(archive_digest);
        astrid_core::platform_fs::verify_no_redirects(&target)
            .context("capsule cache target is redirected or unsafe")?;
        Ok(target)
    }
}

fn validate_cache_component(label: &str, value: &str, digest: bool) -> anyhow::Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.contains("..")
        && (!digest
            || (value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))))
        && Path::new(value)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)));
    if !valid {
        anyhow::bail!("{label} is not a canonical cache component")
    }
    Ok(())
}

/// Remove every disposable user capsule materialization from the runtime
/// cache after validating the complete tree without following redirects.
///
/// Durable packages are never touched. A fresh materialization is created
/// from a verified storage snapshot when needed, so deleting stale or
/// interrupted cache generations at boot is safe and avoids reusing an
/// unverified crash residue.
pub fn clear_capsule_materialization_cache(home: &AstridHome) -> anyhow::Result<()> {
    let root = home.run_dir().join("capsules");
    let metadata = match std::fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect capsule materialization cache"),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "capsule materialization cache is redirected or not a directory: {}",
            root.display()
        );
    }
    validate_cache_tree(&root)?;
    for entry in std::fs::read_dir(&root).context("read capsule materialization cache")? {
        let path = entry
            .context("read capsule materialization cache entry")?
            .path();
        remove_cache_tree(&path)?;
    }
    Ok(())
}

fn validate_cache_tree(path: &Path) -> anyhow::Result<()> {
    astrid_core::platform_fs::verify_no_redirects(path)
        .with_context(|| format!("verify cache path {}", path.display()))?;
    for entry in std::fs::read_dir(path).with_context(|| format!("read {}", path.display()))? {
        let path = entry
            .with_context(|| format!("read cache entry under {}", path.display()))?
            .path();
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("inspect {}", path.display()))?;
        if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
            anyhow::bail!(
                "cache contains a redirect or special entry: {}",
                path.display()
            );
        }
        if metadata.is_dir() {
            validate_cache_tree(&path)?;
        } else {
            astrid_core::platform_fs::verify_no_redirects(&path)
                .with_context(|| format!("verify cache file {}", path.display()))?;
        }
    }
    Ok(())
}

fn remove_cache_tree(path: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect cache path {}", path.display()))?;
    if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
        anyhow::bail!(
            "cache changed to a redirect or special entry: {}",
            path.display()
        );
    }
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path).with_context(|| format!("read {}", path.display()))? {
            remove_cache_tree(
                &entry
                    .with_context(|| format!("read cache entry under {}", path.display()))?
                    .path(),
            )?;
        }
        std::fs::remove_dir(path).with_context(|| format!("remove {}", path.display()))?;
    } else {
        std::fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    }
    Ok(())
}

/// Resolve the old native env path for an explicit migration tool.
///
/// Runtime/install code must not read or write this path. New configuration is
/// persisted by the daemon's typed control namespace; this helper remains only
/// so a layout migration can identify released-home input safely.
#[deprecated(
    note = "legacy migration input only; runtime configuration uses typed control storage"
)]
pub fn resolve_env_path(home: &AstridHome, capsule_name: &str) -> anyhow::Result<PathBuf> {
    let principal = install_principal();
    Ok(home
        .principal_home(&principal)
        .env_dir()
        .join(format!("{capsule_name}.env.json")))
}

/// Resolve the path to a capsule's env config file for `principal`.
#[deprecated(
    note = "legacy migration input only; runtime configuration uses typed control storage"
)]
pub fn resolve_env_path_for(
    home: &AstridHome,
    principal: &PrincipalId,
    capsule_name: &str,
) -> anyhow::Result<PathBuf> {
    let ph = home.principal_home(principal);
    Ok(ph.env_dir().join(format!("{capsule_name}.env.json")))
}

/// Retired compatibility hook. Native env files are never restored during an
/// install; use the explicit storage migration command instead.
pub fn restore_env_from_backup(home: &AstridHome, backup_dir: &Path, capsule_name: &str) {
    restore_env_from_backup_for(home, &install_principal(), backup_dir, capsule_name);
}

/// Retired compatibility hook; intentionally does nothing.
pub fn restore_env_from_backup_for(
    _home: &AstridHome,
    _principal: &PrincipalId,
    _backup_dir: &Path,
    _capsule_name: &str,
) {
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_target_uses_injected_layout() {
        let layout = WorkspaceLayout::new(".alternate-runtime").unwrap();
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_target_dir_for_in_workspace(
                &AstridHome::from_path("/home/runtime"),
                &install_principal(),
                "example",
                true,
                Some(root.path()),
                &layout,
            )
            .unwrap(),
            root.path()
                .canonicalize()
                .unwrap()
                .join(".alternate-runtime/capsules/example")
        );
    }

    #[test]
    fn cache_target_is_owner_and_generation_scoped() {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path());
        std::fs::create_dir_all(home.run_dir().join("capsules")).unwrap();
        let first = resolve_cache_target_dir(
            &home,
            PrincipalUid::from_bytes([1; 32]),
            "example",
            &"a".repeat(64),
            false,
            None,
            &WorkspaceLayout::default(),
        )
        .unwrap();
        let other_owner = resolve_cache_target_dir(
            &home,
            PrincipalUid::from_bytes([2; 32]),
            "example",
            &"a".repeat(64),
            false,
            None,
            &WorkspaceLayout::default(),
        )
        .unwrap();
        let other_generation = resolve_cache_target_dir(
            &home,
            PrincipalUid::from_bytes([1; 32]),
            "example",
            &"b".repeat(64),
            false,
            None,
            &WorkspaceLayout::default(),
        )
        .unwrap();
        assert_ne!(first, other_owner);
        assert_ne!(first, other_generation);
        assert!(first.ends_with(format!("example/{}", "a".repeat(64))));
    }

    #[test]
    fn cache_target_rejects_noncanonical_digest() {
        let error = resolve_cache_target_dir(
            &AstridHome::from_path("/home/runtime"),
            PrincipalUid::from_bytes([1; 32]),
            "example",
            "../untrusted",
            false,
            None,
            &WorkspaceLayout::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("canonical cache component"));
    }

    #[test]
    fn cache_cleanup_removes_crash_residue() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        let residue = home
            .run_dir()
            .join("capsules/uid/example")
            .join("a".repeat(64));
        std::fs::create_dir_all(&residue).unwrap();
        std::fs::write(residue.join("authority.pending"), b"partial").unwrap();
        clear_capsule_materialization_cache(&home).unwrap();
        assert!(
            std::fs::read_dir(home.run_dir().join("capsules"))
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn workspace_target_rejects_redirected_capsule_tree() {
        use std::os::unix::fs::symlink;

        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let state = workspace.path().join(".alternate-runtime");
        std::fs::create_dir(&state).unwrap();
        symlink(outside.path(), state.join("capsules")).unwrap();

        let error = resolve_target_dir_for_in_workspace(
            &AstridHome::from_path(home.path()),
            &install_principal(),
            "example",
            true,
            Some(workspace.path()),
            &WorkspaceLayout::new(".alternate-runtime").unwrap(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("unsafe"));
    }
}
