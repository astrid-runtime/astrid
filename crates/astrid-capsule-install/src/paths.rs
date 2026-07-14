//! Path resolution for capsule install destinations and env config.

use std::path::{Path, PathBuf};

use anyhow::Context;
use astrid_core::PrincipalId;
use astrid_core::dirs::{AstridHome, WorkspaceLayout};

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
/// User installs (`workspace = false`) land in the principal's home
/// under `capsules/<id>/`, for the [`install_principal`]. Workspace
/// installs go under the selected project state directory.
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
        Ok(workspace_layout.capsules_dir(root).join(id))
    } else {
        let ph = home.principal_home(principal);
        Ok(ph.capsules_dir().join(id))
    }
}

/// Resolve the path to a capsule's env config file.
///
/// Returns `home/{principal}/.config/env/{capsule}.env.json`.
pub fn resolve_env_path(home: &AstridHome, capsule_name: &str) -> anyhow::Result<PathBuf> {
    resolve_env_path_for(home, &install_principal(), capsule_name)
}

/// Resolve the path to a capsule's env config file for `principal`.
pub fn resolve_env_path_for(
    home: &AstridHome,
    principal: &PrincipalId,
    capsule_name: &str,
) -> anyhow::Result<PathBuf> {
    let ph = home.principal_home(principal);
    let env_dir = ph.env_dir();
    std::fs::create_dir_all(&env_dir)?;
    Ok(env_dir.join(format!("{capsule_name}.env.json")))
}

/// Copy `.env.json` from a backup directory to the new env path if it exists.
///
/// Called after a reinstall to ensure user-configured environment variables survive.
pub fn restore_env_from_backup(home: &AstridHome, backup_dir: &Path, capsule_name: &str) {
    restore_env_from_backup_for(home, &install_principal(), backup_dir, capsule_name);
}

/// Copy `.env.json` from a backup directory to `principal`'s env path if it exists.
pub fn restore_env_from_backup_for(
    home: &AstridHome,
    principal: &PrincipalId,
    backup_dir: &Path,
    capsule_name: &str,
) {
    let old_env = backup_dir.join(".env.json");
    if old_env.exists()
        && let Ok(env_path) = resolve_env_path_for(home, principal, capsule_name)
    {
        let _ = std::fs::copy(&old_env, env_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_target_uses_injected_layout() {
        let layout = WorkspaceLayout::new(".alternate-runtime").unwrap();
        let root = Path::new("/workspace");
        assert_eq!(
            resolve_target_dir_for_in_workspace(
                &AstridHome::from_path("/home/runtime"),
                &install_principal(),
                "example",
                true,
                Some(root),
                &layout,
            )
            .unwrap(),
            PathBuf::from("/workspace/.alternate-runtime/capsules/example")
        );
    }
}
