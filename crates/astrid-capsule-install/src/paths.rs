//! Path resolution for capsule install destinations and env config.

use std::path::{Path, PathBuf};

use anyhow::Context;
use astrid_core::dirs::AstridHome;

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
/// installs go to `<cwd>/.astrid/capsules/<id>/`.
pub fn resolve_target_dir(home: &AstridHome, id: &str, workspace: bool) -> anyhow::Result<PathBuf> {
    if workspace {
        let root = std::env::current_dir().context("could not determine current directory")?;
        Ok(root.join(".astrid").join("capsules").join(id))
    } else {
        let ph = home.principal_home(&install_principal());
        Ok(ph.capsules_dir().join(id))
    }
}

/// Resolve the path to a capsule's env config file.
///
/// Returns `home/{principal}/.config/env/{capsule}.env.json`.
pub fn resolve_env_path(home: &AstridHome, capsule_name: &str) -> anyhow::Result<PathBuf> {
    let ph = home.principal_home(&install_principal());
    let env_dir = ph.env_dir();
    std::fs::create_dir_all(&env_dir)?;
    Ok(env_dir.join(format!("{capsule_name}.env.json")))
}

/// Copy `.env.json` from a backup directory to the new env path if it exists.
///
/// Called after a reinstall to ensure user-configured environment variables survive.
pub fn restore_env_from_backup(home: &AstridHome, backup_dir: &Path, capsule_name: &str) {
    let old_env = backup_dir.join(".env.json");
    if old_env.exists()
        && let Ok(env_path) = resolve_env_path(home, capsule_name)
    {
        let _ = std::fs::copy(&old_env, env_path);
    }
}
