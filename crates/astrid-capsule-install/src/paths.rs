//! Path resolution for capsule install destinations and env config.

use std::path::{Path, PathBuf};

use anyhow::Context;
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;

/// The default principal a non-workspace install targets.
///
/// CLI installs land in the default principal's home, and so do everything
/// keyed off that home: the capsule directory, the env config, and the
/// `home://wit/` interface mirror. This is the single source of truth for the
/// DEFAULT target. Per-principal installs (#1069) thread a real id through
/// `InstallOptions::target_principal` into the `*_for` variants below, so those
/// locations can never drift apart. Resolving the principal in one place keeps
/// the mirror honest instead of re-hardcoding `PrincipalId::default()` per call
/// site.
#[must_use]
pub fn install_principal() -> PrincipalId {
    PrincipalId::default()
}

/// Resolve the directory a capsule should be installed into, for the default
/// install principal. Thin wrapper over [`resolve_target_dir_for`].
pub fn resolve_target_dir(home: &AstridHome, id: &str, workspace: bool) -> anyhow::Result<PathBuf> {
    resolve_target_dir_for(home, &install_principal(), id, workspace)
}

/// Resolve the directory a capsule should be installed into, for a SPECIFIC
/// principal (#1069).
///
/// User installs (`workspace = false`) land in `principal`'s home under
/// `.local/capsules/<id>/`. Workspace installs go to
/// `<cwd>/.astrid/capsules/<id>/` regardless of principal (workspace installs
/// are not per-principal — they belong to the working directory).
pub fn resolve_target_dir_for(
    home: &AstridHome,
    principal: &PrincipalId,
    id: &str,
    workspace: bool,
) -> anyhow::Result<PathBuf> {
    if workspace {
        let root = std::env::current_dir().context("could not determine current directory")?;
        Ok(root.join(".astrid").join("capsules").join(id))
    } else {
        let ph = home.principal_home(principal);
        Ok(ph.capsules_dir().join(id))
    }
}

/// Resolve the path to a capsule's env config file, for the default install
/// principal. Thin wrapper over [`resolve_env_path_for`].
pub fn resolve_env_path(home: &AstridHome, capsule_name: &str) -> anyhow::Result<PathBuf> {
    resolve_env_path_for(home, &install_principal(), capsule_name)
}

/// Resolve the path to a capsule's env config file, for a SPECIFIC principal
/// (#1069). Returns `home/{principal}/.config/env/{capsule}.env.json`.
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

/// Copy `.env.json` from a backup directory to the new env path if it exists,
/// for the default install principal. Thin wrapper over
/// [`restore_env_from_backup_for`].
pub fn restore_env_from_backup(home: &AstridHome, backup_dir: &Path, capsule_name: &str) {
    restore_env_from_backup_for(home, &install_principal(), backup_dir, capsule_name);
}

/// Copy `.env.json` from a backup directory to the new env path if it exists,
/// for a SPECIFIC principal (#1069).
///
/// Called after a reinstall to ensure user-configured environment variables survive.
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
