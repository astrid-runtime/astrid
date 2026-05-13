//! CLI active-agent context.
//!
//! Stores the operator's currently-targeted agent in
//! `~/.astrid/run/cli-context.toml`. Per-agent commands without an
//! explicit `--agent`/`-a` flag default to this principal. Solo
//! self-hosters never touch this file — when it's missing or empty,
//! commands fall back to [`PrincipalId::default`] (`"default"`).
//!
//! The file lives under `run/` rather than `etc/` because the active
//! context is operator-local and ephemeral: it does not persist across
//! reboots, it is not part of system policy, and it is not consumed by
//! the daemon (the kernel sees only the IPC message principal field).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use serde::{Deserialize, Serialize};

/// On-disk shape of `cli-context.toml`. A single field today; carrying
/// it in a struct lets us add fields (last-used remote host, default
/// output format) without a migration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ContextFile {
    /// The active agent principal. `None` means "use the default
    /// principal" — same behaviour as a missing file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_agent: Option<String>,
}

/// Compute the path to `cli-context.toml`.
///
/// # Errors
///
/// Returns an error if `AstridHome::resolve` fails — typically because
/// `$HOME` is unset and there's no fallback.
pub(crate) fn context_path() -> Result<PathBuf> {
    let home = AstridHome::resolve().context("Failed to resolve Astrid home directory")?;
    Ok(home.run_dir().join("cli-context.toml"))
}

/// Read the active agent from `cli-context.toml`. Returns
/// [`PrincipalId::default`] when the file is missing, empty, or
/// has no `active_agent` field.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be read, parsed, or
/// validated as a [`PrincipalId`].
pub(crate) fn active_agent() -> Result<PrincipalId> {
    let path = context_path()?;
    active_agent_from(&path)
}

/// Path-injectable variant of [`active_agent`] for tests.
fn active_agent_from(path: &Path) -> Result<PrincipalId> {
    if !path.exists() {
        return Ok(PrincipalId::default());
    }
    let bytes =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let parsed: ContextFile =
        toml::from_str(&bytes).with_context(|| format!("Failed to parse {}", path.display()))?;
    parsed.active_agent.map_or_else(
        || Ok(PrincipalId::default()),
        |s| PrincipalId::new(s).context("invalid principal id in cli-context.toml"),
    )
}

/// Resolve the operating principal for a per-agent command. The
/// explicit `--agent` flag wins over the active context; an empty flag
/// falls back to [`active_agent`].
///
/// # Errors
///
/// Returns an error if `flag` is present but not a valid
/// [`PrincipalId`], or if the active context file is malformed.
pub(crate) fn resolve_agent(flag: Option<&str>) -> Result<PrincipalId> {
    if let Some(s) = flag {
        return PrincipalId::new(s).with_context(|| format!("invalid agent name: {s}"));
    }
    active_agent()
}

/// Persist a new active agent into `cli-context.toml`. Creates the
/// `run/` directory if absent and writes atomically (`.tmp` then
/// `rename`) so a crashed write never leaves a partial file behind.
///
/// # Errors
///
/// Returns an error if the directory cannot be created, the temp file
/// cannot be written, or the atomic rename fails.
pub(crate) fn set_active_agent(principal: &PrincipalId) -> Result<()> {
    let path = context_path()?;
    set_active_agent_at(&path, principal)
}

/// Path-injectable variant of [`set_active_agent`] for tests.
fn set_active_agent_at(path: &Path, principal: &PrincipalId) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    let body = ContextFile {
        active_agent: Some(principal.to_string()),
    };
    let serialized =
        toml::to_string_pretty(&body).context("Failed to serialize cli-context.toml")?;
    let tmp = path.with_extension("toml.tmp");
    fs::write(&tmp, &serialized).with_context(|| format!("Failed to write {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("Failed to rename {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Remove the active agent setting (revert to default).
///
/// # Errors
///
/// Returns an error if the file exists but cannot be removed for a
/// reason other than not-found.
pub(crate) fn clear_active_agent() -> Result<()> {
    let path = context_path()?;
    clear_active_agent_at(&path)
}

/// Path-injectable variant of [`clear_active_agent`] for tests.
fn clear_active_agent_at(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("Failed to remove {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_yields_default_principal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cli-context.toml");
        assert_eq!(active_agent_from(&path).unwrap(), PrincipalId::default());
    }

    #[test]
    fn round_trip_set_then_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cli-context.toml");
        let charlie = PrincipalId::new("charlie").unwrap();
        set_active_agent_at(&path, &charlie).unwrap();
        assert_eq!(active_agent_from(&path).unwrap(), charlie);
    }

    #[test]
    fn clear_returns_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cli-context.toml");
        let alice = PrincipalId::new("alice").unwrap();
        set_active_agent_at(&path, &alice).unwrap();
        clear_active_agent_at(&path).unwrap();
        assert_eq!(active_agent_from(&path).unwrap(), PrincipalId::default());
    }

    #[test]
    fn explicit_flag_wins_over_default() {
        // resolve_agent with Some(name) never reads the file, so this
        // is independent of the per-process AstridHome state.
        let resolved = resolve_agent(Some("bob")).unwrap();
        assert_eq!(resolved.as_str(), "bob");
    }

    #[test]
    fn invalid_flag_rejected() {
        let err = resolve_agent(Some("bad name")).expect_err("invalid");
        assert!(err.to_string().contains("invalid agent name"));
    }

    #[test]
    fn empty_active_agent_field_returns_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cli-context.toml");
        fs::write(&path, "").unwrap();
        assert_eq!(active_agent_from(&path).unwrap(), PrincipalId::default());
    }

    #[test]
    fn malformed_principal_in_file_is_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cli-context.toml");
        fs::write(&path, "active_agent = \"bad name\"\n").unwrap();
        let err = active_agent_from(&path).expect_err("malformed");
        assert!(err.to_string().contains("invalid principal"), "got: {err}");
    }

    #[test]
    fn atomic_write_does_not_leave_tmp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cli-context.toml");
        let alice = PrincipalId::new("alice").unwrap();
        set_active_agent_at(&path, &alice).unwrap();
        let tmp = path.with_extension("toml.tmp");
        assert!(!tmp.exists(), "tempfile should be renamed away");
    }
}
