//! `--grant-capsules`: attach capsule-access grants for the capsules a
//! distro just installed to the target principal, via the same
//! `admin.agent.modify` kernel path as `astrid agent modify --add-capsule`.
//!
//! Split out of `init.rs` (referenced via `#[path]`) so that file stays
//! under the per-file CI line cap. The two entry points `run_init` calls
//! are [`validate_grant_capsules`] (a pure up-front guard) and
//! [`apply_or_hint_grants`] (the post-install grant / hint dispatcher).

use std::fs::{File, OpenOptions};
use std::future::Future;

use anyhow::{Context, bail};
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody};
use fs2::FileExt;

use crate::theme::Theme;

/// Guard: `--grant-capsules` may only be honoured alongside a distro
/// install, because the grant set is exactly the capsules that distro
/// installs. `distro_present` is whether a non-empty distro source
/// resolved. Pure so the invariant is unit-testable without a network
/// install.
///
/// # Errors
/// Returns an error when `grant_capsules` is set but no distro source is
/// present.
pub(super) fn validate_grant_capsules(
    grant_capsules: bool,
    distro_present: bool,
) -> anyhow::Result<()> {
    if grant_capsules && !distro_present {
        bail!(
            "--grant-capsules requires a resolved distro: grants apply to the capsules a distro installs"
        );
    }
    Ok(())
}

/// What the post-install grant step should do, given the flag and how many
/// capsules installed. Explicit requests always exercise the kernel grant
/// path; the CLI never infers privilege from a principal name.
#[derive(Debug, PartialEq, Eq)]
enum GrantAction {
    /// Nothing installed this run — no grants, no hint.
    Nothing,
    /// Flag omitted — print the manual hint.
    Hint,
    /// Flag set — apply the grants.
    Grant,
}

fn grant_action(grant_capsules: bool, installed_count: usize) -> GrantAction {
    if installed_count == 0 {
        return GrantAction::Nothing;
    }
    if grant_capsules {
        GrantAction::Grant
    } else {
        GrantAction::Hint
    }
}

/// Render the exact `astrid agent modify … --add-capsule …` command that
/// grants `capsules` to `principal`. Shared by the discoverability hint
/// (flag omitted) and the grant-failure recovery message so both print an
/// identical, copy-pasteable command.
fn agent_modify_grant_command(
    operator: &PrincipalId,
    target: &PrincipalId,
    capsules: &[String],
) -> String {
    let flags = capsules
        .iter()
        .map(|c| format!("--add-capsule {c}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("astrid --principal {operator} agent modify {target} {flags}")
}

/// Read-only authorization and target-existence check for the exact mutation
/// `--grant-capsules` will perform. This runs before init creates local state.
pub(super) async fn preflight_grants(
    operator: &PrincipalId,
    target: &PrincipalId,
) -> anyhow::Result<()> {
    preflight_sequence(
        crate::commands::daemon::ensure_daemon("init grant preflight"),
        || async move {
            let mut client = crate::admin_client::AdminClient::connect(operator.clone())
                .await
                .context("grant preflight could not connect to the daemon")?;
            let body = client
                .request(AdminRequestKind::AgentModifyCheck {
                    principal: target.clone(),
                })
                .await
                .context("grant preflight request failed")?;
            match crate::admin_client::into_result(body)? {
                AdminResponseBody::Success(_) => Ok(()),
                other => bail!("grant preflight returned an unexpected response: {other:?}"),
            }
        },
    )
    .await
}

async fn preflight_sequence<E, C, F>(ensure_daemon: E, check: C) -> anyhow::Result<()>
where
    E: Future<Output = anyhow::Result<()>>,
    C: FnOnce() -> F,
    F: Future<Output = anyhow::Result<()>>,
{
    ensure_daemon
        .await
        .context("grant preflight could not ensure the runtime daemon")?;
    check().await
}

/// Owner-private, non-blocking lock serializing distro provisioning for one
/// `(AstridHome, target principal)` pair. The file remains in place after
/// unlock so concurrent processes always contend on the same inode.
pub(super) struct ProvisioningLock {
    _file: File,
}

impl ProvisioningLock {
    pub(super) fn acquire(home: &AstridHome, target: &PrincipalId) -> anyhow::Result<Self> {
        let config_dir = home.principal_home(target).config_dir();
        std::fs::create_dir_all(&config_dir)
            .with_context(|| format!("failed to create {}", config_dir.display()))?;
        set_owner_private_dir(&config_dir)?;

        let path = config_dir.join("distro.init.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        set_owner_private_file(&path)?;
        FileExt::try_lock_exclusive(&file).with_context(|| {
            format!("another distro provision is already running for target principal '{target}'")
        })?;
        Ok(Self { _file: file })
    }
}

/// Prove that every fresh-lock entry still describes an installed capsule for
/// the target before those names become an authorization grant set.
pub(super) fn validate_locked_capsules(
    home: &AstridHome,
    target: &PrincipalId,
    locked: &[super::LockedCapsule],
) -> anyhow::Result<Vec<String>> {
    let mut installed = Vec::with_capacity(locked.len());
    for capsule in locked {
        let target_dir = super::super::capsule::install::resolve_target_dir_for(
            home,
            target,
            &capsule.name,
            false,
        )?;
        let manifest_path = target_dir.join("Capsule.toml");
        let manifest = astrid_capsule::discovery::load_manifest(&manifest_path).with_context(|| {
            format!(
                "Distro.lock is fresh but capsule '{}' is not installed correctly for '{}'; rerun init after removing the stale lock",
                capsule.name, target
            )
        })?;
        if manifest.package.name != capsule.name {
            bail!(
                "Distro.lock capsule '{}' resolves to installed manifest '{}'; refusing to grant stale identity",
                capsule.name,
                manifest.package.name
            );
        }
        if !capsule.version.is_empty() && manifest.package.version != capsule.version {
            bail!(
                "Distro.lock capsule '{}' expects version {}, but installed metadata reports {}",
                capsule.name,
                capsule.version,
                manifest.package.version
            );
        }
        let meta = super::super::capsule::meta::read_meta(&target_dir).ok_or_else(|| {
            anyhow::anyhow!(
                "Distro.lock capsule '{}' has no readable install metadata for target '{}'",
                capsule.name,
                target
            )
        })?;
        if !capsule.version.is_empty() && meta.version != capsule.version {
            bail!(
                "Distro.lock capsule '{}' expects version {}, but meta.json reports {}",
                capsule.name,
                capsule.version,
                meta.version
            );
        }
        if !capsule.hash.is_empty() {
            let installed_hash = meta.wasm_hash.map(|hash| format!("blake3:{hash}"));
            if installed_hash.as_deref() != Some(capsule.hash.as_str()) {
                bail!(
                    "Distro.lock capsule '{}' hash does not match its installed metadata",
                    capsule.name
                );
            }
        }
        installed.push(capsule.name.clone());
    }
    Ok(installed)
}

#[cfg(unix)]
fn set_owner_private_dir(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_private_dir(_path: &std::path::Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_owner_private_file(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_private_file(_path: &std::path::Path) -> anyhow::Result<()> {
    Ok(())
}

/// Apply capsule-access grants for the installed set (opt-in), or print
/// the discoverability hint when the flag was omitted.
///
/// On the grant path the capsules are already installed and the lock is
/// written; a failure here (daemon unreachable, caller lacks `agent:modify`)
/// returns `Err` so `init` exits non-zero, but always prints the exact
/// manual command to finish. The kernel applies the whole `add_capsules`
/// set atomically, so grants are all-or-nothing rather than partial.
pub(super) async fn apply_or_hint_grants(
    operator: &PrincipalId,
    target: &PrincipalId,
    installed: &[String],
    grant_capsules: bool,
) -> anyhow::Result<()> {
    match grant_action(grant_capsules, installed.len()) {
        GrantAction::Nothing => Ok(()),
        GrantAction::Hint => {
            eprintln!();
            eprintln!(
                "{}",
                Theme::info(&format!(
                    "Capsules were installed for '{target}' but not granted. To let it invoke them:"
                ))
            );
            eprintln!(
                "  {}",
                agent_modify_grant_command(operator, target, installed)
            );
            eprintln!("  (or re-run `astrid init` with --grant-capsules)");
            Ok(())
        },
        GrantAction::Grant => grant_installed_capsules(operator, target, installed).await,
    }
}

/// Grant the installed capsule set to `principal` via the shared
/// `admin.agent.modify` path (the same one `astrid agent modify
/// --add-capsule` uses). Idempotent: a re-run over an already-granted
/// principal reports "no change" instead of erroring or duplicating.
async fn grant_installed_capsules(
    operator: &PrincipalId,
    target: &PrincipalId,
    installed: &[String],
) -> anyhow::Result<()> {
    eprintln!();
    eprintln!(
        "{}",
        Theme::info(&format!(
            "Granting {} capsule(s) to '{target}'...",
            installed.len()
        ))
    );

    let mut client = match crate::admin_client::AdminClient::connect(operator.clone()).await {
        Ok(c) => c,
        Err(e) => {
            bail!(
                "capsules are installed, but connecting to the daemon to grant access failed: {e}\n  \
                 Grant them once the daemon is running:\n  {}",
                agent_modify_grant_command(operator, target, installed)
            );
        },
    };

    match crate::commands::agent::apply_agent_modify(&mut client, target, &[], &[], installed, &[])
        .await
    {
        Ok(outcome) if outcome.changed => {
            eprintln!(
                "{}",
                Theme::success(&format!(
                    "Granted capsule access to '{target}': [{}]",
                    outcome.capsules.join(", ")
                ))
            );
            Ok(())
        },
        Ok(_) => {
            eprintln!(
                "{}",
                Theme::info(&format!(
                    "'{target}' already had access to every installed capsule (no change)."
                ))
            );
            Ok(())
        },
        Err(e) => {
            bail!(
                "capsules are installed, but granting capsule access failed: {e}\n  \
                 Finish manually:\n  {}",
                agent_modify_grant_command(operator, target, installed)
            );
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (c) The flag is only meaningful with a distro to resolve the grant
    /// set: setting it without a distro source is a hard error.
    #[test]
    fn grant_capsules_requires_a_distro() {
        // Flag set, no distro → error.
        let err = validate_grant_capsules(true, false).unwrap_err();
        assert!(err.to_string().contains("--grant-capsules"), "got: {err}");
        assert!(err.to_string().contains("resolved distro"), "got: {err}");

        // Flag set with a distro → allowed.
        assert!(validate_grant_capsules(true, true).is_ok());
        // Flag unset → always allowed (distro present or not).
        assert!(validate_grant_capsules(false, false).is_ok());
        assert!(validate_grant_capsules(false, true).is_ok());
    }

    /// With the flag set, an installed set takes the grant path.
    #[test]
    fn grant_action_grants_for_non_default_with_flag() {
        assert_eq!(grant_action(true, 3), GrantAction::Grant);
    }

    /// Omitting the flag leaves grants absent and prints the hint.
    #[test]
    fn grant_action_hints_when_flag_omitted() {
        assert_eq!(grant_action(false, 3), GrantAction::Hint);
    }

    #[test]
    fn explicit_grant_does_not_special_case_reserved_names() {
        assert_eq!(grant_action(true, 3), GrantAction::Grant);
    }

    /// Nothing installed → no grant attempt and no hint, whatever the flag.
    #[test]
    fn grant_action_does_nothing_with_empty_install_set() {
        assert_eq!(grant_action(true, 0), GrantAction::Nothing);
        assert_eq!(grant_action(false, 0), GrantAction::Nothing);
    }

    /// (d) Idempotency: a re-run always re-derives the same Grant action
    /// (the CLI unconditionally re-issues the grant), and the kernel's
    /// `apply_set_delta` dedups so an already-granted principal reports "no
    /// change" rather than erroring or duplicating. The decision function
    /// is pure over its inputs, so two identical runs plan identically.
    #[test]
    fn grant_action_is_stable_across_reruns() {
        let first = grant_action(true, 2);
        let second = grant_action(true, 2);
        assert_eq!(first, second, "a re-run must plan the same grant");
        assert_eq!(first, GrantAction::Grant);
    }

    /// Both the no-flag hint and the failure-recovery message print an
    /// identical, copy-pasteable `agent modify` command carrying every
    /// installed capsule as a repeated `--add-capsule`.
    #[test]
    fn agent_modify_grant_command_lists_every_capsule() {
        let operator = PrincipalId::new("operator").unwrap();
        let alice = PrincipalId::new("alice").unwrap();
        let caps = vec!["cli".to_string(), "openai".to_string()];
        let cmd = agent_modify_grant_command(&operator, &alice, &caps);
        assert_eq!(
            cmd,
            "astrid --principal operator agent modify alice --add-capsule cli --add-capsule openai"
        );
    }

    #[test]
    fn fresh_lock_without_flag_plans_operator_aware_hint_only() {
        let operator = PrincipalId::new("operator").unwrap();
        let target = PrincipalId::new("agent-1").unwrap();
        let installed = vec!["cli".to_string()];

        assert_eq!(grant_action(false, installed.len()), GrantAction::Hint);
        assert_eq!(
            agent_modify_grant_command(&operator, &target, &installed),
            "astrid --principal operator agent modify agent-1 --add-capsule cli"
        );
    }

    #[test]
    fn provisioning_lock_rejects_contention_and_can_be_reacquired() {
        let dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(dir.path());
        let target = PrincipalId::new("alice").unwrap();
        let first = ProvisioningLock::acquire(&home, &target).unwrap();
        let err = ProvisioningLock::acquire(&home, &target)
            .err()
            .expect("a concurrent provision must not acquire the same lock");
        assert!(err.to_string().contains("already running"), "got: {err:#}");
        drop(first);
        ProvisioningLock::acquire(&home, &target).unwrap();
    }

    #[tokio::test]
    async fn preflight_propagates_daemon_start_failure_without_target_state() {
        let dir = tempfile::tempdir().unwrap();
        let target_state = dir.path().join("home/target");
        let check_called = std::cell::Cell::new(false);

        let err = preflight_sequence(async { anyhow::bail!("daemon boot failed") }, || async {
            check_called.set(true);
            Ok(())
        })
        .await
        .unwrap_err();

        assert!(err.to_string().contains("could not ensure"), "got: {err:#}");
        assert!(!check_called.get());
        assert!(!target_state.exists());
    }

    #[tokio::test]
    async fn preflight_propagates_authorization_failure_without_target_state() {
        let dir = tempfile::tempdir().unwrap();
        let target_state = dir.path().join("home/target");

        let err = preflight_sequence(async { Ok(()) }, || async {
            anyhow::bail!("agent:modify denied")
        })
        .await
        .unwrap_err();

        assert!(err.to_string().contains("agent:modify denied"));
        assert!(!target_state.exists());
    }

    #[test]
    fn fresh_lock_requires_matching_installed_manifest_and_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(dir.path());
        let target = PrincipalId::new("alice").unwrap();
        let install_dir =
            super::super::capsule::install::resolve_target_dir_for(&home, &target, "cli", false)
                .unwrap();
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(
            install_dir.join("Capsule.toml"),
            "[package]\nname = \"cli\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        let meta = super::super::capsule::meta::CapsuleMeta {
            version: "1.0.0".to_string(),
            wasm_hash: Some("abcd".to_string()),
            ..Default::default()
        };
        super::super::capsule::meta::write_meta(&install_dir, &meta).unwrap();
        let locked = vec![super::LockedCapsule {
            name: "cli".to_string(),
            version: "1.0.0".to_string(),
            source: "@example/cli".to_string(),
            hash: "blake3:abcd".to_string(),
            resolved_ref: Some("v1.0.0".to_string()),
        }];

        assert_eq!(
            validate_locked_capsules(&home, &target, &locked).unwrap(),
            vec!["cli"]
        );

        let mismatched = super::super::capsule::meta::CapsuleMeta {
            version: "2.0.0".to_string(),
            wasm_hash: Some("abcd".to_string()),
            ..Default::default()
        };
        super::super::capsule::meta::write_meta(&install_dir, &mismatched).unwrap();
        let err = validate_locked_capsules(&home, &target, &locked).unwrap_err();
        assert!(err.to_string().contains("meta.json reports 2.0.0"));
    }

    #[cfg(unix)]
    #[test]
    fn provisioning_lock_is_owner_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(dir.path());
        let target = PrincipalId::new("alice").unwrap();
        let _lock = ProvisioningLock::acquire(&home, &target).unwrap();
        let config_dir = home.principal_home(&target).config_dir();
        let lock_path = config_dir.join("distro.init.lock");
        assert_eq!(
            std::fs::metadata(config_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(lock_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
