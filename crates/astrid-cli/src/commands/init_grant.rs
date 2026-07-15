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
use astrid_capsule::capsule::CapsuleId;
use astrid_capsule::manifest::CapsuleManifest;
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
            let mut client = crate::admin_client::connect_for_workspace_as(operator.clone())
                .await
                .context("grant preflight could not connect to the selected workspace daemon")?;
            let body = client
                .request(AdminRequestKind::AgentModify {
                    principal: target.clone(),
                    add_groups: Vec::new(),
                    remove_groups: Vec::new(),
                    add_capsules: Vec::new(),
                    remove_capsules: Vec::new(),
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
        let expected = CapsuleId::new(capsule.name.clone())?;
        let target_dir = super::super::capsule::install::resolve_target_dir_for(
            home,
            target,
            expected.as_str(),
            false,
        )?;
        let manifest_path = target_dir.join("Capsule.toml");
        let manifest = astrid_capsule::discovery::load_manifest(&manifest_path).with_context(|| {
            format!(
                "Distro.lock is fresh but capsule '{}' is not installed correctly for '{}'; rerun init after removing the stale lock",
                capsule.name, target
            )
        })?;
        let actual = CapsuleId::new(manifest.package.name.clone())?;
        if actual != expected {
            bail!(
                "Distro.lock capsule '{expected}' resolves to installed manifest '{actual}'; refusing to grant stale identity"
            );
        }
        let meta = super::super::capsule::meta::read_meta(&target_dir).ok_or_else(|| {
            anyhow::anyhow!(
                "Distro.lock capsule '{}' has no readable install metadata for target '{}'",
                capsule.name,
                target
            )
        })?;
        if manifest.package.version != meta.version {
            bail!(
                "installed capsule '{}' version disagrees between Capsule.toml ({}) and meta.json ({})",
                expected,
                manifest.package.version,
                meta.version
            );
        }
        if !capsule.version.is_empty() && meta.version != capsule.version {
            bail!(
                "Distro.lock capsule '{}' expects version {}, but meta.json reports {}",
                capsule.name,
                capsule.version,
                meta.version
            );
        }
        validate_locked_wasm(
            home,
            &expected,
            &manifest,
            meta.wasm_hash.as_deref(),
            &capsule.hash,
        )?;
        installed.push(expected.as_str().to_string());
    }
    Ok(installed)
}

/// Reuse a fresh lock only when its installed state still verifies. A current
/// distro id/version with stale or incomplete install provenance falls through
/// to the normal checked install path so init can regenerate the lock.
pub(super) fn validated_grant_set_for_reuse(
    home: &AstridHome,
    target: &PrincipalId,
    locked: &[super::LockedCapsule],
) -> Option<Vec<String>> {
    match validate_locked_capsules(home, target, locked) {
        Ok(installed) => Some(installed),
        Err(error) => {
            eprintln!(
                "{}",
                Theme::warning(&format!(
                    "Distro.lock is current but installed state failed verification ({error:#}); reinstalling"
                ))
            );
            None
        },
    }
}

fn validate_locked_wasm(
    home: &AstridHome,
    capsule: &CapsuleId,
    manifest: &CapsuleManifest,
    meta_hash: Option<&str>,
    locked_hash: &str,
) -> anyhow::Result<()> {
    let declares_wasm = manifest_declares_wasm(manifest);
    let Some(meta_hash) = meta_hash else {
        if declares_wasm {
            bail!("Distro.lock capsule '{capsule}' declares WASM but has no installed WASM hash");
        }
        if !locked_hash.is_empty() {
            bail!("Distro.lock non-WASM capsule '{capsule}' must not carry a WASM hash");
        }
        return Ok(());
    };

    if !declares_wasm {
        bail!(
            "Distro.lock capsule '{capsule}' does not declare WASM but installed metadata carries a WASM hash"
        );
    }
    let locked = parse_locked_blake3(capsule, locked_hash)?;
    let locked_hex = locked.to_hex().to_string();
    if meta_hash != locked_hex {
        bail!("Distro.lock capsule '{capsule}' hash disagrees with installed metadata");
    }
    let blob_path = home.bin_dir().join(format!("{locked_hex}.wasm"));
    let bytes = std::fs::read(&blob_path).with_context(|| {
        format!(
            "Distro.lock capsule '{}' content blob is missing or unreadable at {}",
            capsule,
            blob_path.display()
        )
    })?;
    let actual = blake3::hash(&bytes);
    if actual != locked {
        bail!("Distro.lock capsule '{capsule}' content blob bytes do not match hash {locked_hash}");
    }
    Ok(())
}

fn parse_locked_blake3(capsule: &CapsuleId, value: &str) -> anyhow::Result<blake3::Hash> {
    let Some(hex) = value.strip_prefix("blake3:") else {
        bail!("Distro.lock capsule '{capsule}' requires a canonical blake3:<hex> WASM hash");
    };
    let hash = blake3::Hash::from_hex(hex).map_err(|_| {
        anyhow::anyhow!("Distro.lock capsule '{capsule}' has an invalid BLAKE3 hash")
    })?;
    if hex.len() != 64 || hash.to_hex().as_str() != hex {
        bail!("Distro.lock capsule '{capsule}' requires a canonical lowercase BLAKE3 hash");
    }
    Ok(hash)
}

fn manifest_declares_wasm(manifest: &CapsuleManifest) -> bool {
    manifest
        .components
        .iter()
        .any(|component| component.path.extension().and_then(|ext| ext.to_str()) == Some("wasm"))
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

    let mut client = match crate::admin_client::connect_for_workspace_as(operator.clone()).await {
        Ok(c) => c,
        Err(e) => {
            bail!(
                "capsules are installed, but connecting to the selected workspace daemon to grant access failed: {e}\n  \
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
    use crate::commands::capsule::{install, meta};
    use crate::commands::init::LockedCapsule;

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
        let wasm = b"real wasm bytes";
        let hash = blake3::hash(wasm).to_hex().to_string();
        let install_dir = install::resolve_target_dir_for(&home, &target, "cli", false).unwrap();
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(
            install_dir.join("Capsule.toml"),
            "[package]\nname = \"cli\"\nversion = \"1.0.0\"\n\n[[component]]\nid = \"main\"\nfile = \"cli.wasm\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(home.bin_dir()).unwrap();
        std::fs::write(home.bin_dir().join(format!("{hash}.wasm")), wasm).unwrap();
        let meta = meta::CapsuleMeta {
            version: "1.0.0".to_string(),
            wasm_hash: Some(hash.clone()),
            ..Default::default()
        };
        meta::write_meta(&install_dir, &meta).unwrap();
        let locked = vec![LockedCapsule {
            name: "cli".to_string(),
            version: "1.0.0".to_string(),
            source: "@example/cli".to_string(),
            hash: format!("blake3:{hash}"),
            resolved_ref: Some("v1.0.0".to_string()),
        }];

        assert_eq!(
            validate_locked_capsules(&home, &target, &locked).unwrap(),
            vec!["cli"]
        );

        let mismatched = meta::CapsuleMeta {
            version: "2.0.0".to_string(),
            wasm_hash: Some(hash),
            ..Default::default()
        };
        meta::write_meta(&install_dir, &mismatched).unwrap();
        let err = validate_locked_capsules(&home, &target, &locked).unwrap_err();
        assert!(err.to_string().contains("disagrees between Capsule.toml"));
    }

    #[test]
    fn fresh_lock_rehashes_content_blob_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(dir.path());
        let target = PrincipalId::new("alice").unwrap();
        let install_dir = install::resolve_target_dir_for(&home, &target, "cli", false).unwrap();
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(
            install_dir.join("Capsule.toml"),
            "[package]\nname = \"cli\"\nversion = \"1.0.0\"\n\n[[component]]\nfile = \"cli.wasm\"\n",
        )
        .unwrap();
        let hash = blake3::hash(b"original").to_hex().to_string();
        meta::write_meta(
            &install_dir,
            &meta::CapsuleMeta {
                version: "1.0.0".to_string(),
                wasm_hash: Some(hash.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        std::fs::create_dir_all(home.bin_dir()).unwrap();
        let blob = home.bin_dir().join(format!("{hash}.wasm"));
        std::fs::write(&blob, b"tampered").unwrap();
        let locked = vec![LockedCapsule {
            name: "cli".to_string(),
            version: "1.0.0".to_string(),
            source: "@example/cli".to_string(),
            hash: format!("blake3:{hash}"),
            resolved_ref: Some("v1.0.0".to_string()),
        }];

        let err = validate_locked_capsules(&home, &target, &locked).unwrap_err();
        assert!(err.to_string().contains("blob bytes do not match"));
        assert!(validated_grant_set_for_reuse(&home, &target, &locked).is_none());
        std::fs::remove_file(blob).unwrap();
        let err = validate_locked_capsules(&home, &target, &locked).unwrap_err();
        assert!(err.to_string().contains("missing or unreadable"));
    }

    #[test]
    fn fresh_lock_allows_empty_hash_only_for_non_wasm_capsule() {
        let dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(dir.path());
        let target = PrincipalId::new("alice").unwrap();
        let install_dir = install::resolve_target_dir_for(&home, &target, "mcp", false).unwrap();
        std::fs::create_dir_all(&install_dir).unwrap();
        let manifest_path = install_dir.join("Capsule.toml");
        std::fs::write(
            &manifest_path,
            "[package]\nname = \"mcp\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        meta::write_meta(
            &install_dir,
            &meta::CapsuleMeta {
                version: "1.0.0".to_string(),
                wasm_hash: None,
                ..Default::default()
            },
        )
        .unwrap();
        let locked = vec![LockedCapsule {
            name: "mcp".to_string(),
            version: "1.0.0".to_string(),
            source: "@example/mcp".to_string(),
            hash: String::new(),
            resolved_ref: Some("v1.0.0".to_string()),
        }];
        assert_eq!(
            validate_locked_capsules(&home, &target, &locked).unwrap(),
            vec!["mcp"]
        );

        let stray_hash = blake3::hash(b"stray").to_hex().to_string();
        meta::write_meta(
            &install_dir,
            &meta::CapsuleMeta {
                version: "1.0.0".to_string(),
                wasm_hash: Some(stray_hash.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        let mut hashed_non_wasm = locked.clone();
        hashed_non_wasm[0].hash = format!("blake3:{stray_hash}");
        let err = validate_locked_capsules(&home, &target, &hashed_non_wasm).unwrap_err();
        assert!(err.to_string().contains("does not declare WASM"));

        meta::write_meta(
            &install_dir,
            &meta::CapsuleMeta {
                version: "1.0.0".to_string(),
                wasm_hash: None,
                ..Default::default()
            },
        )
        .unwrap();

        std::fs::write(
            manifest_path,
            "[package]\nname = \"mcp\"\nversion = \"1.0.0\"\n\n[[component]]\nfile = \"helper.js\"\n\n[[component]]\nfile = \"mcp.wasm\"\n",
        )
        .unwrap();
        let err = validate_locked_capsules(&home, &target, &locked).unwrap_err();
        assert!(err.to_string().contains("declares WASM"));
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
