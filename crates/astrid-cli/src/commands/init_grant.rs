//! `--grant-capsules`: attach capsule-access grants for the capsules a
//! distro just installed to the target principal, via the same
//! `admin.agent.modify` kernel path as `astrid agent modify --add-capsule`.
//!
//! Split out of `init.rs` (referenced via `#[path]`) so that file stays
//! under the per-file CI line cap. The two entry points `run_init` calls
//! are [`validate_grant_capsules`] (a pure up-front guard) and
//! [`apply_or_hint_grants`] (the post-install grant / hint dispatcher).

use anyhow::bail;
use astrid_core::PrincipalId;

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
        bail!("--grant-capsules requires --distro: grants apply to the capsules a distro installs");
    }
    Ok(())
}

/// Whether a principal needs explicit per-capsule grants at all.
///
/// The bootstrap `default` principal holds the admin `*` capability, which
/// bypasses the per-principal capsule-access filter entirely (see
/// `astrid_capsule::access`), so per-capsule grants are meaningless for it.
/// We key on the reserved `default` name — decision-scoped to the one
/// principal the runtime special-cases as the single-tenant admin anchor.
fn principal_needs_grants(principal: &PrincipalId) -> bool {
    *principal != PrincipalId::default()
}

/// What the post-install grant step should do for `principal`, given the
/// flag and how many capsules installed. Pure decision function so the
/// branch matrix (no-op / hint / grant) is unit-testable in isolation.
#[derive(Debug, PartialEq, Eq)]
enum GrantAction {
    /// Nothing installed this run — no grants, no hint.
    Nothing,
    /// `default` principal — grants are a no-op (admin `*` bypass).
    DefaultNoOp,
    /// Flag omitted for a non-default principal — print the manual hint.
    Hint,
    /// Flag set for a non-default principal — apply the grants.
    Grant,
}

fn grant_action(
    principal: &PrincipalId,
    grant_capsules: bool,
    installed_count: usize,
) -> GrantAction {
    if installed_count == 0 {
        return GrantAction::Nothing;
    }
    if !principal_needs_grants(principal) {
        return GrantAction::DefaultNoOp;
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
fn agent_modify_grant_command(principal: &PrincipalId, capsules: &[String]) -> String {
    let flags = capsules
        .iter()
        .map(|c| format!("--add-capsule {c}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("astrid agent modify {principal} {flags}")
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
    principal: &PrincipalId,
    installed: &[String],
    grant_capsules: bool,
) -> anyhow::Result<()> {
    match grant_action(principal, grant_capsules, installed.len()) {
        GrantAction::Nothing => Ok(()),
        GrantAction::DefaultNoOp => {
            if grant_capsules {
                eprintln!(
                    "{}",
                    Theme::info(
                        "--grant-capsules: 'default' already has admin access to all capsules — nothing to grant."
                    )
                );
            }
            Ok(())
        },
        GrantAction::Hint => {
            eprintln!();
            eprintln!(
                "{}",
                Theme::info(&format!(
                    "Capsules were installed for '{principal}' but not granted. To let it invoke them:"
                ))
            );
            eprintln!("  {}", agent_modify_grant_command(principal, installed));
            eprintln!("  (or re-run `astrid init` with --grant-capsules)");
            Ok(())
        },
        GrantAction::Grant => grant_installed_capsules(principal, installed).await,
    }
}

/// Grant the installed capsule set to `principal` via the shared
/// `admin.agent.modify` path (the same one `astrid agent modify
/// --add-capsule` uses). Idempotent: a re-run over an already-granted
/// principal reports "no change" instead of erroring or duplicating.
async fn grant_installed_capsules(
    principal: &PrincipalId,
    installed: &[String],
) -> anyhow::Result<()> {
    eprintln!();
    eprintln!(
        "{}",
        Theme::info(&format!(
            "Granting {} capsule(s) to '{principal}'...",
            installed.len()
        ))
    );

    let mut client = match crate::admin_client::connect_as_active_agent().await {
        Ok(c) => c,
        Err(e) => {
            bail!(
                "capsules are installed, but connecting to the daemon to grant access failed: {e}\n  \
                 Grant them once the daemon is running:\n  {}",
                agent_modify_grant_command(principal, installed)
            );
        },
    };

    match crate::commands::agent::apply_agent_modify(
        &mut client,
        principal,
        &[],
        &[],
        installed,
        &[],
    )
    .await
    {
        Ok(outcome) if outcome.changed => {
            eprintln!(
                "{}",
                Theme::success(&format!(
                    "Granted capsule access to '{principal}': [{}]",
                    outcome.capsules.join(", ")
                ))
            );
            Ok(())
        },
        Ok(_) => {
            eprintln!(
                "{}",
                Theme::info(&format!(
                    "'{principal}' already had access to every installed capsule (no change)."
                ))
            );
            Ok(())
        },
        Err(e) => {
            bail!(
                "capsules are installed, but granting capsule access failed: {e}\n  \
                 Finish manually:\n  {}",
                agent_modify_grant_command(principal, installed)
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
        assert!(err.to_string().contains("--distro"), "got: {err}");

        // Flag set with a distro → allowed.
        assert!(validate_grant_capsules(true, true).is_ok());
        // Flag unset → always allowed (distro present or not).
        assert!(validate_grant_capsules(false, false).is_ok());
        assert!(validate_grant_capsules(false, true).is_ok());
    }

    /// (a) With the flag set, a non-default principal that installed
    /// capsules takes the grant path — grants land for exactly the
    /// installed set.
    #[test]
    fn grant_action_grants_for_non_default_with_flag() {
        let alice = PrincipalId::new("alice").unwrap();
        assert_eq!(grant_action(&alice, true, 3), GrantAction::Grant);
    }

    /// (b) Omitting the flag for a non-default principal leaves grants
    /// absent and takes the discoverability-hint path instead.
    #[test]
    fn grant_action_hints_when_flag_omitted() {
        let alice = PrincipalId::new("alice").unwrap();
        assert_eq!(grant_action(&alice, false, 3), GrantAction::Hint);
    }

    /// (4) The `default` principal holds admin `*`, so per-capsule grants
    /// are a no-op regardless of the flag — never Grant or Hint.
    #[test]
    fn grant_action_is_noop_for_default_principal() {
        let default = PrincipalId::default();
        assert_eq!(grant_action(&default, true, 3), GrantAction::DefaultNoOp);
        // Even without the flag, `default` is never nagged with the hint.
        assert_eq!(grant_action(&default, false, 3), GrantAction::DefaultNoOp);
    }

    /// Nothing installed → no grant attempt and no hint, whatever the flag.
    #[test]
    fn grant_action_does_nothing_with_empty_install_set() {
        let alice = PrincipalId::new("alice").unwrap();
        assert_eq!(grant_action(&alice, true, 0), GrantAction::Nothing);
        assert_eq!(grant_action(&alice, false, 0), GrantAction::Nothing);
        // The empty-set check fires before the `default` short-circuit.
        let default = PrincipalId::default();
        assert_eq!(grant_action(&default, true, 0), GrantAction::Nothing);
    }

    /// (d) Idempotency: a re-run always re-derives the same Grant action
    /// (the CLI unconditionally re-issues the grant), and the kernel's
    /// `apply_set_delta` dedups so an already-granted principal reports "no
    /// change" rather than erroring or duplicating. The decision function
    /// is pure over its inputs, so two identical runs plan identically.
    #[test]
    fn grant_action_is_stable_across_reruns() {
        let alice = PrincipalId::new("alice").unwrap();
        let first = grant_action(&alice, true, 2);
        let second = grant_action(&alice, true, 2);
        assert_eq!(first, second, "a re-run must plan the same grant");
        assert_eq!(first, GrantAction::Grant);
    }

    /// Both the no-flag hint and the failure-recovery message print an
    /// identical, copy-pasteable `agent modify` command carrying every
    /// installed capsule as a repeated `--add-capsule`.
    #[test]
    fn agent_modify_grant_command_lists_every_capsule() {
        let alice = PrincipalId::new("alice").unwrap();
        let caps = vec!["cli".to_string(), "openai".to_string()];
        let cmd = agent_modify_grant_command(&alice, &caps);
        assert_eq!(
            cmd,
            "astrid agent modify alice --add-capsule cli --add-capsule openai"
        );
    }
}
