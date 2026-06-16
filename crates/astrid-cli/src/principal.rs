//! Process-wide CLI principal.
//!
//! The `astrid` CLI acts as exactly one principal for its whole
//! lifetime. The uplink proxy pins the first principal it sees on a
//! connection: it auto-attributes unstamped messages to that principal
//! and DROPS any message stamped with a different one. A mixed stream
//! therefore loses messages silently, so the CLI must present one
//! consistent principal on every IPC message it sends.
//!
//! The principal is resolved ONCE at startup ([`resolve_process`]) with
//! precedence explicit `--principal` flag > `ASTRID_PRINCIPAL` env >
//! the operator's active-agent context (`cli-context.toml`, set by
//! `astrid agent use`) > `default`. clap folds the env var into the
//! flag value, so the explicit-source resolver ([`resolve`]) sees a
//! single `Option<&str>`; the active-agent fallback only applies when
//! neither flag nor env is set, preserving the pre-flag admin-command
//! attribution. The resolved principal is validated through
//! [`PrincipalId::new`] before any socket connection, then stored in a
//! [`OnceLock`] read by every transport ([`crate::socket_client`],
//! [`crate::admin_client`]) so each outbound message stamps the same
//! identity without threading it through every handler signature.

use std::sync::OnceLock;

use anyhow::{Context, Result};
use astrid_core::PrincipalId;

/// Process-wide resolved principal, set once in `main` after argument
/// parsing and read by the transport constructors.
static PRINCIPAL: OnceLock<PrincipalId> = OnceLock::new();

/// Validate an explicit principal source. `value` is the flag-or-env
/// value clap produced (`Some` when `--principal` or `ASTRID_PRINCIPAL`
/// was set, `None` otherwise). `None` resolves to `None` here so the
/// caller can apply the lower-precedence active-agent fallback;
/// `Some(s)` is validated through [`PrincipalId::new`].
///
/// Pure over its input so precedence and validation can be unit-tested
/// without touching the environment (`clippy.toml` bans
/// `std::env::set_var`).
///
/// # Errors
/// Returns an error naming the constraint if `value` is present but is
/// not a valid [`PrincipalId`] (1-64 chars of `[a-zA-Z0-9_-]`).
pub(crate) fn resolve(value: Option<&str>) -> Result<Option<PrincipalId>> {
    match value {
        Some(s) => PrincipalId::new(s).map(Some).with_context(|| {
            format!(
                "invalid --principal/ASTRID_PRINCIPAL value {s:?}: \
                     must be 1-64 characters of [a-zA-Z0-9_-]"
            )
        }),
        None => Ok(None),
    }
}

/// Resolve the process principal with full precedence: explicit
/// flag/env ([`resolve`]) > active-agent context > [`PrincipalId::default`].
///
/// The active-agent fallback preserves the pre-flag attribution for
/// admin commands (`astrid agent use X` then `astrid caps list` acts as
/// `X`); a malformed `cli-context.toml` surfaces as an error rather
/// than silently downgrading to `default`.
///
/// # Errors
/// Returns an error if the explicit value is invalid, or if the
/// active-agent context file exists but is malformed.
pub(crate) fn resolve_process(value: Option<&str>) -> Result<PrincipalId> {
    if let Some(explicit) = resolve(value)? {
        return Ok(explicit);
    }
    crate::context::active_agent()
}

/// Store the resolved principal for the process. Called once from
/// `main` immediately after [`resolve`]. Idempotent: a second call is a
/// no-op (the first value wins), which keeps the contract simple even
/// though the binary only sets it once.
pub(crate) fn set(principal: PrincipalId) {
    let _ = PRINCIPAL.set(principal);
}

/// The process principal. Falls back to [`PrincipalId::default`] if
/// [`set`] was never called (e.g. a code path that builds a transport
/// before `main` resolved the flag — there is none today, but the
/// fallback keeps callers total and matches the no-flag default).
pub(crate) fn current() -> PrincipalId {
    PRINCIPAL.get().cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_defers_to_lower_precedence() {
        // No flag/env: `resolve` yields `None` so the caller applies
        // the active-agent context / default fallback.
        assert_eq!(resolve(None).unwrap(), None);
    }

    #[test]
    fn explicit_value_wins() {
        // clap has already folded flag-or-env into this single value,
        // so a present value is the resolved principal regardless of
        // source. Precedence flag > env is enforced by clap's `env`
        // attribute (flag overrides env when both are set).
        assert_eq!(resolve(Some("alice")).unwrap().unwrap().as_str(), "alice");
    }

    #[test]
    fn max_length_accepted() {
        let name = "a".repeat(64);
        assert_eq!(resolve(Some(&name)).unwrap().unwrap().as_str(), name);
    }

    #[test]
    fn invalid_chars_rejected_with_constraint_message() {
        let err = resolve(Some("bad name")).expect_err("space is invalid");
        let msg = err.to_string();
        assert!(msg.contains("invalid"), "got: {msg}");
        assert!(msg.contains("[a-zA-Z0-9_-]"), "constraint named: {msg}");
    }

    #[test]
    fn empty_value_rejected() {
        assert!(resolve(Some("")).is_err());
    }

    #[test]
    fn over_length_rejected() {
        let name = "a".repeat(65);
        assert!(resolve(Some(&name)).is_err());
    }
}
