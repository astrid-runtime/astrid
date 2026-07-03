//! Auto-provisioning of per-principal home directories at dispatch.
//!
//! When an IPC message arrives stamped with a principal the dispatcher has
//! not seen, the principal's home directory tree is created so downstream
//! capsule invocations find their per-principal scope in place. The home
//! under which provisioning happens is **injected** — the kernel passes its
//! already-booted [`AstridHome`], tests pass a tempdir home — and when no
//! home is injected, provisioning is disabled entirely (fail-closed): no
//! filesystem writes and no process-environment resolution, ever. Library
//! dispatch code resolving `$ASTRID_HOME`/`$HOME` at the point of use is
//! how `cargo test` once scaffolded a thousand fixture principals into a
//! developer's real `~/.astrid` (#1145).

use std::collections::HashSet;

use astrid_core::dirs::AstridHome;
use tracing::{debug, warn};

/// Maximum number of principals tracked before the set stops growing.
/// 10K principals = ~640KB of memory (64-byte strings). Beyond this,
/// new principals are still dispatched but not cached — they'll hit
/// the filesystem check on every event instead of the O(1) HashSet.
const MAX_KNOWN_PRINCIPALS: usize = 10_000;

/// Per-dispatcher gate that provisions home directories for newly seen
/// principals under an injected [`AstridHome`].
///
/// Owned by [`EventDispatcher::run`](super::EventDispatcher::run); one
/// instance per dispatch loop, carrying the seen-principal cache across
/// events.
pub(super) struct PrincipalProvisioner {
    /// The injected home root. `None` disables provisioning entirely —
    /// the dispatcher never consults the process environment and never
    /// writes to the filesystem (fail-closed, #1145).
    home: Option<AstridHome>,
    /// When an identity store is configured, only the "default"
    /// principal is auto-provisioned. Other principals must be
    /// explicitly created via the identity flow (uplink calls
    /// create_user → AstridUserId with principal → uplink sets
    /// principal on IPC). This prevents unauthenticated directory
    /// creation from arbitrary IPC principal strings.
    gate_to_default: bool,
    /// Principals whose homes are known to exist (provisioned by this
    /// loop, or "default", which the kernel boot sequence provisions).
    known: HashSet<String>,
}

impl PrincipalProvisioner {
    /// Create a provisioner for one dispatch loop.
    pub(super) fn new(home: Option<AstridHome>, gate_to_default: bool) -> Self {
        let mut known = HashSet::new();
        // The "default" principal is always provisioned by the kernel
        // boot sequence.
        known.insert("default".to_string());
        Self {
            home,
            gate_to_default,
            known,
        }
    }

    /// Observe the principal stamped on an incoming IPC message and
    /// provision its home directory if it is newly seen.
    ///
    /// A no-op when no home was injected, when the message carries no
    /// principal, or when the principal is already known.
    pub(super) fn observe(&mut self, principal: Option<&str>) {
        // Fail-closed: without an injected home there is nothing to
        // provision under — never fall back to env resolution (#1145).
        let Some(home) = self.home.as_ref() else {
            return;
        };
        let Some(principal_str) = principal else {
            return;
        };
        if self.known.contains(principal_str) {
            return;
        }
        let Ok(pid) = astrid_core::PrincipalId::new(principal_str) else {
            warn!(
                principal = %principal_str,
                "IPC message has invalid principal string, ignoring"
            );
            return;
        };
        if self.gate_to_default && pid != astrid_core::PrincipalId::default() {
            return;
        }
        let ph = home.principal_home(&pid);
        if let Err(e) = ph.ensure() {
            // Don't cache — allow retry on next event (#544).
            warn!(
                principal = %pid,
                error = %e,
                "Failed to auto-provision principal home"
            );
        } else {
            debug!(
                principal = %pid,
                "Auto-provisioned principal home directory"
            );
            // Only cache on success so transient failures can retry on
            // the next event (#544).
            if self.known.len() < MAX_KNOWN_PRINCIPALS {
                self.known.insert(principal_str.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fail-closed floor for #1145: with no injected home the provisioner
    /// must never touch the filesystem or the process environment, even
    /// for a brand-new principal.
    #[test]
    fn no_injected_home_never_provisions() {
        let mut p = PrincipalProvisioner::new(None, false);
        p.observe(Some("alice"));
        assert!(
            !p.known.contains("alice"),
            "nothing may be recorded as provisioned when no home is injected"
        );
    }

    /// With an injected home, a newly seen principal's home tree is
    /// created under that root — and only that root.
    #[test]
    fn injected_home_provisions_under_it() {
        let dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(dir.path());
        let mut p = PrincipalProvisioner::new(Some(home), false);
        p.observe(Some("alice"));
        assert!(
            dir.path().join("home").join("alice").is_dir(),
            "alice's principal home must be created under the injected root"
        );
        assert!(p.known.contains("alice"), "cached after success");
    }

    /// The identity-store gate restricts auto-provisioning to "default".
    #[test]
    fn identity_gate_restricts_to_default() {
        let dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(dir.path());
        let mut p = PrincipalProvisioner::new(Some(home), true);
        p.observe(Some("alice"));
        assert!(
            !dir.path().join("home").join("alice").exists(),
            "non-default principals are not auto-provisioned when gated"
        );
    }

    /// An invalid principal string is ignored without any writes.
    #[test]
    fn invalid_principal_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(dir.path());
        let mut p = PrincipalProvisioner::new(Some(home), false);
        p.observe(Some("../escape"));
        assert!(
            !dir.path().join("home").exists(),
            "an invalid principal must provision nothing"
        );
    }
}
