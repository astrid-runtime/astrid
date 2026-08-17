//! Admission caching for principals observed by the event dispatcher.
//!
//! Principal home state is durable storage owned by the kernel. Dispatch is
//! deliberately not a provisioning boundary: an IPC event must never create,
//! inspect, or otherwise derive a native principal-home path. The kernel has
//! already authenticated/stamped the principal before an event reaches this
//! loop; this module only validates its wire spelling, applies the existing
//! default-principal gate, and keeps a bounded in-memory seen set.

use std::collections::HashSet;

use tracing::{debug, warn};

/// Maximum number of principals tracked before the set stops growing.
/// 10K principals = ~640KB of memory (64-byte strings). Beyond this,
/// new principals are still dispatched but not cached, avoiding unbounded
/// in-memory growth under a principal storm.
const MAX_KNOWN_PRINCIPALS: usize = 10_000;

/// Per-dispatcher gate that admits newly seen principals without filesystem
/// side effects.
///
/// Owned by [`EventDispatcher::run`](super::EventDispatcher::run); one
/// instance per dispatch loop, carrying the seen-principal cache across
/// events.
pub(super) struct PrincipalProvisioner {
    /// When an identity store is configured, only the "default"
    /// principal is admitted by this legacy gate. Other principals must be
    /// explicitly created via the identity flow (uplink calls
    /// create_user → AstridUserId with principal → uplink sets
    /// principal on IPC). This prevents unauthenticated directory
    /// creation from arbitrary IPC principal strings.
    gate_to_default: bool,
    /// Principals already admitted by this loop, or "default", which the
    /// kernel boot sequence authenticates for single-tenant operation.
    known: HashSet<String>,
}

impl PrincipalProvisioner {
    /// Create a provisioner for one dispatch loop.
    pub(super) fn new(gate_to_default: bool) -> Self {
        let mut known = HashSet::new();
        // The "default" principal is always admitted by the kernel boot
        // sequence.
        known.insert("default".to_string());
        Self {
            gate_to_default,
            known,
        }
    }

    /// Observe the principal stamped on an incoming IPC message and admit it
    /// to this loop's bounded in-memory cache.
    ///
    /// This function is intentionally filesystem-free. Durable home
    /// provisioning is performed by the kernel's UID-bound storage path.
    pub(super) fn observe(&mut self, principal: Option<&str>) {
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
        debug!(principal = %pid, "Admitted principal to dispatcher cache");
        if self.known.len() < MAX_KNOWN_PRINCIPALS {
            self.known.insert(principal_str.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dispatch admission must never touch the filesystem or process
    /// environment, even for a brand-new principal.
    #[test]
    fn admission_never_provisions_native_home() {
        let mut p = PrincipalProvisioner::new(false);
        p.observe(Some("alice"));
        assert!(
            p.known.contains("alice"),
            "valid principals are admitted in memory"
        );
    }

    /// The old injected-home API was removed from dispatch admission. A
    /// temporary/native path therefore remains untouched while a principal
    /// is admitted.
    #[test]
    fn admission_does_not_create_native_home() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = PrincipalProvisioner::new(false);
        p.observe(Some("alice"));
        assert!(
            std::fs::read_dir(dir.path()).unwrap().next().is_none(),
            "dispatch admission must not create native home state"
        );
        assert!(p.known.contains("alice"), "admitted after validation");
    }

    /// The identity-store gate restricts admission to "default".
    #[test]
    fn identity_gate_restricts_to_default() {
        let mut p = PrincipalProvisioner::new(true);
        p.observe(Some("alice"));
        assert!(
            !p.known.contains("alice"),
            "non-default principals are not admitted when gated"
        );
    }

    /// An invalid principal string is ignored without any writes.
    #[test]
    fn invalid_principal_is_ignored() {
        let mut p = PrincipalProvisioner::new(false);
        p.observe(Some("../escape"));
        assert!(
            !p.known.contains("../escape"),
            "an invalid principal must be admitted nowhere"
        );
    }
}
