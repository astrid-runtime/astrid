//! Per-principal capsule-access resolution for the dispatch hot path.
//!
//! Closes the security gap where the capsule **tool surface was global**:
//! any principal could invoke any installed capsule's tools because
//! dispatch matched on topic alone. Access is now **per-principal**, gated
//! by the kernel at dispatch on the user-invocable surface only
//! (`tool.v1.execute.*`, `cli.v1.command.execute`); see
//! [`crate::dispatcher`].
//!
//! # The grant set
//!
//! A principal may invoke a capsule only if the capsule's
//! [`CapsuleId`](crate::capsule::CapsuleId) is in that principal's
//! [`PrincipalProfile::capsules`](astrid_core::profile::PrincipalProfile)
//! grant set, **or** the principal is an admin (holds the `*` capability),
//! which bypasses the filter entirely. New principals get no capsule access
//! by default; the bootstrap `default`/admin principal is unaffected via the
//! `*` bypass (we never special-case by name).
//!
//! # Hot-path discipline
//!
//! Dispatch is the per-event hot path (cf. the #813 worker-starvation
//! cliffs). Resolution must be cheap and lock-free under steady state:
//! - The grant set + admin status come from the in-memory
//!   [`PrincipalProfileCache`], whose [`resolve`](PrincipalProfileCache::resolve)
//!   takes only an `RwLock` **read** after the first miss per principal —
//!   the same machinery `authorize_request` uses kernel-side, and the same
//!   no-hot-path-write rule the fuel/memory ledgers follow.
//! - The group config is read through an [`ArcSwap`] load (lock-free), so a
//!   runtime group mutation (e.g. adding a principal to `admin`) is observed
//!   on the next event without a daemon restart, matching the kernel's own
//!   `kernel.groups.load_full()` per-check read.
//!
//! Mirroring the ledger pattern, one resolver is built kernel-side and
//! cloned (cheap `Arc` clones) into the dispatcher.
//!
//! # Fail-closed
//!
//! An unknown / `None` / `anonymous` caller, or any profile-resolution
//! error, yields **no** capsule access — never default-allow.

use std::sync::Arc;

use arc_swap::ArcSwap;
use astrid_capabilities::CapabilityCheck;
use astrid_core::GroupConfig;
use astrid_core::principal::PrincipalId;
use tracing::warn;

use crate::capsule::CapsuleId;
use crate::profile_cache::PrincipalProfileCache;

/// Resolves whether a principal may invoke a given capsule, for the
/// dispatcher's user-invocable-surface filter.
///
/// Bundles the kernel-owned [`PrincipalProfileCache`] (grant set + admin
/// status) and the live [`GroupConfig`] (admin via group-inherited `*`).
/// Cloning is cheap — both fields are `Arc`.
#[derive(Clone)]
pub struct CapsuleAccessResolver {
    /// Per-principal profile cache. First resolve for a principal reads
    /// disk; subsequent resolves are an `RwLock`-read `Arc` clone.
    profile_cache: Arc<PrincipalProfileCache>,
    /// Live group config. Read via a lock-free [`ArcSwap`] load so admin
    /// status reflects runtime group mutations without a restart.
    groups: Arc<ArcSwap<GroupConfig>>,
}

impl std::fmt::Debug for CapsuleAccessResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The cache and group config are large and not useful here; only
        // identify the type so `#[derive(Debug)]` consumers compile.
        f.debug_struct("CapsuleAccessResolver")
            .finish_non_exhaustive()
    }
}

impl CapsuleAccessResolver {
    /// Build a resolver from the kernel-owned profile cache and live group
    /// config.
    #[must_use]
    pub fn new(
        profile_cache: Arc<PrincipalProfileCache>,
        groups: Arc<ArcSwap<GroupConfig>>,
    ) -> Self {
        Self {
            profile_cache,
            groups,
        }
    }

    /// Return `true` if `principal` may invoke `capsule`.
    ///
    /// Resolution order:
    /// 1. **Fail-closed identity gate** — a `None`, empty, `anonymous`, or
    ///    syntactically invalid principal yields `false` (no grant set).
    /// 2. **Profile resolve** — a resolution error (malformed TOML, IO
    ///    error) yields `false`. Never default-allow on error.
    /// 3. **Admin bypass** — a caller holding `*` (directly, via a grant,
    ///    or via an `admin`-group `*`) returns `true` for any capsule.
    /// 4. **Grant-set membership** — otherwise, `true` iff the capsule id
    ///    appears in the principal's `capsules` grant set.
    ///
    /// `principal` is the kernel-stamped value carried on the originating
    /// IPC message — never a capsule- or caller-supplied claim — so a
    /// principal cannot forge its way past the filter.
    #[must_use]
    pub fn is_capsule_allowed(&self, principal: Option<&str>, capsule: &CapsuleId) -> bool {
        // (1) Identity gate. `anonymous` is the explicit unauthenticated
        // sentinel; treat it like an absent principal — no grant set.
        let Some(principal_str) = principal else {
            return false;
        };
        if principal_str.is_empty() || principal_str == "anonymous" {
            return false;
        }
        let Ok(pid) = PrincipalId::new(principal_str) else {
            warn!(
                security_event = true,
                principal = %principal_str,
                "Capsule-access check: invalid principal string — deny (fail-closed)"
            );
            return false;
        };

        // (2) Profile resolve. Fail-closed on any error.
        let profile = match self.profile_cache.resolve(&pid) {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    security_event = true,
                    principal = %pid,
                    error = %e,
                    "Capsule-access check: profile resolution failed — deny (fail-closed)"
                );
                return false;
            },
        };

        // (3) Admin bypass — reuse the SAME machinery `authorize_request`
        // uses. A `*` holder (admin) bypasses the per-principal filter.
        let groups = self.groups.load();
        let check = CapabilityCheck::new(profile.as_ref(), groups.as_ref(), pid.clone());
        if check.has("*") {
            return true;
        }

        // (4) Grant-set membership.
        profile
            .capsules
            .iter()
            .any(|granted| granted == capsule.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use astrid_core::dirs::AstridHome;
    use astrid_core::groups::{BUILTIN_ADMIN, GroupConfig};
    use astrid_core::profile::PrincipalProfile;

    fn fixture() -> (tempfile::TempDir, AstridHome, CapsuleAccessResolver) {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(dir.path());
        let cache = Arc::new(PrincipalProfileCache::with_home(home.clone()));
        let groups = Arc::new(ArcSwap::from_pointee(GroupConfig::builtin_only()));
        (dir, home, CapsuleAccessResolver::new(cache, groups))
    }

    fn write(home: &AstridHome, principal: &str, profile: &PrincipalProfile) {
        let pid = PrincipalId::new(principal).unwrap();
        profile.save(home, &pid).expect("save");
    }

    fn cap(id: &str) -> CapsuleId {
        CapsuleId::from_static(id)
    }

    #[test]
    fn none_principal_denied() {
        let (_d, _h, r) = fixture();
        assert!(!r.is_capsule_allowed(None, &cap("identity")));
    }

    #[test]
    fn empty_and_anonymous_denied() {
        let (_d, _h, r) = fixture();
        assert!(!r.is_capsule_allowed(Some(""), &cap("identity")));
        assert!(!r.is_capsule_allowed(Some("anonymous"), &cap("identity")));
    }

    #[test]
    fn invalid_principal_string_denied() {
        let (_d, _h, r) = fixture();
        // Contains characters a PrincipalId rejects.
        assert!(!r.is_capsule_allowed(Some("bad/principal"), &cap("identity")));
    }

    #[test]
    fn ungranted_denied_granted_allowed() {
        let (_d, home, r) = fixture();
        write(
            &home,
            "alice",
            &PrincipalProfile {
                capsules: vec!["identity".into()],
                ..PrincipalProfile::default()
            },
        );
        assert!(r.is_capsule_allowed(Some("alice"), &cap("identity")));
        assert!(!r.is_capsule_allowed(Some("alice"), &cap("registry")));
    }

    #[test]
    fn admin_bypasses() {
        let (_d, home, r) = fixture();
        write(
            &home,
            "root",
            &PrincipalProfile {
                groups: vec![BUILTIN_ADMIN.to_string()],
                ..PrincipalProfile::default()
            },
        );
        // Admin holds `*`, so any capsule is allowed without an explicit grant.
        assert!(r.is_capsule_allowed(Some("root"), &cap("identity")));
        assert!(r.is_capsule_allowed(Some("root"), &cap("anything-else")));
    }

    #[test]
    fn unknown_principal_denied_no_profile() {
        let (_d, _h, r) = fixture();
        // No profile on disk → default profile → empty grant set → deny.
        assert!(!r.is_capsule_allowed(Some("ghost"), &cap("identity")));
    }

    #[test]
    fn resolve_error_denies() {
        let (_d, home, r) = fixture();
        let pid = PrincipalId::new("broken").unwrap();
        let path = home.profile_path(&pid);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Future profile_version fails validation → resolve returns Err.
        std::fs::write(&path, "profile_version = 9999\n").unwrap();
        assert!(!r.is_capsule_allowed(Some("broken"), &cap("identity")));
    }
}
