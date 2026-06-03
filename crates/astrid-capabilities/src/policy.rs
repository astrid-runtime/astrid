//! Static capability-check primitive (issue #670).
//!
//! [`CapabilityCheck`] evaluates whether a resolved
//! [`PrincipalProfile`](astrid_core::PrincipalProfile) holds a given
//! capability string, consulting the principal's group membership and
//! per-principal grant/revoke lists against a shared
//! [`GroupConfig`](astrid_core::GroupConfig).
//!
//! This is a **different namespace** from the runtime
//! [`CapabilityToken`](crate::CapabilityToken) infrastructure:
//!
//! - Runtime tokens (`ed25519`-signed, URI-patterned, single-use/expiring)
//!   gate capsule-level sensitive actions like MCP tool invocation.
//! - Static capabilities (colon-delimited identifiers) gate the kernel's
//!   management-API surface: shutdown, capsule reload/install, status
//!   queries, approval responses.
//!
//! The two systems coexist and are mutually exclusive in what they
//! authorize.
//!
//! # Precedence
//!
//! Evaluation follows a strict ordering, documented in issue #670 and
//! asserted by the unit tests below:
//!
//! 1. **Revokes always win.** A revoke pattern that matches `cap`
//!    immediately denies the check, even for `admin` group members.
//! 2. **Grants.** Any direct grant pattern on the principal profile that
//!    matches `cap` allows the check.
//! 3. **Group-inherited capabilities.** Each group the principal belongs
//!    to contributes its own capability patterns; a missing group name
//!    fails closed (no inherited caps) and the caller is expected to
//!    `warn!` log the typo. Group resolution is case-sensitive and
//!    built-in groups (`admin`, `agent`, `restricted`) are always
//!    present in the [`GroupConfig`](astrid_core::GroupConfig).
//!
//! # Purity
//!
//! [`CapabilityCheck::has`] and [`CapabilityCheck::require`] are pure
//! functions over the two input references — no I/O, no locking, no
//! caching. The caller is expected to have resolved the profile and
//! the group config beforehand.

use astrid_core::{GroupConfig, PrincipalId, PrincipalProfile, capability_matches};
use thiserror::Error;
use tracing::warn;

/// Error returned by [`CapabilityCheck::require`] when the principal
/// does not hold the requested capability.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum PermissionError {
    /// The principal's profile (group membership + grants) does not
    /// satisfy the required capability.
    #[error("permission denied for principal {principal}: missing capability {required}")]
    MissingCapability {
        /// The resolved principal identifier.
        principal: PrincipalId,
        /// The capability pattern that was required.
        required: String,
    },
    /// The principal holds the capability via a group or grant, but a
    /// more specific revoke pattern overrides it.
    #[error(
        "permission denied for principal {principal}: capability {required} is revoked via {revoke_pattern:?}"
    )]
    RevokedCapability {
        /// The resolved principal identifier.
        principal: PrincipalId,
        /// The capability pattern that was required.
        required: String,
        /// The revoke pattern that matched.
        revoke_pattern: String,
    },
    /// The principal's profile has `enabled = false`. The kernel refuses
    /// every request from a disabled principal regardless of held
    /// capabilities. Re-enable via `astrid.v1.admin.agent.enable` from
    /// an admin principal whose profile remains enabled.
    #[error("permission denied for principal {principal}: agent is disabled")]
    PrincipalDisabled {
        /// The resolved principal identifier.
        principal: PrincipalId,
    },
}

/// Borrowed evaluator over a resolved profile and the shared group
/// configuration.
///
/// Zero-allocation and thread-safe: both inputs are shared references,
/// so multiple concurrent handlers can evaluate against the same
/// `&GroupConfig`/`&PrincipalProfile` without contention.
#[derive(Debug, Clone)]
pub struct CapabilityCheck<'a> {
    profile: &'a PrincipalProfile,
    groups: &'a GroupConfig,
    principal: PrincipalId,
}

impl<'a> CapabilityCheck<'a> {
    /// Build a new check for `profile` against `groups`, associated with
    /// the resolved principal `principal` for audit and error messages.
    #[must_use]
    pub fn new(
        profile: &'a PrincipalProfile,
        groups: &'a GroupConfig,
        principal: PrincipalId,
    ) -> Self {
        Self {
            profile,
            groups,
            principal,
        }
    }

    /// Return `true` if the principal holds capability `cap`.
    ///
    /// Precedence: revokes > grants > group-inherited. Missing group
    /// names are fail-closed and logged at `warn!`.
    #[must_use]
    pub fn has(&self, cap: &str) -> bool {
        if matches_any(self.profile.revokes.iter().map(String::as_str), cap) {
            return false;
        }
        if matches_any(self.profile.grants.iter().map(String::as_str), cap) {
            return true;
        }
        self.holds_via_groups(cap)
    }

    /// Enforce that the principal holds capability `cap`.
    ///
    /// # Errors
    ///
    /// Returns [`PermissionError::RevokedCapability`] if the capability
    /// is satisfied via a grant or group but a revoke pattern overrides
    /// it, or [`PermissionError::MissingCapability`] if the capability
    /// is simply not held.
    pub fn require(&self, cap: &str) -> Result<(), PermissionError> {
        if let Some(revoke) = self.first_matching_revoke(cap) {
            return Err(PermissionError::RevokedCapability {
                principal: self.principal.clone(),
                required: cap.to_string(),
                revoke_pattern: revoke.to_string(),
            });
        }
        if matches_any(self.profile.grants.iter().map(String::as_str), cap) {
            return Ok(());
        }
        if self.holds_via_groups(cap) {
            return Ok(());
        }
        Err(PermissionError::MissingCapability {
            principal: self.principal.clone(),
            required: cap.to_string(),
        })
    }

    fn first_matching_revoke(&self, cap: &str) -> Option<&'a str> {
        self.profile
            .revokes
            .iter()
            .map(String::as_str)
            .find(|p| capability_matches(p, cap))
    }

    fn holds_via_groups(&self, cap: &str) -> bool {
        for name in &self.profile.groups {
            let Some(group) = self.groups.get(name) else {
                warn!(
                    security_event = true,
                    principal = %self.principal,
                    group = %name,
                    "Principal profile references unknown group — no capabilities inherited"
                );
                continue;
            };
            if matches_any(group.capabilities.iter().map(String::as_str), cap) {
                return true;
            }
        }
        false
    }
}

fn matches_any<'b, I>(patterns: I, cap: &str) -> bool
where
    I: IntoIterator<Item = &'b str>,
{
    patterns.into_iter().any(|p| capability_matches(p, cap))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gc() -> GroupConfig {
        GroupConfig::builtin_only()
    }

    fn profile_in(groups: &[&str]) -> PrincipalProfile {
        let mut p = PrincipalProfile::default();
        p.groups = groups.iter().map(|s| (*s).to_string()).collect();
        p
    }

    fn pid() -> PrincipalId {
        PrincipalId::new("alice").unwrap()
    }

    #[test]
    fn admin_has_universal() {
        let p = profile_in(&["admin"]);
        let cfg = gc();
        let chk = CapabilityCheck::new(&p, &cfg, pid());
        assert!(chk.has("system:shutdown"));
        assert!(chk.has("self:capsule:install"));
        assert!(chk.has("capsule:install"));
        assert!(chk.has("audit:read:alice"));
    }

    #[test]
    fn agent_has_self_but_not_system() {
        let p = profile_in(&["agent"]);
        let cfg = gc();
        let chk = CapabilityCheck::new(&p, &cfg, pid());
        assert!(chk.has("self:capsule:install"));
        assert!(chk.has("self:capsule:reload"));
        assert!(chk.has("delegate:self:X"));
        assert!(!chk.has("system:shutdown"));
        assert!(!chk.has("capsule:install"));
    }

    #[test]
    fn resources_unbounded_is_admin_only() {
        // The capsule resource-bound exemption capability: admin holds it via
        // `*`, a plain agent does not. This is the axis the run-loop CPU/memory
        // bound keys exemption on.
        let cfg = gc();
        let admin = profile_in(&["admin"]);
        assert!(
            CapabilityCheck::new(&admin, &cfg, pid()).has(astrid_core::CAP_RESOURCES_UNBOUNDED),
            "admin must hold CAP_RESOURCES_UNBOUNDED via `*`"
        );
        let agent = profile_in(&["agent"]);
        assert!(
            !CapabilityCheck::new(&agent, &cfg, pid()).has(astrid_core::CAP_RESOURCES_UNBOUNDED),
            "agent must NOT hold CAP_RESOURCES_UNBOUNDED"
        );
    }

    #[test]
    fn restricted_has_nothing_by_default() {
        let p = profile_in(&["restricted"]);
        let cfg = gc();
        let chk = CapabilityCheck::new(&p, &cfg, pid());
        assert!(!chk.has("system:status"));
        assert!(!chk.has("self:capsule:install"));
    }

    #[test]
    fn grant_overrides_group_lack() {
        let mut p = profile_in(&["restricted"]);
        p.grants.push("system:shutdown".into());
        let cfg = gc();
        let chk = CapabilityCheck::new(&p, &cfg, pid());
        assert!(chk.has("system:shutdown"));
    }

    #[test]
    fn revoke_overrides_admin() {
        let mut p = profile_in(&["admin"]);
        p.revokes.push("system:shutdown".into());
        let cfg = gc();
        let chk = CapabilityCheck::new(&p, &cfg, pid());
        assert!(!chk.has("system:shutdown"));
        // Admin still holds other caps.
        assert!(chk.has("system:status"));
        assert!(chk.has("self:capsule:install"));
    }

    #[test]
    fn revoke_overrides_direct_grant() {
        let mut p = profile_in(&["restricted"]);
        p.grants.push("capsule:install".into());
        p.revokes.push("capsule:install".into());
        let cfg = gc();
        let chk = CapabilityCheck::new(&p, &cfg, pid());
        assert!(!chk.has("capsule:install"));
    }

    #[test]
    fn revoke_via_prefix_pattern() {
        let mut p = profile_in(&["admin"]);
        p.revokes.push("self:*".into());
        let cfg = gc();
        let chk = CapabilityCheck::new(&p, &cfg, pid());
        assert!(!chk.has("self:capsule:install"));
        assert!(chk.has("capsule:install"));
    }

    #[test]
    fn unknown_group_fails_closed() {
        let p = profile_in(&["nonexistent-group"]);
        let cfg = gc();
        let chk = CapabilityCheck::new(&p, &cfg, pid());
        assert!(!chk.has("system:shutdown"));
        assert!(!chk.has("self:capsule:install"));
    }

    #[test]
    fn unknown_group_does_not_mask_other_memberships() {
        let p = profile_in(&["nonexistent", "agent"]);
        let cfg = gc();
        let chk = CapabilityCheck::new(&p, &cfg, pid());
        assert!(chk.has("self:capsule:install"));
        assert!(!chk.has("system:shutdown"));
    }

    #[test]
    fn require_returns_missing_for_absent() {
        let p = profile_in(&["agent"]);
        let cfg = gc();
        let chk = CapabilityCheck::new(&p, &cfg, pid());
        let err = chk.require("system:shutdown").unwrap_err();
        match err {
            PermissionError::MissingCapability { required, .. } => {
                assert_eq!(required, "system:shutdown");
            },
            other => panic!("expected MissingCapability, got: {other:?}"),
        }
    }

    #[test]
    fn require_returns_revoked_when_revoke_matches() {
        let mut p = profile_in(&["admin"]);
        p.revokes.push("system:shutdown".into());
        let cfg = gc();
        let chk = CapabilityCheck::new(&p, &cfg, pid());
        let err = chk.require("system:shutdown").unwrap_err();
        match err {
            PermissionError::RevokedCapability {
                required,
                revoke_pattern,
                ..
            } => {
                assert_eq!(required, "system:shutdown");
                assert_eq!(revoke_pattern, "system:shutdown");
            },
            other => panic!("expected RevokedCapability, got: {other:?}"),
        }
    }

    #[test]
    fn require_ok_for_present_capability() {
        let p = profile_in(&["admin"]);
        let cfg = gc();
        let chk = CapabilityCheck::new(&p, &cfg, pid());
        chk.require("system:shutdown").unwrap();
    }

    #[test]
    fn empty_profile_has_nothing() {
        let p = PrincipalProfile::default();
        let cfg = gc();
        let chk = CapabilityCheck::new(&p, &cfg, pid());
        assert!(!chk.has("system:shutdown"));
        assert!(!chk.has("self:capsule:install"));
    }

    #[test]
    fn custom_group_capabilities_apply() {
        let cfg = GroupConfig::from_toml_str(
            "
            [groups.ops]
            capabilities = [\"capsule:install\", \"capsule:remove\"]
        ",
        )
        .unwrap();
        let p = profile_in(&["ops"]);
        let chk = CapabilityCheck::new(&p, &cfg, pid());
        assert!(chk.has("capsule:install"));
        assert!(!chk.has("capsule:reload"));
    }

    #[test]
    fn grant_for_unrelated_cap_does_not_allow_requested_cap() {
        let mut p = profile_in(&["restricted"]);
        p.grants.push("capsule:install".into());
        let cfg = gc();
        let chk = CapabilityCheck::new(&p, &cfg, pid());
        assert!(!chk.has("system:shutdown"));
    }
}
