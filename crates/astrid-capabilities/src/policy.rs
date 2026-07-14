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

use std::borrow::Cow;

use astrid_core::{
    CapabilityPattern, DeviceScope, GroupConfig, PrincipalId, PrincipalProfile,
    ValidatedGroupConfig, ValidatedProfileFields, capability_matches,
};
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
    /// The principal holds the capability, but the device that authenticated
    /// this request carries a [`DeviceScope::Scoped`](astrid_core::DeviceScope)
    /// floor that does not admit it (the `allow` list does not match, or a
    /// `deny` pattern overrides). The principal could exercise this capability
    /// from a full-scope device; this specific device cannot.
    #[error(
        "permission denied for principal {principal}: capability {required} is outside the authenticating device's scope"
    )]
    DeviceScopeDenied {
        /// The resolved principal identifier.
        principal: PrincipalId,
        /// The capability pattern that was required.
        required: String,
    },
}

/// Borrowed evaluator over a resolved profile and the shared group
/// configuration.
///
/// The profile and group config are validated into borrowed typed views at
/// construction, so repeated capability checks reuse the same field
/// classification instead of reparsing strings. The evaluator remains
/// thread-safe: all runtime inputs are shared references.
#[derive(Debug, Clone)]
pub struct CapabilityCheck<'a> {
    profile: Result<ValidatedProfileFields<'a>, String>,
    groups: Result<ValidatedGroupConfig<'a>, String>,
    principal: Cow<'a, PrincipalId>,
    /// Optional per-device attenuation floor. `None` (the default) means the
    /// check is unattenuated — the principal's full effective capability set
    /// applies, which is the behaviour for every full-scope / un-paired
    /// connection. A `Some(Scoped { .. })` floor additionally narrows an
    /// ALLOW decision; a `Some(Full)` floor is equivalent to `None`.
    device_scope: Option<&'a DeviceScope>,
}

impl<'a> CapabilityCheck<'a> {
    /// Build a new check for `profile` against `groups`, associated with
    /// the resolved principal `principal` for audit and error messages.
    ///
    /// The check is unattenuated by default; apply a per-device floor with
    /// [`with_device_scope`](Self::with_device_scope).
    #[must_use]
    pub fn new(
        profile: &'a PrincipalProfile,
        groups: &'a GroupConfig,
        principal: PrincipalId,
    ) -> Self {
        let profile = profile.typed_fields().map_err(|e| e.to_string());
        let groups = groups.typed().map_err(|e| e.to_string());
        Self {
            profile,
            groups,
            principal: Cow::Owned(principal),
            device_scope: None,
        }
    }

    /// Build a new check while borrowing the resolved principal identifier.
    ///
    /// This is equivalent to [`Self::new`] but avoids cloning an identifier
    /// for checks that only need the boolean result from [`Self::has`]. A
    /// denied [`Self::require`] still returns an owned identifier in its
    /// [`PermissionError`].
    #[must_use]
    pub fn new_borrowed(
        profile: &'a PrincipalProfile,
        groups: &'a GroupConfig,
        principal: &'a PrincipalId,
    ) -> Self {
        let profile = profile.typed_fields().map_err(|e| e.to_string());
        let groups = groups.typed().map_err(|e| e.to_string());
        Self {
            profile,
            groups,
            principal: Cow::Borrowed(principal),
            device_scope: None,
        }
    }

    /// Attenuate this check with a per-device [`DeviceScope`] floor.
    ///
    /// The floor is applied AFTER the principal decision: it can only narrow
    /// an ALLOW, never widen a DENY. A [`DeviceScope::Full`] floor leaves the
    /// decision unchanged (equivalent to not setting one), preserving the
    /// behaviour of every full-scope device and every migrated legacy key.
    #[must_use]
    pub fn with_device_scope(mut self, scope: &'a DeviceScope) -> Self {
        self.device_scope = Some(scope);
        self
    }

    /// Return `true` if the principal holds capability `cap` AND the
    /// authenticating device's scope admits it.
    ///
    /// Precedence: revokes > grants > group-inherited, then the device-scope
    /// floor. Missing group names are fail-closed and logged at `warn!`. The
    /// device floor is purely restrictive — a `Scoped` device can never make
    /// a capability the principal lacks become held.
    #[must_use]
    pub fn has(&self, cap: &str) -> bool {
        let profile = match &self.profile {
            Ok(profile) => profile,
            Err(e) => {
                warn!(
                    security_event = true,
                    principal = %self.principal.as_ref(),
                    error = %e,
                    "Principal profile contains invalid typed fields — no capabilities inherited"
                );
                return false;
            },
        };
        if !self.principal_has(profile, cap) {
            return false;
        }
        self.device_scope_admits(cap)
    }

    /// Enforce that the principal holds capability `cap` and the
    /// authenticating device's scope admits it.
    ///
    /// # Errors
    ///
    /// Returns [`PermissionError::RevokedCapability`] if the capability
    /// is satisfied via a grant or group but a revoke pattern overrides
    /// it, [`PermissionError::MissingCapability`] if the capability is
    /// simply not held by the principal, or
    /// [`PermissionError::DeviceScopeDenied`] if the principal holds it but
    /// the authenticating device's scope does not admit it.
    pub fn require(&self, cap: &str) -> Result<(), PermissionError> {
        let profile = match &self.profile {
            Ok(profile) => profile,
            Err(e) => {
                warn!(
                    security_event = true,
                    principal = %self.principal.as_ref(),
                    error = %e,
                    "Principal profile contains invalid typed fields — denying capability"
                );
                return Err(PermissionError::MissingCapability {
                    principal: self.principal.as_ref().clone(),
                    required: cap.to_string(),
                });
            },
        };
        if let Some(revoke) = Self::first_matching_revoke(profile, cap) {
            return Err(PermissionError::RevokedCapability {
                principal: self.principal.as_ref().clone(),
                required: cap.to_string(),
                revoke_pattern: revoke.to_string(),
            });
        }
        let principal_holds =
            matches_any(profile.grants.iter().map(CapabilityPattern::as_str), cap)
                || self.holds_via_groups(profile, cap);
        if !principal_holds {
            return Err(PermissionError::MissingCapability {
                principal: self.principal.as_ref().clone(),
                required: cap.to_string(),
            });
        }
        // Principal floor satisfied. Apply the per-device scope floor last so
        // a scoped device's narrower grant can deny without ever widening.
        if !self.device_scope_admits(cap) {
            return Err(PermissionError::DeviceScopeDenied {
                principal: self.principal.as_ref().clone(),
                required: cap.to_string(),
            });
        }
        Ok(())
    }

    /// The unattenuated principal decision: revokes > grants > group-inherited.
    fn principal_has(&self, profile: &ValidatedProfileFields<'_>, cap: &str) -> bool {
        if matches_any(profile.revokes.iter().map(CapabilityPattern::as_str), cap) {
            return false;
        }
        if matches_any(profile.grants.iter().map(CapabilityPattern::as_str), cap) {
            return true;
        }
        self.holds_via_groups(profile, cap)
    }

    /// Whether the authenticating device's scope admits `cap`.
    ///
    /// `None` or [`DeviceScope::Full`] always admits (no attenuation). A
    /// [`DeviceScope::Scoped`] floor admits iff `cap` matches an `allow`
    /// pattern and matches no `deny` pattern (deny wins).
    fn device_scope_admits(&self, cap: &str) -> bool {
        match self.device_scope {
            None | Some(DeviceScope::Full) => true,
            Some(DeviceScope::Scoped { allow, deny }) => {
                matches_any(allow.iter().map(String::as_str), cap)
                    && !matches_any(deny.iter().map(String::as_str), cap)
            },
        }
    }

    fn first_matching_revoke<'profile>(
        profile: &'profile ValidatedProfileFields<'_>,
        cap: &str,
    ) -> Option<&'profile str> {
        profile
            .revokes
            .iter()
            .map(CapabilityPattern::as_str)
            .find(|p| capability_matches(p, cap))
    }

    fn holds_via_groups(&self, profile: &ValidatedProfileFields<'_>, cap: &str) -> bool {
        let groups = match &self.groups {
            Ok(groups) => groups,
            Err(e) => {
                warn!(
                    security_event = true,
                    principal = %self.principal.as_ref(),
                    error = %e,
                    "Group config contains invalid typed fields — no group capabilities inherited"
                );
                return false;
            },
        };
        for name in &profile.groups {
            let Some(group) = groups.get(name) else {
                warn!(
                    security_event = true,
                    principal = %self.principal.as_ref(),
                    group = %name,
                    "Principal profile references unknown group — no capabilities inherited"
                );
                continue;
            };
            if matches_any(
                group.capabilities.iter().map(CapabilityPattern::as_str),
                cap,
            ) {
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

/// Validate that a requested device scope stays within the issuer's authority
/// — the no-escalation guarantee enforced at pair-token issue time.
///
/// `issuer_check` is the issuer's *effective* check: its principal decision
/// already narrowed by the issuer's OWN authenticating device scope (a scoped
/// device can only mint a child no broader than itself). For a
/// [`DeviceScope::Scoped`] request, every `allow` pattern `P` must satisfy
/// `issuer_check.has(P)` — the issuer can only confer capabilities it actually
/// holds. `deny` patterns need no validation: they purely restrict, so a child
/// denying something is always safe.
///
/// A [`DeviceScope::Full`] request is *not* validated here — minting an
/// unattenuated device is gated separately by the `self:auth:pair:admin`
/// capability at the call site (a full device inherits the principal's whole
/// effective set, which the principal already holds by definition).
///
/// # Errors
///
/// Returns [`PermissionError::MissingCapability`] naming the first `allow`
/// pattern the issuer does not effectively hold, so the issue is rejected
/// fail-closed. `MissingCapability` (not `DeviceScopeDenied`) is the accurate
/// shape here: this is the *issuer authority* subset check, and the pattern may
/// be unheld because the principal lacks it OR because the issuer's own device
/// scope excludes it — "{cap} is not held by {issuer}" is correct either way,
/// whereas "outside the authenticating device's scope" would mis-attribute the
/// principal-lacks-it case.
pub fn device_scope_within(
    issuer_check: &CapabilityCheck<'_>,
    requested: &DeviceScope,
) -> Result<(), PermissionError> {
    let DeviceScope::Scoped { allow, .. } = requested else {
        return Ok(());
    };
    for pattern in allow {
        if !issuer_check.has(pattern) {
            return Err(PermissionError::MissingCapability {
                principal: issuer_check.principal.as_ref().clone(),
                required: pattern.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gc() -> GroupConfig {
        GroupConfig::builtin_only()
    }

    fn profile_in(groups: &[&str]) -> PrincipalProfile {
        PrincipalProfile {
            groups: groups.iter().map(|s| (*s).to_string()).collect(),
            ..Default::default()
        }
    }

    fn cap(pattern: &str) -> String {
        pattern.to_string()
    }

    fn pid() -> PrincipalId {
        PrincipalId::new("alice").unwrap()
    }

    #[test]
    fn borrowed_principal_check_preserves_allow_semantics() {
        let profile = profile_in(&["agent"]);
        let groups = gc();
        let principal = pid();
        let check = CapabilityCheck::new_borrowed(&profile, &groups, &principal);

        assert!(check.has("self:capsule:install"));
        assert!(!check.has("system:shutdown"));
        assert_eq!(principal, pid());
    }

    #[test]
    fn borrowed_principal_is_owned_in_permission_errors() {
        let profile = profile_in(&["restricted"]);
        let groups = gc();
        let principal = pid();
        let check = CapabilityCheck::new_borrowed(&profile, &groups, &principal);

        assert_eq!(
            check.require("system:shutdown"),
            Err(PermissionError::MissingCapability {
                principal: principal.clone(),
                required: "system:shutdown".to_owned(),
            })
        );
        assert_eq!(principal, pid());
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
        p.grants.push(cap("system:shutdown"));
        let cfg = gc();
        let chk = CapabilityCheck::new(&p, &cfg, pid());
        assert!(chk.has("system:shutdown"));
    }

    #[test]
    fn revoke_overrides_admin() {
        let mut p = profile_in(&["admin"]);
        p.revokes.push(cap("system:shutdown"));
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
        p.grants.push(cap("capsule:install"));
        p.revokes.push(cap("capsule:install"));
        let cfg = gc();
        let chk = CapabilityCheck::new(&p, &cfg, pid());
        assert!(!chk.has("capsule:install"));
    }

    #[test]
    fn revoke_via_prefix_pattern() {
        let mut p = profile_in(&["admin"]);
        p.revokes.push(cap("self:*"));
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
        p.revokes.push(cap("system:shutdown"));
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
    fn invalid_group_config_fails_closed_for_inherited_caps() {
        let cfg = GroupConfig {
            groups: std::collections::HashMap::from([(
                "ops/team".to_string(),
                astrid_core::Group {
                    capabilities: vec!["*".to_string()],
                    description: None,
                    unsafe_admin: true,
                },
            )]),
        };
        let mut p = profile_in(&["restricted"]);
        p.grants.push(cap("capsule:install"));
        let chk = CapabilityCheck::new(&p, &cfg, pid());

        assert!(
            !chk.has("system:shutdown"),
            "invalid group config must not confer inherited capabilities"
        );
        assert!(
            chk.has("capsule:install"),
            "direct grants do not depend on group inheritance"
        );
    }

    #[test]
    fn manual_group_star_without_opt_in_fails_closed_for_inherited_caps() {
        let cfg = GroupConfig {
            groups: std::collections::HashMap::from([(
                "privileged".to_string(),
                astrid_core::Group {
                    capabilities: vec!["*".to_string()],
                    description: None,
                    unsafe_admin: false,
                },
            )]),
        };
        let p = profile_in(&["privileged"]);
        let chk = CapabilityCheck::new(&p, &cfg, pid());

        assert!(
            !chk.has("system:shutdown"),
            "manual non-admin groups must not inherit universal access without unsafe_admin"
        );
    }

    #[test]
    fn grant_for_unrelated_cap_does_not_allow_requested_cap() {
        let mut p = profile_in(&["restricted"]);
        p.grants.push(cap("capsule:install"));
        let cfg = gc();
        let chk = CapabilityCheck::new(&p, &cfg, pid());
        assert!(!chk.has("system:shutdown"));
    }

    // ── Device-scope attenuation ──────────────────────────────────────────

    #[test]
    fn device_full_scope_is_unattenuated() {
        // A Full device floor leaves the principal decision untouched —
        // identical to no floor at all.
        let p = profile_in(&["agent"]);
        let cfg = gc();
        let scope = DeviceScope::Full;
        let chk = CapabilityCheck::new(&p, &cfg, pid()).with_device_scope(&scope);
        assert!(chk.has("self:capsule:install"));
        assert!(!chk.has("system:shutdown"));
        chk.require("self:capsule:install").unwrap();
    }

    #[test]
    fn device_scope_allows_when_principal_allows_and_device_allows() {
        let p = profile_in(&["agent"]);
        let cfg = gc();
        let scope = DeviceScope::Scoped {
            allow: vec!["self:*".into()],
            deny: vec![],
        };
        let chk = CapabilityCheck::new(&p, &cfg, pid()).with_device_scope(&scope);
        assert!(chk.has("self:capsule:install"));
        chk.require("self:capsule:install").unwrap();
    }

    #[test]
    fn device_scope_deny_wins_over_allow() {
        // Principal holds it, device allow matches, but a device deny pattern
        // overrides → DeviceScopeDenied.
        let p = profile_in(&["agent"]);
        let cfg = gc();
        let scope = DeviceScope::Scoped {
            allow: vec!["self:*".into()],
            deny: vec!["self:capsule:install".into()],
        };
        let chk = CapabilityCheck::new(&p, &cfg, pid()).with_device_scope(&scope);
        assert!(!chk.has("self:capsule:install"));
        let err = chk.require("self:capsule:install").unwrap_err();
        match err {
            PermissionError::DeviceScopeDenied {
                required,
                principal,
            } => {
                assert_eq!(required, "self:capsule:install");
                assert_eq!(principal, pid());
            },
            other => panic!("expected DeviceScopeDenied, got: {other:?}"),
        }
    }

    #[test]
    fn device_scope_cannot_widen_principal_deny() {
        // Principal does NOT hold the capability; even a permissive device
        // allow can't grant it — the principal floor still applies.
        let p = profile_in(&["agent"]);
        let cfg = gc();
        let scope = DeviceScope::Scoped {
            allow: vec!["*".into()],
            deny: vec![],
        };
        let chk = CapabilityCheck::new(&p, &cfg, pid()).with_device_scope(&scope);
        assert!(!chk.has("system:shutdown"));
        let err = chk.require("system:shutdown").unwrap_err();
        // The principal floor is what denies — not the device scope.
        match err {
            PermissionError::MissingCapability { required, .. } => {
                assert_eq!(required, "system:shutdown");
            },
            other => panic!("expected MissingCapability, got: {other:?}"),
        }
    }

    #[test]
    fn device_scope_outside_allow_is_denied() {
        // Principal holds it (agent has self:*), but the device allow list
        // doesn't cover this capability → denied.
        let p = profile_in(&["agent"]);
        let cfg = gc();
        let scope = DeviceScope::Scoped {
            allow: vec!["self:capsule:list".into()],
            deny: vec![],
        };
        let chk = CapabilityCheck::new(&p, &cfg, pid()).with_device_scope(&scope);
        assert!(chk.has("self:capsule:list"));
        assert!(!chk.has("self:capsule:install"));
        assert!(matches!(
            chk.require("self:capsule:install").unwrap_err(),
            PermissionError::DeviceScopeDenied { .. }
        ));
    }

    #[test]
    fn device_scope_wildcard_intersection() {
        // The headline use-case: principal self:*, device allow self:* deny
        // self:auth:pair → a self capability is allowed, the paired-denied one
        // is denied. Mirrors the `use-only` preset semantics.
        let mut p = profile_in(&["agent"]);
        // Give the agent the self-scoped pair capability so the principal floor
        // alone would allow it; the device scope is what restricts it.
        p.grants.push(cap("self:auth:pair"));
        let cfg = gc();
        let scope = DeviceScope::Scoped {
            allow: vec!["self:*".into()],
            deny: vec!["self:auth:pair".into(), "self:auth:pair:admin".into()],
        };
        let chk = CapabilityCheck::new(&p, &cfg, pid()).with_device_scope(&scope);

        // A general self capability is admitted.
        assert!(chk.has("self:agent:prompt"));
        chk.require("self:agent:prompt").unwrap();

        // The denied pairing capability is rejected even though the principal
        // holds it and the allow pattern matches.
        assert!(!chk.has("self:auth:pair"));
        assert!(matches!(
            chk.require("self:auth:pair").unwrap_err(),
            PermissionError::DeviceScopeDenied { .. }
        ));
    }

    #[test]
    fn device_scope_revoke_still_takes_top_precedence() {
        // A principal revoke must still win even with a permissive device
        // scope — the revoke is the highest-precedence floor.
        let mut p = profile_in(&["admin"]);
        p.revokes.push(cap("system:shutdown"));
        let cfg = gc();
        let scope = DeviceScope::Scoped {
            allow: vec!["*".into()],
            deny: vec![],
        };
        let chk = CapabilityCheck::new(&p, &cfg, pid()).with_device_scope(&scope);
        assert!(!chk.has("system:shutdown"));
        assert!(matches!(
            chk.require("system:shutdown").unwrap_err(),
            PermissionError::RevokedCapability { .. }
        ));
    }
}
