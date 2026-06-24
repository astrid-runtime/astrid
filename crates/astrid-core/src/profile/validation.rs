//! Semantic validation for [`PrincipalProfile`] and its nested configs.
//!
//! Validation runs on both load and save — a malformed profile on disk is
//! never silently accepted, and a malformed in-memory profile is never
//! persisted.

use crate::capability_grammar::validate_capability;

use super::{
    AuthConfig, BACKGROUND_PROCESSES_UPPER_BOUND, CURRENT_PROFILE_VERSION, MAX_CAPSULE_GRANT_LEN,
    MAX_GROUP_NAME_LEN, NetworkConfig, PrincipalProfile, ProcessConfig, ProfileError,
    ProfileResult, Quotas, TIMEOUT_SECS_UPPER_BOUND,
};

impl PrincipalProfile {
    /// Enforce semantic validation rules. Invoked on both load and save.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Invalid`] on the first failing rule; order
    /// of rule evaluation is not part of the public contract.
    pub fn validate(&self) -> ProfileResult<()> {
        if self.profile_version > CURRENT_PROFILE_VERSION {
            return Err(ProfileError::Invalid(format!(
                "profile_version {} exceeds supported version {}",
                self.profile_version, CURRENT_PROFILE_VERSION
            )));
        }
        self.quotas.validate()?;
        self.auth.validate()?;
        for group in &self.groups {
            validate_group_name(group)?;
        }
        for cap in &self.grants {
            validate_capability(cap).map_err(|e| {
                ProfileError::Invalid(format!("grants entry {cap:?} rejected: {e}"))
            })?;
        }
        for cap in &self.revokes {
            validate_capability(cap).map_err(|e| {
                ProfileError::Invalid(format!("revokes entry {cap:?} rejected: {e}"))
            })?;
        }
        for capsule in &self.capsules {
            validate_capsule_grant(capsule)?;
        }
        self.network.validate()?;
        self.process.validate()?;
        Ok(())
    }
}

impl Quotas {
    /// Validate quota bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Invalid`] if any quota is zero where
    /// non-zero is required, or exceeds its documented upper bound.
    pub fn validate(&self) -> ProfileResult<()> {
        if self.max_memory_bytes == 0 {
            return Err(ProfileError::Invalid(
                "quotas.max_memory_bytes must be > 0".into(),
            ));
        }
        if self.max_timeout_secs == 0 || self.max_timeout_secs > TIMEOUT_SECS_UPPER_BOUND {
            return Err(ProfileError::Invalid(format!(
                "quotas.max_timeout_secs must be in 1..={TIMEOUT_SECS_UPPER_BOUND}",
            )));
        }
        if self.max_ipc_throughput_bytes == 0 {
            return Err(ProfileError::Invalid(
                "quotas.max_ipc_throughput_bytes must be > 0".into(),
            ));
        }
        if self.max_background_processes > BACKGROUND_PROCESSES_UPPER_BOUND {
            return Err(ProfileError::Invalid(format!(
                "quotas.max_background_processes must be <= {BACKGROUND_PROCESSES_UPPER_BOUND}",
            )));
        }
        if self.max_storage_bytes == 0 {
            return Err(ProfileError::Invalid(
                "quotas.max_storage_bytes must be > 0".into(),
            ));
        }
        if self.max_cpu_fuel_per_sec == 0 {
            // Fail-closed: a zero CPU rate would trap every guest instruction
            // immediately. There is no "unlimited" sentinel — exemption is a
            // capability (`CAP_RESOURCES_UNBOUNDED`), never a quota value.
            return Err(ProfileError::Invalid(
                "quotas.max_cpu_fuel_per_sec must be > 0".into(),
            ));
        }
        Ok(())
    }
}

impl AuthConfig {
    /// Validate registered device keys. Method variants are enforced by serde
    /// via the closed [`AuthMethod`](super::AuthMethod) enum.
    ///
    /// Each [`DeviceKey`](super::DeviceKey) must carry a non-empty, 64-char
    /// lowercase-hex pubkey and a non-empty `key_id`. For a
    /// [`DeviceScope::Scoped`](super::DeviceScope::Scoped) device, every
    /// `allow`/`deny` pattern must be a syntactically valid capability string
    /// (same grammar as grants/revokes), so an attacker-crafted profile can't
    /// smuggle a shell-metachar or double-glob through the device scope and
    /// have it reach the matcher.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Invalid`] on the first failing rule.
    pub fn validate(&self) -> ProfileResult<()> {
        for key in &self.public_keys {
            validate_device_key(key)?;
        }
        Ok(())
    }
}

/// Validate a single registered device key (pubkey shape + `key_id` presence +
/// scope-pattern grammar). Fail-closed: the first failing rule errors.
fn validate_device_key(key: &super::DeviceKey) -> ProfileResult<()> {
    use super::DeviceScope;

    if key.pubkey.is_empty() {
        return Err(ProfileError::Invalid(
            "auth.public_keys: device pubkey must be non-empty".into(),
        ));
    }
    if key.pubkey.len() != 64 || !key.pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ProfileError::Invalid(format!(
            "auth.public_keys: device pubkey must be 64 hex chars, got {:?}",
            key.pubkey
        )));
    }
    // Canonical form is lowercase; an uppercase entry means an un-normalised
    // key reached storage, which would defeat the deterministic key_id /
    // dedup-by-pubkey contract.
    if key.pubkey.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(ProfileError::Invalid(
            "auth.public_keys: device pubkey must be lowercase hex".into(),
        ));
    }
    if key.key_id.is_empty() {
        return Err(ProfileError::Invalid(
            "auth.public_keys: device key_id must be non-empty".into(),
        ));
    }
    if let DeviceScope::Scoped { allow, deny } = &key.scope {
        for pattern in allow.iter().chain(deny.iter()) {
            validate_capability(pattern).map_err(|e| {
                ProfileError::Invalid(format!(
                    "auth.public_keys: device scope pattern {pattern:?} rejected: {e}"
                ))
            })?;
        }
    }
    Ok(())
}

impl NetworkConfig {
    /// Validate egress entries.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Invalid`] if any entry is an empty string.
    /// Richer grammar checking is deferred to Layer 5.
    pub fn validate(&self) -> ProfileResult<()> {
        for pattern in &self.egress {
            if pattern.trim().is_empty() {
                return Err(ProfileError::Invalid(
                    "network.egress entries must be non-empty".into(),
                ));
            }
        }
        for (capsule_id, endpoints) in &self.capsule_egress {
            if capsule_id.trim().is_empty() {
                return Err(ProfileError::Invalid(
                    "network.capsule_egress keys (capsule ids) must be non-empty".into(),
                ));
            }
            for endpoint in endpoints {
                if endpoint.trim().is_empty() {
                    return Err(ProfileError::Invalid(
                        "network.capsule_egress endpoints must be non-empty".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

impl ProcessConfig {
    /// Validate process-allow entries.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Invalid`] if any entry is an empty string.
    /// Richer grammar checking is deferred to Layer 5.
    pub fn validate(&self) -> ProfileResult<()> {
        for entry in &self.allow {
            if entry.trim().is_empty() {
                return Err(ProfileError::Invalid(
                    "process.allow entries must be non-empty".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Validate a single capsule-grant entry against the same character set a
/// `CapsuleId` enforces — non-empty, lowercase alphanumeric and hyphens
/// only — plus a defensive length cap of [`MAX_CAPSULE_GRANT_LEN`].
///
/// The length cap is the profile's own sanity bound on operator-supplied
/// input, NOT a mirror of `CapsuleId`: `astrid_capsule::CapsuleId::validate`
/// caps the charset but imposes no length limit. A grant entry that cannot
/// name a real capsule is rejected on load — fail-closed: a malformed grant
/// never silently widens (or, by failing the whole profile, narrows) access
/// in a way the operator did not intend.
fn validate_capsule_grant(id: &str) -> ProfileResult<()> {
    if id.is_empty() {
        return Err(ProfileError::Invalid(
            "capsules entries must be non-empty".into(),
        ));
    }
    if id.len() > MAX_CAPSULE_GRANT_LEN {
        return Err(ProfileError::Invalid(format!(
            "capsules entry exceeds {MAX_CAPSULE_GRANT_LEN} characters: {id:?}",
        )));
    }
    if let Some(bad) = id
        .chars()
        .find(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit() && *c != '-')
    {
        return Err(ProfileError::Invalid(format!(
            "capsules entry {id:?} contains invalid character {bad:?} (allowed: a-z, 0-9, -)",
        )));
    }
    Ok(())
}

/// Same character set + length cap as [`PrincipalId`](crate::PrincipalId):
/// `[a-zA-Z0-9_-]` and up to [`MAX_GROUP_NAME_LEN`] characters.
fn validate_group_name(name: &str) -> ProfileResult<()> {
    if name.is_empty() {
        return Err(ProfileError::Invalid(
            "groups entries must be non-empty".into(),
        ));
    }
    if name.len() > MAX_GROUP_NAME_LEN {
        return Err(ProfileError::Invalid(format!(
            "groups entry exceeds {MAX_GROUP_NAME_LEN} characters: {name:?}",
        )));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && *c != '-' && *c != '_')
    {
        return Err(ProfileError::Invalid(format!(
            "groups entry {name:?} contains invalid character {bad:?} (allowed: a-z, A-Z, 0-9, -, _)",
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)] // tests mutate a known-good baseline
mod tests {
    use super::*;

    // ── Quotas ────────────────────────────────────────────────────────

    #[test]
    fn rejects_zero_memory() {
        let mut p = PrincipalProfile::default();
        p.quotas.max_memory_bytes = 0;
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    #[test]
    fn rejects_zero_timeout() {
        let mut p = PrincipalProfile::default();
        p.quotas.max_timeout_secs = 0;
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    #[test]
    fn rejects_timeout_over_cap() {
        let mut p = PrincipalProfile::default();
        p.quotas.max_timeout_secs = TIMEOUT_SECS_UPPER_BOUND + 1;
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    #[test]
    fn accepts_timeout_at_cap() {
        let mut p = PrincipalProfile::default();
        p.quotas.max_timeout_secs = TIMEOUT_SECS_UPPER_BOUND;
        p.validate().unwrap();
    }

    #[test]
    fn rejects_zero_ipc_throughput() {
        let mut p = PrincipalProfile::default();
        p.quotas.max_ipc_throughput_bytes = 0;
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    #[test]
    fn rejects_background_procs_over_cap() {
        let mut p = PrincipalProfile::default();
        p.quotas.max_background_processes = BACKGROUND_PROCESSES_UPPER_BOUND + 1;
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    #[test]
    fn accepts_background_procs_at_cap() {
        let mut p = PrincipalProfile::default();
        p.quotas.max_background_processes = BACKGROUND_PROCESSES_UPPER_BOUND;
        p.validate().unwrap();
    }

    #[test]
    fn rejects_zero_storage() {
        let mut p = PrincipalProfile::default();
        p.quotas.max_storage_bytes = 0;
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    #[test]
    fn rejects_zero_cpu_fuel_per_sec() {
        let mut p = PrincipalProfile::default();
        p.quotas.max_cpu_fuel_per_sec = 0;
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    // ── Auth ──────────────────────────────────────────────────────────

    #[test]
    fn accepts_all_known_auth_methods() {
        use super::super::AuthMethod;
        let mut p = PrincipalProfile::default();
        p.auth.methods = vec![AuthMethod::Keypair, AuthMethod::Passkey, AuthMethod::System];
        p.validate().unwrap();
    }

    #[test]
    fn accepts_full_scope_device_key() {
        use super::super::{DeviceKey, DeviceScope};
        let mut p = PrincipalProfile::default();
        p.auth.public_keys = vec![DeviceKey::new("a".repeat(64), DeviceScope::Full, None, 0)];
        p.validate().unwrap();
    }

    #[test]
    fn accepts_scoped_device_key_with_valid_patterns() {
        use super::super::{DeviceKey, DeviceScope};
        let mut p = PrincipalProfile::default();
        p.auth.public_keys = vec![DeviceKey::new(
            "b".repeat(64),
            DeviceScope::Scoped {
                allow: vec!["self:*".into()],
                deny: vec!["self:auth:pair".into()],
            },
            Some("laptop".into()),
            0,
        )];
        p.validate().unwrap();
    }

    #[test]
    fn rejects_device_key_with_bad_pubkey_len() {
        use super::super::{DeviceKey, DeviceScope};
        let mut p = PrincipalProfile::default();
        // Construct directly so the bad pubkey bypasses the deserialize-time
        // validation and reaches the profile validator.
        p.auth.public_keys = vec![DeviceKey {
            key_id: "deadbeef".into(),
            pubkey: "abc".into(),
            scope: DeviceScope::Full,
            label: None,
            created_at: 0,
        }];
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    #[test]
    fn rejects_device_key_with_empty_key_id() {
        use super::super::{DeviceKey, DeviceScope};
        let mut p = PrincipalProfile::default();
        p.auth.public_keys = vec![DeviceKey {
            key_id: String::new(),
            pubkey: "a".repeat(64),
            scope: DeviceScope::Full,
            label: None,
            created_at: 0,
        }];
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    #[test]
    fn rejects_device_scope_pattern_with_shell_metachar() {
        use super::super::{DeviceKey, DeviceScope};
        let mut p = PrincipalProfile::default();
        p.auth.public_keys = vec![DeviceKey::new(
            "c".repeat(64),
            DeviceScope::Scoped {
                allow: vec!["self:shutdown;rm".into()],
                deny: vec![],
            },
            None,
            0,
        )];
        let err = p.validate().unwrap_err();
        match err {
            ProfileError::Invalid(msg) => {
                assert!(msg.contains("device scope pattern"), "msg: {msg}");
            },
            other => panic!("expected Invalid, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_device_pubkey_uppercase() {
        use super::super::{DeviceKey, DeviceScope};
        let mut p = PrincipalProfile::default();
        p.auth.public_keys = vec![DeviceKey {
            key_id: "deadbeef".into(),
            pubkey: "A".repeat(64),
            scope: DeviceScope::Full,
            label: None,
            created_at: 0,
        }];
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    // ── Groups ────────────────────────────────────────────────────────

    #[test]
    fn accepts_valid_group_names() {
        let mut p = PrincipalProfile::default();
        p.groups = vec![
            "admins".into(),
            "ops_team".into(),
            "agent-007".into(),
            "X".into(),
            "a".repeat(MAX_GROUP_NAME_LEN),
        ];
        p.validate().unwrap();
    }

    #[test]
    fn rejects_empty_group() {
        let mut p = PrincipalProfile::default();
        p.groups = vec![String::new()];
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    #[test]
    fn rejects_group_with_bad_char() {
        let mut p = PrincipalProfile::default();
        p.groups = vec!["ops/team".into()];
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    #[test]
    fn rejects_group_too_long() {
        let mut p = PrincipalProfile::default();
        p.groups = vec!["a".repeat(MAX_GROUP_NAME_LEN + 1)];
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    // ── Capsule grants ────────────────────────────────────────────────

    #[test]
    fn accepts_valid_capsule_grants() {
        let mut p = PrincipalProfile::default();
        p.capsules = vec![
            "identity".into(),
            "registry".into(),
            "context-engine".into(),
            "openai-compat".into(),
            "a".repeat(MAX_CAPSULE_GRANT_LEN),
        ];
        p.validate().unwrap();
    }

    #[test]
    fn rejects_empty_capsule_grant() {
        let mut p = PrincipalProfile::default();
        p.capsules = vec![String::new()];
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    #[test]
    fn rejects_capsule_grant_with_uppercase() {
        let mut p = PrincipalProfile::default();
        p.capsules = vec!["Identity".into()];
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    #[test]
    fn rejects_capsule_grant_with_bad_char() {
        let mut p = PrincipalProfile::default();
        p.capsules = vec!["ident_ity".into()];
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    #[test]
    fn rejects_capsule_grant_too_long() {
        let mut p = PrincipalProfile::default();
        p.capsules = vec!["a".repeat(MAX_CAPSULE_GRANT_LEN + 1)];
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    // ── Grants / revokes (capability grammar) ─────────────────────────

    #[test]
    fn accepts_valid_grants_and_revokes() {
        let mut p = PrincipalProfile::default();
        p.grants = vec!["system:shutdown".into(), "self:*".into(), "*".into()];
        p.revokes = vec!["audit:read:alice".into(), "a:*:b".into()];
        p.validate().unwrap();
    }

    #[test]
    fn rejects_grant_with_shell_metachar() {
        let mut p = PrincipalProfile::default();
        p.grants = vec!["system:shutdown;rm".into()];
        let err = p.validate().unwrap_err();
        match err {
            ProfileError::Invalid(msg) => assert!(msg.contains("grants entry"), "msg: {msg}"),
            other => panic!("expected Invalid, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_grant_with_double_glob() {
        let mut p = PrincipalProfile::default();
        p.grants = vec!["capsule:**".into()];
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    #[test]
    fn rejects_empty_grant_entry() {
        let mut p = PrincipalProfile::default();
        p.grants = vec![String::new()];
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    #[test]
    fn rejects_revoke_with_trailing_colon() {
        let mut p = PrincipalProfile::default();
        p.revokes = vec!["system:".into()];
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    // ── Network / process ─────────────────────────────────────────────

    #[test]
    fn rejects_whitespace_egress() {
        let mut p = PrincipalProfile::default();
        p.network.egress = vec!["   ".into()];
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    #[test]
    fn rejects_empty_process_allow() {
        let mut p = PrincipalProfile::default();
        p.process.allow = vec![String::new()];
        assert!(matches!(p.validate(), Err(ProfileError::Invalid(_))));
    }

    // ── Version gate ──────────────────────────────────────────────────

    #[test]
    fn rejects_future_version() {
        let mut p = PrincipalProfile::default();
        p.profile_version = CURRENT_PROFILE_VERSION + 1;
        let err = p.validate().unwrap_err();
        match err {
            ProfileError::Invalid(msg) => assert!(msg.contains("profile_version"), "msg: {msg}"),
            other => panic!("expected Invalid, got: {other:?}"),
        }
    }
}
