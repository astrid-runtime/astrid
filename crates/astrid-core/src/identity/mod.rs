//! # Astrid User Identity
//!
//! Provides [`AstridUserId`], the canonical internal user identity across all
//! platforms, and [`FrontendLink`], a mapping from platform-specific identities
//! to Astrid users.

/// Signed first-owner provisioning facts.
pub mod first_owner;
/// Durable human and fleet ownership identities.
pub mod ownership;
/// Stable principal identity.
pub mod principal;
/// Core identity types.
pub mod types;

pub use first_owner::{
    FIRST_OWNER_MESSAGE_LEN, FirstOwnerClaim, FirstOwnerClaimError, FirstOwnerGeneration,
};
pub use ownership::{
    FleetGenesis, FleetIdentity, FleetMembership, FleetRole, FleetUid, OwnershipIdentityError,
    PrincipalOwnership, UserGenesis, UserIdentity, UserUid,
};
pub use principal::{PrincipalGenesis, PrincipalIdentity, PrincipalIdentityError, PrincipalUid};
pub use types::{AstridUserId, FrontendLink, normalize_platform};

#[cfg(test)]
mod tests {
    use super::types::AstridUserId;
    use super::*;

    #[test]
    fn test_astrid_user_id_creation() {
        let user1 = AstridUserId::new();
        let user2 = AstridUserId::new();
        assert_ne!(user1.id, user2.id);
    }

    #[test]
    fn test_astrid_user_id_default_principal() {
        let user = AstridUserId::new();
        assert_eq!(user.principal.as_str(), "default");
    }

    #[test]
    fn test_astrid_user_id_display() {
        let user = AstridUserId::new();
        let display = user.to_string();
        assert!(display.starts_with("user:"));

        let user_with_name = AstridUserId::new().with_display_name("Alice");
        let display = user_with_name.to_string();
        assert!(display.starts_with("Alice("));
    }

    #[test]
    fn test_principal_derived_from_display_name() {
        let user = AstridUserId::new().with_display_name("Josh Bouw");
        assert_eq!(user.principal.as_str(), "josh-bouw");
    }

    #[test]
    fn test_principal_derived_unicode_fallback() {
        // All non-ASCII chars → hyphens → collapsed → empty → fallback.
        let user = AstridUserId::new().with_display_name("日本語");
        assert!(
            user.principal.as_str().starts_with("user-"),
            "expected uuid fallback, got: {}",
            user.principal.as_str()
        );
    }

    #[test]
    fn test_principal_derived_empty_string() {
        let user = AstridUserId::new().with_display_name("");
        assert!(
            user.principal.as_str().starts_with("user-"),
            "expected uuid fallback, got: {}",
            user.principal.as_str()
        );
    }

    #[test]
    fn test_principal_derived_special_chars() {
        let user = AstridUserId::new().with_display_name("alice@example.com");
        assert_eq!(user.principal.as_str(), "alice-example-com");
    }

    #[test]
    fn test_principal_derived_truncation() {
        let long_name = "a".repeat(100);
        let user = AstridUserId::new().with_display_name(&long_name);
        assert!(user.principal.as_str().len() <= 64);
    }

    #[test]
    fn test_principal_explicit_override_after_display_name() {
        let principal = crate::PrincipalId::new("custom-principal").unwrap();
        let user = AstridUserId::new()
            .with_display_name("Alice")
            .with_principal(principal);
        assert_eq!(user.principal.as_str(), "custom-principal");
    }

    #[test]
    fn test_principal_preserved_when_set_before_display_name() {
        // Documented order: with_principal() then with_display_name()
        // should preserve the explicit principal.
        let principal = crate::PrincipalId::new("custom-principal").unwrap();
        let user = AstridUserId::new()
            .with_principal(principal)
            .with_display_name("Alice");
        assert_eq!(user.principal.as_str(), "custom-principal");
        assert_eq!(user.display_name.as_deref(), Some("Alice"));
    }

    #[test]
    fn test_legacy_user_deserializes_without_principal() {
        // Records created before the principal field was added must
        // deserialize with the default principal, not fail.
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "public_key": null,
            "display_name": "legacy-user",
            "created_at": "2024-01-01T00:00:00Z"
        }"#;
        let user: AstridUserId = serde_json::from_str(json)
            .expect("legacy user record should deserialize without principal field");
        assert_eq!(user.principal.as_str(), "default");
        assert_eq!(user.display_name.as_deref(), Some("legacy-user"));
    }

    #[test]
    fn normalize_platform_trims_and_lowercases() {
        assert_eq!(normalize_platform("Discord"), "discord");
        assert_eq!(normalize_platform("  TELEGRAM  "), "telegram");
        assert_eq!(normalize_platform("matrix"), "matrix");
        assert_eq!(normalize_platform("  Matrix  "), "matrix");
    }
}
