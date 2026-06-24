//! Capability tokens - cryptographically signed authorization.
//!
//! A capability token grants specific permissions to access resources.
//! Tokens are:
//! - Signed by the runtime's ed25519 key
//! - Linked to the approval event that created them
//! - Scoped (session or persistent)
//! - Time-bounded (optional expiration)

use astrid_core::principal::PrincipalId;
use astrid_core::{Permission, Timestamp, TokenId};
use astrid_crypto::{ContentHash, KeyPair, PublicKey, Signature};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CapabilityError, CapabilityResult};
use crate::pattern::ResourcePattern;

/// Version of the signing data format.
///
/// v1 — original format without principal scoping.
/// v2 — Layer 4 of multi-tenancy (issue #668) — appends a length-prefixed
///      principal string to the signed payload. v1 persistent tokens on
///      disk after upgrade fail signature verification with
///      [`CapabilityError::InvalidSignature`]; operators must re-mint them
///      (see [`CapabilityStore::find_capability`](crate::CapabilityStore::find_capability)
///      for the runtime log).
const SIGNING_DATA_VERSION: u8 = 0x02;

/// Default clock skew tolerance in seconds.
const DEFAULT_CLOCK_SKEW_SECS: i64 = 30;

/// Write a length-prefixed byte slice to the output buffer.
///
/// Format: 4-byte little-endian length followed by the data.
#[expect(clippy::cast_possible_truncation)]
fn write_length_prefixed(data: &mut Vec<u8>, bytes: &[u8]) {
    // Length is limited to u32::MAX; larger slices would be truncated.
    // This is acceptable as capability token fields are small.
    data.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(bytes);
}

/// Unique identifier for an audit entry (used for linking).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuditEntryId(pub Uuid);

impl AuditEntryId {
    /// Create a new audit entry ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for AuditEntryId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for AuditEntryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "audit:{}", &self.0.to_string()[..8])
    }
}

/// Token scope - how long it lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenScope {
    /// Valid only for the current session (in-memory).
    Session,
    /// Persisted across sessions.
    Persistent,
}

impl std::fmt::Display for TokenScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session => write!(f, "session"),
            Self::Persistent => write!(f, "persistent"),
        }
    }
}

/// A capability token granting permissions for a resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// Unique token identifier.
    pub id: TokenId,
    /// Resource pattern this token applies to.
    pub resource: ResourcePattern,
    /// Permissions granted.
    pub permissions: Vec<Permission>,
    /// When the token was issued.
    pub issued_at: Timestamp,
    /// When the token expires (None = no expiration within scope).
    pub expires_at: Option<Timestamp>,
    /// Token scope (session or persistent).
    pub scope: TokenScope,
    /// Public key of the issuer (runtime).
    pub issuer: PublicKey,
    /// User who approved this token (key ID, first 8 bytes).
    pub user_id: [u8; 8],
    /// Audit entry ID linking to the approval event.
    pub approval_audit_id: AuditEntryId,
    /// Whether this token can only be used once (replay protection).
    #[serde(default)]
    pub single_use: bool,
    /// Principal this token was minted for.
    ///
    /// Signed into the payload (Layer 4 / issue #668): a token minted for
    /// Alice cannot authorise Bob's invocation even if copied forward, and
    /// a forger cannot rewrite the principal without the runtime private
    /// key. The field has no serde default — old v1 tokens without it
    /// deserialize as `MissingField` and get rejected at load time.
    pub principal: PrincipalId,
    /// Cryptographic signature of the token.
    pub signature: Signature,
}

impl CapabilityToken {
    /// Create a new capability token.
    ///
    /// This is typically called by the runtime after user approval.
    /// `principal` is bound into the signed payload and is the only
    /// principal allowed to consume the token on subsequent lookups.
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn create(
        resource: ResourcePattern,
        permissions: Vec<Permission>,
        scope: TokenScope,
        user_id: [u8; 8],
        approval_audit_id: AuditEntryId,
        runtime_key: &KeyPair,
        ttl: Option<Duration>,
        principal: PrincipalId,
    ) -> Self {
        Self::create_with_options(
            resource,
            permissions,
            scope,
            user_id,
            approval_audit_id,
            runtime_key,
            ttl,
            false,
            principal,
        )
    }

    /// Create a new capability token with additional options.
    ///
    /// This is typically called by the runtime after user approval.
    /// See [`create`](Self::create) for the role of `principal`.
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn create_with_options(
        resource: ResourcePattern,
        permissions: Vec<Permission>,
        scope: TokenScope,
        user_id: [u8; 8],
        approval_audit_id: AuditEntryId,
        runtime_key: &KeyPair,
        ttl: Option<Duration>,
        single_use: bool,
        principal: PrincipalId,
    ) -> Self {
        let id = TokenId::new();
        let issued_at = Timestamp::now();
        let expires_at = ttl.map(|d| {
            // Safety: chrono Duration addition to DateTime cannot overflow for reasonable durations
            #[expect(clippy::arithmetic_side_effects)]
            let expiry = Utc::now() + d;
            Timestamp::from_datetime(expiry)
        });
        let issuer = runtime_key.export_public_key();

        // Create token without signature for signing
        let mut token = Self {
            id,
            resource,
            permissions,
            issued_at,
            expires_at,
            scope,
            issuer,
            user_id,
            approval_audit_id,
            single_use,
            principal,
            signature: Signature::from_bytes([0u8; 64]), // Placeholder
        };

        // Sign the token
        let signing_data = token.signing_data();
        token.signature = runtime_key.sign(&signing_data);

        token
    }

    /// Get the data used for signing (excludes the signature itself).
    ///
    /// Format (v2, issue #668):
    /// - 1 byte: version (0x02)
    /// - Length-prefixed token ID (UUID bytes)
    /// - Length-prefixed resource pattern string
    /// - 4 bytes: number of permissions
    /// - For each permission: length-prefixed string
    /// - 8 bytes: `issued_at` timestamp (i64 LE)
    /// - 1 byte: `has_expiration` flag
    /// - If `has_expiration`: 8 bytes expiration timestamp (i64 LE)
    /// - Length-prefixed scope string
    /// - 32 bytes: issuer public key
    /// - 8 bytes: `user_id`
    /// - Length-prefixed audit entry ID (UUID bytes)
    /// - 1 byte: `single_use` flag
    /// - Length-prefixed principal string (v2 addition)
    ///
    /// v1 tokens (without the principal suffix) fail signature verification
    /// against v2 verifiers and must be re-minted. There is no silent upgrade
    /// path — changing the signing format is a cryptographic break.
    #[must_use]
    #[expect(clippy::cast_possible_truncation)]
    pub fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(512);

        // Version prefix
        data.push(SIGNING_DATA_VERSION);

        // Token ID
        write_length_prefixed(&mut data, self.id.0.as_bytes());

        // Resource pattern
        write_length_prefixed(&mut data, self.resource.as_str().as_bytes());

        // Permissions count and values
        data.extend_from_slice(&(self.permissions.len() as u32).to_le_bytes());
        for perm in &self.permissions {
            write_length_prefixed(&mut data, perm.to_string().as_bytes());
        }

        // Issued at
        data.extend_from_slice(&self.issued_at.0.timestamp().to_le_bytes());

        // Expiration (with presence flag)
        if let Some(expires) = &self.expires_at {
            data.push(0x01); // has expiration
            data.extend_from_slice(&expires.0.timestamp().to_le_bytes());
        } else {
            data.push(0x00); // no expiration
        }

        // Scope
        write_length_prefixed(&mut data, self.scope.to_string().as_bytes());

        // Issuer (fixed 32 bytes)
        data.extend_from_slice(self.issuer.as_bytes());

        // User ID (fixed 8 bytes)
        data.extend_from_slice(&self.user_id);

        // Approval audit ID
        write_length_prefixed(&mut data, self.approval_audit_id.0.as_bytes());

        // Single use flag
        data.push(u8::from(self.single_use));

        // Principal (v2). Length-prefixed so the format stays self-describing
        // and extensible. The raw string is always valid UTF-8 (PrincipalId
        // enforces ASCII alphanumeric + `-_` at construction).
        write_length_prefixed(&mut data, self.principal.as_str().as_bytes());

        data
    }

    /// Verify the token's signature.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::InvalidSignature`] if the signature is invalid.
    pub fn verify_signature(&self) -> CapabilityResult<()> {
        let signing_data = self.signing_data();
        self.issuer
            .verify(&signing_data, &self.signature)
            .map_err(|_| CapabilityError::InvalidSignature)
    }

    /// Check if the token has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.is_expired_with_skew(0)
    }

    /// Check if the token has expired, with clock skew tolerance.
    ///
    /// A positive `skew_secs` value allows tokens that expired up to
    /// that many seconds ago to still be considered valid.
    #[must_use]
    pub fn is_expired_with_skew(&self, skew_secs: i64) -> bool {
        self.expires_at.as_ref().is_some_and(|exp| {
            let now = Utc::now();
            // Safety: chrono Duration addition to DateTime cannot overflow for reasonable skew values
            #[expect(clippy::arithmetic_side_effects)]
            let adjusted_expiry = exp.0 + Duration::seconds(skew_secs);
            now > adjusted_expiry
        })
    }

    /// Check if the token is valid (not expired, signature OK).
    ///
    /// Uses the default clock skew tolerance (30 seconds).
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::TokenExpired`] if expired,
    /// or [`CapabilityError::InvalidSignature`] if the signature is invalid.
    pub fn validate(&self) -> CapabilityResult<()> {
        self.validate_with_skew(DEFAULT_CLOCK_SKEW_SECS)
    }

    /// Check if the token is valid with custom clock skew tolerance.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::TokenExpired`] if expired,
    /// or [`CapabilityError::InvalidSignature`] if the signature is invalid.
    pub fn validate_with_skew(&self, skew_secs: i64) -> CapabilityResult<()> {
        if self.is_expired_with_skew(skew_secs) {
            return Err(CapabilityError::TokenExpired {
                token_id: self.id.to_string(),
            });
        }
        self.verify_signature()
    }

    /// Check if this is a single-use token.
    #[must_use]
    pub fn is_single_use(&self) -> bool {
        self.single_use
    }

    /// Check if this token grants a permission for a resource.
    #[must_use]
    pub fn grants(&self, resource: &str, permission: Permission) -> bool {
        self.resource.matches(resource) && self.permissions.contains(&permission)
    }

    /// Hash the token for audit purposes.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::hash(&self.signing_data())
    }
}

impl PartialEq for CapabilityToken {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for CapabilityToken {}

impl std::hash::Hash for CapabilityToken {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// Builder for creating capability tokens with fluent API.
#[cfg(test)]
pub(crate) struct TokenBuilder {
    resource: ResourcePattern,
    permissions: Vec<Permission>,
    scope: TokenScope,
    ttl: Option<Duration>,
    single_use: bool,
}

#[cfg(test)]
impl TokenBuilder {
    /// Create a new token builder.
    #[must_use]
    pub(crate) fn new(resource: ResourcePattern) -> Self {
        Self {
            resource,
            permissions: Vec::new(),
            scope: TokenScope::Session,
            ttl: None,
            single_use: false,
        }
    }

    /// Add a permission.
    #[must_use]
    pub(crate) fn permission(mut self, perm: Permission) -> Self {
        if !self.permissions.contains(&perm) {
            self.permissions.push(perm);
        }
        self
    }

    /// Add multiple permissions.
    #[must_use]
    pub(crate) fn permissions(mut self, perms: impl IntoIterator<Item = Permission>) -> Self {
        for perm in perms {
            if !self.permissions.contains(&perm) {
                self.permissions.push(perm);
            }
        }
        self
    }

    /// Set the scope.
    #[must_use]
    pub(crate) fn scope(mut self, scope: TokenScope) -> Self {
        self.scope = scope;
        self
    }

    /// Set persistent scope.
    #[must_use]
    pub(crate) fn persistent(self) -> Self {
        self.scope(TokenScope::Persistent)
    }

    /// Set session scope.
    #[must_use]
    pub(crate) fn session(self) -> Self {
        self.scope(TokenScope::Session)
    }

    /// Set time-to-live.
    #[must_use]
    pub(crate) fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Mark token as single-use (for replay protection).
    #[must_use]
    pub(crate) fn single_use(mut self) -> Self {
        self.single_use = true;
        self
    }

    /// Build the token (requires runtime key and user context).
    #[must_use]
    pub(crate) fn build(
        self,
        user_id: [u8; 8],
        approval_audit_id: AuditEntryId,
        runtime_key: &KeyPair,
    ) -> CapabilityToken {
        CapabilityToken::create_with_options(
            self.resource,
            self.permissions,
            self.scope,
            user_id,
            approval_audit_id,
            runtime_key,
            self.ttl,
            self.single_use,
            PrincipalId::default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_core::Permission;

    fn test_keypair() -> KeyPair {
        KeyPair::generate()
    }

    #[test]
    fn test_token_creation() {
        let keypair = test_keypair();
        let pattern = ResourcePattern::exact("mcp://filesystem:read_file").unwrap();

        let token = CapabilityToken::create(
            pattern,
            vec![Permission::Invoke],
            TokenScope::Session,
            keypair.key_id(),
            AuditEntryId::new(),
            &keypair,
            None,
            PrincipalId::default(),
        );

        assert!(!token.is_expired());
        assert!(token.verify_signature().is_ok());
    }

    #[test]
    fn test_token_grants() {
        let keypair = test_keypair();
        let pattern = ResourcePattern::new("mcp://filesystem:*").unwrap();

        let token = CapabilityToken::create(
            pattern,
            vec![Permission::Invoke, Permission::Read],
            TokenScope::Session,
            keypair.key_id(),
            AuditEntryId::new(),
            &keypair,
            None,
            PrincipalId::default(),
        );

        assert!(token.grants("mcp://filesystem:read_file", Permission::Invoke));
        assert!(token.grants("mcp://filesystem:write_file", Permission::Invoke));
        assert!(!token.grants("mcp://filesystem:read_file", Permission::Write));
        assert!(!token.grants("mcp://memory:read", Permission::Invoke));
    }

    #[test]
    fn test_token_expiration() {
        let keypair = test_keypair();
        let pattern = ResourcePattern::exact("test://resource").unwrap();

        // Create expired token (beyond clock skew tolerance of 30s)
        let token = CapabilityToken::create(
            pattern,
            vec![Permission::Read],
            TokenScope::Session,
            keypair.key_id(),
            AuditEntryId::new(),
            &keypair,
            Some(Duration::seconds(-60)), // Expired well beyond skew tolerance
            PrincipalId::default(),
        );

        assert!(token.is_expired());
        assert!(matches!(
            token.validate(),
            Err(CapabilityError::TokenExpired { .. })
        ));
    }

    #[test]
    fn test_token_expiration_with_clock_skew() {
        let keypair = test_keypair();
        let pattern = ResourcePattern::exact("test://resource").unwrap();

        // Create token that just expired but is within clock skew tolerance
        let token = CapabilityToken::create(
            pattern,
            vec![Permission::Read],
            TokenScope::Session,
            keypair.key_id(),
            AuditEntryId::new(),
            &keypair,
            Some(Duration::seconds(-10)), // Just expired
            PrincipalId::default(),
        );

        // Without skew tolerance, it's expired
        assert!(token.is_expired());
        assert!(token.is_expired_with_skew(0));

        // With default 30s skew tolerance, it's still valid
        assert!(!token.is_expired_with_skew(30));
        assert!(token.validate().is_ok());
    }

    #[test]
    fn test_token_builder() {
        let keypair = test_keypair();

        let token =
            TokenBuilder::new(ResourcePattern::exact("mcp://filesystem:read_file").unwrap())
                .permissions(vec![Permission::Invoke, Permission::Read])
                .permission(Permission::Write)
                .session()
                .persistent()
                .single_use()
                .ttl(Duration::hours(24))
                .build(keypair.key_id(), AuditEntryId::new(), &keypair);

        assert_eq!(token.scope, TokenScope::Persistent);
        assert!(token.expires_at.is_some());
        assert!(token.permissions.contains(&Permission::Invoke));
        assert!(token.permissions.contains(&Permission::Read));
        assert!(token.permissions.contains(&Permission::Write));
    }

    #[test]
    fn test_token_signature_verification() {
        let keypair = test_keypair();
        let pattern = ResourcePattern::exact("test://resource").unwrap();

        let mut token = CapabilityToken::create(
            pattern,
            vec![Permission::Read],
            TokenScope::Session,
            keypair.key_id(),
            AuditEntryId::new(),
            &keypair,
            None,
            PrincipalId::default(),
        );

        // Valid signature
        assert!(token.verify_signature().is_ok());

        // Tamper with token
        token.permissions.push(Permission::Write);

        // Signature should now fail
        assert!(matches!(
            token.verify_signature(),
            Err(CapabilityError::InvalidSignature)
        ));
    }

    #[test]
    fn test_token_content_hash() {
        let keypair = test_keypair();
        let pattern = ResourcePattern::exact("test://resource").unwrap();

        let token = CapabilityToken::create(
            pattern.clone(),
            vec![Permission::Read],
            TokenScope::Session,
            keypair.key_id(),
            AuditEntryId::new(),
            &keypair,
            None,
            PrincipalId::default(),
        );

        let hash = token.content_hash();
        assert!(!hash.is_zero());

        // Different token should have different hash
        let token2 = CapabilityToken::create(
            pattern,
            vec![Permission::Write],
            TokenScope::Session,
            keypair.key_id(),
            AuditEntryId::new(),
            &keypair,
            None,
            PrincipalId::default(),
        );

        assert_ne!(token.content_hash(), token2.content_hash());
    }

    #[test]
    fn test_v2_signing_includes_principal() {
        let keypair = test_keypair();
        let pattern = ResourcePattern::exact("mcp://test:tool").unwrap();
        let audit = AuditEntryId::new();

        let alice = CapabilityToken::create(
            pattern.clone(),
            vec![Permission::Invoke],
            TokenScope::Session,
            keypair.key_id(),
            audit.clone(),
            &keypair,
            None,
            PrincipalId::new("alice").unwrap(),
        );
        let bob = CapabilityToken::create(
            pattern,
            vec![Permission::Invoke],
            TokenScope::Session,
            keypair.key_id(),
            audit,
            &keypair,
            None,
            PrincipalId::new("bob").unwrap(),
        );

        // Different principals produce different signing data even with all
        // other fields identical (issued_at drift aside — this is the v2
        // contribution).
        assert_ne!(alice.signing_data(), bob.signing_data());
        // Both still verify against their own payload.
        assert!(alice.verify_signature().is_ok());
        assert!(bob.verify_signature().is_ok());
    }

    #[test]
    fn test_v1_signed_token_fails_verification_under_v2() {
        // Simulate a v1 token still on disk by manually computing its signing
        // payload using the pre-v2 layout (no trailing principal), then
        // presenting it to the current verifier. `verify_signature()` must
        // reject because the current `signing_data()` now includes a
        // principal suffix that the v1 signature was not computed over.
        let keypair = test_keypair();
        let pattern = ResourcePattern::exact("mcp://test:tool").unwrap();

        // Build a token and sign it against a payload that *omits* the
        // principal — the v1 layout. We intentionally reach across the
        // private API to reproduce that legacy byte string exactly.
        let mut token = CapabilityToken::create(
            pattern,
            vec![Permission::Invoke],
            TokenScope::Session,
            keypair.key_id(),
            AuditEntryId::new(),
            &keypair,
            None,
            PrincipalId::default(),
        );
        // Rebuild the v1 payload by truncating the v2 bytes before the
        // length-prefixed principal (4-byte LE length + "default"). This is
        // the legacy format — v1 tokens on disk after an upgrade will have
        // exactly this shape in their signed region.
        let v2_payload = token.signing_data();
        let principal_suffix_len = 4usize + "default".len();
        let v1_payload = &v2_payload[..v2_payload.len() - principal_suffix_len];
        token.signature = keypair.sign(v1_payload);

        // Now the current v2 verifier must fail-closed on this v1 signature.
        assert!(matches!(
            token.verify_signature(),
            Err(CapabilityError::InvalidSignature)
        ));
        assert!(matches!(
            token.validate(),
            Err(CapabilityError::InvalidSignature)
        ));
    }
}
