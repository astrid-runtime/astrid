//! Capability validation logic.
//!
//! Validates tokens and checks authorization for operations.

use astrid_core::Permission;
use astrid_core::principal::PrincipalId;
use astrid_crypto::PublicKey;

use crate::error::{CapabilityError, CapabilityResult};
use crate::store::CapabilityStore;
use crate::token::CapabilityToken;

/// Authorization result after validation.
#[derive(Debug, Clone)]
pub enum AuthorizationResult {
    /// Authorized by a specific token.
    Authorized {
        /// The token that granted authorization.
        token: Box<CapabilityToken>,
    },
    /// Not authorized - approval required.
    RequiresApproval {
        /// The resource being accessed.
        resource: String,
        /// The required permission.
        permission: Permission,
    },
}

impl AuthorizationResult {
    /// Check if authorized.
    #[must_use]
    pub fn is_authorized(&self) -> bool {
        matches!(self, Self::Authorized { .. })
    }

    /// Get the authorizing token if authorized.
    #[must_use]
    pub fn token(&self) -> Option<&CapabilityToken> {
        match self {
            Self::Authorized { token } => Some(token),
            Self::RequiresApproval { .. } => None,
        }
    }
}

/// Capability validator for checking authorization.
pub struct CapabilityValidator<'a> {
    store: &'a CapabilityStore,
    trusted_issuers: Vec<PublicKey>,
}

impl<'a> CapabilityValidator<'a> {
    /// Create a new validator with a capability store.
    #[must_use]
    pub fn new(store: &'a CapabilityStore) -> Self {
        Self {
            store,
            trusted_issuers: Vec::new(),
        }
    }

    /// Add a trusted issuer (runtime public key).
    #[must_use]
    pub fn trust_issuer(mut self, issuer: PublicKey) -> Self {
        self.trusted_issuers.push(issuer);
        self
    }

    /// Check authorization for `principal` on `(resource, permission)`.
    ///
    /// Tokens are filtered by their `CapabilityToken::principal` before
    /// expiry/signature checks — a token minted for another principal will
    /// never be considered, even if the resource pattern matches. See
    /// [`CapabilityStore::find_capability`] for the fail-closed semantics.
    pub async fn check(
        &self,
        principal: &PrincipalId,
        resource: &str,
        permission: Permission,
    ) -> AuthorizationResult {
        if let Some(token) = self
            .store
            .find_capability(principal, resource, permission)
            .await
        {
            // Validate the token
            if self.validate_token(&token).is_ok() {
                return AuthorizationResult::Authorized {
                    token: Box::new(token),
                };
            }
        }

        AuthorizationResult::RequiresApproval {
            resource: resource.to_string(),
            permission,
        }
    }

    /// Validate a specific token.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is expired, has an invalid signature,
    /// or is not from a trusted issuer.
    pub fn validate_token(&self, token: &CapabilityToken) -> CapabilityResult<()> {
        // Check expiration
        if token.is_expired() {
            return Err(CapabilityError::TokenExpired {
                token_id: token.id.to_string(),
            });
        }

        // Verify signature
        token.verify_signature()?;

        // Check issuer trust (if we have a list)
        if !self.trusted_issuers.is_empty() && !self.trusted_issuers.contains(&token.issuer) {
            return Err(CapabilityError::InvalidSignature);
        }

        Ok(())
    }

    /// Validate a token by ID, rejecting cross-principal use.
    ///
    /// `validate_token` itself is intentionally principal-agnostic (it
    /// checks expiry + signature + issuer trust). `validate_by_id` layers
    /// the principal filter on top: the looked-up token's
    /// `CapabilityToken::principal` must equal `principal` or the call
    /// fails closed with [`CapabilityError::InvalidSignature`] (same error
    /// class as a cryptographic mismatch — cross-principal reuse must
    /// surface as an authorization failure, not a routing miss).
    ///
    /// # Errors
    ///
    /// Returns an error if the token is not found, revoked, owned by a
    /// different principal, or fails validation.
    pub async fn validate_by_id(
        &self,
        principal: &PrincipalId,
        token_id: &astrid_core::TokenId,
    ) -> CapabilityResult<()> {
        let token =
            self.store
                .get(token_id)
                .await?
                .ok_or_else(|| CapabilityError::TokenNotFound {
                    token_id: token_id.to_string(),
                })?;

        if token.principal != *principal {
            tracing::warn!(
                token_id = %token_id,
                token_principal = %token.principal,
                caller_principal = %principal,
                "cross-principal validate_by_id rejected"
            );
            return Err(CapabilityError::InvalidSignature);
        }

        self.validate_token(&token)
    }
}

/// Check multiple permissions at once.
#[cfg(test)]
pub(crate) struct MultiPermissionCheck {
    checks: Vec<(String, Permission)>,
}

#[cfg(test)]
impl MultiPermissionCheck {
    /// Create a new multi-permission check.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self { checks: Vec::new() }
    }

    /// Add a permission check.
    #[must_use]
    pub(crate) fn add(mut self, resource: impl Into<String>, permission: Permission) -> Self {
        self.checks.push((resource.into(), permission));
        self
    }

    /// Run all checks against a validator for `principal`.
    pub(crate) async fn check_all(
        &self,
        principal: &PrincipalId,
        validator: &CapabilityValidator<'_>,
    ) -> Vec<(String, Permission, AuthorizationResult)> {
        let mut results = Vec::with_capacity(self.checks.len());
        for (resource, permission) in &self.checks {
            let result = validator.check(principal, resource, *permission).await;
            results.push((resource.clone(), *permission, result));
        }
        results
    }

    /// Check if all permissions are authorized for `principal`.
    pub(crate) async fn all_authorized(
        &self,
        principal: &PrincipalId,
        validator: &CapabilityValidator<'_>,
    ) -> bool {
        for (resource, permission) in &self.checks {
            if !validator
                .check(principal, resource, *permission)
                .await
                .is_authorized()
            {
                return false;
            }
        }
        true
    }

    /// Get permissions that require approval for `principal`.
    pub(crate) async fn needs_approval(
        &self,
        principal: &PrincipalId,
        validator: &CapabilityValidator<'_>,
    ) -> Vec<(String, Permission)> {
        let mut needing = Vec::new();
        for check in &self.checks {
            let (resource, permission) = check;
            if !validator
                .check(principal, resource, *permission)
                .await
                .is_authorized()
            {
                needing.push(check.clone());
            }
        }
        needing
    }
}

#[cfg(test)]
impl Default for MultiPermissionCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::ResourcePattern;
    use crate::token::{AuditEntryId, TokenScope};
    use astrid_crypto::KeyPair;

    fn test_keypair() -> KeyPair {
        KeyPair::generate()
    }

    fn default_principal() -> PrincipalId {
        PrincipalId::default()
    }

    #[tokio::test]
    async fn test_authorization_check() {
        let store = CapabilityStore::in_memory();
        let keypair = test_keypair();

        let token = CapabilityToken::create(
            ResourcePattern::exact("mcp://test:tool").unwrap(),
            vec![Permission::Invoke],
            TokenScope::Session,
            keypair.key_id(),
            AuditEntryId::new(),
            &keypair,
            None,
            default_principal(),
        );

        store.add(token).await.unwrap();

        let validator = CapabilityValidator::new(&store);

        let result = validator
            .check(&default_principal(), "mcp://test:tool", Permission::Invoke)
            .await;
        assert!(result.is_authorized());

        let result = validator
            .check(&default_principal(), "mcp://test:other", Permission::Invoke)
            .await;
        assert!(!result.is_authorized());
    }

    #[tokio::test]
    async fn test_check_rejects_cross_principal_token() {
        let store = CapabilityStore::in_memory();
        let keypair = test_keypair();
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();

        let token = CapabilityToken::create(
            ResourcePattern::exact("mcp://test:tool").unwrap(),
            vec![Permission::Invoke],
            TokenScope::Session,
            keypair.key_id(),
            AuditEntryId::new(),
            &keypair,
            None,
            bob.clone(),
        );
        store.add(token).await.unwrap();

        let validator = CapabilityValidator::new(&store);
        // Bob can use his own token.
        assert!(
            validator
                .check(&bob, "mcp://test:tool", Permission::Invoke)
                .await
                .is_authorized()
        );
        // Alice cannot — even though the resource pattern matches.
        assert!(
            !validator
                .check(&alice, "mcp://test:tool", Permission::Invoke)
                .await
                .is_authorized()
        );
    }

    #[tokio::test]
    async fn test_validate_by_id_rejects_cross_principal() {
        let store = CapabilityStore::in_memory();
        let keypair = test_keypair();
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();

        let token = CapabilityToken::create(
            ResourcePattern::exact("mcp://test:tool").unwrap(),
            vec![Permission::Invoke],
            TokenScope::Session,
            keypair.key_id(),
            AuditEntryId::new(),
            &keypair,
            None,
            bob.clone(),
        );
        let token_id = token.id.clone();
        store.add(token).await.unwrap();

        let validator = CapabilityValidator::new(&store);
        assert!(validator.validate_by_id(&bob, &token_id).await.is_ok());
        let result = validator.validate_by_id(&alice, &token_id).await;
        assert!(matches!(result, Err(CapabilityError::InvalidSignature)));
    }

    #[tokio::test]
    async fn test_trusted_issuer() {
        let store = CapabilityStore::in_memory();
        let keypair = test_keypair();
        let other_keypair = test_keypair();

        let token = CapabilityToken::create(
            ResourcePattern::exact("mcp://test:tool").unwrap(),
            vec![Permission::Invoke],
            TokenScope::Session,
            keypair.key_id(),
            AuditEntryId::new(),
            &keypair,
            None,
            default_principal(),
        );

        store.add(token.clone()).await.unwrap();

        // Validator that only trusts other_keypair
        let validator =
            CapabilityValidator::new(&store).trust_issuer(other_keypair.export_public_key());

        // Should fail - token not from trusted issuer
        assert!(validator.validate_token(&token).is_err());

        // Validator that trusts our keypair
        let validator2 = CapabilityValidator::new(&store).trust_issuer(keypair.export_public_key());

        assert!(validator2.validate_token(&token).is_ok());
    }

    #[tokio::test]
    async fn test_multi_permission_check() {
        let store = CapabilityStore::in_memory();
        let keypair = test_keypair();

        let token = CapabilityToken::create(
            ResourcePattern::exact("mcp://test:read").unwrap(),
            vec![Permission::Invoke],
            TokenScope::Session,
            keypair.key_id(),
            AuditEntryId::new(),
            &keypair,
            None,
            default_principal(),
        );

        store.add(token).await.unwrap();

        let validator = CapabilityValidator::new(&store);

        let check = MultiPermissionCheck::new()
            .add("mcp://test:read", Permission::Invoke)
            .add("mcp://test:write", Permission::Invoke);

        let checked = check.check_all(&default_principal(), &validator).await;
        assert_eq!(checked.len(), 2);

        assert!(!check.all_authorized(&default_principal(), &validator).await);

        let needs = check.needs_approval(&default_principal(), &validator).await;
        assert_eq!(needs.len(), 1);
        assert_eq!(needs[0].0, "mcp://test:write");
    }
}
