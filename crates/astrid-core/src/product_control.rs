//! Scoped credentials for product-owned runtime control clients.
//!
//! A product integration must never receive the daemon session token or a
//! principal private key.  Instead, the runtime issues an opaque credential
//! bound to one principal, an optional device, a short explicit allowlist, and
//! an expiry.  The runtime stores only a hash of the secret and can revoke the
//! grant at any time.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::SystemTime;

use rand::{TryRng, rngs::SysRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

use crate::PrincipalId;

/// A read-only operation available to a product control client.
///
/// This is intentionally closed.  Adding a control operation requires a
/// runtime review rather than silently broadening every existing grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProductControlOperation {
    /// Read the daemon's process and runtime status.
    RuntimeStatus,
    /// Read agent readiness without changing runtime state.
    AgentReadiness,
    /// Read the installed capsule inventory.
    CapsuleInventory,
}

/// Opaque bearer credential held by the product control client.
///
/// The secret is never persisted by the runtime.  `Debug` deliberately
/// redacts it so operational logs cannot disclose authority.
#[derive(Clone, PartialEq, Eq)]
pub struct ProductControlCredential {
    grant_id: Uuid,
    secret: [u8; 32],
}

impl ProductControlCredential {
    /// Generate a fresh credential bound to a new grant identifier.
    ///
    /// # Panics
    ///
    /// Panics if the operating-system CSPRNG is unavailable.
    #[must_use]
    pub fn generate() -> Self {
        let mut secret = [0_u8; 32];
        SysRng
            .try_fill_bytes(&mut secret)
            .expect("OS CSPRNG unavailable while generating product control credential");
        Self {
            grant_id: Uuid::new_v4(),
            secret,
        }
    }

    /// Serialize the credential for an owner-only client secret store.
    #[must_use]
    pub fn to_wire(&self) -> String {
        format!("{}:{}", self.grant_id, hex::encode(self.secret))
    }

    /// Parse a credential written by [`Self::to_wire`].
    ///
    /// # Errors
    ///
    /// Returns [`ProductControlError::MalformedCredential`] when the grant id
    /// or 256-bit secret is invalid.
    pub fn from_wire(value: &str) -> Result<Self, ProductControlError> {
        let (grant_id, secret) = value
            .split_once(':')
            .ok_or(ProductControlError::MalformedCredential)?;
        let grant_id =
            Uuid::parse_str(grant_id).map_err(|_| ProductControlError::MalformedCredential)?;
        let decoded = hex::decode(secret).map_err(|_| ProductControlError::MalformedCredential)?;
        let secret: [u8; 32] = decoded
            .try_into()
            .map_err(|_| ProductControlError::MalformedCredential)?;
        Ok(Self { grant_id, secret })
    }

    /// Return the non-secret identifier used for revocation and auditing.
    #[must_use]
    pub const fn grant_id(&self) -> Uuid {
        self.grant_id
    }

    fn secret_hash(&self) -> [u8; 32] {
        Sha256::digest(self.secret).into()
    }
}

impl fmt::Debug for ProductControlCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProductControlCredential")
            .field("grant_id", &self.grant_id)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Runtime-owned verifier and revocation registry for product credentials.
#[derive(Default)]
pub struct ProductControlAuthorizer {
    grants: HashMap<Uuid, ProductControlGrant>,
}

impl ProductControlAuthorizer {
    /// Issue a scoped credential for one principal and optional device.
    #[must_use]
    pub fn issue(
        &mut self,
        principal: PrincipalId,
        device_key_id: Option<String>,
        operations: impl IntoIterator<Item = ProductControlOperation>,
        expires_at: SystemTime,
    ) -> ProductControlCredential {
        let credential = ProductControlCredential::generate();
        self.register(
            &credential,
            principal,
            device_key_id,
            operations,
            expires_at,
        );
        credential
    }

    /// Register a credential generated and retained by the product launcher.
    ///
    /// This is the normal production flow: the product owns its secret and
    /// supplies it to the runtime at launch, while the runtime stores only its
    /// verifier.  Re-registering the same grant identifier replaces its prior
    /// scope, which makes rotation explicit and revocation durable for the
    /// lifetime of this authorizer.
    pub fn register(
        &mut self,
        credential: &ProductControlCredential,
        principal: PrincipalId,
        device_key_id: Option<String>,
        operations: impl IntoIterator<Item = ProductControlOperation>,
        expires_at: SystemTime,
    ) {
        let grant = ProductControlGrant {
            secret_hash: credential.secret_hash(),
            principal,
            device_key_id,
            operations: operations.into_iter().collect(),
            expires_at,
            revoked: false,
        };
        self.grants.insert(credential.grant_id, grant);
    }

    /// Revoke a credential by its non-secret grant identifier.
    ///
    /// Returns `true` when an active grant was revoked.
    pub fn revoke(&mut self, grant_id: Uuid) -> bool {
        let Some(grant) = self.grants.get_mut(&grant_id) else {
            return false;
        };
        if grant.revoked {
            return false;
        }
        grant.revoked = true;
        true
    }

    /// Verify a credential before the runtime accepts a product operation.
    ///
    /// There is deliberately no anonymous or legacy path: a missing,
    /// malformed, expired, revoked, cross-principal, cross-device, or
    /// out-of-scope credential fails closed.
    ///
    /// # Errors
    ///
    /// Returns a precise local error for audit and caller diagnostics.  A
    /// network-facing control service should map these to a uniform denial.
    pub fn authorize(
        &self,
        credential: &ProductControlCredential,
        principal: &PrincipalId,
        device_key_id: Option<&str>,
        operation: ProductControlOperation,
        now: SystemTime,
    ) -> Result<(), ProductControlError> {
        let grant = self
            .grants
            .get(&credential.grant_id)
            .ok_or(ProductControlError::UnknownGrant)?;

        if !bool::from(grant.secret_hash.ct_eq(&credential.secret_hash())) {
            return Err(ProductControlError::UnknownGrant);
        }
        if grant.revoked {
            return Err(ProductControlError::Revoked);
        }
        if now >= grant.expires_at {
            return Err(ProductControlError::Expired);
        }
        if &grant.principal != principal {
            return Err(ProductControlError::PrincipalMismatch);
        }
        if grant.device_key_id.as_deref() != device_key_id {
            return Err(ProductControlError::DeviceMismatch);
        }
        if !grant.operations.contains(&operation) {
            return Err(ProductControlError::OperationDenied);
        }
        Ok(())
    }
}

struct ProductControlGrant {
    secret_hash: [u8; 32],
    principal: PrincipalId,
    device_key_id: Option<String>,
    operations: HashSet<ProductControlOperation>,
    expires_at: SystemTime,
    revoked: bool,
}

/// A failed product-control authorization.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ProductControlError {
    /// Credential wire data was malformed.
    #[error("malformed product control credential")]
    MalformedCredential,
    /// Credential was never issued by this runtime, or its secret is invalid.
    #[error("unknown product control credential")]
    UnknownGrant,
    /// Credential was explicitly revoked.
    #[error("product control credential is revoked")]
    Revoked,
    /// Credential reached its expiry time.
    #[error("product control credential is expired")]
    Expired,
    /// Credential is bound to another principal.
    #[error("product control credential principal does not match")]
    PrincipalMismatch,
    /// Credential is bound to another device, or only one side supplied one.
    #[error("product control credential device does not match")]
    DeviceMismatch,
    /// Credential was used for an operation outside its allowlist.
    #[error("product control operation is not allowed")]
    OperationDenied,
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;

    fn principal(value: &str) -> PrincipalId {
        PrincipalId::new(value).expect("valid test principal")
    }

    fn issue_status_grant(authorizer: &mut ProductControlAuthorizer) -> ProductControlCredential {
        authorizer.issue(
            principal("unicity-aos"),
            Some("device-a".to_string()),
            [ProductControlOperation::RuntimeStatus],
            SystemTime::now() + Duration::from_secs(60),
        )
    }

    #[test]
    fn authorizes_the_bound_principal_device_and_operation() {
        let mut authorizer = ProductControlAuthorizer::default();
        let credential = issue_status_grant(&mut authorizer);

        assert_eq!(
            authorizer.authorize(
                &credential,
                &principal("unicity-aos"),
                Some("device-a"),
                ProductControlOperation::RuntimeStatus,
                SystemTime::now(),
            ),
            Ok(())
        );
    }

    #[test]
    fn wire_round_trip_preserves_authority() {
        let mut authorizer = ProductControlAuthorizer::default();
        let credential = issue_status_grant(&mut authorizer);
        let restored =
            ProductControlCredential::from_wire(&credential.to_wire()).expect("parse wire");

        assert_eq!(
            authorizer.authorize(
                &restored,
                &principal("unicity-aos"),
                Some("device-a"),
                ProductControlOperation::RuntimeStatus,
                SystemTime::now(),
            ),
            Ok(())
        );
    }

    #[test]
    fn product_owned_credential_can_be_registered_without_disclosing_a_runtime_secret() {
        let mut authorizer = ProductControlAuthorizer::default();
        let credential = ProductControlCredential::generate();
        authorizer.register(
            &credential,
            principal("unicity-aos"),
            None,
            [ProductControlOperation::AgentReadiness],
            SystemTime::now() + Duration::from_secs(60),
        );

        assert_eq!(
            authorizer.authorize(
                &credential,
                &principal("unicity-aos"),
                None,
                ProductControlOperation::AgentReadiness,
                SystemTime::now(),
            ),
            Ok(())
        );
    }

    #[test]
    fn malformed_credential_is_rejected() {
        assert_eq!(
            ProductControlCredential::from_wire("not-a-credential"),
            Err(ProductControlError::MalformedCredential)
        );
    }

    #[test]
    fn expired_credential_is_rejected() {
        let mut authorizer = ProductControlAuthorizer::default();
        let credential = authorizer.issue(
            principal("unicity-aos"),
            None,
            [ProductControlOperation::RuntimeStatus],
            SystemTime::now() - Duration::from_secs(1),
        );

        assert_eq!(
            authorizer.authorize(
                &credential,
                &principal("unicity-aos"),
                None,
                ProductControlOperation::RuntimeStatus,
                SystemTime::now(),
            ),
            Err(ProductControlError::Expired)
        );
    }

    #[test]
    fn revoked_credential_is_rejected() {
        let mut authorizer = ProductControlAuthorizer::default();
        let credential = issue_status_grant(&mut authorizer);
        assert!(authorizer.revoke(credential.grant_id()));

        assert_eq!(
            authorizer.authorize(
                &credential,
                &principal("unicity-aos"),
                Some("device-a"),
                ProductControlOperation::RuntimeStatus,
                SystemTime::now(),
            ),
            Err(ProductControlError::Revoked)
        );
    }

    #[test]
    fn cross_principal_and_cross_device_use_are_rejected() {
        let mut authorizer = ProductControlAuthorizer::default();
        let credential = issue_status_grant(&mut authorizer);

        assert_eq!(
            authorizer.authorize(
                &credential,
                &principal("other"),
                Some("device-a"),
                ProductControlOperation::RuntimeStatus,
                SystemTime::now(),
            ),
            Err(ProductControlError::PrincipalMismatch)
        );
        assert_eq!(
            authorizer.authorize(
                &credential,
                &principal("unicity-aos"),
                Some("device-b"),
                ProductControlOperation::RuntimeStatus,
                SystemTime::now(),
            ),
            Err(ProductControlError::DeviceMismatch)
        );
    }

    #[test]
    fn out_of_scope_operation_is_rejected() {
        let mut authorizer = ProductControlAuthorizer::default();
        let credential = issue_status_grant(&mut authorizer);

        assert_eq!(
            authorizer.authorize(
                &credential,
                &principal("unicity-aos"),
                Some("device-a"),
                ProductControlOperation::CapsuleInventory,
                SystemTime::now(),
            ),
            Err(ProductControlError::OperationDenied)
        );
    }
}
