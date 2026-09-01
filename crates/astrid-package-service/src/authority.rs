//! Ed25519 authority decisions bound to one canonical context.

use crate::context::OperationContext;
use crate::digest::{AuthorityDigest, ContextDigest, DigestWriter, TypedDigest};
use crate::error::{PackageServiceError, PackageServiceResult};
use crate::identity::AuthorityIssuerIdentity;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Classes of admitted authority issuers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityClass {
    /// Explicit authenticated principal approval.
    ExplicitApproval,
    /// An authenticated operator policy generation.
    OperatorPolicy,
}

/// A decision that has verified the exact context and issuer signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedAuthority {
    class: AuthorityClass,
    issuer: AuthorityIssuerIdentity,
    verifying_key: [u8; 32],
    context_digest: ContextDigest,
    digest: AuthorityDigest,
}

impl AuthenticatedAuthority {
    /// Verifies an Ed25519 decision over the exact canonical context.
    ///
    /// # Errors
    /// Returns expiry, malformed-key, signature, or binding failures without
    /// producing an authority value.
    pub fn verify(
        context: &OperationContext,
        class: AuthorityClass,
        issuer: AuthorityIssuerIdentity,
        verifying_key: [u8; 32],
        signature: [u8; 64],
        now: u64,
    ) -> PackageServiceResult<Self> {
        if now >= context.expiry() {
            return Err(PackageServiceError::AuthorityExpired);
        }
        let key = VerifyingKey::from_bytes(&verifying_key)
            .map_err(|_| PackageServiceError::InvalidAuthoritySignature)?;
        let signature = Signature::from_bytes(&signature);
        let message = Self::message(issuer, context.digest());
        key.verify(&message, &signature)
            .map_err(|_| PackageServiceError::InvalidAuthoritySignature)?;
        let digest = Self::compute_digest(class, issuer, verifying_key, context.digest());
        Ok(Self {
            class,
            issuer,
            verifying_key,
            context_digest: *context.digest(),
            digest,
        })
    }

    /// Returns the exact bytes an issuer must sign for this context.
    ///
    /// This public derivation lets an external or internal authority boundary
    /// sign the same canonical payload this model verifies.
    #[must_use]
    pub fn signing_payload(issuer: AuthorityIssuerIdentity, context: &OperationContext) -> Vec<u8> {
        Self::message(issuer, context.digest())
    }

    fn message(issuer: AuthorityIssuerIdentity, context: &ContextDigest) -> Vec<u8> {
        let mut writer = DigestWriter::new();
        writer.tag(1);
        writer.bytes(issuer.as_bytes());
        writer.digest(context);
        let digest: TypedDigest<0> = writer.finish("astrid.package.authority-message.v1");
        let mut message = Vec::with_capacity(64);
        message.extend_from_slice(b"astrid.package.authority-message.v1");
        message.extend_from_slice(digest.as_bytes());
        message
    }

    fn compute_digest(
        class: AuthorityClass,
        issuer: AuthorityIssuerIdentity,
        verifying_key: [u8; 32],
        context: &ContextDigest,
    ) -> AuthorityDigest {
        let mut writer = DigestWriter::new();
        writer.tag(match class {
            AuthorityClass::ExplicitApproval => 1,
            AuthorityClass::OperatorPolicy => 2,
        });
        writer.bytes(issuer.as_bytes());
        writer.bytes(&verifying_key);
        writer.digest(context);
        writer.finish("astrid.package.authority.v1")
    }

    /// Returns the issuer class.
    #[must_use]
    pub const fn class(&self) -> AuthorityClass {
        self.class
    }

    /// Returns the issuer identity.
    #[must_use]
    pub const fn issuer(&self) -> &AuthorityIssuerIdentity {
        &self.issuer
    }

    /// Returns the exact signed context digest.
    #[must_use]
    pub const fn context_digest(&self) -> &ContextDigest {
        &self.context_digest
    }

    /// Returns the canonical authority digest retained by receipts.
    #[must_use]
    pub const fn digest(&self) -> AuthorityDigest {
        self.digest
    }

    /// Checks whether this verified decision binds the exact context.
    ///
    /// # Errors
    /// Returns [`PackageServiceError::AuthorityMismatch`] for any other context.
    pub fn verify_context(&self, context: OperationContext) -> PackageServiceResult<()> {
        if self.context_digest.as_bytes() == context.digest().as_bytes() {
            Ok(())
        } else {
            Err(PackageServiceError::AuthorityMismatch)
        }
    }
}
