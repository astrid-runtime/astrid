use crate::context::{
    AdmittedService, ApproverIdentity, AuthenticatedIngress, Operation, OperationContext,
};
use crate::digest::{AuthorityDecisionDigest, Blake3Digest, ContextDigest, DigestWriter};
use crate::error::{PackageServiceError, PackageServiceResult};
use crate::identity::AuthorityIssuerIdentity;

/// Verified issuer class of an authority decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityIssuerClass {
    /// Automatic authority limited to this runtime's build identity.
    RuntimeBuildPolicy,
    /// An authenticated principal's explicit approval.
    ExplicitApproval,
    /// An authenticated operator distribution channel.
    OperatorDistribution,
    /// One-way preservation bridge for an already verified installed state.
    VerifiedLegacyMigration,
}

/// Verified issuer and channel evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityIssuer {
    class: AuthorityIssuerClass,
    identity: AuthorityIssuerIdentity,
    channel: AuthorityIssuerIdentity,
    channel_evidence: Blake3Digest,
}

impl AuthorityIssuer {
    /// Constructs a verified issuer from the authority boundary.
    pub fn new(
        class: AuthorityIssuerClass,
        identity: AuthorityIssuerIdentity,
        channel: AuthorityIssuerIdentity,
        channel_evidence: Blake3Digest,
    ) -> PackageServiceResult<Self> {
        if identity.as_bytes() == &[0; 32]
            || channel.as_bytes() == &[0; 32]
            || channel_evidence.as_bytes() == &[0; 32]
        {
            return Err(PackageServiceError::AuthorityIssuerRejected);
        }
        Ok(Self {
            class,
            identity,
            channel,
            channel_evidence,
        })
    }

    pub(crate) const fn class(&self) -> AuthorityIssuerClass {
        self.class
    }

    pub(crate) fn write(&self, writer: &mut DigestWriter) {
        writer.tag(match self.class {
            AuthorityIssuerClass::RuntimeBuildPolicy => 1,
            AuthorityIssuerClass::ExplicitApproval => 2,
            AuthorityIssuerClass::OperatorDistribution => 3,
            AuthorityIssuerClass::VerifiedLegacyMigration => 4,
        });
        writer.bytes(self.identity.as_bytes());
        writer.bytes(self.channel.as_bytes());
        writer.digest(&self.channel_evidence);
    }
}

/// Authority evidence bound to one complete canonical context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityDecision {
    issuer: AuthorityIssuer,
    context_digest: ContextDigest,
    evidence: Blake3Digest,
}

impl AuthorityDecision {
    /// Returns the exact context digest covered by this decision.
    #[must_use]
    pub const fn context_digest(&self) -> &ContextDigest {
        &self.context_digest
    }

    /// Computes the canonical decision digest retained by installed state.
    #[must_use]
    pub fn digest(&self) -> AuthorityDecisionDigest {
        let mut writer = DigestWriter::new();
        self.issuer.write(&mut writer);
        writer.digest(&self.context_digest);
        writer.digest(&self.evidence);
        writer.finish("astrid.package.authority-decision.v1")
    }
}

/// A decision that has passed this model's exact-binding checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedAuthority(AuthorityDecision);

impl AuthenticatedAuthority {
    /// Binds issuer evidence to the canonical context digest.
    pub fn bind(
        context: &OperationContext,
        issuer: AuthorityIssuer,
        evidence: Blake3Digest,
    ) -> PackageServiceResult<Self> {
        if evidence.as_bytes() == &[0; 32] {
            return Err(PackageServiceError::AuthorityIssuerRejected);
        }
        Ok(Self(AuthorityDecision {
            issuer,
            context_digest: *context.digest(),
            evidence,
        }))
    }

    pub(crate) fn decision_digest(&self) -> AuthorityDecisionDigest {
        self.0.digest()
    }

    pub(crate) fn verify(
        &self,
        context: &OperationContext,
        ingress: &AuthenticatedIngress,
        service: &AdmittedService,
        now: crate::context::Timestamp,
    ) -> PackageServiceResult<()> {
        if context.expiry() <= now {
            return Err(PackageServiceError::AuthorityExpired);
        }
        if self.0.context_digest != *context.digest() {
            return Err(PackageServiceError::AuthorityContextMismatch);
        }
        if self.0.evidence.as_bytes() == &[0; 32] {
            return Err(PackageServiceError::AuthorityIssuerRejected);
        }
        match self.0.issuer.class() {
            AuthorityIssuerClass::VerifiedLegacyMigration
                if context.operation() != Operation::Recover =>
            {
                return Err(PackageServiceError::AuthorityIssuerRejected);
            },
            AuthorityIssuerClass::ExplicitApproval
                if !matches!(context.approver_identity(), ApproverIdentity::Principal(_)) =>
            {
                return Err(PackageServiceError::AuthorityIssuerRejected);
            },
            _ => {},
        }
        if ingress.caller() != context.effective_caller()
            || service.component() != context.service_component()
            || service.generation() != context.service_generation()
            || ingress.evidence().as_bytes() == &[0; 32]
            || service.evidence().as_bytes() == &[0; 32]
        {
            return Err(PackageServiceError::StampedIdentityMismatch);
        }
        Ok(())
    }
}
