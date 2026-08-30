//! Private package-lifecycle contract and executable state model.
//!
//! This crate intentionally has no transport, durable-storage, or package
//! parsing implementation. Its values are suitable for an authenticated host
//! to persist as one owner/package value and later reconcile using runtime
//! evidence. The contract is private and makes no compatibility commitment.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(unreachable_pub)]

mod authority;
mod bytes;
mod context;
mod digest;
mod error;
mod identity;
mod journal;
mod lifecycle;
mod policy;
mod state;

pub use authority::{
    AuthenticatedAuthority, AuthorityDecision, AuthorityIssuer, AuthorityIssuerClass,
};
pub use bytes::{PrincipalUid, RecoveryToken};
pub use context::Duration;
pub use context::{
    AdmittedService, ApproverIdentity, AuthenticatedIngress, IngressChannel, Operation,
    OperationContext, OperationContextSpec, ResourceBudget, ResourceClass, ResourceClasses,
    Timestamp, operation_commit_plan_digest,
};
pub use digest::{
    AuthorityDecisionDigest, Blake3Digest, BudgetDigest, ContextDigest, DigestWriter, PlanDigest,
    ProvenanceDigest, ReceiptDigest, RequestDigest, Sha256Digest, StateDigest, TypedDigest,
};
pub use error::{PackageServiceError, PackageServiceResult};
pub use identity::{
    ArtifactFormatVersion, ArtifactIdentity, AuthorityIssuerIdentity, BoundedEvidence,
    ComponentIdentity, JOURNAL_SCHEMA_VERSION, JournalSchemaVersion, ManifestFormatVersion,
    ManifestIdentity, Nonce, PROTOCOL_VERSION, PackageName, PackageObject, PackageVersion,
    ProtocolVersion, ProvenanceClass, ProvenanceEvidence, STATE_SCHEMA_VERSION, ServiceGeneration,
    StateSchemaVersion, ValidatedArtifact,
};
pub use journal::{
    DrainPlan, DrainResult, JournalStatus, OperationJournalRecord, OperationReceipt,
    PackageSlotRecord, ReceiptOutcome, RecoveryEvidence, ReplayOutcome, Tombstone,
};
pub use lifecycle::PackageServiceModel;
pub use policy::{JournalPolicy, JournalRetention, Occupancy, RetentionWindow};
pub use state::{
    CanonicalInstalledState, DrainDestination, ExpectedPackageState, InstalledStateSpec,
    LifecycleState, PackageSlot,
};
