//! Private registry-neutral package-service contract and pure state model.
//!
//! This crate deliberately contains no transport, parsing, durable storage
//! engine, execution wiring, or external authority mapping. A host persists
//! its canonical values; this model defines the transition and replay law
//! applied to those values.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(unreachable_pub)]

mod authority;
mod context;
mod digest;
mod error;
mod identity;
mod journal;
mod model;
mod state;

pub use authority::{AuthenticatedAuthority, AuthorityClass};
pub use context::{
    ExpectedPackageState, LifecyclePlan, Operation, OperationContext, OperationContextSpec,
    ResourceBudget,
};
pub use digest::{
    AuthorityDigest, BudgetDigest, ContextDigest, DigestWriter, PlanDigest, ProvenanceDigest,
    ReceiptDigest, RuntimeReceiptDigest, StateDigest, TypedDigest,
};
pub use error::{PackageServiceError, PackageServiceResult};
pub use identity::{
    ArtifactIdentity, AuthorityIssuerIdentity, BudgetIdentity, ManifestIdentity, Nonce,
    PROTOCOL_VERSION, PackageObject, ServiceIdentity, ValidatedArtifact,
};
pub use journal::{
    DrainProof, JournalStatus, OperationReceipt, OperationRecord, ReceiptOutcome, RecoveryEvidence,
    ReplayOutcome,
};
pub use model::{JournalPolicy, PackageServiceModel};
pub use state::{
    CanonicalInstalledState, DrainDestination, DrainLineage, InstalledStateSpec, LifecycleState,
    PackageSlot, SlotRecord,
};
