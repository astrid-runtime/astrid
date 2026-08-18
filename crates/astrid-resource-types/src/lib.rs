//! Portable, behavior-neutral resource vocabulary for Astrid.
//!
//! Values in this crate are identifiers, descriptors, receipts, and state
//! labels. They are safe to carry across process and machine boundaries, but
//! they never confer authority. In particular, serialized rights, owner and
//! generation tuples are not bearer handles. A live Astrid enforcement point
//! must resolve them against its non-serializable resource table and current
//! authority epoch before permitting an operation.
//!
//! Optional derived Serde forms are compatibility serialization only; they
//! are not canonical persistence or wire bytes and never confer authority.
//!
//! This crate deliberately contains no issuance, policy, clock, randomness,
//! filesystem, provider, IPC, or operating-system behavior.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod encoding;
mod generation;
mod ids;
mod owner;
mod rights;
mod state;

pub use encoding::{CanonicalDecode, CanonicalEncode, CanonicalTypeTag, EncodingError};
pub use generation::{
    AuthorityEpoch, GenerationDomain, GenerationError, GenerationValue, LifecycleGeneration,
    ObjectGeneration, ProviderGeneration,
};
pub use ids::{
    AccountId, ApplicationGenerationRef, BudgetId, CausalRequestId, DerivationId, OperationId,
    ProviderId, ResourceId, ResourceTypeId, SystemGenerationRef,
};
pub use owner::OwnerId;
pub use rights::Rights;
pub use state::{
    ResourceErrorCode, ResourceKind, ResourceLifecycleState, ResourceOutcomeCode, TransferClass,
};

/// Version used by the canonical byte encodings in this crate.
pub const CANONICAL_VERSION: u8 = 1;
