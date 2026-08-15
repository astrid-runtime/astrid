//! Astrid Storage — unified persistence layer.
//!
//! Provides raw key-value storage for the Astrid runtime.
//!
//! # Raw Key-Value ([`KvStore`])
//!
//! Direct byte-level `get`/`set`/`delete` over an injected backend. Native
//! Astrid uses the durable principal store; `SurrealKV` remains available only
//! as a legacy migration reader and differential-test oracle.
//!
//! Primary use case: WASM guest storage with scoped namespaces per plugin.
//!
//! # Scaling
//!
//! | Deployment | KV backend |
//! |------------|------------|
//! | Dev / single-agent | Durable principal store |
//! | Production / multi-node | Durable principal store plus future placement execution |
//!
//! Distributed placement for the principal store remains separate
//! implementation work rather than a backend setting.
//!
//! # Feature Flags
//!
//! - **`legacy-surrealkv`** — legacy `SurrealKV` reader and migrator
//! - **`full`** — legacy compatibility features

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

extern crate alloc;

pub mod content;
/// Canonical content-defined chunk DAG implementation.
pub mod content_dag;
/// Principal-store execution engine.
pub mod engine;
pub mod error;
pub mod identity;
pub mod kv;
pub mod ownership;
mod principal_directory;
mod principal_graph;
#[cfg(not(target_family = "wasm"))]
pub mod principal_state;
#[cfg(not(target_family = "wasm"))]
mod resident_cache;
#[cfg(not(target_family = "wasm"))]
/// Kernel-owned resident-memory authorities used by native storage.
pub mod resources;
pub mod secret;
/// Portable executable model for principal state.
pub mod storage_model;

#[cfg(not(target_family = "wasm"))]
pub use content::{
    AtomicProjectionNameReservation, ProjectedContentPath, ProjectedNameSegment,
    ProjectionCollisionGroup, ProjectionCollisionKind, ProjectionEscapeReason,
    ProjectionEscapedName, ProjectionNameComparison, ProjectionNameError, ProjectionNameMapping,
    ProjectionNamePlan, ProjectionNamePolicy, ProjectionNameSyntax, ProjectionReservationOutcome,
    plan_projection_names,
};
pub use content::{
    BulkIngestDiagnostics, BulkIngestPolicy, ChunkingProfile, ContentBatchEntry,
    ContentBatchWriteOutcome, ContentChangeCache, ContentDescriptor, ContentEntry, ContentIngest,
    ContentName, ContentNameError, ContentObservation, ContentWriteOutcome, PrincipalContentError,
    PrincipalContentReadHandle, PrincipalContentStore, SourceEpoch, SourceFingerprint,
    SourceObservation, SourceScopeId, SourceTrust, StableSourceId,
};
pub use error::{StorageError, StorageResult};
pub use identity::{IdentityError, IdentityStore, KvIdentityStore};
pub use kv::{
    KvEntry, KvPrincipalResolver, KvQuotaResolver, KvStore, MemoryKvStore, PrincipalKvStore,
    ScopedKvStore, TreeKvStore,
};
pub use ownership::{
    FleetRecord, OwnershipError, OwnershipSnapshot, OwnershipStore, PrincipalDeletionGuard,
};
pub use principal_directory::PrincipalDirectory;
pub use secret::{
    DenySecretStore, FileSecretStore, KvSecretStore, ReadThroughSecretStore, SecretStore,
    SecretStoreError, build_secret_store,
};

#[cfg(feature = "keychain")]
pub use secret::{FallbackSecretStore, KeychainSecretStore};

#[cfg(not(target_family = "wasm"))]
pub use engine::{
    DurableEnginePolicy, GroupCommitPolicy, ObjectCacheCapacity, ObjectCacheConfig,
    ObjectCacheController, ObjectCacheMemoryBudget, ObjectCacheStats, PrincipalObjectCacheBudget,
    RecoveryRetryPolicy,
};
#[cfg(feature = "legacy-surrealkv")]
pub use kv::SurrealKvStore;
#[cfg(not(target_family = "wasm"))]
pub use principal_state::{
    Blake3ObjectIdentityV1, Blake3PhysicalIdentityV1, NativeContentStagingArea,
    NativePrincipalContentStore, RUNTIME_STORE_FORMAT_ID, ReadyStagedContent,
    RuntimePrincipalStore, StagedContentId, StagedContentWriter, StateOwner, StateOwnerCodecV1,
    StateOwnerCodecV2, StateOwnerResolver, StateOwnerV1, open_runtime_kv,
    open_runtime_kv_with_directory, open_runtime_principal_store,
    open_runtime_principal_store_with_directory, open_runtime_principal_store_with_object_cache,
    open_runtime_principal_store_with_policy,
};
#[cfg(not(target_family = "wasm"))]
pub use resident_cache::GovernedObjectCache;
