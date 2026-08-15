//! Named principal-owned content over canonical chunk DAGs.
//!
//! Content values share the same principal root and immutable object arena as
//! KV. The catalog charges every visible name and byte logically even when
//! chunks or complete files are physically deduplicated.

mod catalog;
mod change_detection;
mod kv_projection;
#[cfg(not(target_family = "wasm"))]
mod projection_names;
mod store;
#[cfg(test)]
mod tests;

use std::num::NonZeroUsize;
use std::time::Duration;
use std::{fmt, io};

use crate::engine::PrincipalProjectionError;
use crate::storage_model::{ObjectId, RootState};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use crate::content_dag::{ChunkingProfile, ContentDescriptor};
pub use change_detection::{
    ContentChangeCache, SourceEpoch, SourceFingerprint, SourceObservation, SourceScopeId,
    SourceTrust, StableSourceId,
};
#[cfg(not(target_family = "wasm"))]
pub use projection_names::{
    AtomicProjectionNameReservation, ProjectedContentPath, ProjectedNameSegment,
    ProjectionCollisionGroup, ProjectionCollisionKind, ProjectionEscapeReason,
    ProjectionEscapedName, ProjectionNameComparison, ProjectionNameError, ProjectionNameMapping,
    ProjectionNamePlan, ProjectionNamePolicy, ProjectionNameSyntax, ProjectionReservationOutcome,
    plan_projection_names,
};
pub use store::{PrincipalContentReadHandle, PrincipalContentStore};

use crate::content_dag::ContentError;

pub(crate) use catalog::{
    CONTENT_COMPONENT_LABEL, CatalogValidation, root_from_record, validate_catalog,
};
#[cfg(test)]
pub(crate) use catalog::{CatalogValue, LegacyCatalog, encode_legacy_catalog};

use crate::error::StorageError;

/// Canonical name of one principal-owned content value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentName(String);

impl Serialize for ContentName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ContentName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Failure to validate a principal content name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentNameError {
    /// The name was empty.
    Empty,
    /// The name contained a null byte.
    ContainsNull,
    /// Persisted name bytes were not valid UTF-8.
    InvalidUtf8,
}

impl fmt::Display for ContentNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("principal content name is empty"),
            Self::ContainsNull => {
                formatter.write_str("principal content name contains a null byte")
            },
            Self::InvalidUtf8 => formatter.write_str("principal content name is not valid UTF-8"),
        }
    }
}

impl std::error::Error for ContentNameError {}

impl ContentName {
    /// Validate a principal content name.
    ///
    /// Names are opaque UTF-8 catalog keys, not host paths. Slash is permitted
    /// and has no traversal semantics.
    ///
    /// # Errors
    ///
    /// Returns [`ContentNameError::Empty`] or
    /// [`ContentNameError::ContainsNull`] when validation fails.
    pub fn new(value: impl Into<String>) -> Result<Self, ContentNameError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ContentNameError::Empty);
        }
        if value.as_bytes().contains(&0) {
            return Err(ContentNameError::ContainsNull);
        }
        Ok(Self(value))
    }

    /// Borrow the canonical UTF-8 name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the name and return its UTF-8 representation.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, PrincipalContentError> {
        let value = std::str::from_utf8(bytes)
            .map_err(|_| PrincipalContentError::InvalidName(ContentNameError::InvalidUtf8))?
            .to_owned();
        Self::new(value).map_err(PrincipalContentError::InvalidName)
    }
}

impl AsRef<str> for ContentName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ContentName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for ContentName {
    type Err = ContentNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for ContentName {
    type Error = ContentNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ContentName> for String {
    fn from(value: ContentName) -> Self {
        value.into_inner()
    }
}

/// One named entry in a principal's content catalog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentEntry {
    name: ContentName,
    file: ObjectId,
    logical_bytes: u64,
}

impl ContentEntry {
    pub(crate) const fn new(name: ContentName, file: ObjectId, logical_bytes: u64) -> Self {
        Self {
            name,
            file,
            logical_bytes,
        }
    }

    /// Borrow the catalog name.
    #[must_use]
    pub const fn name(&self) -> &ContentName {
        &self.name
    }

    /// Return the immutable file object.
    #[must_use]
    pub const fn file(&self) -> ObjectId {
        self.file
    }

    /// Return the visible byte length.
    #[must_use]
    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }
}

/// Result of one successful content publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentWriteOutcome {
    descriptor: ContentDescriptor,
    principal_root: RootState,
    objects_inserted: u64,
}

/// One blocking byte source prepared for atomic batch publication.
pub struct ContentIngest<R> {
    name: ContentName,
    source: R,
    profile: ChunkingProfile,
    observation: Option<SourceObservation>,
}

/// Operator-selectable CPU parallelism for bulk content construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BulkIngestPolicy {
    worker_threads: NonZeroUsize,
}

impl BulkIngestPolicy {
    /// Construct an explicit worker limit.
    #[must_use]
    pub const fn new(worker_threads: NonZeroUsize) -> Self {
        Self { worker_threads }
    }

    /// Return the maximum number of concurrent source workers.
    #[must_use]
    pub const fn worker_threads(self) -> NonZeroUsize {
        self.worker_threads
    }
}

impl Default for BulkIngestPolicy {
    fn default() -> Self {
        // Library code cannot infer how much of the host belongs to this
        // principal. Runtimes inject an explicit limit after resource
        // admission; the implicit path remains bounded and serial.
        Self::new(NonZeroUsize::MIN)
    }
}

impl<R> ContentIngest<R> {
    /// Prepare a source under Astrid's pinned content profile.
    #[must_use]
    pub const fn new(name: ContentName, source: R) -> Self {
        Self {
            name,
            source,
            profile: ChunkingProfile::ASTRID_V1,
            observation: None,
        }
    }

    /// Prepare a source under an explicit persistent chunking profile.
    #[must_use]
    pub const fn with_profile(name: ContentName, source: R, profile: ChunkingProfile) -> Self {
        Self {
            name,
            source,
            profile,
            observation: None,
        }
    }

    /// Attach the platform adapter's source-version observation.
    #[must_use]
    pub fn with_observation(mut self, observation: SourceObservation) -> Self {
        self.observation = Some(observation);
        self
    }

    pub(crate) fn into_parts(self) -> (ContentName, R, ChunkingProfile, Option<SourceObservation>) {
        (self.name, self.source, self.profile, self.observation)
    }
}

/// Evidence for why a batch entry did or did not require byte reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentObservation {
    /// The builder directly observed and identified every source byte.
    BytesObserved,
    /// A trusted unchanged token reused a prior byte-verified descriptor.
    ChangeTokenObserved,
}

/// One name and immutable descriptor published by a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentBatchEntry {
    name: ContentName,
    descriptor: ContentDescriptor,
    observation: ContentObservation,
}

impl ContentBatchEntry {
    pub(crate) const fn new(
        name: ContentName,
        descriptor: ContentDescriptor,
        observation: ContentObservation,
    ) -> Self {
        Self {
            name,
            descriptor,
            observation,
        }
    }

    /// Borrow the published name.
    #[must_use]
    pub const fn name(&self) -> &ContentName {
        &self.name
    }

    /// Return the immutable descriptor published under the name.
    #[must_use]
    pub const fn descriptor(&self) -> ContentDescriptor {
        self.descriptor
    }

    /// Return whether bytes or a trusted unchanged token established reuse.
    #[must_use]
    pub const fn observation(&self) -> ContentObservation {
        self.observation
    }
}

/// Result of atomically publishing a batch of named content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentBatchWriteOutcome {
    entries: Vec<ContentBatchEntry>,
    principal_root: RootState,
    objects_inserted: u64,
}

/// Operator-only timing and memory evidence for one bulk ingest.
///
/// These measurements describe shared engine work and must never cross a
/// capsule, mount, or other principal-visible boundary. In particular, a
/// caller must not turn admission timing into a deduplication oracle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BulkIngestDiagnostics {
    pipeline_elapsed: Duration,
    source_build_elapsed: Duration,
    admission_elapsed: Duration,
    publication_elapsed: Duration,
    peak_pending_admission_bytes: usize,
    phases: BulkIngestPhaseDurations,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct BulkIngestPhaseDurations {
    pub(crate) object_preparation: Duration,
    pub(crate) admission_probe: Duration,
    pub(crate) direct_identity: Duration,
    pub(crate) arena_append: Duration,
    pub(crate) physical_map_update: Duration,
    pub(crate) closure_validation: Duration,
    pub(crate) root_publication: Duration,
    pub(crate) flush: Duration,
}

impl BulkIngestDiagnostics {
    pub(crate) const fn new(
        pipeline_elapsed: Duration,
        source_build_elapsed: Duration,
        admission_elapsed: Duration,
        publication_elapsed: Duration,
        peak_pending_admission_bytes: usize,
        phases: BulkIngestPhaseDurations,
    ) -> Self {
        Self {
            pipeline_elapsed,
            source_build_elapsed,
            admission_elapsed,
            publication_elapsed,
            peak_pending_admission_bytes,
            phases,
        }
    }

    /// Return wall time from the first uncached source build through admission.
    #[must_use]
    pub const fn pipeline_elapsed(self) -> Duration {
        self.pipeline_elapsed
    }

    /// Return cumulative worker time spent reading, chunking, and building DAGs.
    ///
    /// Concurrent workers overlap, so this is a work total rather than
    /// end-to-end wall time.
    #[must_use]
    pub const fn source_build_elapsed(self) -> Duration {
        self.source_build_elapsed
    }

    /// Return cumulative time spent in the authoritative object appender.
    #[must_use]
    pub const fn admission_elapsed(self) -> Duration {
        self.admission_elapsed
    }

    /// Return wall time spent validating and publishing the principal root.
    #[must_use]
    pub const fn publication_elapsed(self) -> Duration {
        self.publication_elapsed
    }

    /// Return the maximum bytes awaiting or undergoing object admission.
    #[must_use]
    pub const fn peak_pending_admission_bytes(self) -> usize {
        self.peak_pending_admission_bytes
    }

    /// Return canonical object validation, identity, and frame-preparation time.
    #[must_use]
    pub const fn object_preparation_elapsed(self) -> Duration {
        self.phases.object_preparation
    }

    /// Return authoritative existing-object probe time.
    #[must_use]
    pub const fn admission_probe_elapsed(self) -> Duration {
        self.phases.admission_probe
    }

    /// Return direct physical-identity construction time.
    #[must_use]
    pub const fn direct_identity_elapsed(self) -> Duration {
        self.phases.direct_identity
    }

    /// Return immutable arena-append time.
    #[must_use]
    pub const fn arena_append_elapsed(self) -> Duration {
        self.phases.arena_append
    }

    /// Return physical representation-map update time.
    #[must_use]
    pub const fn physical_map_update_elapsed(self) -> Duration {
        self.phases.physical_map_update
    }

    /// Return owning-closure validation time.
    #[must_use]
    pub const fn closure_validation_elapsed(self) -> Duration {
        self.phases.closure_validation
    }

    /// Return authoritative root-journal append time.
    #[must_use]
    pub const fn root_publication_elapsed(self) -> Duration {
        self.phases.root_publication
    }

    /// Return durable media-flush time.
    #[must_use]
    pub const fn flush_elapsed(self) -> Duration {
        self.phases.flush
    }
}

impl ContentBatchWriteOutcome {
    pub(crate) const fn new(
        entries: Vec<ContentBatchEntry>,
        principal_root: RootState,
        objects_inserted: u64,
    ) -> Self {
        Self {
            entries,
            principal_root,
            objects_inserted,
        }
    }

    /// Borrow entries in canonical content-name order.
    #[must_use]
    pub fn entries(&self) -> &[ContentBatchEntry] {
        &self.entries
    }

    /// Return the single principal root authorizing the complete batch.
    #[must_use]
    pub const fn principal_root(&self) -> RootState {
        self.principal_root
    }

    /// Return privileged physical-admission diagnostics for the batch.
    ///
    /// This value must remain below guest-visible boundaries because it can
    /// reveal cross-principal deduplication.
    #[must_use]
    pub const fn objects_inserted(&self) -> u64 {
        self.objects_inserted
    }
}

impl ContentWriteOutcome {
    pub(crate) const fn new(
        descriptor: ContentDescriptor,
        principal_root: RootState,
        objects_inserted: u64,
    ) -> Self {
        Self {
            descriptor,
            principal_root,
            objects_inserted,
        }
    }

    /// Return the immutable file descriptor.
    #[must_use]
    pub const fn descriptor(self) -> ContentDescriptor {
        self.descriptor
    }

    /// Return the newly authoritative principal root.
    #[must_use]
    pub const fn principal_root(self) -> RootState {
        self.principal_root
    }

    /// Return the number of newly admitted physical objects.
    ///
    /// This is a kernel-side diagnostic for tests and operations. It must not
    /// cross a capsule, mount, or other principal-visible API boundary because
    /// it reveals whether content already existed in the shared store.
    #[must_use]
    pub const fn objects_inserted(self) -> u64 {
        self.objects_inserted
    }
}

/// Failure to read or mutate principal-owned content.
#[derive(Debug)]
#[non_exhaustive]
pub enum PrincipalContentError {
    /// Atomic batch publication requires at least one source.
    EmptyBatch,
    /// An atomic batch named the same catalog entry more than once.
    DuplicateBatchName(ContentName),
    /// Content name validation failed.
    InvalidName(ContentNameError),
    /// Canonical content-DAG construction or decoding failed.
    Content(ContentError),
    /// Streaming byte source failed before a complete file was staged.
    ContentSource(io::Error),
    /// Shared principal projection engine failed.
    Projection(PrincipalProjectionError),
    /// Principal state or catalog did not match its canonical grammar.
    InvalidGraph {
        /// Invalid object.
        object: ObjectId,
        /// Stable diagnostic detail.
        detail: &'static str,
    },
    /// Accounting exceeded its integer representation.
    AccountingOverflow,
    /// A growth operation exceeded the principal's live storage budget.
    QuotaExceeded {
        /// Logical and name bytes after the proposed write.
        used: u64,
        /// Effective principal limit.
        limit: u64,
    },
    /// Live quota resolution failed.
    QuotaPolicy(StorageError),
}

impl fmt::Display for PrincipalContentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBatch => formatter.write_str("principal content batch is empty"),
            Self::DuplicateBatchName(name) => {
                write!(formatter, "principal content batch repeats name {name}")
            },
            Self::InvalidName(error) => error.fmt(formatter),
            Self::Content(error) => error.fmt(formatter),
            Self::ContentSource(error) => write!(formatter, "principal content source: {error}"),
            Self::Projection(error) => error.fmt(formatter),
            Self::InvalidGraph { object, detail } => {
                write!(
                    formatter,
                    "invalid principal content graph {object:?}: {detail}"
                )
            },
            Self::AccountingOverflow => {
                formatter.write_str("principal content accounting overflow")
            },
            Self::QuotaExceeded { used, limit } => {
                write!(
                    formatter,
                    "principal content quota exceeded: {used} > {limit}"
                )
            },
            Self::QuotaPolicy(error) => {
                write!(formatter, "resolve principal content quota: {error}")
            },
        }
    }
}

impl std::error::Error for PrincipalContentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidName(error) => Some(error),
            Self::Content(error) => Some(error),
            Self::ContentSource(error) => Some(error),
            Self::Projection(error) => Some(error),
            Self::QuotaPolicy(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ContentError> for PrincipalContentError {
    fn from(error: ContentError) -> Self {
        Self::Content(error)
    }
}

impl From<PrincipalProjectionError> for PrincipalContentError {
    fn from(error: PrincipalProjectionError) -> Self {
        Self::Projection(error)
    }
}
