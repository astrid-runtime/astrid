//! Portable executable model for Astrid's principal store.
//!
//! This crate contains the smallest useful semantics of the proposed storage
//! architecture:
//!
//! - immutable, typed object records;
//! - complete graph-closure validation;
//! - atomic compare-and-swap of principal roots;
//! - idempotent import and deterministic export;
//! - root-and-pin-based garbage collection;
//! - stable per-principal accounting;
//! - owning versus evidence/lineage/derived reference semantics;
//! - verified partial state views and structural transition witnesses;
//! - placement epochs that do not alter logical roots.
//!
//! It intentionally contains no I/O, async runtime, policy engine, clock,
//! cryptographic implementation, or host filesystem dependency. Production
//! implementations must refine this model and add those boundaries explicitly.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

extern crate alloc;
use alloc::vec::Vec;
use core::fmt;
use core::num::{NonZeroU16, NonZeroU32};
/// Logical identity of one canonical typed object.
///
/// The model treats digest construction as an integration boundary. A
/// production implementation derives this value from a domain-separated hash
/// of the object format version, object kind, complete canonical object
/// encoding, and identity-bearing accounting fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId([u8; 32]);

impl ObjectId {
    /// Construct an object identifier from its digest bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Reachability meaning of a reference between immutable objects.
///
/// Only [`Self::Owns`] contributes to a principal's durable closure, usage,
/// default export, and garbage-collection reachability. Other relations bind
/// identity without silently transferring ownership or retention.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReferenceKind {
    /// Strong ownership: the target is required to reconstruct the source.
    Owns,
    /// Observation or audit evidence retained under its own root or pin.
    Evidence,
    /// Historical/fork/merge lineage that does not import the target closure.
    Lineage,
    /// Rebuildable index or materialization.
    Derived,
}

impl ReferenceKind {
    /// Return the stable identity code for this reachability meaning.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Owns => 0,
            Self::Evidence => 1,
            Self::Lineage => 2,
            Self::Derived => 3,
        }
    }

    /// Decode a stable reachability code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Owns),
            1 => Some(Self::Evidence),
            2 => Some(Self::Lineage),
            3 => Some(Self::Derived),
            _ => None,
        }
    }
}

/// Canonical relation label within an immutable object.
///
/// Labels are opaque bytes: individual object schemas decide whether they
/// represent a directory name, KV slot, structural field, or another
/// relation. This wrapper prevents canonical payload bytes, object
/// identifiers, and relation labels from being interchanged accidentally.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReferenceLabel<B = Vec<u8>>(B);

impl<B> ReferenceLabel<B> {
    /// Construct a typed reference label over owned or borrowed bytes.
    #[must_use]
    pub const fn new(bytes: B) -> Self {
        Self(bytes)
    }

    /// Consume the label and return its underlying byte representation.
    #[must_use]
    pub fn into_inner(self) -> B {
        self.0
    }
}

impl<B: AsRef<[u8]>> ReferenceLabel<B> {
    /// Borrow the canonical label bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Vec<u8>> for ReferenceLabel<Vec<u8>> {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for ReferenceLabel<B> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// A typed, labelled reference to another immutable object.
///
/// The label identifies the relation inside the source object: for example a
/// principal-state field, directory name, KV slot, or chunk position.
/// Different labels may intentionally point to the same target.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectReference {
    label: ReferenceLabel,
    target: ObjectId,
    kind: ReferenceKind,
}

impl ObjectReference {
    /// Construct a typed object reference.
    #[must_use]
    pub const fn new(label: ReferenceLabel, target: ObjectId, kind: ReferenceKind) -> Self {
        Self {
            label,
            target,
            kind,
        }
    }

    /// Construct a strong ownership reference.
    #[must_use]
    pub const fn owns(label: ReferenceLabel, target: ObjectId) -> Self {
        Self::new(label, target, ReferenceKind::Owns)
    }

    /// Borrow the canonical relation label.
    #[must_use]
    pub const fn label(&self) -> &ReferenceLabel {
        &self.label
    }

    /// Return the referenced object identifier.
    #[must_use]
    pub const fn target(&self) -> ObjectId {
        self.target
    }

    /// Return the reference's reachability meaning.
    #[must_use]
    pub const fn kind(&self) -> ReferenceKind {
        self.kind
    }
}

/// Identity of one encoded physical representation.
///
/// A logical [`ObjectId`] can have more than one blob representation as
/// encryption, compression, or erasure-coding profiles change. Physical
/// placement names `BlobId`; principal roots name `ObjectId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlobId([u8; 32]);

impl BlobId {
    /// Construct a blob identifier from its digest bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Identifier for a retained snapshot, export, legal hold, or reader root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PinId(u64);

impl PinId {
    /// Construct a pin identifier.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the persisted numeric pin identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Version of a physical placement map.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlacementEpoch(u64);

impl PlacementEpoch {
    /// Construct a placement epoch.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the persisted numeric epoch.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Identifier for one physical storage node or failure-domain endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StorageNodeId(u32);

impl StorageNodeId {
    /// Construct a storage-node identifier.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the persisted numeric node identifier.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Accounting class of an object record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectClass {
    /// User-visible data such as a file chunk or KV value.
    Data,
    /// Structural data such as a directory, tree branch, or commit.
    Metadata,
}

impl ObjectClass {
    /// Return the stable identity code for this accounting class.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Metadata => 1,
        }
    }

    /// Decode a stable accounting-class code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Data),
            1 => Some(Self::Metadata),
            _ => None,
        }
    }
}

/// Versioned semantic kind of one immutable object.
///
/// The numeric codes are part of logical identity. Persistent encodings may
/// use different framing, but must preserve this value when computing
/// [`ObjectId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ObjectKind {
    /// Raw user-visible bytes.
    Chunk,
    /// Ordered tree over large content chunks.
    ChunkTree,
    /// File metadata and content root.
    File,
    /// Symlink target bytes, never followed during validation.
    Symlink,
    /// Canonical directory entries.
    Directory,
    /// Canonical key/value leaf.
    KvLeaf,
    /// Internal key/value tree branch.
    KvBranch,
    /// Capsule namespace to KV-root mapping.
    NamespaceMap,
    /// Complete principal-owned durable state.
    PrincipalState,
    /// Principal-root transition envelope.
    Commit,
    /// Durable owner-internal workspace branch record.
    WorkspaceBranch,
    /// Observation, receipt, or audit evidence.
    Evidence,
    /// Rebuildable index or materialization.
    Derived,
    /// Semantics-visible execution surface shared by compatible engine builds.
    RuntimeSemanticProfile,
    /// Complete canonical request for one derivation.
    DerivationInvocation,
    /// Verified relation from one derivation invocation to its results.
    DerivationEvidence,
    /// Garbage-collection plan and its closed-world safety proof.
    GcPlanEvidence,
    /// Executed garbage-collection transition bound to one exact plan.
    GcCommitEvidence,
}

impl ObjectKind {
    /// Return the stable identity code for this kind.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Chunk => 0,
            Self::ChunkTree => 1,
            Self::File => 2,
            Self::Symlink => 3,
            Self::Directory => 4,
            Self::KvLeaf => 5,
            Self::KvBranch => 6,
            Self::NamespaceMap => 7,
            Self::PrincipalState => 8,
            Self::Commit => 9,
            Self::WorkspaceBranch => 17,
            Self::Evidence => 10,
            Self::Derived => 11,
            Self::RuntimeSemanticProfile => 12,
            Self::DerivationInvocation => 13,
            Self::DerivationEvidence => 14,
            Self::GcPlanEvidence => 15,
            Self::GcCommitEvidence => 16,
        }
    }

    /// Decode a stable semantic-kind code.
    #[must_use]
    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            0 => Some(Self::Chunk),
            1 => Some(Self::ChunkTree),
            2 => Some(Self::File),
            3 => Some(Self::Symlink),
            4 => Some(Self::Directory),
            5 => Some(Self::KvLeaf),
            6 => Some(Self::KvBranch),
            7 => Some(Self::NamespaceMap),
            8 => Some(Self::PrincipalState),
            9 => Some(Self::Commit),
            17 => Some(Self::WorkspaceBranch),
            10 => Some(Self::Evidence),
            11 => Some(Self::Derived),
            12 => Some(Self::RuntimeSemanticProfile),
            13 => Some(Self::DerivationInvocation),
            14 => Some(Self::DerivationEvidence),
            15 => Some(Self::GcPlanEvidence),
            16 => Some(Self::GcCommitEvidence),
            _ => None,
        }
    }
}

/// Non-zero schema version of one [`ObjectKind`].
///
/// Versions are scoped to a kind so unrelated object families can evolve
/// without rewriting every identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectFormatVersion(NonZeroU16);

impl ObjectFormatVersion {
    /// First schema version for a kind.
    pub const V1: Self = Self(NonZeroU16::MIN);

    /// Construct a non-zero object-format version.
    #[must_use]
    pub const fn new(value: u16) -> Option<Self> {
        match NonZeroU16::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return the numeric schema version.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

/// Canonical object bytes and their typed child references.
///
/// `logical_bytes` is the number of user-visible bytes contributed by this
/// object. Structural objects normally contribute zero. The complete canonical
/// record—including payload and references—remains part of retained accounting
/// regardless of class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectRecord {
    kind: ObjectKind,
    format_version: ObjectFormatVersion,
    canonical_bytes: Vec<u8>,
    references: Vec<ObjectReference>,
    logical_bytes: u64,
    class: ObjectClass,
}

impl ObjectRecord {
    // Stable widths in the logical canonical record encoding. Durable engines
    // may add framing, checksums, algorithm tags, and indexes; those belong to
    // physical-store accounting rather than a principal's retained quota.
    const FIXED_RETAINED_BYTES: u64 = 2 // object kind
        + 2 // format version
        + 1 // accounting class
        + 8 // logical byte contribution
        + 8 // canonical payload length
        + 8; // reference count
    const FIXED_REFERENCE_BYTES: u64 = 8 // label length
        + 32 // target ObjectId
        + 1; // reference kind

    /// Construct a canonical object record.
    ///
    /// References must be strictly increasing by relation label. Requiring one
    /// target per label makes duplicate relations and order-dependent encodings
    /// unrepresentable while permitting two labels to share content.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::NonCanonicalReferences`] when references are not
    /// strictly increasing.
    pub fn new(
        kind: ObjectKind,
        format_version: ObjectFormatVersion,
        canonical_bytes: Vec<u8>,
        references: Vec<ObjectReference>,
        logical_bytes: u64,
        class: ObjectClass,
    ) -> Result<Self, ModelError> {
        if references
            .windows(2)
            .any(|pair| pair[0].label >= pair[1].label)
        {
            return Err(ModelError::NonCanonicalReferences);
        }
        Ok(Self {
            kind,
            format_version,
            canonical_bytes,
            references,
            logical_bytes,
            class,
        })
    }

    /// Return the semantic object kind.
    #[must_use]
    pub const fn kind(&self) -> ObjectKind {
        self.kind
    }

    /// Return the kind-scoped object schema version.
    #[must_use]
    pub const fn format_version(&self) -> ObjectFormatVersion {
        self.format_version
    }

    /// Borrow the canonical bytes used for collision checking.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Borrow the object's child references.
    #[must_use]
    pub fn references(&self) -> &[ObjectReference] {
        &self.references
    }

    /// Iterate over strong ownership references.
    #[must_use]
    pub fn owning_references(&self) -> impl DoubleEndedIterator<Item = ObjectId> + '_ {
        self.references
            .iter()
            .filter(|reference| reference.kind == ReferenceKind::Owns)
            .map(|reference| reference.target)
    }

    /// Return the stable bytes charged for retaining this canonical record.
    ///
    /// The total covers every identity-bearing field in the logical record:
    /// fixed fields, canonical payload bytes, and each reference's label,
    /// target identifier, and reachability kind. It deliberately excludes
    /// engine framing, checksums, indexes, and allocation overhead, which are
    /// physical-store costs rather than stable per-principal accounting.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::ArithmeticOverflow`] when a length or the total
    /// cannot be represented as `u64`.
    pub fn retained_bytes(&self) -> Result<u64, ModelError> {
        let canonical_bytes = u64::try_from(self.canonical_bytes.len())
            .map_err(|_| ModelError::ArithmeticOverflow)?;
        let mut retained = Self::FIXED_RETAINED_BYTES
            .checked_add(canonical_bytes)
            .ok_or(ModelError::ArithmeticOverflow)?;
        for reference in &self.references {
            let label_bytes = u64::try_from(reference.label.as_bytes().len())
                .map_err(|_| ModelError::ArithmeticOverflow)?;
            retained = retained
                .checked_add(Self::FIXED_REFERENCE_BYTES)
                .and_then(|total| total.checked_add(label_bytes))
                .ok_or(ModelError::ArithmeticOverflow)?;
        }
        Ok(retained)
    }

    /// Find a reference by its canonical relation label.
    #[must_use]
    pub fn reference<B: AsRef<[u8]>>(&self, label: &ReferenceLabel<B>) -> Option<&ObjectReference> {
        self.references
            .binary_search_by(|reference| reference.label.as_bytes().cmp(label.as_bytes()))
            .ok()
            .map(|index| &self.references[index])
    }

    /// Replace one strong reference target while preserving its relation.
    ///
    /// # Errors
    ///
    /// Returns a typed proof error if the relation is absent, is not an
    /// ownership edge, or does not point to `expected`.
    pub fn replace_owned_target(
        &self,
        label: &ReferenceLabel<impl AsRef<[u8]>>,
        expected: ObjectId,
        replacement: ObjectId,
    ) -> Result<Self, ModelError> {
        let mut next = self.clone();
        let index = next
            .references
            .binary_search_by(|reference| reference.label.as_bytes().cmp(label.as_bytes()))
            .map_err(|_| ModelError::MissingReference {
                label: ReferenceLabel::new(label.as_bytes().to_vec()),
            })?;
        let reference = &mut next.references[index];
        if reference.kind != ReferenceKind::Owns {
            return Err(ModelError::ReferenceNotOwned {
                label: ReferenceLabel::new(label.as_bytes().to_vec()),
            });
        }
        if reference.target != expected {
            return Err(ModelError::ReferenceTargetMismatch {
                label: ReferenceLabel::new(label.as_bytes().to_vec()),
                expected,
                actual: reference.target,
            });
        }
        reference.target = replacement;
        Ok(next)
    }

    /// Return the user-visible byte contribution.
    #[must_use]
    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }

    /// Return the accounting class.
    #[must_use]
    pub const fn class(&self) -> ObjectClass {
        self.class
    }
}

/// Computes the content identity of a canonical object record.
///
/// Production integrations must domain-separate and hash the complete object
/// format, including payload, labelled references, reference kinds, accounting
/// fields, object kind, and format version. Keeping this operation behind a
/// trait lets the executable model remain `no_std` and hash-agile.
pub trait ObjectIdentity {
    /// Compute the logical identity of `record`.
    ///
    /// Implementations must be deterministic and must encode every
    /// identity-bearing field. Collision handling remains mandatory even for a
    /// cryptographic implementation.
    fn identify(&self, record: &ObjectRecord) -> ObjectId;
}

mod derivation;
mod derivation_evidence;
mod gc_evidence;
mod physical;
mod proof;

pub use derivation::{
    AuthorityEpochId, CanonicalParametersId, ComputationSharingDomainId, DerivationContractId,
    DerivationInvocation, DerivationModelError, DeterministicSeedId, EngineBuildId, ExecutionClass,
    ExecutionMeasurementsId, HostFunctionSemanticBinding, InvocationId, InvocationInput,
    OutputContractId, RuntimeSemanticProfile, RuntimeSemanticProfileId, SemanticContractId,
    SnapshotId, TransformId,
};
pub use derivation_evidence::{
    DerivationEvidence, DerivationEvidenceError, DerivationOutput, VerifierEvidenceId,
};
pub use gc_evidence::{
    GcCommitEvidence, GcCommitId, GcEvidenceError, GcFactSnapshotId, GcPlanEvidence, GcPlanId,
    RetentionPolicyId, TensorLogicProofId,
};
pub use physical::{
    CanonicalChunkingProfile, CanonicalPhysicalMap, Coverage, Dependency, PhysicalIdentity,
    PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode, PhysicalMapNodeId, PhysicalModelError,
    PlacementEntry, PlacementSet, PlacementSetId, ProfileDependency, ProfileKind, Recipe,
    ReconstructionBounds, Replica, ReplicaLocator, RepresentationAdmissionEvidence,
    RepresentationAdmissionMethod, RepresentationAdmissionSubjectId,
    RepresentationAdmissionTranscript, RepresentationCatalogueRoot, RepresentationCatalogueRootId,
    RepresentationOutputObservation, RepresentationProfile, RepresentationProfileId,
    RepresentationRecord, RepresentationRecordId, RepresentationState, RepresentationStateId,
};
pub use proof::{
    OwnedSubtreePatch, ReferencePath, StateSelector, StateViewProof, TransitionWitness,
    VerifiedStateView,
};

/// Monotonic generation of one principal root.
///
/// A generation is scoped by principal and advances only after a successful
/// compare-and-swap. The newtype prevents generations from being confused
/// with byte counts, epochs, or other numeric storage fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RootGeneration(u64);

impl RootGeneration {
    /// Generation assigned to a principal's first committed root.
    pub const INITIAL: Self = Self(0);

    /// Construct a root generation from its persisted value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the persisted numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advance to the next generation.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

/// Current committed root of a principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootState {
    /// Monotonically increasing compare-and-swap generation.
    pub generation: RootGeneration,
    /// Immutable commit object naming the principal state.
    pub commit: ObjectId,
}

/// Result of inserting an immutable object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertOutcome {
    /// The object was not present and was inserted.
    Inserted,
    /// An identical object was already present.
    AlreadyPresent,
}

/// Result of registering an encoded representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepresentationOutcome {
    /// The blob-to-content relation was not present and was inserted.
    Registered,
    /// The same blob was already registered for the same logical object.
    AlreadyPresent,
}

/// Non-zero durability requirement for an encoded representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReplicaCount(NonZeroU32);

impl ReplicaCount {
    /// Construct a non-zero replica requirement.
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        match NonZeroU32::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return the required number of replicas.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Per-principal logical and retained accounting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrincipalUsage {
    /// Number of distinct objects reachable from the current root.
    pub object_count: u64,
    /// Sum of user-visible byte contributions.
    pub logical_bytes: u64,
    /// Sum of complete canonical-record bytes for all reachable objects.
    pub retained_object_bytes: u64,
    /// Complete canonical-record bytes belonging to metadata-class objects.
    pub metadata_bytes: u64,
}

/// Result of a garbage-collection pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Number of objects removed.
    pub objects_removed: u64,
    /// Complete canonical-record bytes removed.
    pub bytes_removed: u64,
}

/// Errors raised when a model invariant would be violated.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ModelError {
    /// One object identifier was presented with different canonical bytes or
    /// references.
    ObjectCollision(ObjectId),
    /// A referenced object is absent.
    MissingObject(ObjectId),
    /// One physical blob identifier was presented as a representation of two
    /// different logical objects.
    BlobCollision(BlobId),
    /// The object graph contains a cycle.
    ObjectCycle(ObjectId),
    /// Child reference labels were not in strictly increasing canonical order.
    NonCanonicalReferences,
    /// A state selector was empty, unordered, duplicated, or prefix-redundant.
    NonCanonicalSelector,
    /// Proof records were not strictly ordered by declared object identifier.
    NonCanonicalProofRecords,
    /// An object does not match its declared content identity.
    ObjectIdentityMismatch {
        /// Identifier declared by an import, transaction, or proof.
        declared: ObjectId,
        /// Identifier recomputed from the canonical record.
        computed: ObjectId,
    },
    /// An object required to traverse or verify a partial proof was absent.
    MissingProofObject(ObjectId),
    /// A labelled reference required by a selector or patch was absent.
    MissingReference {
        /// Canonical relation label.
        label: ReferenceLabel,
    },
    /// A selector or patch attempted to traverse a non-owning reference.
    ReferenceNotOwned {
        /// Canonical relation label.
        label: ReferenceLabel,
    },
    /// A labelled reference did not point to the expected object.
    ReferenceTargetMismatch {
        /// Canonical relation label.
        label: ReferenceLabel,
        /// Target expected by the caller.
        expected: ObjectId,
        /// Target present in the object.
        actual: ObjectId,
    },
    /// A proof disclosed an object outside its selected paths and closures.
    ExtraneousProofObject(ObjectId),
    /// An import supplied an object outside the declared root closure.
    ExtraneousImportObject(ObjectId),
    /// A structural patch path reached a different target.
    PatchTargetMismatch {
        /// Object the patch declared it would replace.
        expected: ObjectId,
        /// Object reached by the authenticated path.
        actual: ObjectId,
    },
    /// A transition witness recomputed a different after root.
    TransitionRootMismatch {
        /// After root declared by the witness.
        declared: ObjectId,
        /// After root computed by applying the patch.
        computed: ObjectId,
    },
    /// A principal does not exist but an update was requested.
    PrincipalMissing,
    /// A principal root named an object other than a commit envelope.
    RootNotCommit {
        /// Object offered as the principal commit.
        object: ObjectId,
        /// Actual semantic kind of the object.
        actual: ObjectKind,
    },
    /// The caller's expected root does not equal the current root.
    RootConflict {
        /// Root expected by the caller.
        expected: Option<RootState>,
        /// Root currently installed.
        actual: Option<RootState>,
    },
    /// A numeric total or generation overflowed.
    ArithmeticOverflow,
    /// The pin identifier already exists.
    PinAlreadyExists(PinId),
    /// The pin identifier does not exist.
    PinMissing(PinId),
    /// A placement epoch is already installed.
    PlacementEpochAlreadyExists(PlacementEpoch),
    /// A placement epoch does not exist.
    PlacementEpochMissing(PlacementEpoch),
    /// A placement epoch did not advance the active epoch monotonically.
    StalePlacementEpoch {
        /// Epoch proposed by the caller.
        proposed: PlacementEpoch,
        /// Epoch currently active.
        active: PlacementEpoch,
    },
    /// A placement plan named an unregistered encoded representation.
    UnregisteredBlob(BlobId),
    /// A placement plan did not include a live object's representation.
    MissingPlacement {
        /// Placement epoch being validated.
        epoch: PlacementEpoch,
        /// Live object with no placed representation.
        object: ObjectId,
    },
    /// A live logical object has no registered physical representation.
    MissingRepresentation(ObjectId),
    /// A blob's replica set is smaller than the declared minimum.
    InsufficientReplicas {
        /// Placement epoch being validated.
        epoch: PlacementEpoch,
        /// Encoded blob with insufficient replicas.
        blob: BlobId,
        /// Required number of replicas.
        required: ReplicaCount,
        /// Number supplied by the plan.
        actual: u32,
    },
    /// The active placement epoch cannot be retired.
    ActivePlacementEpoch(PlacementEpoch),
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectCollision(id) => write!(formatter, "object collision for {id:?}"),
            Self::MissingObject(id) => write!(formatter, "missing object {id:?}"),
            Self::BlobCollision(id) => write!(formatter, "blob collision for {id:?}"),
            Self::ObjectCycle(id) => write!(formatter, "object cycle at {id:?}"),
            Self::NonCanonicalReferences => {
                formatter.write_str("object reference labels are not strictly increasing")
            },
            Self::NonCanonicalSelector => formatter.write_str("state selector is not canonical"),
            Self::NonCanonicalProofRecords => {
                formatter.write_str("proof records are not strictly ordered")
            },
            Self::ObjectIdentityMismatch { declared, computed } => write!(
                formatter,
                "object identity mismatch: declared {declared:?}, computed {computed:?}"
            ),
            Self::MissingProofObject(id) => write!(formatter, "missing proof object {id:?}"),
            Self::MissingReference { label } => {
                write!(formatter, "missing reference labelled {label:?}")
            },
            Self::ReferenceNotOwned { label } => {
                write!(
                    formatter,
                    "reference labelled {label:?} is not an ownership edge"
                )
            },
            Self::ReferenceTargetMismatch {
                label,
                expected,
                actual,
            } => write!(
                formatter,
                "reference {label:?} target mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::ExtraneousProofObject(id) => {
                write!(formatter, "extraneous proof object {id:?}")
            },
            Self::ExtraneousImportObject(id) => {
                write!(formatter, "extraneous imported object {id:?}")
            },
            Self::PatchTargetMismatch { expected, actual } => write!(
                formatter,
                "patch target mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::TransitionRootMismatch { declared, computed } => write!(
                formatter,
                "transition root mismatch: declared {declared:?}, computed {computed:?}"
            ),
            Self::PrincipalMissing => formatter.write_str("principal does not exist"),
            Self::RootNotCommit { object, actual } => {
                write!(
                    formatter,
                    "principal root {object:?} has kind {actual:?}, expected Commit"
                )
            },
            Self::RootConflict { expected, actual } => {
                write!(
                    formatter,
                    "principal root conflict: expected {expected:?}, actual {actual:?}"
                )
            },
            Self::ArithmeticOverflow => formatter.write_str("storage accounting overflow"),
            Self::PinAlreadyExists(id) => write!(formatter, "pin {id:?} already exists"),
            Self::PinMissing(id) => write!(formatter, "pin {id:?} does not exist"),
            Self::PlacementEpochAlreadyExists(epoch) => {
                write!(formatter, "placement epoch {epoch:?} already exists")
            },
            Self::PlacementEpochMissing(epoch) => {
                write!(formatter, "placement epoch {epoch:?} does not exist")
            },
            Self::StalePlacementEpoch { proposed, active } => write!(
                formatter,
                "placement epoch {proposed:?} does not advance active epoch {active:?}"
            ),
            Self::UnregisteredBlob(blob) => {
                write!(formatter, "placement plan names unregistered blob {blob:?}")
            },
            Self::MissingPlacement { epoch, object } => {
                write!(formatter, "epoch {epoch:?} does not place {object:?}")
            },
            Self::MissingRepresentation(object) => {
                write!(formatter, "object {object:?} has no blob representation")
            },
            Self::InsufficientReplicas {
                epoch,
                blob,
                required,
                actual,
            } => write!(
                formatter,
                "epoch {epoch:?} places {blob:?} on {actual} nodes, requires {}",
                required.get()
            ),
            Self::ActivePlacementEpoch(epoch) => {
                write!(
                    formatter,
                    "active placement epoch {epoch:?} cannot be retired"
                )
            },
        }
    }
}

impl core::error::Error for ModelError {}

mod world;
pub use world::World;

#[cfg(test)]
mod derivation_tests;

#[cfg(test)]
mod gc_evidence_tests;

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
