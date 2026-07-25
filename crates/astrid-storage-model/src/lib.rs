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

#![no_std]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

/// Logical identity of one canonical typed object.
///
/// The model treats digest construction as an integration boundary. A
/// production implementation derives this value from a domain-separated hash
/// of the object format version, object kind, and canonical plaintext.
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

/// A typed, labelled reference to another immutable object.
///
/// The label identifies the relation inside the source object: for example a
/// principal-state field, directory name, KV slot, or chunk position.
/// Different labels may intentionally point to the same target.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectReference {
    label: Vec<u8>,
    target: ObjectId,
    kind: ReferenceKind,
}

impl ObjectReference {
    /// Construct a typed object reference.
    #[must_use]
    pub const fn new(label: Vec<u8>, target: ObjectId, kind: ReferenceKind) -> Self {
        Self {
            label,
            target,
            kind,
        }
    }

    /// Construct a strong ownership reference.
    #[must_use]
    pub const fn owns(label: Vec<u8>, target: ObjectId) -> Self {
        Self::new(label, target, ReferenceKind::Owns)
    }

    /// Borrow the canonical relation label.
    #[must_use]
    pub fn label(&self) -> &[u8] {
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
}

/// Accounting class of an object record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectClass {
    /// User-visible data such as a file chunk or KV value.
    Data,
    /// Structural data such as a directory, tree branch, or commit.
    Metadata,
}

/// Canonical object bytes and their typed child references.
///
/// `logical_bytes` is the number of user-visible bytes contributed by this
/// object. Structural objects normally contribute zero. `canonical_bytes`
/// remains part of retained and physical accounting regardless of class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectRecord {
    canonical_bytes: Vec<u8>,
    references: Vec<ObjectReference>,
    logical_bytes: u64,
    class: ObjectClass,
}

impl ObjectRecord {
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
            canonical_bytes,
            references,
            logical_bytes,
            class,
        })
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

    /// Find a reference by its canonical relation label.
    #[must_use]
    pub fn reference(&self, label: &[u8]) -> Option<&ObjectReference> {
        self.references
            .binary_search_by(|reference| reference.label.as_slice().cmp(label))
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
        label: &[u8],
        expected: ObjectId,
        replacement: ObjectId,
    ) -> Result<Self, ModelError> {
        let mut next = self.clone();
        let index = next
            .references
            .binary_search_by(|reference| reference.label.as_slice().cmp(label))
            .map_err(|_| ModelError::MissingReference {
                label: label.to_vec(),
            })?;
        let reference = &mut next.references[index];
        if reference.kind != ReferenceKind::Owns {
            return Err(ModelError::ReferenceNotOwned {
                label: label.to_vec(),
            });
        }
        if reference.target != expected {
            return Err(ModelError::ReferenceTargetMismatch {
                label: label.to_vec(),
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
    fn identify(&self, record: &ObjectRecord) -> ObjectId;
}

mod proof;

pub use proof::{
    OwnedSubtreePatch, ReferencePath, StateSelector, StateViewProof, TransitionWitness,
    VerifiedStateView,
};

/// Current committed root of a principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootState {
    /// Monotonically increasing compare-and-swap generation.
    pub generation: u64,
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

/// Per-principal logical and retained accounting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrincipalUsage {
    /// Number of distinct objects reachable from the current root.
    pub object_count: u64,
    /// Sum of user-visible byte contributions.
    pub logical_bytes: u64,
    /// Sum of canonical bytes for all distinct reachable objects.
    pub retained_object_bytes: u64,
    /// Retained bytes belonging to metadata-class objects.
    pub metadata_bytes: u64,
}

/// Result of a garbage-collection pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Number of objects removed.
    pub objects_removed: u64,
    /// Canonical object bytes removed.
    pub bytes_removed: u64,
}

/// Errors raised when a model invariant would be violated.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// A proof object does not match its declared content identity.
    ProofIdentityMismatch {
        /// Identifier carried by the proof.
        declared: ObjectId,
        /// Identifier recomputed from the canonical record.
        computed: ObjectId,
    },
    /// An object required to traverse or verify a partial proof was absent.
    MissingProofObject(ObjectId),
    /// A labelled reference required by a selector or patch was absent.
    MissingReference {
        /// Canonical relation label.
        label: Vec<u8>,
    },
    /// A selector or patch attempted to traverse a non-owning reference.
    ReferenceNotOwned {
        /// Canonical relation label.
        label: Vec<u8>,
    },
    /// A labelled reference did not point to the expected object.
    ReferenceTargetMismatch {
        /// Canonical relation label.
        label: Vec<u8>,
        /// Target expected by the caller.
        expected: ObjectId,
        /// Target present in the object.
        actual: ObjectId,
    },
    /// A proof disclosed an object outside its selected paths and closures.
    ExtraneousProofObject(ObjectId),
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
    /// A principal already exists but genesis creation was requested.
    PrincipalAlreadyExists,
    /// A principal does not exist but an update was requested.
    PrincipalMissing,
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
        required: u32,
        /// Number supplied by the plan.
        actual: u32,
    },
    /// A zero replica requirement is invalid.
    ZeroReplicaRequirement,
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
            Self::ProofIdentityMismatch { declared, computed } => write!(
                formatter,
                "proof object identity mismatch: declared {declared:?}, computed {computed:?}"
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
            Self::PatchTargetMismatch { expected, actual } => write!(
                formatter,
                "patch target mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::TransitionRootMismatch { declared, computed } => write!(
                formatter,
                "transition root mismatch: declared {declared:?}, computed {computed:?}"
            ),
            Self::PrincipalAlreadyExists => formatter.write_str("principal already exists"),
            Self::PrincipalMissing => formatter.write_str("principal does not exist"),
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
                "epoch {epoch:?} places {blob:?} on {actual} nodes, requires {required}"
            ),
            Self::ZeroReplicaRequirement => {
                formatter.write_str("minimum replica count must be non-zero")
            },
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
#[path = "model_tests.rs"]
mod tests;
