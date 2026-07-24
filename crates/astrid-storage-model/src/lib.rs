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

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
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

/// Canonical sequence of reference labels from a source root to a selected
/// owned subtree.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReferencePath(Vec<Vec<u8>>);

impl ReferencePath {
    /// Construct a reference path. An empty path selects the source root.
    #[must_use]
    pub const fn new(labels: Vec<Vec<u8>>) -> Self {
        Self(labels)
    }

    /// Borrow the ordered relation labels.
    #[must_use]
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.0
    }
}

/// Canonical set of non-redundant paths selected from one committed root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateSelector {
    paths: Vec<ReferencePath>,
}

impl StateSelector {
    /// Construct a selector from strictly ordered, non-overlapping paths.
    ///
    /// A path cannot be a prefix of another selected path because selecting the
    /// ancestor already selects its complete owned closure.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::NonCanonicalSelector`] for an empty, unordered,
    /// duplicate, or prefix-redundant path set.
    pub fn new(paths: Vec<ReferencePath>) -> Result<Self, ModelError> {
        if paths.is_empty()
            || paths
                .windows(2)
                .any(|pair| pair[0] >= pair[1] || path_is_prefix(&pair[0], &pair[1]))
        {
            return Err(ModelError::NonCanonicalSelector);
        }
        Ok(Self { paths })
    }

    /// Borrow the selected paths.
    #[must_use]
    pub fn paths(&self) -> &[ReferencePath] {
        &self.paths
    }
}

/// Partial authenticated object set for a verified state view.
///
/// Records include every ancestor needed to follow each selected path and the
/// complete owning closure below every selected root. Unselected siblings stay
/// blinded as object identifiers inside their disclosed parent records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateViewProof {
    source: ObjectId,
    selector: StateSelector,
    records: Vec<(ObjectId, ObjectRecord)>,
}

impl StateViewProof {
    /// Construct a canonically ordered view proof.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::NonCanonicalProofRecords`] if record identifiers
    /// are not strictly increasing.
    pub fn new(
        source: ObjectId,
        selector: StateSelector,
        records: Vec<(ObjectId, ObjectRecord)>,
    ) -> Result<Self, ModelError> {
        validate_record_order(&records)?;
        Ok(Self {
            source,
            selector,
            records,
        })
    }

    /// Verify object identities, selector paths, selected closures, and proof
    /// minimality.
    ///
    /// # Errors
    ///
    /// Rejects missing, substituted, non-owning, or extraneous proof objects.
    pub fn verify<I: ObjectIdentity>(&self, identity: &I) -> Result<VerifiedStateView, ModelError> {
        let records = verified_record_map(identity, &self.records)?;
        let mut allowed = BTreeSet::new();
        let mut selected_roots = Vec::with_capacity(self.selector.paths.len());

        for path in &self.selector.paths {
            let mut current = self.source;
            allowed.insert(current);
            for label in path.labels() {
                let record = records
                    .get(&current)
                    .ok_or(ModelError::MissingProofObject(current))?;
                let reference =
                    record
                        .reference(label)
                        .ok_or_else(|| ModelError::MissingReference {
                            label: label.clone(),
                        })?;
                if reference.kind != ReferenceKind::Owns {
                    return Err(ModelError::ReferenceNotOwned {
                        label: label.clone(),
                    });
                }
                current = reference.target;
                allowed.insert(current);
            }
            let closure = closure_in(&records, current)?;
            allowed.extend(closure);
            selected_roots.push(current);
        }

        if let Some(extraneous) = records.keys().find(|id| !allowed.contains(id)) {
            return Err(ModelError::ExtraneousProofObject(*extraneous));
        }

        Ok(VerifiedStateView {
            source: self.source,
            selected_roots,
            object_count: records.len(),
        })
    }
}

/// Result of successfully verifying a state view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedStateView {
    source: ObjectId,
    selected_roots: Vec<ObjectId>,
    object_count: usize,
}

impl VerifiedStateView {
    /// Return the committed source root.
    #[must_use]
    pub const fn source(&self) -> ObjectId {
        self.source
    }

    /// Borrow the roots selected in canonical path order.
    #[must_use]
    pub fn selected_roots(&self) -> &[ObjectId] {
        &self.selected_roots
    }

    /// Return the number of disclosed proof records.
    #[must_use]
    pub const fn object_count(&self) -> usize {
        self.object_count
    }
}

/// Smallest generic structural patch: replace one owned subtree at a labelled
/// path.
///
/// Subsystem-specific file and KV patch grammars can refine this operation.
/// This primitive proves only the authenticated root rewrite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedSubtreePatch {
    path: ReferencePath,
    expected: ObjectId,
    replacement: ObjectId,
}

impl OwnedSubtreePatch {
    /// Construct an owned-subtree replacement.
    #[must_use]
    pub const fn new(path: ReferencePath, expected: ObjectId, replacement: ObjectId) -> Self {
        Self {
            path,
            expected,
            replacement,
        }
    }
}

/// Partial authenticated proof that one labelled subtree replacement advances
/// `before` to `after`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionWitness {
    before: ObjectId,
    after: ObjectId,
    patch: OwnedSubtreePatch,
    records: Vec<(ObjectId, ObjectRecord)>,
}

impl TransitionWitness {
    /// Construct a canonically ordered transition witness.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::NonCanonicalProofRecords`] if record identifiers
    /// are not strictly increasing.
    pub fn new(
        before: ObjectId,
        after: ObjectId,
        patch: OwnedSubtreePatch,
        records: Vec<(ObjectId, ObjectRecord)>,
    ) -> Result<Self, ModelError> {
        validate_record_order(&records)?;
        Ok(Self {
            before,
            after,
            patch,
            records,
        })
    }

    /// Verify the partial before-state and recompute the after root.
    ///
    /// The replacement closure's durability is a separate commit invariant;
    /// this witness proves only the structural root transition.
    ///
    /// # Errors
    ///
    /// Rejects substituted roots, targets, paths, records, or non-owning edges.
    pub fn verify<I: ObjectIdentity>(&self, identity: &I) -> Result<ObjectId, ModelError> {
        let records = verified_record_map(identity, &self.records)?;
        if self.patch.path.labels().is_empty() {
            if let Some(extraneous) = records.keys().next() {
                return Err(ModelError::ExtraneousProofObject(*extraneous));
            }
            if self.before != self.patch.expected {
                return Err(ModelError::PatchTargetMismatch {
                    expected: self.patch.expected,
                    actual: self.before,
                });
            }
            if self.after != self.patch.replacement {
                return Err(ModelError::TransitionRootMismatch {
                    declared: self.after,
                    computed: self.patch.replacement,
                });
            }
            return Ok(self.after);
        }

        let mut current = self.before;
        let mut ancestors = Vec::<(ObjectId, ObjectRecord, Vec<u8>, ObjectId)>::new();
        let mut used = BTreeSet::new();
        for label in self.patch.path.labels() {
            let record = records
                .get(&current)
                .ok_or(ModelError::MissingProofObject(current))?;
            let reference =
                record
                    .reference(label)
                    .ok_or_else(|| ModelError::MissingReference {
                        label: label.clone(),
                    })?;
            if reference.kind != ReferenceKind::Owns {
                return Err(ModelError::ReferenceNotOwned {
                    label: label.clone(),
                });
            }
            used.insert(current);
            ancestors.push((current, record.clone(), label.clone(), reference.target));
            current = reference.target;
        }

        if current != self.patch.expected {
            return Err(ModelError::PatchTargetMismatch {
                expected: self.patch.expected,
                actual: current,
            });
        }
        if let Some(extraneous) = records.keys().find(|id| !used.contains(id)) {
            return Err(ModelError::ExtraneousProofObject(*extraneous));
        }

        let mut replacement = self.patch.replacement;
        for (_, record, label, old_child) in ancestors.into_iter().rev() {
            let updated = record.replace_owned_target(&label, old_child, replacement)?;
            replacement = identity.identify(&updated);
        }
        if replacement != self.after {
            return Err(ModelError::TransitionRootMismatch {
                declared: self.after,
                computed: replacement,
            });
        }
        Ok(replacement)
    }
}

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

/// In-memory reference world for principal-store operations.
///
/// `P` is the integration layer's principal identifier. The model requires
/// stable ordering only; it does not prescribe Astrid's public principal wire
/// representation.
#[derive(Clone, Debug)]
pub struct World<P: Ord> {
    objects: BTreeMap<ObjectId, ObjectRecord>,
    representations: BTreeMap<BlobId, ObjectId>,
    roots: BTreeMap<P, RootState>,
    pins: BTreeMap<PinId, ObjectId>,
    placement_epochs: BTreeSet<PlacementEpoch>,
    placements: BTreeMap<(PlacementEpoch, BlobId), BTreeSet<StorageNodeId>>,
    active_placement_epoch: Option<PlacementEpoch>,
}

impl<P: Ord> Default for World<P> {
    fn default() -> Self {
        Self {
            objects: BTreeMap::new(),
            representations: BTreeMap::new(),
            roots: BTreeMap::new(),
            pins: BTreeMap::new(),
            placement_epochs: BTreeSet::new(),
            placements: BTreeMap::new(),
            active_placement_epoch: None,
        }
    }
}

impl<P: Ord> World<P> {
    /// Construct an empty model world.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the number of immutable objects held by the world.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Return the current root for `principal`.
    #[must_use]
    pub fn root(&self, principal: &P) -> Option<RootState> {
        self.roots.get(principal).copied()
    }

    /// Insert an immutable object.
    ///
    /// Re-inserting an identical record is idempotent. Reusing an identifier
    /// for any different record is a fatal collision.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::ObjectCollision`] when an existing identifier has
    /// different canonical content.
    pub fn insert_object(
        &mut self,
        id: ObjectId,
        record: ObjectRecord,
    ) -> Result<InsertOutcome, ModelError> {
        match self.objects.get(&id) {
            Some(existing) if existing == &record => Ok(InsertOutcome::AlreadyPresent),
            Some(_) => Err(ModelError::ObjectCollision(id)),
            None => {
                self.objects.insert(id, record);
                Ok(InsertOutcome::Inserted)
            },
        }
    }

    /// Register an encoded physical blob as a representation of a logical
    /// object.
    ///
    /// A logical object may have several blobs. A blob may represent only one
    /// logical object.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::MissingObject`] when the logical object is absent
    /// or [`ModelError::BlobCollision`] when the blob is already assigned to
    /// different content.
    pub fn register_representation(
        &mut self,
        object: ObjectId,
        blob: BlobId,
    ) -> Result<RepresentationOutcome, ModelError> {
        if !self.objects.contains_key(&object) {
            return Err(ModelError::MissingObject(object));
        }
        match self.representations.get(&blob) {
            Some(existing) if *existing == object => Ok(RepresentationOutcome::AlreadyPresent),
            Some(_) => Err(ModelError::BlobCollision(blob)),
            None => {
                self.representations.insert(blob, object);
                Ok(RepresentationOutcome::Registered)
            },
        }
    }

    /// Calculate the complete, cycle-free closure rooted at `root`.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::MissingObject`] for an incomplete graph or
    /// [`ModelError::ObjectCycle`] for a cyclic graph.
    pub fn closure(&self, root: ObjectId) -> Result<BTreeSet<ObjectId>, ModelError> {
        closure_in(&self.objects, root)
    }

    /// Atomically install a principal's root using compare-and-swap semantics.
    ///
    /// `expected = None` creates a new principal at generation zero.
    /// Updating an existing principal requires its exact current root. The
    /// complete commit closure is validated before any visible root mutation.
    ///
    /// # Errors
    ///
    /// Returns a graph-validation error, root conflict, or generation
    /// overflow without changing the visible root.
    pub fn compare_and_swap_root(
        &mut self,
        principal: P,
        expected: Option<RootState>,
        commit: ObjectId,
    ) -> Result<RootState, ModelError> {
        self.closure(commit)?;
        let actual = self.roots.get(&principal).copied();
        if actual != expected {
            return Err(ModelError::RootConflict { expected, actual });
        }
        let generation = match actual {
            Some(root) => root
                .generation
                .checked_add(1)
                .ok_or(ModelError::ArithmeticOverflow)?,
            None => 0,
        };
        let next = RootState { generation, commit };
        self.roots.insert(principal, next);
        Ok(next)
    }

    /// Atomically remove a principal's current root.
    ///
    /// Object bytes remain until garbage collection proves they are
    /// unreachable from every other principal and pin. This distinction is
    /// what makes deletion safe for shared immutable objects.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::RootConflict`] when `expected` is stale or the
    /// principal does not exist.
    pub fn compare_and_remove_root(
        &mut self,
        principal: &P,
        expected: RootState,
    ) -> Result<RootState, ModelError> {
        let actual = self.roots.get(principal).copied();
        if actual != Some(expected) {
            return Err(ModelError::RootConflict {
                expected: Some(expected),
                actual,
            });
        }
        self.roots.remove(principal);
        Ok(expected)
    }

    /// Export a deterministic copy of a complete root closure.
    ///
    /// # Errors
    ///
    /// Returns a graph-validation error when the root is incomplete or cyclic.
    pub fn export_closure(
        &self,
        root: ObjectId,
    ) -> Result<Vec<(ObjectId, ObjectRecord)>, ModelError> {
        let ids = self.closure(root)?;
        let mut records = Vec::with_capacity(ids.len());
        for id in ids {
            let record = self.objects.get(&id).ok_or(ModelError::MissingObject(id))?;
            records.push((id, record.clone()));
        }
        Ok(records)
    }

    /// Atomically import and validate an immutable closure.
    ///
    /// No staged record becomes visible when any record collides or the
    /// declared root is incomplete. The returned value counts newly inserted
    /// objects; importing the same closure again returns zero.
    ///
    /// # Errors
    ///
    /// Returns a collision or graph-validation error without mutating the
    /// world.
    pub fn import_closure(
        &mut self,
        records: &[(ObjectId, ObjectRecord)],
        root: ObjectId,
    ) -> Result<u64, ModelError> {
        let mut staged = self.objects.clone();
        let mut inserted = 0_u64;
        for (id, record) in records {
            match staged.get(id) {
                Some(existing) if existing == record => {},
                Some(_) => return Err(ModelError::ObjectCollision(*id)),
                None => {
                    staged.insert(*id, record.clone());
                    inserted = inserted
                        .checked_add(1)
                        .ok_or(ModelError::ArithmeticOverflow)?;
                },
            }
        }
        closure_in(&staged, root)?;
        self.objects = staged;
        Ok(inserted)
    }

    /// Retain a root independently of a principal's current root.
    ///
    /// # Errors
    ///
    /// Returns a graph-validation error or [`ModelError::PinAlreadyExists`].
    pub fn pin(&mut self, pin: PinId, root: ObjectId) -> Result<(), ModelError> {
        self.closure(root)?;
        if self.pins.contains_key(&pin) {
            return Err(ModelError::PinAlreadyExists(pin));
        }
        self.pins.insert(pin, root);
        Ok(())
    }

    /// Release a retained root.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::PinMissing`] when the pin is unknown.
    pub fn unpin(&mut self, pin: PinId) -> Result<ObjectId, ModelError> {
        self.pins.remove(&pin).ok_or(ModelError::PinMissing(pin))
    }

    /// Calculate stable usage for a principal's current root.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::PrincipalMissing`], a graph-validation error, or
    /// an accounting overflow.
    pub fn principal_usage(&self, principal: &P) -> Result<PrincipalUsage, ModelError> {
        let root = self
            .roots
            .get(principal)
            .ok_or(ModelError::PrincipalMissing)?;
        let closure = self.closure(root.commit)?;
        let mut usage = PrincipalUsage::default();
        for id in closure {
            let record = self.objects.get(&id).ok_or(ModelError::MissingObject(id))?;
            let retained = u64::try_from(record.canonical_bytes.len())
                .map_err(|_| ModelError::ArithmeticOverflow)?;
            usage.object_count = usage
                .object_count
                .checked_add(1)
                .ok_or(ModelError::ArithmeticOverflow)?;
            usage.logical_bytes = usage
                .logical_bytes
                .checked_add(record.logical_bytes)
                .ok_or(ModelError::ArithmeticOverflow)?;
            usage.retained_object_bytes = usage
                .retained_object_bytes
                .checked_add(retained)
                .ok_or(ModelError::ArithmeticOverflow)?;
            if record.class == ObjectClass::Metadata {
                usage.metadata_bytes = usage
                    .metadata_bytes
                    .checked_add(retained)
                    .ok_or(ModelError::ArithmeticOverflow)?;
            }
        }
        Ok(usage)
    }

    /// Remove every object unreachable from all current roots and pins.
    ///
    /// # Errors
    ///
    /// Returns a graph-validation error or accounting overflow. No object is
    /// removed if an authoritative root is invalid.
    pub fn collect_garbage(&mut self) -> Result<GcReport, ModelError> {
        let live = self.live_objects()?;
        let mut report = GcReport::default();
        let garbage: Vec<ObjectId> = self
            .objects
            .keys()
            .filter(|id| !live.contains(id))
            .copied()
            .collect();
        for id in &garbage {
            let record = self.objects.get(id).ok_or(ModelError::MissingObject(*id))?;
            let bytes = u64::try_from(record.canonical_bytes.len())
                .map_err(|_| ModelError::ArithmeticOverflow)?;
            report.objects_removed = report
                .objects_removed
                .checked_add(1)
                .ok_or(ModelError::ArithmeticOverflow)?;
            report.bytes_removed = report
                .bytes_removed
                .checked_add(bytes)
                .ok_or(ModelError::ArithmeticOverflow)?;
        }
        for id in garbage {
            self.objects.remove(&id);
        }
        self.representations
            .retain(|_, object| self.objects.contains_key(object));
        self.placements
            .retain(|(_, blob), _| self.representations.contains_key(blob));
        Ok(report)
    }

    /// Publish a complete physical placement epoch atomically.
    ///
    /// Every logically live object must have at least `minimum_replicas`
    /// distinct nodes in the supplied plan. Old epochs remain present so
    /// production integrations can honor reader leases before retiring them.
    /// Logical principal roots are never modified.
    ///
    /// # Errors
    ///
    /// Returns an epoch conflict, graph-validation error, missing placement,
    /// insufficient replica count, or numeric conversion error.
    pub fn publish_placement_epoch(
        &mut self,
        epoch: PlacementEpoch,
        plan: &[(BlobId, Vec<StorageNodeId>)],
        minimum_replicas: u32,
    ) -> Result<(), ModelError> {
        if minimum_replicas == 0 {
            return Err(ModelError::ZeroReplicaRequirement);
        }
        if self.placement_epochs.contains(&epoch) {
            return Err(ModelError::PlacementEpochAlreadyExists(epoch));
        }

        let live = self.live_objects()?;
        let mut staged = BTreeMap::<BlobId, BTreeSet<StorageNodeId>>::new();
        for (blob, nodes) in plan {
            let entry = staged.entry(*blob).or_default();
            entry.extend(nodes.iter().copied());
        }
        for object in live {
            let registered: Vec<BlobId> = self
                .representations
                .iter()
                .filter(|(_, content)| **content == object)
                .map(|(blob, _)| *blob)
                .collect();
            if registered.is_empty() {
                return Err(ModelError::MissingRepresentation(object));
            }
            let mut best: Option<(BlobId, u32)> = None;
            for blob in registered {
                let Some(nodes) = staged.get(&blob) else {
                    continue;
                };
                let actual =
                    u32::try_from(nodes.len()).map_err(|_| ModelError::ArithmeticOverflow)?;
                if best.is_none_or(|(_, best_actual)| actual > best_actual) {
                    best = Some((blob, actual));
                }
            }
            let Some((blob, actual)) = best else {
                return Err(ModelError::MissingPlacement { epoch, object });
            };
            if actual < minimum_replicas {
                return Err(ModelError::InsufficientReplicas {
                    epoch,
                    blob,
                    required: minimum_replicas,
                    actual,
                });
            }
        }

        for (blob, nodes) in staged {
            self.placements.insert((epoch, blob), nodes);
        }
        self.placement_epochs.insert(epoch);
        self.active_placement_epoch = Some(epoch);
        Ok(())
    }

    /// Return the active physical placement epoch.
    #[must_use]
    pub const fn active_placement_epoch(&self) -> Option<PlacementEpoch> {
        self.active_placement_epoch
    }

    /// Borrow the replica set for a blob in a placement epoch.
    #[must_use]
    pub fn replicas(
        &self,
        epoch: PlacementEpoch,
        blob: BlobId,
    ) -> Option<&BTreeSet<StorageNodeId>> {
        self.placements.get(&(epoch, blob))
    }

    /// Retire a non-active placement epoch.
    ///
    /// Production code additionally waits for old-epoch reader and replication
    /// leases. This model operation represents the point after those leases
    /// have drained.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::ActivePlacementEpoch`] when `epoch` is active.
    pub fn retire_placement_epoch(&mut self, epoch: PlacementEpoch) -> Result<(), ModelError> {
        if self.active_placement_epoch == Some(epoch) {
            return Err(ModelError::ActivePlacementEpoch(epoch));
        }
        self.placements
            .retain(|(stored_epoch, _), _| *stored_epoch != epoch);
        self.placement_epochs.remove(&epoch);
        Ok(())
    }

    fn live_objects(&self) -> Result<BTreeSet<ObjectId>, ModelError> {
        let mut live = BTreeSet::new();
        for root in self.roots.values() {
            live.extend(self.closure(root.commit)?);
        }
        for root in self.pins.values() {
            live.extend(self.closure(*root)?);
        }
        Ok(live)
    }
}

fn path_is_prefix(prefix: &ReferencePath, path: &ReferencePath) -> bool {
    prefix.labels().len() <= path.labels().len()
        && prefix
            .labels()
            .iter()
            .zip(path.labels())
            .all(|(left, right)| left == right)
}

fn validate_record_order(records: &[(ObjectId, ObjectRecord)]) -> Result<(), ModelError> {
    if records.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(ModelError::NonCanonicalProofRecords);
    }
    Ok(())
}

fn verified_record_map<I: ObjectIdentity>(
    identity: &I,
    records: &[(ObjectId, ObjectRecord)],
) -> Result<BTreeMap<ObjectId, ObjectRecord>, ModelError> {
    let mut result = BTreeMap::new();
    for (declared, record) in records {
        let computed = identity.identify(record);
        if computed != *declared {
            return Err(ModelError::ProofIdentityMismatch {
                declared: *declared,
                computed,
            });
        }
        result.insert(*declared, record.clone());
    }
    Ok(result)
}

fn closure_in(
    objects: &BTreeMap<ObjectId, ObjectRecord>,
    root: ObjectId,
) -> Result<BTreeSet<ObjectId>, ModelError> {
    let mut result = BTreeSet::new();
    let mut marks = BTreeMap::<ObjectId, u8>::new();
    let mut stack = vec![(root, false)];

    while let Some((id, expanded)) = stack.pop() {
        if expanded {
            marks.insert(id, 2);
            result.insert(id);
            continue;
        }
        match marks.get(&id).copied() {
            Some(2) => continue,
            Some(1) => return Err(ModelError::ObjectCycle(id)),
            Some(_) | None => {},
        }
        let record = objects.get(&id).ok_or(ModelError::MissingObject(id))?;
        marks.insert(id, 1);
        stack.push((id, true));
        for child in record.owning_references().rev() {
            stack.push((child, false));
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn id(value: u8) -> ObjectId {
        ObjectId::new([value; 32])
    }

    fn blob(value: u8) -> BlobId {
        BlobId::new([value; 32])
    }

    fn data(value: u8) -> ObjectRecord {
        ObjectRecord::new(vec![value], vec![], 1, ObjectClass::Data).unwrap()
    }

    fn metadata(value: u8, references: Vec<ObjectId>) -> ObjectRecord {
        let references = references
            .into_iter()
            .enumerate()
            .map(|(index, target)| {
                ObjectReference::owns(vec![u8::try_from(index).unwrap()], target)
            })
            .collect();
        ObjectRecord::new(vec![value], references, 0, ObjectClass::Metadata).unwrap()
    }

    fn metadata_refs(value: u8, references: Vec<ObjectReference>) -> ObjectRecord {
        ObjectRecord::new(vec![value], references, 0, ObjectClass::Metadata).unwrap()
    }

    #[derive(Clone, Copy)]
    struct TestIdentity;

    impl ObjectIdentity for TestIdentity {
        fn identify(&self, record: &ObjectRecord) -> ObjectId {
            fn mix(mut state: u64, bytes: &[u8]) -> u64 {
                for byte in bytes {
                    state ^= u64::from(*byte);
                    state = state.wrapping_mul(0x0000_0100_0000_01b3);
                }
                state
            }

            let mut state = mix(
                0xcbf2_9ce4_8422_2325,
                &u64::try_from(record.canonical_bytes().len())
                    .unwrap()
                    .to_le_bytes(),
            );
            state = mix(state, record.canonical_bytes());
            state = mix(state, &record.logical_bytes().to_le_bytes());
            state = mix(
                state,
                &[match record.class() {
                    ObjectClass::Data => 0,
                    ObjectClass::Metadata => 1,
                }],
            );
            for reference in record.references() {
                state = mix(
                    state,
                    &u64::try_from(reference.label().len())
                        .unwrap()
                        .to_le_bytes(),
                );
                state = mix(state, reference.label());
                state = mix(state, reference.target().as_bytes());
                state = mix(
                    state,
                    &[match reference.kind() {
                        ReferenceKind::Owns => 0,
                        ReferenceKind::Evidence => 1,
                        ReferenceKind::Lineage => 2,
                        ReferenceKind::Derived => 3,
                    }],
                );
            }

            let mut bytes = [0_u8; 32];
            for (index, chunk) in bytes.chunks_exact_mut(8).enumerate() {
                state = mix(state, &[u8::try_from(index).unwrap()]);
                chunk.copy_from_slice(&state.to_le_bytes());
            }
            ObjectId::new(bytes)
        }
    }

    struct ProofTree {
        identity: TestIdentity,
        root: (ObjectId, ObjectRecord),
        home: (ObjectId, ObjectRecord),
        first: (ObjectId, ObjectRecord),
        second: (ObjectId, ObjectRecord),
    }

    fn proof_tree() -> ProofTree {
        let identity = TestIdentity;
        let first_record = data(1);
        let first = identity.identify(&first_record);
        let second_record = data(2);
        let second = identity.identify(&second_record);
        let home_record = metadata_refs(
            3,
            vec![
                ObjectReference::owns(b"a".to_vec(), first),
                ObjectReference::owns(b"b".to_vec(), second),
            ],
        );
        let home = identity.identify(&home_record);
        let root_record = metadata_refs(
            4,
            vec![
                ObjectReference::new(b"audit".to_vec(), id(99), ReferenceKind::Evidence),
                ObjectReference::owns(b"home".to_vec(), home),
            ],
        );
        let root = identity.identify(&root_record);
        ProofTree {
            identity,
            root: (root, root_record),
            home: (home, home_record),
            first: (first, first_record),
            second: (second, second_record),
        }
    }

    fn ordered_records(
        mut records: Vec<(ObjectId, ObjectRecord)>,
    ) -> Vec<(ObjectId, ObjectRecord)> {
        records.sort_by_key(|(object, _)| *object);
        records
    }

    fn insert_small_tree(world: &mut World<&'static str>) {
        world.insert_object(id(1), data(1)).unwrap();
        world.insert_object(id(2), data(2)).unwrap();
        world
            .insert_object(id(3), metadata(3, vec![id(1), id(2)]))
            .unwrap();
        world.register_representation(id(1), blob(1)).unwrap();
        world.register_representation(id(2), blob(2)).unwrap();
        world.register_representation(id(3), blob(3)).unwrap();
    }

    #[test]
    fn identifier_collision_is_never_silently_deduplicated() {
        let mut world = World::<&str>::new();
        assert_eq!(
            world.insert_object(id(1), data(1)),
            Ok(InsertOutcome::Inserted)
        );
        assert_eq!(
            world.insert_object(id(1), data(1)),
            Ok(InsertOutcome::AlreadyPresent)
        );
        assert_eq!(
            world.insert_object(id(1), data(2)),
            Err(ModelError::ObjectCollision(id(1)))
        );
    }

    #[test]
    fn physical_blob_cannot_alias_different_logical_content() {
        let mut world = World::<&str>::new();
        world.insert_object(id(1), data(1)).unwrap();
        world.insert_object(id(2), data(2)).unwrap();
        assert_eq!(
            world.register_representation(id(1), blob(9)),
            Ok(RepresentationOutcome::Registered)
        );
        assert_eq!(
            world.register_representation(id(1), blob(9)),
            Ok(RepresentationOutcome::AlreadyPresent)
        );
        assert_eq!(
            world.register_representation(id(2), blob(9)),
            Err(ModelError::BlobCollision(blob(9)))
        );
    }

    #[test]
    fn incomplete_root_is_not_visible() {
        let mut world = World::<&str>::new();
        world
            .insert_object(id(3), metadata(3, vec![id(1)]))
            .unwrap();
        assert_eq!(
            world.compare_and_swap_root("alice", None, id(3)),
            Err(ModelError::MissingObject(id(1)))
        );
        assert_eq!(world.root(&"alice"), None);
    }

    #[test]
    fn non_owning_reference_does_not_expand_principal_closure() {
        let mut world = World::<&str>::new();
        world
            .insert_object(
                id(2),
                metadata_refs(
                    2,
                    vec![ObjectReference::new(
                        vec![0],
                        id(1),
                        ReferenceKind::Evidence,
                    )],
                ),
            )
            .unwrap();

        world.compare_and_swap_root("alice", None, id(2)).unwrap();

        assert_eq!(world.closure(id(2)).unwrap(), BTreeSet::from([id(2)]));
        assert_eq!(
            world.principal_usage(&"alice").unwrap(),
            PrincipalUsage {
                object_count: 1,
                logical_bytes: 0,
                retained_object_bytes: 1,
                metadata_bytes: 1,
            }
        );
    }

    #[test]
    fn evidence_requires_its_own_pin_for_retention() {
        let mut world = World::<&str>::new();
        world.insert_object(id(1), data(1)).unwrap();
        world
            .insert_object(
                id(2),
                metadata_refs(
                    2,
                    vec![ObjectReference::new(
                        vec![0],
                        id(1),
                        ReferenceKind::Evidence,
                    )],
                ),
            )
            .unwrap();
        world.compare_and_swap_root("alice", None, id(2)).unwrap();
        world.pin(PinId::new(7), id(1)).unwrap();

        assert_eq!(world.collect_garbage().unwrap().objects_removed, 0);
        world.unpin(PinId::new(7)).unwrap();
        assert_eq!(
            world.collect_garbage().unwrap(),
            GcReport {
                objects_removed: 1,
                bytes_removed: 1,
            }
        );
        assert_eq!(world.closure(id(2)).unwrap(), BTreeSet::from([id(2)]));
    }

    #[test]
    fn one_label_cannot_have_conflicting_reference_relations() {
        let references = vec![
            ObjectReference::owns(vec![0], id(1)),
            ObjectReference::new(vec![0], id(2), ReferenceKind::Lineage),
        ];

        assert_eq!(
            ObjectRecord::new(vec![2], references, 0, ObjectClass::Metadata),
            Err(ModelError::NonCanonicalReferences)
        );
    }

    #[test]
    fn different_labels_may_share_one_owned_target() {
        let mut world = World::<&str>::new();
        world.insert_object(id(1), data(1)).unwrap();
        world
            .insert_object(
                id(2),
                metadata_refs(
                    2,
                    vec![
                        ObjectReference::owns(vec![0], id(1)),
                        ObjectReference::owns(vec![1], id(1)),
                    ],
                ),
            )
            .unwrap();
        world.compare_and_swap_root("alice", None, id(2)).unwrap();

        assert_eq!(
            world.closure(id(2)).unwrap(),
            BTreeSet::from([id(1), id(2)])
        );
        assert_eq!(world.principal_usage(&"alice").unwrap().object_count, 2);
    }

    #[test]
    fn selector_rejects_empty_duplicate_and_redundant_paths() {
        assert_eq!(
            StateSelector::new(vec![]),
            Err(ModelError::NonCanonicalSelector)
        );
        let home = ReferencePath::new(vec![b"home".to_vec()]);
        assert_eq!(
            StateSelector::new(vec![home.clone(), home.clone()]),
            Err(ModelError::NonCanonicalSelector)
        );
        let child = ReferencePath::new(vec![b"home".to_vec(), b"a".to_vec()]);
        assert_eq!(
            StateSelector::new(vec![home, child]),
            Err(ModelError::NonCanonicalSelector)
        );
    }

    #[test]
    fn view_proof_discloses_only_selected_owned_closure() {
        let tree = proof_tree();
        let selector = StateSelector::new(vec![ReferencePath::new(vec![
            b"home".to_vec(),
            b"a".to_vec(),
        ])])
        .unwrap();
        let records = ordered_records(vec![
            tree.root.clone(),
            tree.home.clone(),
            tree.first.clone(),
        ]);
        let proof = StateViewProof::new(tree.root.0, selector, records).unwrap();

        assert_eq!(
            proof.verify(&tree.identity).unwrap(),
            VerifiedStateView {
                source: tree.root.0,
                selected_roots: vec![tree.first.0],
                object_count: 3,
            }
        );
    }

    #[test]
    fn view_proof_rejects_substitution_excess_and_non_owning_path() {
        let tree = proof_tree();
        let selected_first = StateSelector::new(vec![ReferencePath::new(vec![
            b"home".to_vec(),
            b"a".to_vec(),
        ])])
        .unwrap();

        let substituted = ordered_records(vec![
            tree.root.clone(),
            tree.home.clone(),
            (tree.first.0, data(9)),
        ]);
        let proof = StateViewProof::new(tree.root.0, selected_first.clone(), substituted).unwrap();
        assert!(matches!(
            proof.verify(&tree.identity),
            Err(ModelError::ProofIdentityMismatch { .. })
        ));

        let excessive = ordered_records(vec![
            tree.root.clone(),
            tree.home.clone(),
            tree.first.clone(),
            tree.second.clone(),
        ]);
        let proof = StateViewProof::new(tree.root.0, selected_first, excessive).unwrap();
        assert_eq!(
            proof.verify(&tree.identity),
            Err(ModelError::ExtraneousProofObject(tree.second.0))
        );

        let audit_selector =
            StateSelector::new(vec![ReferencePath::new(vec![b"audit".to_vec()])]).unwrap();
        let proof =
            StateViewProof::new(tree.root.0, audit_selector, vec![tree.root.clone()]).unwrap();
        assert_eq!(
            proof.verify(&tree.identity),
            Err(ModelError::ReferenceNotOwned {
                label: b"audit".to_vec(),
            })
        );
    }

    #[test]
    fn view_proof_requires_complete_selected_closure() {
        let tree = proof_tree();
        let selector =
            StateSelector::new(vec![ReferencePath::new(vec![b"home".to_vec()])]).unwrap();
        let records = ordered_records(vec![tree.root.clone(), tree.home.clone()]);
        let proof = StateViewProof::new(tree.root.0, selector, records).unwrap();

        assert!(matches!(
            proof.verify(&tree.identity),
            Err(ModelError::MissingObject(missing))
                if missing == tree.first.0 || missing == tree.second.0
        ));
    }

    #[test]
    fn transition_witness_recomputes_labelled_root_replacement() {
        let tree = proof_tree();
        let replacement_record = data(9);
        let replacement = tree.identity.identify(&replacement_record);
        let next_home_record = tree
            .home
            .1
            .replace_owned_target(b"a", tree.first.0, replacement)
            .unwrap();
        let next_home = tree.identity.identify(&next_home_record);
        let next_root_record = tree
            .root
            .1
            .replace_owned_target(b"home", tree.home.0, next_home)
            .unwrap();
        let next_root = tree.identity.identify(&next_root_record);
        let patch = OwnedSubtreePatch::new(
            ReferencePath::new(vec![b"home".to_vec(), b"a".to_vec()]),
            tree.first.0,
            replacement,
        );
        let records = ordered_records(vec![tree.root.clone(), tree.home.clone()]);
        let witness = TransitionWitness::new(tree.root.0, next_root, patch, records).unwrap();

        assert_eq!(witness.verify(&tree.identity), Ok(next_root));
        let mut wrong_after = witness;
        wrong_after.after = id(77);
        assert!(matches!(
            wrong_after.verify(&tree.identity),
            Err(ModelError::TransitionRootMismatch { .. })
        ));
    }

    #[test]
    fn transition_witness_rejects_wrong_target_root_and_extra_records() {
        let tree = proof_tree();
        let replacement = tree.identity.identify(&data(9));
        let wrong_target = OwnedSubtreePatch::new(
            ReferencePath::new(vec![b"home".to_vec(), b"b".to_vec()]),
            tree.first.0,
            replacement,
        );
        let records = ordered_records(vec![tree.root.clone(), tree.home.clone()]);
        let witness =
            TransitionWitness::new(tree.root.0, tree.root.0, wrong_target, records).unwrap();
        assert_eq!(
            witness.verify(&tree.identity),
            Err(ModelError::PatchTargetMismatch {
                expected: tree.first.0,
                actual: tree.second.0,
            })
        );

        let root_patch =
            OwnedSubtreePatch::new(ReferencePath::new(vec![]), tree.root.0, replacement);
        let witness = TransitionWitness::new(
            tree.root.0,
            replacement,
            root_patch,
            vec![tree.root.clone()],
        )
        .unwrap();
        assert_eq!(
            witness.verify(&tree.identity),
            Err(ModelError::ExtraneousProofObject(tree.root.0))
        );
    }

    #[test]
    fn cyclic_root_is_not_visible() {
        let mut world = World::<&str>::new();
        world
            .insert_object(id(1), metadata(1, vec![id(2)]))
            .unwrap();
        world
            .insert_object(id(2), metadata(2, vec![id(1)]))
            .unwrap();

        assert_eq!(
            world.compare_and_swap_root("alice", None, id(1)),
            Err(ModelError::ObjectCycle(id(1)))
        );
        assert_eq!(world.root(&"alice"), None);
    }

    #[test]
    fn compare_and_swap_prevents_lost_update() {
        let mut world = World::<&str>::new();
        insert_small_tree(&mut world);
        let first = world.compare_and_swap_root("alice", None, id(3)).unwrap();
        world.insert_object(id(4), data(4)).unwrap();

        let stale = RootState {
            generation: 99,
            commit: id(3),
        };
        assert!(matches!(
            world.compare_and_swap_root("alice", Some(stale), id(4)),
            Err(ModelError::RootConflict { .. })
        ));
        assert_eq!(world.root(&"alice"), Some(first));
    }

    #[test]
    fn export_import_is_complete_and_idempotent() {
        let mut source = World::<&str>::new();
        insert_small_tree(&mut source);
        let records = source.export_closure(id(3)).unwrap();

        let mut destination = World::<&str>::new();
        assert_eq!(destination.import_closure(&records, id(3)).unwrap(), 3);
        assert_eq!(destination.import_closure(&records, id(3)).unwrap(), 0);
        assert_eq!(destination.export_closure(id(3)).unwrap(), records);
    }

    #[test]
    fn failed_import_is_invisible() {
        let mut source = World::<&str>::new();
        insert_small_tree(&mut source);
        let mut records = source.export_closure(id(3)).unwrap();
        records.retain(|(object, _)| *object != id(1));

        let mut destination = World::<&str>::new();
        assert_eq!(
            destination.import_closure(&records, id(3)),
            Err(ModelError::MissingObject(id(1)))
        );
        assert_eq!(destination.object_count(), 0);
    }

    #[test]
    fn every_incomplete_small_import_is_invisible() {
        let mut source = World::<&str>::new();
        insert_small_tree(&mut source);
        let records = source.export_closure(id(3)).unwrap();

        for keep_first in [false, true] {
            for keep_second in [false, true] {
                for keep_third in [false, true] {
                    let choices = [keep_first, keep_second, keep_third];
                    let subset: Vec<_> = records
                        .iter()
                        .zip(choices)
                        .filter(|(_, keep)| *keep)
                        .map(|(record, _)| record.clone())
                        .collect();
                    let mut destination = World::<&str>::new();
                    let result = destination.import_closure(&subset, id(3));
                    if keep_first && keep_second && keep_third {
                        assert_eq!(result, Ok(3));
                        assert_eq!(destination.object_count(), 3);
                    } else {
                        assert!(matches!(result, Err(ModelError::MissingObject(_))));
                        assert_eq!(destination.object_count(), 0);
                    }
                }
            }
        }
    }

    #[test]
    fn collision_rolls_back_other_staged_import_objects() {
        let mut destination = World::<&str>::new();
        destination.insert_object(id(1), data(9)).unwrap();
        let records = vec![(id(2), data(2)), (id(1), data(1))];

        assert_eq!(
            destination.import_closure(&records, id(2)),
            Err(ModelError::ObjectCollision(id(1)))
        );
        assert_eq!(destination.object_count(), 1);
        assert_eq!(
            destination.insert_object(id(2), data(2)),
            Ok(InsertOutcome::Inserted)
        );
    }

    #[test]
    fn garbage_collection_respects_roots_and_pins() {
        let mut world = World::<&str>::new();
        insert_small_tree(&mut world);
        world.insert_object(id(9), data(9)).unwrap();
        world.compare_and_swap_root("alice", None, id(3)).unwrap();
        world.pin(PinId::new(7), id(9)).unwrap();

        assert_eq!(world.collect_garbage().unwrap().objects_removed, 0);
        world.unpin(PinId::new(7)).unwrap();
        assert_eq!(
            world.collect_garbage().unwrap(),
            GcReport {
                objects_removed: 1,
                bytes_removed: 1,
            }
        );
    }

    #[test]
    fn another_principal_does_not_change_enforced_usage() {
        let mut world = World::<&str>::new();
        insert_small_tree(&mut world);
        world.compare_and_swap_root("alice", None, id(3)).unwrap();
        let before = world.principal_usage(&"alice").unwrap();

        world.compare_and_swap_root("bob", None, id(3)).unwrap();
        assert_eq!(world.principal_usage(&"alice").unwrap(), before);
        assert_eq!(
            before,
            PrincipalUsage {
                object_count: 3,
                logical_bytes: 2,
                retained_object_bytes: 3,
                metadata_bytes: 1,
            }
        );
    }

    #[test]
    fn deleting_one_principal_preserves_shared_objects() {
        let mut world = World::<&str>::new();
        world.insert_object(id(1), data(1)).unwrap();
        world.insert_object(id(2), data(2)).unwrap();
        world
            .insert_object(id(3), metadata(3, vec![id(1), id(2)]))
            .unwrap();
        world
            .insert_object(id(4), metadata(4, vec![id(1)]))
            .unwrap();

        let alice = world.compare_and_swap_root("alice", None, id(3)).unwrap();
        world.compare_and_swap_root("bob", None, id(4)).unwrap();
        world.compare_and_remove_root(&"alice", alice).unwrap();

        assert_eq!(
            world.collect_garbage().unwrap(),
            GcReport {
                objects_removed: 2,
                bytes_removed: 2,
            }
        );
        assert_eq!(world.principal_usage(&"bob").unwrap().logical_bytes, 1);
        assert_eq!(world.object_count(), 2);
    }

    #[test]
    fn placement_epoch_changes_no_logical_root() {
        let mut world = World::<&str>::new();
        insert_small_tree(&mut world);
        let root = world.compare_and_swap_root("alice", None, id(3)).unwrap();

        let first = PlacementEpoch::new(1);
        let plan = vec![
            (blob(1), vec![StorageNodeId::new(1), StorageNodeId::new(2)]),
            (blob(2), vec![StorageNodeId::new(1), StorageNodeId::new(2)]),
            (blob(3), vec![StorageNodeId::new(1), StorageNodeId::new(2)]),
        ];
        world.publish_placement_epoch(first, &plan, 2).unwrap();

        world.register_representation(id(1), blob(11)).unwrap();
        world.register_representation(id(2), blob(12)).unwrap();
        world.register_representation(id(3), blob(13)).unwrap();
        let second = PlacementEpoch::new(2);
        let moved = vec![
            (blob(11), vec![StorageNodeId::new(2), StorageNodeId::new(3)]),
            (blob(12), vec![StorageNodeId::new(2), StorageNodeId::new(3)]),
            (blob(13), vec![StorageNodeId::new(2), StorageNodeId::new(3)]),
        ];
        world.publish_placement_epoch(second, &moved, 2).unwrap();

        assert_eq!(world.root(&"alice"), Some(root));
        assert!(world.replicas(first, blob(1)).is_some());
        assert!(world.replicas(second, blob(11)).is_some());
        assert_eq!(
            world.retire_placement_epoch(second),
            Err(ModelError::ActivePlacementEpoch(second))
        );
        world.retire_placement_epoch(first).unwrap();
        assert!(world.replicas(first, blob(1)).is_none());
    }

    #[test]
    fn under_replicated_epoch_is_not_published() {
        let mut world = World::<&str>::new();
        insert_small_tree(&mut world);
        world.compare_and_swap_root("alice", None, id(3)).unwrap();
        let epoch = PlacementEpoch::new(1);
        let plan = vec![
            (blob(1), vec![StorageNodeId::new(1)]),
            (blob(2), vec![StorageNodeId::new(1)]),
            (blob(3), vec![StorageNodeId::new(1)]),
        ];

        assert!(matches!(
            world.publish_placement_epoch(epoch, &plan, 2),
            Err(ModelError::InsufficientReplicas { .. })
        ));
        assert_eq!(world.active_placement_epoch(), None);
        assert!(world.replicas(epoch, blob(1)).is_none());
    }
}
