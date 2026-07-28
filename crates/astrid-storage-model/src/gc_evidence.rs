//! Canonical linked evidence for planned and executed garbage collection.

use alloc::{vec, vec::Vec};
use core::fmt;

use super::{
    ExecutionMeasurementsId, ModelError, ObjectClass, ObjectFormatVersion, ObjectId,
    ObjectIdentity, ObjectKind, ObjectRecord, ObjectReference, ReferenceKind, ReferenceLabel,
};

const SNAPSHOT_LABEL: &[u8] = b"00-fact-snapshot";
const RETENTION_POLICY_LABEL: &[u8] = b"01-retention-policy";
const TENSOR_LOGIC_PROOF_LABEL: &[u8] = b"02-tensor-logic-proof";
const CONDEMNED_PREFIX: &[u8] = b"10-condemned/";

const COMMIT_PLAN_LABEL: &[u8] = b"00-plan";
const COMMIT_SNAPSHOT_LABEL: &[u8] = b"01-fact-snapshot";
const PLACEMENT_BEFORE_LABEL: &[u8] = b"02-placement-before";
const PLACEMENT_AFTER_LABEL: &[u8] = b"03-placement-after";
const COMMIT_MEASUREMENTS_LABEL: &[u8] = b"04-execution-measurements";

macro_rules! gc_id_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(ObjectId);

        impl $name {
            /// Construct the domain identifier from a logical object identity.
            #[must_use]
            pub const fn new(object: ObjectId) -> Self {
                Self(object)
            }

            /// Return the underlying logical object identity.
            #[must_use]
            pub const fn object_id(self) -> ObjectId {
                self.0
            }
        }
    };
}

gc_id_newtype!(
    /// Identity of the complete frozen relation/fence snapshot for one GC plan.
    GcFactSnapshotId
);
gc_id_newtype!(
    /// Identity of the history, pin, handle, erasure, and quarantine policy.
    RetentionPolicyId
);
gc_id_newtype!(
    /// Identity of the byte-stable Tensor Logic audit proof for one plan.
    TensorLogicProofId
);
gc_id_newtype!(
    /// Identity of one canonical garbage-collection plan.
    GcPlanId
);
gc_id_newtype!(
    /// Identity of a complete physical placement-set description.
    PlacementSetId
);
gc_id_newtype!(
    /// Identity of one canonical garbage-collection commit receipt.
    GcCommitId
);

/// Immutable deletion plan audited against one exact fact snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GcPlanEvidence {
    snapshot: GcFactSnapshotId,
    retention_policy: RetentionPolicyId,
    tensor_logic_proof: TensorLogicProofId,
    condemned: Vec<ObjectId>,
}

impl GcPlanEvidence {
    /// Construct a canonical plan.
    ///
    /// `condemned` is a set encoded in strictly increasing `ObjectId` order.
    /// Tensor Logic proves the relation over `snapshot`; native GC fences still
    /// enforce liveness and publication.
    ///
    /// # Errors
    ///
    /// Returns a canonical-set error for an empty, duplicated, or unordered
    /// condemned set.
    pub fn new(
        snapshot: GcFactSnapshotId,
        retention_policy: RetentionPolicyId,
        tensor_logic_proof: TensorLogicProofId,
        condemned: Vec<ObjectId>,
    ) -> Result<Self, GcEvidenceError> {
        if condemned.is_empty() {
            return Err(GcEvidenceError::EmptyCondemnedSet);
        }
        if condemned.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(GcEvidenceError::NonCanonicalCondemnedSet);
        }
        Ok(Self {
            snapshot,
            retention_policy,
            tensor_logic_proof,
            condemned,
        })
    }

    /// Return the exact frozen fact snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> GcFactSnapshotId {
        self.snapshot
    }

    /// Return the retention policy interpreted by this plan.
    #[must_use]
    pub const fn retention_policy(&self) -> RetentionPolicyId {
        self.retention_policy
    }

    /// Return the Tensor Logic auditor proof.
    #[must_use]
    pub const fn tensor_logic_proof(&self) -> TensorLogicProofId {
        self.tensor_logic_proof
    }

    /// Borrow the canonical condemned `ObjectId` set.
    #[must_use]
    pub fn condemned(&self) -> &[ObjectId] {
        &self.condemned
    }

    /// Encode the plan as one canonical format-v1 object.
    ///
    /// # Errors
    ///
    /// Returns an object-record or length error if the canonical plan cannot
    /// be represented.
    pub fn to_object_record(&self) -> Result<ObjectRecord, GcEvidenceError> {
        let mut references = vec![
            ObjectReference::owns(
                ReferenceLabel::new(SNAPSHOT_LABEL.to_vec()),
                self.snapshot.object_id(),
            ),
            ObjectReference::owns(
                ReferenceLabel::new(RETENTION_POLICY_LABEL.to_vec()),
                self.retention_policy.object_id(),
            ),
            ObjectReference::owns(
                ReferenceLabel::new(TENSOR_LOGIC_PROOF_LABEL.to_vec()),
                self.tensor_logic_proof.object_id(),
            ),
        ];
        for (index, object) in self.condemned.iter().copied().enumerate() {
            references.push(evidence_indexed_reference(CONDEMNED_PREFIX, index, object)?);
        }
        ObjectRecord::new(
            ObjectKind::GcPlanEvidence,
            ObjectFormatVersion::V1,
            Vec::new(),
            references,
            0,
            ObjectClass::Metadata,
        )
        .map_err(GcEvidenceError::InvalidObjectRecord)
    }

    /// Compute the canonical plan identity.
    ///
    /// # Errors
    ///
    /// Returns an encoding error if the plan record cannot be built.
    pub fn identify<I: ObjectIdentity>(&self, identity: &I) -> Result<GcPlanId, GcEvidenceError> {
        self.to_object_record()
            .map(|record| GcPlanId::new(identity.identify(&record)))
    }

    /// Decode and fully canonicalize one plan object.
    ///
    /// # Errors
    ///
    /// Rejects malformed kinds, references, ordinals, sets, and encodings.
    pub fn from_object_record(record: &ObjectRecord) -> Result<Self, GcEvidenceError> {
        validate_header(record, ObjectKind::GcPlanEvidence, 0)?;
        let mut snapshot = None;
        let mut retention_policy = None;
        let mut tensor_logic_proof = None;
        let mut condemned = Vec::new();
        for reference in record.references() {
            let label = reference.label().as_bytes();
            match label {
                SNAPSHOT_LABEL => {
                    require_kind(reference, ReferenceKind::Owns)?;
                    set_once(&mut snapshot, GcFactSnapshotId::new(reference.target()))?;
                },
                RETENTION_POLICY_LABEL => {
                    require_kind(reference, ReferenceKind::Owns)?;
                    set_once(
                        &mut retention_policy,
                        RetentionPolicyId::new(reference.target()),
                    )?;
                },
                TENSOR_LOGIC_PROOF_LABEL => {
                    require_kind(reference, ReferenceKind::Owns)?;
                    set_once(
                        &mut tensor_logic_proof,
                        TensorLogicProofId::new(reference.target()),
                    )?;
                },
                _ if label.starts_with(CONDEMNED_PREFIX) => {
                    require_kind(reference, ReferenceKind::Evidence)?;
                    validate_indexed_label(CONDEMNED_PREFIX, label, condemned.len())?;
                    condemned.push(reference.target());
                },
                _ => return Err(GcEvidenceError::UnknownCanonicalField),
            }
        }
        let plan = Self::new(
            required(snapshot, "snapshot")?,
            required(retention_policy, "retention_policy")?,
            required(tensor_logic_proof, "tensor_logic_proof")?,
            condemned,
        )?;
        if plan.to_object_record()? != *record {
            return Err(GcEvidenceError::NonCanonicalObjectRecord);
        }
        Ok(plan)
    }
}

/// Receipt for the exact physical transition that executed one GC plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GcCommitEvidence {
    plan: GcPlanId,
    snapshot: GcFactSnapshotId,
    placement_before: PlacementSetId,
    placement_after: PlacementSetId,
    execution_measurements: ExecutionMeasurementsId,
}

impl GcCommitEvidence {
    /// Construct a receipt while the native liveness fence is held.
    ///
    /// `fence_snapshot` must be computed again at commit time. A plan proved
    /// against any other snapshot cannot be attached to the executed deletion.
    ///
    /// # Errors
    ///
    /// Returns [`GcEvidenceError::FenceSnapshotChanged`] when the commit-time
    /// digest differs from the plan, or
    /// [`GcEvidenceError::UnchangedPlacement`] when no transition occurred.
    pub fn new<I: ObjectIdentity>(
        identity: &I,
        plan_model: &GcPlanEvidence,
        fence_snapshot: GcFactSnapshotId,
        placement_before: PlacementSetId,
        placement_after: PlacementSetId,
        execution_measurements: ExecutionMeasurementsId,
    ) -> Result<Self, GcEvidenceError> {
        if plan_model.snapshot != fence_snapshot {
            return Err(GcEvidenceError::FenceSnapshotChanged {
                planned: plan_model.snapshot,
                actual: fence_snapshot,
            });
        }
        if placement_before == placement_after {
            return Err(GcEvidenceError::UnchangedPlacement);
        }
        Ok(Self {
            plan: plan_model.identify(identity)?,
            snapshot: fence_snapshot,
            placement_before,
            placement_after,
            execution_measurements,
        })
    }

    /// Return the exact plan this receipt executes.
    #[must_use]
    pub const fn plan(&self) -> GcPlanId {
        self.plan
    }

    /// Return the fence-held fact snapshot rechecked at commit.
    #[must_use]
    pub const fn snapshot(&self) -> GcFactSnapshotId {
        self.snapshot
    }

    /// Return the complete placement set before collection.
    #[must_use]
    pub const fn placement_before(&self) -> PlacementSetId {
        self.placement_before
    }

    /// Return the complete durable placement set after collection.
    #[must_use]
    pub const fn placement_after(&self) -> PlacementSetId {
        self.placement_after
    }

    /// Return canonical execution measurements.
    #[must_use]
    pub const fn execution_measurements(&self) -> ExecutionMeasurementsId {
        self.execution_measurements
    }

    /// Recompute the plan identity and verify the receipt remains linked to it.
    ///
    /// # Errors
    ///
    /// Returns a plan-identity or snapshot mismatch.
    pub fn validate_plan<I: ObjectIdentity>(
        &self,
        plan: &GcPlanEvidence,
        identity: &I,
    ) -> Result<(), GcEvidenceError> {
        let actual_plan = plan.identify(identity)?;
        if actual_plan != self.plan {
            return Err(GcEvidenceError::PlanIdentityMismatch);
        }
        if plan.snapshot != self.snapshot {
            return Err(GcEvidenceError::FenceSnapshotChanged {
                planned: plan.snapshot,
                actual: self.snapshot,
            });
        }
        Ok(())
    }

    /// Encode the commit receipt as one canonical format-v1 object.
    ///
    /// # Errors
    ///
    /// Returns an object-record error if the receipt cannot be represented.
    pub fn to_object_record(&self) -> Result<ObjectRecord, GcEvidenceError> {
        ObjectRecord::new(
            ObjectKind::GcCommitEvidence,
            ObjectFormatVersion::V1,
            Vec::new(),
            vec![
                ObjectReference::owns(
                    ReferenceLabel::new(COMMIT_PLAN_LABEL.to_vec()),
                    self.plan.object_id(),
                ),
                evidence_reference(COMMIT_SNAPSHOT_LABEL, self.snapshot.object_id()),
                evidence_reference(PLACEMENT_BEFORE_LABEL, self.placement_before.object_id()),
                evidence_reference(PLACEMENT_AFTER_LABEL, self.placement_after.object_id()),
                evidence_reference(
                    COMMIT_MEASUREMENTS_LABEL,
                    self.execution_measurements.object_id(),
                ),
            ],
            0,
            ObjectClass::Metadata,
        )
        .map_err(GcEvidenceError::InvalidObjectRecord)
    }

    /// Compute the canonical commit-receipt identity.
    ///
    /// # Errors
    ///
    /// Returns an encoding error if the receipt record cannot be built.
    pub fn identify<I: ObjectIdentity>(&self, identity: &I) -> Result<GcCommitId, GcEvidenceError> {
        self.to_object_record()
            .map(|record| GcCommitId::new(identity.identify(&record)))
    }

    /// Decode and fully canonicalize one GC commit receipt.
    ///
    /// The decoded receipt must still be paired with its plan through
    /// [`Self::validate_plan`] before it is trusted.
    ///
    /// # Errors
    ///
    /// Rejects malformed kinds, references, fields, and encodings.
    pub fn from_object_record(record: &ObjectRecord) -> Result<Self, GcEvidenceError> {
        validate_header(record, ObjectKind::GcCommitEvidence, 0)?;
        let mut plan = None;
        let mut snapshot = None;
        let mut placement_before = None;
        let mut placement_after = None;
        let mut execution_measurements = None;
        for reference in record.references() {
            let target = reference.target();
            match reference.label().as_bytes() {
                COMMIT_PLAN_LABEL => {
                    require_kind(reference, ReferenceKind::Owns)?;
                    set_once(&mut plan, GcPlanId::new(target))?;
                },
                COMMIT_SNAPSHOT_LABEL => {
                    require_kind(reference, ReferenceKind::Evidence)?;
                    set_once(&mut snapshot, GcFactSnapshotId::new(target))?;
                },
                PLACEMENT_BEFORE_LABEL => {
                    require_kind(reference, ReferenceKind::Evidence)?;
                    set_once(&mut placement_before, PlacementSetId::new(target))?;
                },
                PLACEMENT_AFTER_LABEL => {
                    require_kind(reference, ReferenceKind::Evidence)?;
                    set_once(&mut placement_after, PlacementSetId::new(target))?;
                },
                COMMIT_MEASUREMENTS_LABEL => {
                    require_kind(reference, ReferenceKind::Evidence)?;
                    set_once(
                        &mut execution_measurements,
                        ExecutionMeasurementsId::new(target),
                    )?;
                },
                _ => return Err(GcEvidenceError::UnknownCanonicalField),
            }
        }
        let receipt = Self {
            plan: required(plan, "plan")?,
            snapshot: required(snapshot, "snapshot")?,
            placement_before: required(placement_before, "placement_before")?,
            placement_after: required(placement_after, "placement_after")?,
            execution_measurements: required(execution_measurements, "execution_measurements")?,
        };
        if receipt.placement_before == receipt.placement_after {
            return Err(GcEvidenceError::UnchangedPlacement);
        }
        if receipt.to_object_record()? != *record {
            return Err(GcEvidenceError::NonCanonicalObjectRecord);
        }
        Ok(receipt)
    }
}

/// Canonical GC-evidence validation error.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GcEvidenceError {
    /// A plan attempted to collect no objects.
    EmptyCondemnedSet,
    /// Condemned `ObjectId` values were unordered or duplicated.
    NonCanonicalCondemnedSet,
    /// The object kind did not match the selected schema.
    WrongObjectKind,
    /// The object used a non-v1 format version.
    UnsupportedFormatVersion,
    /// The object payload or accounting class was malformed.
    InvalidCanonicalPayload,
    /// A required canonical field was absent.
    MissingCanonicalField(&'static str),
    /// A canonical field occurred more than once.
    DuplicateCanonicalField,
    /// A reference label did not belong to the schema.
    UnknownCanonicalField,
    /// A reference carried the wrong retention relation.
    InvalidReferenceKind,
    /// A condemned-set ordinal was malformed or non-contiguous.
    InvalidIndexedLabel,
    /// The decoded value did not reproduce the exact object record.
    NonCanonicalObjectRecord,
    /// Commit-time liveness facts changed after plan proof.
    FenceSnapshotChanged {
        /// Fact snapshot named by the plan.
        planned: GcFactSnapshotId,
        /// Fact snapshot recomputed under the commit fence.
        actual: GcFactSnapshotId,
    },
    /// The receipt named a different plan.
    PlanIdentityMismatch,
    /// A receipt claimed collection without a changed placement set.
    UnchangedPlacement,
    /// Constructing a canonical object record failed.
    InvalidObjectRecord(ModelError),
}

impl fmt::Display for GcEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCondemnedSet => formatter.write_str("GC plan condemned set is empty"),
            Self::NonCanonicalCondemnedSet => {
                formatter.write_str("GC condemned set is not strictly ordered")
            },
            Self::WrongObjectKind => formatter.write_str("wrong GC evidence object kind"),
            Self::UnsupportedFormatVersion => {
                formatter.write_str("unsupported GC evidence format version")
            },
            Self::InvalidCanonicalPayload => {
                formatter.write_str("invalid GC evidence canonical payload")
            },
            Self::MissingCanonicalField(field) => {
                write!(formatter, "missing GC evidence field {field}")
            },
            Self::DuplicateCanonicalField => formatter.write_str("duplicate GC evidence field"),
            Self::UnknownCanonicalField => formatter.write_str("unknown GC evidence field"),
            Self::InvalidReferenceKind => formatter.write_str("invalid GC evidence reference kind"),
            Self::InvalidIndexedLabel => formatter.write_str("invalid GC condemned-set ordinal"),
            Self::NonCanonicalObjectRecord => {
                formatter.write_str("GC evidence object is not canonical")
            },
            Self::FenceSnapshotChanged { planned, actual } => write!(
                formatter,
                "GC fence snapshot changed: planned {planned:?}, actual {actual:?}"
            ),
            Self::PlanIdentityMismatch => formatter.write_str("GC receipt plan identity mismatch"),
            Self::UnchangedPlacement => formatter.write_str("GC receipt placement did not change"),
            Self::InvalidObjectRecord(error) => {
                write!(formatter, "invalid GC evidence object record: {error}")
            },
        }
    }
}

fn evidence_reference(label: &[u8], target: ObjectId) -> ObjectReference {
    ObjectReference::new(
        ReferenceLabel::new(label.to_vec()),
        target,
        ReferenceKind::Evidence,
    )
}

fn evidence_indexed_reference(
    prefix: &[u8],
    index: usize,
    target: ObjectId,
) -> Result<ObjectReference, GcEvidenceError> {
    let index = u64::try_from(index).map_err(|_| GcEvidenceError::InvalidIndexedLabel)?;
    let mut label = prefix.to_vec();
    label.extend_from_slice(&index.to_be_bytes());
    label.push(0);
    Ok(ObjectReference::new(
        ReferenceLabel::new(label),
        target,
        ReferenceKind::Evidence,
    ))
}

fn validate_indexed_label(
    prefix: &[u8],
    label: &[u8],
    expected_index: usize,
) -> Result<(), GcEvidenceError> {
    let index_end = prefix
        .len()
        .checked_add(8)
        .ok_or(GcEvidenceError::InvalidIndexedLabel)?;
    let expected_len = index_end
        .checked_add(1)
        .ok_or(GcEvidenceError::InvalidIndexedLabel)?;
    if label.len() != expected_len || !label.starts_with(prefix) || label.get(index_end) != Some(&0)
    {
        return Err(GcEvidenceError::InvalidIndexedLabel);
    }
    let ordinal: [u8; 8] = label[prefix.len()..index_end]
        .try_into()
        .map_err(|_| GcEvidenceError::InvalidIndexedLabel)?;
    let expected =
        u64::try_from(expected_index).map_err(|_| GcEvidenceError::InvalidIndexedLabel)?;
    if u64::from_be_bytes(ordinal) != expected {
        return Err(GcEvidenceError::InvalidIndexedLabel);
    }
    Ok(())
}

fn validate_header(
    record: &ObjectRecord,
    expected_kind: ObjectKind,
    payload_len: usize,
) -> Result<(), GcEvidenceError> {
    if record.kind() != expected_kind {
        return Err(GcEvidenceError::WrongObjectKind);
    }
    if record.format_version() != ObjectFormatVersion::V1 {
        return Err(GcEvidenceError::UnsupportedFormatVersion);
    }
    if record.canonical_bytes().len() != payload_len
        || record.logical_bytes() != 0
        || record.class() != ObjectClass::Metadata
    {
        return Err(GcEvidenceError::InvalidCanonicalPayload);
    }
    Ok(())
}

fn require_kind(
    reference: &ObjectReference,
    expected: ReferenceKind,
) -> Result<(), GcEvidenceError> {
    if reference.kind() != expected {
        return Err(GcEvidenceError::InvalidReferenceKind);
    }
    Ok(())
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), GcEvidenceError> {
    if slot.replace(value).is_some() {
        return Err(GcEvidenceError::DuplicateCanonicalField);
    }
    Ok(())
}

fn required<T>(slot: Option<T>, name: &'static str) -> Result<T, GcEvidenceError> {
    slot.ok_or(GcEvidenceError::MissingCanonicalField(name))
}
