//! Canonical physical-transition evidence for durable compaction.

use std::collections::BTreeMap;

use astrid_storage_model::{
    ExecutionMeasurementsId, GcCommitEvidence, GcCommitId, GcFactSnapshotId, GcPlanEvidence,
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, PlacementSetId,
    RootState,
};

use super::{
    ArenaLocation, DurableError, PersistentObjectIdentity, PrincipalCodec, VerifiedCompactionPlan,
    encoded_roots,
};

const PLACEMENT_PREFIX: &[u8] = b"astrid-gc-placement-set-v1\0";
const MEASUREMENTS_PREFIX: &[u8] = b"astrid-gc-transition-measurements-v1\0";
pub(super) const BUNDLE_RECORDS: usize = 8;

/// Self-contained records explaining one physically committed compaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactionEvidenceBundle {
    fact_snapshot: ObjectRecord,
    retention_policy: ObjectRecord,
    tensor_logic_proof: ObjectRecord,
    plan: ObjectRecord,
    placement_before: ObjectRecord,
    placement_after: ObjectRecord,
    execution_measurements: ObjectRecord,
    commit: ObjectRecord,
    commit_id: GcCommitId,
}

impl CompactionEvidenceBundle {
    /// Return the identity of the GC commit receipt.
    #[must_use]
    pub const fn commit_id(&self) -> GcCommitId {
        self.commit_id
    }

    /// Borrow the frozen relation snapshot.
    #[must_use]
    pub const fn fact_snapshot(&self) -> &ObjectRecord {
        &self.fact_snapshot
    }

    /// Borrow the exact retention policy.
    #[must_use]
    pub const fn retention_policy(&self) -> &ObjectRecord {
        &self.retention_policy
    }

    /// Borrow the deterministic Tensor Logic proof.
    #[must_use]
    pub const fn tensor_logic_proof(&self) -> &ObjectRecord {
        &self.tensor_logic_proof
    }

    /// Borrow the canonical GC plan.
    #[must_use]
    pub const fn plan(&self) -> &ObjectRecord {
        &self.plan
    }

    /// Borrow the complete pre-transition placement description.
    #[must_use]
    pub const fn placement_before(&self) -> &ObjectRecord {
        &self.placement_before
    }

    /// Borrow the complete committed placement description.
    #[must_use]
    pub const fn placement_after(&self) -> &ObjectRecord {
        &self.placement_after
    }

    /// Borrow the canonical physical transition measurements.
    #[must_use]
    pub const fn execution_measurements(&self) -> &ObjectRecord {
        &self.execution_measurements
    }

    /// Borrow the receipt binding the plan to the physical transition.
    #[must_use]
    pub const fn commit(&self) -> &ObjectRecord {
        &self.commit
    }

    pub(super) fn records(&self) -> [&ObjectRecord; BUNDLE_RECORDS] {
        [
            &self.fact_snapshot,
            &self.retention_policy,
            &self.tensor_logic_proof,
            &self.plan,
            &self.placement_before,
            &self.placement_after,
            &self.execution_measurements,
            &self.commit,
        ]
    }

    pub(super) fn placement_after_id<I: PersistentObjectIdentity>(
        &self,
        identity: &I,
    ) -> PlacementSetId {
        PlacementSetId::new(identity.identify(&self.placement_after))
    }
}

#[derive(Clone, Copy)]
pub(super) struct PlacementView<'a, P: Ord> {
    pub(super) operation_contract: ObjectId,
    pub(super) arena_bytes: u64,
    pub(super) root_journal_bytes: u64,
    pub(super) root_journal_digest: [u8; 32],
    pub(super) index: &'a BTreeMap<ObjectId, ArenaLocation>,
    pub(super) roots: &'a BTreeMap<P, RootState>,
}

#[derive(Clone, Copy)]
pub(super) struct TransitionMeasurements {
    pub(super) objects_before: u64,
    pub(super) objects_after: u64,
    pub(super) objects_reclaimed: u64,
    pub(super) arena_bytes_before: u64,
    pub(super) arena_bytes_after: u64,
    pub(super) root_bytes_before: u64,
    pub(super) root_bytes_after: u64,
}

pub(super) fn build_bundle<P, I, C>(
    authorization: &VerifiedCompactionPlan,
    before: &PlacementView<'_, P>,
    after: &PlacementView<'_, P>,
    measurements: TransitionMeasurements,
    codec: &C,
    identity: &I,
) -> Result<CompactionEvidenceBundle, DurableError>
where
    P: Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    let placement_before = placement_record(before, codec)?;
    let placement_after = placement_record(after, codec)?;
    let execution_measurements = measurements_record(measurements)?;
    let plan = authorization
        .plan
        .to_object_record()
        .map_err(|_| DurableError::InvalidCompactionEvidence("GC plan encoding failed"))?;
    let receipt = GcCommitEvidence::new(
        identity,
        &authorization.plan,
        authorization.facts.snapshot,
        PlacementSetId::new(identity.identify(&placement_before)),
        PlacementSetId::new(identity.identify(&placement_after)),
        ExecutionMeasurementsId::new(identity.identify(&execution_measurements)),
    )
    .map_err(|_| DurableError::InvalidCompactionEvidence("GC receipt construction failed"))?;
    let commit = receipt
        .to_object_record()
        .map_err(|_| DurableError::InvalidCompactionEvidence("GC receipt encoding failed"))?;
    let commit_id = receipt
        .identify(identity)
        .map_err(|_| DurableError::InvalidCompactionEvidence("GC receipt identity failed"))?;
    Ok(CompactionEvidenceBundle {
        fact_snapshot: authorization.facts.snapshot_record.clone(),
        retention_policy: authorization.policy_record.clone(),
        tensor_logic_proof: authorization.proof_record.clone(),
        plan,
        placement_before,
        placement_after,
        execution_measurements,
        commit,
        commit_id,
    })
}

pub(super) fn validate_bundle<I: PersistentObjectIdentity>(
    records: Vec<ObjectRecord>,
    identity: &I,
) -> Result<CompactionEvidenceBundle, DurableError> {
    let records: [ObjectRecord; BUNDLE_RECORDS] = records.try_into().map_err(|_| {
        DurableError::InvalidCompactionEvidence("GC outbox bundle record count mismatch")
    })?;
    let [
        fact_snapshot,
        retention_policy,
        tensor_logic_proof,
        plan,
        placement_before,
        placement_after,
        execution_measurements,
        commit,
    ] = records;
    for record in [
        &fact_snapshot,
        &retention_policy,
        &tensor_logic_proof,
        &placement_before,
        &placement_after,
        &execution_measurements,
    ] {
        require_generic_evidence(record)?;
    }
    let plan_model = GcPlanEvidence::from_object_record(&plan)
        .map_err(|_| DurableError::InvalidCompactionEvidence("GC outbox plan is invalid"))?;
    if plan_model.snapshot() != GcFactSnapshotId::new(identity.identify(&fact_snapshot))
        || plan_model.retention_policy().object_id() != identity.identify(&retention_policy)
        || plan_model.tensor_logic_proof().object_id() != identity.identify(&tensor_logic_proof)
    {
        return Err(DurableError::InvalidCompactionEvidence(
            "GC outbox plan inputs do not match its records",
        ));
    }
    let receipt = GcCommitEvidence::from_object_record(&commit)
        .map_err(|_| DurableError::InvalidCompactionEvidence("GC outbox receipt is invalid"))?;
    receipt.validate_plan(&plan_model, identity).map_err(|_| {
        DurableError::InvalidCompactionEvidence("GC receipt does not bind its plan")
    })?;
    if receipt.placement_before().object_id() != identity.identify(&placement_before)
        || receipt.placement_after().object_id() != identity.identify(&placement_after)
        || receipt.execution_measurements().object_id()
            != identity.identify(&execution_measurements)
    {
        return Err(DurableError::InvalidCompactionEvidence(
            "GC receipt does not bind its physical evidence",
        ));
    }
    let commit_id = receipt
        .identify(identity)
        .map_err(|_| DurableError::InvalidCompactionEvidence("GC receipt identity failed"))?;
    Ok(CompactionEvidenceBundle {
        fact_snapshot,
        retention_policy,
        tensor_logic_proof,
        plan,
        placement_before,
        placement_after,
        execution_measurements,
        commit,
        commit_id,
    })
}

pub(super) fn placement_record<P, C>(
    placement: &PlacementView<'_, P>,
    codec: &C,
) -> Result<ObjectRecord, DurableError>
where
    P: Ord,
    C: PrincipalCodec<P>,
{
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PLACEMENT_PREFIX);
    bytes.extend_from_slice(placement.operation_contract.as_bytes());
    bytes.extend_from_slice(&placement.arena_bytes.to_le_bytes());
    bytes.extend_from_slice(&placement.root_journal_bytes.to_le_bytes());
    bytes.extend_from_slice(&placement.root_journal_digest);
    let object_count =
        u64::try_from(placement.index.len()).map_err(|_| DurableError::EncodingOverflow)?;
    bytes.extend_from_slice(&object_count.to_le_bytes());
    for (id, location) in placement.index {
        bytes.extend_from_slice(id.as_bytes());
        bytes.extend_from_slice(&location.offset.to_le_bytes());
        bytes.extend_from_slice(&location.payload_len.to_le_bytes());
        bytes.extend_from_slice(&location.checksum);
    }
    let roots = encoded_roots(placement.roots, codec)?;
    let root_count = u64::try_from(roots.len()).map_err(|_| DurableError::EncodingOverflow)?;
    bytes.extend_from_slice(&root_count.to_le_bytes());
    for (principal, root) in roots {
        let principal_len =
            u64::try_from(principal.len()).map_err(|_| DurableError::EncodingOverflow)?;
        bytes.extend_from_slice(&principal_len.to_le_bytes());
        bytes.extend_from_slice(&principal);
        bytes.extend_from_slice(&root.generation.get().to_le_bytes());
        bytes.extend_from_slice(root.commit.as_bytes());
    }
    generic_evidence(bytes)
}

fn measurements_record(measurements: TransitionMeasurements) -> Result<ObjectRecord, DurableError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MEASUREMENTS_PREFIX);
    for value in [
        measurements.objects_before,
        measurements.objects_after,
        measurements.objects_reclaimed,
        measurements.arena_bytes_before,
        measurements.arena_bytes_after,
        measurements.root_bytes_before,
        measurements.root_bytes_after,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    generic_evidence(bytes)
}

fn generic_evidence(bytes: Vec<u8>) -> Result<ObjectRecord, DurableError> {
    ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        bytes,
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .map_err(DurableError::Model)
}

fn require_generic_evidence(record: &ObjectRecord) -> Result<(), DurableError> {
    if record.kind() != ObjectKind::Evidence
        || record.format_version() != ObjectFormatVersion::V1
        || record.class() != ObjectClass::Metadata
        || record.logical_bytes() != 0
        || !record.references().is_empty()
    {
        return Err(DurableError::InvalidCompactionEvidence(
            "GC outbox generic Evidence record has an invalid shape",
        ));
    }
    Ok(())
}
