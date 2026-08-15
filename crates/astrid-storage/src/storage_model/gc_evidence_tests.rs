//! Canonical linked GC evidence tests.

use alloc::vec;

use super::*;

#[derive(Clone, Copy)]
struct RecordIdentity;

impl ObjectIdentity for RecordIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        let mut bytes = [0_u8; 32];
        bytes[..2].copy_from_slice(&record.kind().code().to_le_bytes());
        bytes[2] = u8::try_from(record.references().len()).unwrap();
        for reference in record.references() {
            bytes[3] = bytes[3]
                .wrapping_mul(31)
                .wrapping_add(reference.target().as_bytes()[0])
                .wrapping_add(reference.kind().code());
        }
        ObjectId::new(bytes)
    }
}

fn id(value: u8) -> ObjectId {
    ObjectId::new([value; 32])
}

fn plan() -> GcPlanEvidence {
    GcPlanEvidence::new(
        GcFactSnapshotId::new(id(1)),
        RetentionPolicyId::new(id(2)),
        TensorLogicProofId::new(id(3)),
        vec![id(10), id(11), id(12)],
    )
    .unwrap()
}

#[test]
fn gc_plan_round_trips_as_a_canonical_condemned_set() {
    let plan = plan();
    let record = plan.to_object_record().unwrap();
    assert_eq!(
        GcPlanEvidence::from_object_record(&record),
        Ok(plan.clone())
    );
    assert_eq!(
        plan.identify(&RecordIdentity),
        Ok(GcPlanId::new(RecordIdentity.identify(&record)))
    );
    assert!(
        record.references()[..3]
            .iter()
            .all(|reference| reference.kind() == ReferenceKind::Owns)
    );
    assert!(
        record.references()[3..]
            .iter()
            .all(|reference| reference.kind() == ReferenceKind::Evidence)
    );
    assert_eq!(
        GcPlanEvidence::new(
            plan.snapshot(),
            plan.retention_policy(),
            plan.tensor_logic_proof(),
            vec![id(11), id(10)],
        ),
        Err(GcEvidenceError::NonCanonicalCondemnedSet)
    );
}

#[test]
fn commit_receipt_cannot_cross_the_plan_snapshot_fence() {
    let plan = plan();
    assert_eq!(
        GcCommitEvidence::new(
            &RecordIdentity,
            &plan,
            GcFactSnapshotId::new(id(99)),
            PlacementSetId::new(id(20)),
            PlacementSetId::new(id(21)),
            ExecutionMeasurementsId::new(id(22)),
        ),
        Err(GcEvidenceError::FenceSnapshotChanged {
            planned: plan.snapshot(),
            actual: GcFactSnapshotId::new(id(99)),
        })
    );
}

#[test]
fn commit_receipt_owns_and_revalidates_the_exact_plan() {
    let plan = plan();
    let receipt = GcCommitEvidence::new(
        &RecordIdentity,
        &plan,
        plan.snapshot(),
        PlacementSetId::new(id(20)),
        PlacementSetId::new(id(21)),
        ExecutionMeasurementsId::new(id(22)),
    )
    .unwrap();
    let record = receipt.to_object_record().unwrap();
    assert_eq!(
        GcCommitEvidence::from_object_record(&record),
        Ok(receipt.clone())
    );
    assert_eq!(record.references()[0].kind(), ReferenceKind::Owns);
    assert_eq!(receipt.validate_plan(&plan, &RecordIdentity), Ok(()));

    let other_plan = GcPlanEvidence::new(
        plan.snapshot(),
        plan.retention_policy(),
        plan.tensor_logic_proof(),
        vec![id(10), id(11), id(13)],
    )
    .unwrap();
    assert_eq!(
        receipt.validate_plan(&other_plan, &RecordIdentity),
        Err(GcEvidenceError::PlanIdentityMismatch)
    );
}

#[test]
fn decoded_receipt_rejects_noop_placement_claims() {
    let plan = plan();
    assert_eq!(
        GcCommitEvidence::new(
            &RecordIdentity,
            &plan,
            plan.snapshot(),
            PlacementSetId::new(id(20)),
            PlacementSetId::new(id(20)),
            ExecutionMeasurementsId::new(id(22)),
        ),
        Err(GcEvidenceError::UnchangedPlacement)
    );
}
