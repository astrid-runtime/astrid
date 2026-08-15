//! Verification and disposable-index tests for Muninn.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;

use crate::storage_model::{
    AuthorityEpochId, CanonicalParametersId, ComputationSharingDomainId, DerivationContractId,
    DerivationEvidence, DerivationInvocation, DerivationOutput, DeterministicSeedId, EngineBuildId,
    ExecutionClass, ExecutionMeasurementsId, InvocationInput, ObjectClass, ObjectFormatVersion,
    ObjectId, ObjectIdentity, ObjectKind, ObjectRecord, ObjectReference, OutputContractId,
    ReferenceKind, ReferenceLabel, RuntimeSemanticProfileId, TransformId, VerifierEvidenceId,
};

use super::muninn::{
    InMemoryMuninnIndex, MuninnAdmission, MuninnTrustState, MuninnVerificationError,
    VerifiedDerivationEvidence, validate_complete_output_closure, verify_derivation_evidence,
};

#[derive(Clone, Copy, Debug)]
struct TestIdentity;

impl ObjectIdentity for TestIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        let mut hasher = blake3::Hasher::new_derive_key("astrid muninn test identity v1");
        hasher.update(&record.kind().code().to_le_bytes());
        hasher.update(&record.format_version().get().to_le_bytes());
        hasher.update(&(record.canonical_bytes().len() as u128).to_le_bytes());
        hasher.update(record.canonical_bytes());
        hasher.update(&record.logical_bytes().to_le_bytes());
        hasher.update(&[record.class().code()]);
        hasher.update(&(record.references().len() as u128).to_le_bytes());
        for reference in record.references() {
            hasher.update(&(reference.label().as_bytes().len() as u128).to_le_bytes());
            hasher.update(reference.label().as_bytes());
            hasher.update(reference.target().as_bytes());
            hasher.update(&[reference.kind().code()]);
        }
        ObjectId::new(*hasher.finalize().as_bytes())
    }
}

fn opaque(value: u8) -> ObjectId {
    ObjectId::new([value; 32])
}

fn invocation(class: ExecutionClass) -> DerivationInvocation {
    DerivationInvocation::new(
        class,
        TransformId::new(opaque(1)),
        DerivationContractId::new(opaque(2)),
        vec![InvocationInput::new(b"source".to_vec(), opaque(3)).unwrap()],
        CanonicalParametersId::new(opaque(4)),
        RuntimeSemanticProfileId::new(opaque(5)),
        OutputContractId::new(opaque(6)),
        None,
        Some(DeterministicSeedId::new(opaque(7))),
    )
    .unwrap()
}

fn output_closure(seed: u8) -> (ObjectId, BTreeMap<ObjectId, ObjectRecord>) {
    let identity = TestIdentity;
    let chunk = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        vec![seed; 32],
        Vec::new(),
        32,
        ObjectClass::Data,
    )
    .unwrap();
    let chunk_id = identity.identify(&chunk);
    let file = ObjectRecord::new(
        ObjectKind::File,
        ObjectFormatVersion::V1,
        vec![seed],
        vec![ObjectReference::new(
            ReferenceLabel::new(b"00-chunk".to_vec()),
            chunk_id,
            ReferenceKind::Owns,
        )],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let file_id = identity.identify(&file);
    (
        file_id,
        BTreeMap::from([(chunk_id, chunk), (file_id, file)]),
    )
}

fn verified(
    class: ExecutionClass,
    output_seed: u8,
    domain: u8,
) -> Result<VerifiedDerivationEvidence, MuninnVerificationError> {
    verified_with_engine(class, output_seed, domain, 8)
}

fn verified_with_engine(
    class: ExecutionClass,
    output_seed: u8,
    domain: u8,
    engine: u8,
) -> Result<VerifiedDerivationEvidence, MuninnVerificationError> {
    let identity = TestIdentity;
    let invocation = invocation(class);
    let invocation_record = invocation.to_object_record().unwrap();
    let invocation_id = invocation.identify(&identity).unwrap();
    let (output, closure) = output_closure(output_seed);
    let evidence = DerivationEvidence::new(
        invocation_id,
        &invocation,
        EngineBuildId::new(opaque(engine)),
        vec![DerivationOutput::new(b"artifact".to_vec(), output).unwrap()],
        ExecutionMeasurementsId::new(opaque(9)),
        Some(VerifierEvidenceId::new(opaque(10))),
        AuthorityEpochId::new(opaque(11)),
        ComputationSharingDomainId::new(opaque(domain)),
    )
    .unwrap();
    let evidence_record = evidence.to_object_record().unwrap();
    let evidence_id = evidence.identify(&identity).unwrap();
    verify_derivation_evidence(
        &identity,
        evidence_id,
        &evidence_record,
        &invocation_record,
        &closure,
    )
}

#[test]
fn verified_evidence_rebuilds_a_disposable_index() {
    let verified = verified(ExecutionClass::Pure, 20, 30).unwrap();
    let index = InMemoryMuninnIndex::new(NonZeroUsize::new(4).unwrap());
    assert_eq!(index.admit(&verified), MuninnAdmission::Inserted);
    let hit = index
        .lookup(verified.sharing_domain(), verified.invocation())
        .unwrap();
    assert_eq!(hit.evidence(), verified.evidence());
    assert_eq!(hit.outputs(), verified.outputs());

    index.clear();
    assert!(index.is_empty());
    assert_eq!(index.admit(&verified), MuninnAdmission::AlreadyPresent);
    assert_eq!(index.len(), 1);

    let rebuilt =
        InMemoryMuninnIndex::from_retained_evidence(NonZeroUsize::new(4).unwrap(), [&verified]);
    assert_eq!(rebuilt.len(), 1);
}

#[test]
fn effectful_evidence_never_enters_the_reuse_index() {
    assert_eq!(
        verified(ExecutionClass::Effectful, 20, 30),
        Err(MuninnVerificationError::ExecutionClassNotMemoizable)
    );
}

#[test]
fn output_closure_must_be_complete_exact_and_identity_verified() {
    let identity = TestIdentity;
    let invocation = invocation(ExecutionClass::Pure);
    let invocation_record = invocation.to_object_record().unwrap();
    let invocation_id = invocation.identify(&identity).unwrap();
    let (output, mut closure) = output_closure(20);
    let evidence = DerivationEvidence::new(
        invocation_id,
        &invocation,
        EngineBuildId::new(opaque(8)),
        vec![DerivationOutput::new(b"artifact".to_vec(), output).unwrap()],
        ExecutionMeasurementsId::new(opaque(9)),
        None,
        AuthorityEpochId::new(opaque(11)),
        ComputationSharingDomainId::new(opaque(30)),
    )
    .unwrap();
    let evidence_record = evidence.to_object_record().unwrap();
    let evidence_id = evidence.identify(&identity).unwrap();

    let child = closure
        .get(&output)
        .unwrap()
        .owning_references()
        .next()
        .unwrap();
    closure.remove(&child);
    assert_eq!(
        verify_derivation_evidence(
            &identity,
            evidence_id,
            &evidence_record,
            &invocation_record,
            &closure,
        ),
        Err(MuninnVerificationError::MissingOutputObject(child))
    );

    let (_, mut closure) = output_closure(20);
    closure.insert(
        opaque(99),
        ObjectRecord::new(
            ObjectKind::Chunk,
            ObjectFormatVersion::V1,
            b"extra".to_vec(),
            Vec::new(),
            5,
            ObjectClass::Data,
        )
        .unwrap(),
    );
    assert!(matches!(
        verify_derivation_evidence(
            &identity,
            evidence_id,
            &evidence_record,
            &invocation_record,
            &closure,
        ),
        Err(MuninnVerificationError::OutputIdentityMismatch(_))
    ));
}

#[test]
fn conflicting_evidence_is_quarantined_not_silently_replaced() {
    let first = verified(ExecutionClass::Pure, 20, 30).unwrap();
    let conflicting = verified(ExecutionClass::Pure, 21, 30).unwrap();
    assert_eq!(first.invocation(), conflicting.invocation());

    let index = InMemoryMuninnIndex::new(NonZeroUsize::new(4).unwrap());
    assert_eq!(index.admit(&first), MuninnAdmission::Inserted);
    assert_eq!(
        index.admit(&conflicting),
        MuninnAdmission::Conflict {
            existing: first.evidence(),
            incoming: conflicting.evidence(),
        }
    );
    assert!(
        index
            .lookup(first.sharing_domain(), first.invocation())
            .is_none()
    );
    index.clear();
    assert_eq!(
        index.admit(&first),
        MuninnAdmission::AlreadyPresent,
        "clearing resident entries must retain the conflict guard"
    );
    assert!(
        index
            .lookup(first.sharing_domain(), first.invocation())
            .is_none(),
        "a conflicting invocation must stay quarantined after clear"
    );
    assert!(!index.set_trust_state(
        first.sharing_domain(),
        first.invocation(),
        MuninnTrustState::Verified,
        None,
    ));
    assert!(index.set_trust_state(
        first.sharing_domain(),
        first.invocation(),
        MuninnTrustState::Verified,
        Some(opaque(91)),
    ));
    assert!(
        index
            .lookup(first.sharing_domain(), first.invocation())
            .is_some(),
        "explicit rehabilitation evidence may restore reuse"
    );
}

#[test]
fn matching_outputs_may_accumulate_distinct_execution_evidence() {
    let first = verified_with_engine(ExecutionClass::Pure, 20, 30, 8).unwrap();
    let supporting = verified_with_engine(ExecutionClass::Pure, 20, 30, 18).unwrap();
    assert_ne!(first.evidence(), supporting.evidence());
    assert_eq!(first.outputs(), supporting.outputs());

    let index = InMemoryMuninnIndex::new(NonZeroUsize::new(4).unwrap());
    assert_eq!(index.admit(&first), MuninnAdmission::Inserted);
    assert_eq!(index.admit(&supporting), MuninnAdmission::AlreadyPresent);
    assert_eq!(
        index
            .lookup(first.sharing_domain(), first.invocation())
            .unwrap()
            .outputs(),
        first.outputs()
    );
}

#[test]
fn off_side_rebuild_quarantines_conflicts_in_any_input_order() {
    let first = verified(ExecutionClass::Pure, 20, 30).unwrap();
    let conflicting = verified(ExecutionClass::Pure, 21, 30).unwrap();
    for evidence in [[&first, &conflicting], [&conflicting, &first]] {
        let index =
            InMemoryMuninnIndex::from_retained_evidence(NonZeroUsize::new(4).unwrap(), evidence);
        assert!(
            index
                .lookup(first.sharing_domain(), first.invocation())
                .is_none()
        );
    }
}

#[test]
fn capacity_and_domain_partitioning_change_performance_only() {
    let first = verified(ExecutionClass::Pure, 20, 30).unwrap();
    let other_domain = verified(ExecutionClass::Pure, 20, 31).unwrap();
    let index = InMemoryMuninnIndex::new(NonZeroUsize::new(1).unwrap());
    assert_eq!(index.admit(&first), MuninnAdmission::Inserted);
    assert_eq!(
        index.admit(&other_domain),
        MuninnAdmission::CapacityExhausted
    );
    assert!(
        index
            .lookup(other_domain.sharing_domain(), other_domain.invocation())
            .is_none()
    );
    assert!(index.set_trust_state(
        first.sharing_domain(),
        first.invocation(),
        MuninnTrustState::Revoked,
        Some(opaque(90)),
    ));
    assert!(
        index
            .lookup(first.sharing_domain(), first.invocation())
            .is_none()
    );
    assert!(index.evict(first.sharing_domain(), first.invocation()));
    assert!(index.is_empty());
    assert_eq!(
        index.admit(&other_domain),
        MuninnAdmission::CapacityExhausted,
        "eviction must not forget the bounded observation slot"
    );
    assert_eq!(index.admit(&first), MuninnAdmission::AlreadyPresent);
}

#[test]
fn deeply_nested_output_closure_uses_an_explicit_work_list() {
    const DEPTH: u32 = 20_000;

    let identity = TestIdentity;
    let mut records = BTreeMap::new();
    let mut child = None;
    for depth in 0..DEPTH {
        let references = child
            .map(|target| {
                vec![ObjectReference::new(
                    ReferenceLabel::new(b"child".to_vec()),
                    target,
                    ReferenceKind::Owns,
                )]
            })
            .unwrap_or_default();
        let record = ObjectRecord::new(
            ObjectKind::Derived,
            ObjectFormatVersion::V1,
            depth.to_le_bytes().to_vec(),
            references,
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let id = identity.identify(&record);
        records.insert(id, record);
        child = Some(id);
    }

    let reachable = validate_complete_output_closure(&[child.unwrap()], &records).unwrap();
    assert_eq!(reachable.len(), DEPTH as usize);
}
