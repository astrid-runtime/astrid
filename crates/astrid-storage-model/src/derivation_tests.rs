//! Canonical derivation identity tests.

use alloc::vec;

use super::*;

fn id(value: u8) -> ObjectId {
    ObjectId::new([value; 32])
}

fn semantic(value: u8) -> SemanticContractId {
    SemanticContractId::new(id(value))
}

#[derive(Clone, Copy)]
struct RecordIdentity;

impl ObjectIdentity for RecordIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        let mut bytes = [0_u8; 32];
        bytes[..2].copy_from_slice(&record.kind().code().to_le_bytes());
        bytes[2..4].copy_from_slice(&record.format_version().get().to_le_bytes());
        bytes[4] = record.class().code();
        for byte in record.canonical_bytes() {
            bytes[5] = bytes[5].wrapping_mul(31).wrapping_add(*byte);
        }
        for (index, reference) in record.references().iter().enumerate() {
            let slot = 6_usize.checked_add(index % 26).unwrap();
            bytes[slot] = bytes[slot]
                .wrapping_mul(31)
                .wrapping_add(reference.target().as_bytes()[0])
                .wrapping_add(reference.kind().code());
            for label_byte in reference.label().as_bytes() {
                bytes[slot] = bytes[slot].wrapping_mul(31).wrapping_add(*label_byte);
            }
        }
        ObjectId::new(bytes)
    }
}

fn profile() -> RuntimeSemanticProfile {
    RuntimeSemanticProfile::new(
        semantic(1),
        Some(semantic(2)),
        vec![semantic(3), semantic(4)],
        vec![
            HostFunctionSemanticBinding::new(b"astrid:content/read@1".to_vec(), semantic(5))
                .unwrap(),
            HostFunctionSemanticBinding::new(b"astrid:output/write@1".to_vec(), semantic(6))
                .unwrap(),
        ],
        semantic(7),
        semantic(8),
        semantic(9),
    )
    .unwrap()
}

fn invocation(class: ExecutionClass) -> DerivationInvocation {
    let snapshot = match class {
        ExecutionClass::SnapshotBound => Some(SnapshotId::new(id(20))),
        _ => None,
    };
    DerivationInvocation::new(
        class,
        TransformId::new(id(17)),
        DerivationContractId::new(id(10)),
        vec![
            InvocationInput::new(b"source".to_vec(), id(11)).unwrap(),
            InvocationInput::new(b"schema".to_vec(), id(12)).unwrap(),
        ],
        CanonicalParametersId::new(id(13)),
        RuntimeSemanticProfileId::new(id(14)),
        OutputContractId::new(id(15)),
        snapshot,
        Some(DeterministicSeedId::new(id(16))),
    )
    .unwrap()
}

fn evidence(class: ExecutionClass) -> DerivationEvidence {
    let invocation = invocation(class);
    DerivationEvidence::new(
        invocation.identify(&RecordIdentity).unwrap(),
        &invocation,
        EngineBuildId::new(id(40)),
        vec![
            DerivationOutput::new(b"artifact".to_vec(), id(41)).unwrap(),
            DerivationOutput::new(b"manifest".to_vec(), id(42)).unwrap(),
        ],
        ExecutionMeasurementsId::new(id(43)),
        Some(VerifierEvidenceId::new(id(44))),
        AuthorityEpochId::new(id(45)),
        ComputationSharingDomainId::new(id(46)),
    )
    .unwrap()
}

#[test]
fn execution_class_codes_are_stable_and_memoization_is_explicit() {
    for class in [
        ExecutionClass::Pure,
        ExecutionClass::SnapshotBound,
        ExecutionClass::Effectful,
        ExecutionClass::Nondeterministic,
    ] {
        assert_eq!(ExecutionClass::from_code(class.code()), Some(class));
    }
    assert!(ExecutionClass::Pure.is_memoizable());
    assert!(ExecutionClass::SnapshotBound.is_memoizable());
    assert!(!ExecutionClass::Effectful.is_memoizable());
    assert!(!ExecutionClass::Nondeterministic.is_memoizable());
    assert_eq!(ExecutionClass::from_code(u8::MAX), None);
}

#[test]
fn runtime_profile_round_trips_through_one_canonical_record() {
    let profile = profile();
    let record = profile.to_object_record().unwrap();
    assert_eq!(
        RuntimeSemanticProfile::from_object_record(&record),
        Ok(profile.clone())
    );
    assert_eq!(
        profile.identify(&RecordIdentity),
        Ok(RuntimeSemanticProfileId::new(
            RecordIdentity.identify(&record)
        ))
    );
}

#[test]
fn runtime_profile_rejects_ambiguous_collection_order() {
    assert_eq!(
        RuntimeSemanticProfile::new(
            semantic(1),
            None,
            vec![semantic(4), semantic(3)],
            vec![],
            semantic(7),
            semantic(8),
            semantic(9),
        ),
        Err(DerivationModelError::NonCanonicalProposals)
    );
    assert_eq!(
        RuntimeSemanticProfile::new(
            semantic(1),
            None,
            vec![],
            vec![
                HostFunctionSemanticBinding::new(b"z".to_vec(), semantic(5)).unwrap(),
                HostFunctionSemanticBinding::new(b"a".to_vec(), semantic(6)).unwrap(),
            ],
            semantic(7),
            semantic(8),
            semantic(9),
        ),
        Err(DerivationModelError::NonCanonicalHostFunctions)
    );
}

#[test]
fn invocation_round_trips_and_identifies_the_complete_request() {
    let invocation = invocation(ExecutionClass::Pure);
    let record = invocation.to_object_record().unwrap();
    assert_eq!(
        DerivationInvocation::from_object_record(&record),
        Ok(invocation.clone())
    );
    assert_eq!(
        invocation.identify(&RecordIdentity),
        Ok(InvocationId::new(RecordIdentity.identify(&record)))
    );
}

#[test]
fn input_order_is_identity_bearing() {
    let first = invocation(ExecutionClass::Pure);
    let mut reversed_inputs = first.inputs().to_vec();
    reversed_inputs.reverse();
    let second = DerivationInvocation::new(
        first.execution_class(),
        first.transform(),
        first.transform_contract(),
        reversed_inputs,
        first.canonical_parameters(),
        first.runtime_semantic_profile(),
        first.output_contract(),
        first.snapshot(),
        first.seed(),
    )
    .unwrap();
    assert_ne!(
        first.identify(&RecordIdentity).unwrap(),
        second.identify(&RecordIdentity).unwrap()
    );
}

#[test]
fn every_semantics_visible_fixed_field_changes_identity() {
    let base = invocation(ExecutionClass::Pure);
    let changed = [
        DerivationInvocation::new(
            ExecutionClass::Effectful,
            base.transform(),
            base.transform_contract(),
            base.inputs().to_vec(),
            base.canonical_parameters(),
            base.runtime_semantic_profile(),
            base.output_contract(),
            None,
            base.seed(),
        )
        .unwrap(),
        DerivationInvocation::new(
            base.execution_class(),
            base.transform(),
            DerivationContractId::new(id(30)),
            base.inputs().to_vec(),
            base.canonical_parameters(),
            base.runtime_semantic_profile(),
            base.output_contract(),
            None,
            base.seed(),
        )
        .unwrap(),
        DerivationInvocation::new(
            base.execution_class(),
            TransformId::new(id(35)),
            base.transform_contract(),
            base.inputs().to_vec(),
            base.canonical_parameters(),
            base.runtime_semantic_profile(),
            base.output_contract(),
            None,
            base.seed(),
        )
        .unwrap(),
        DerivationInvocation::new(
            base.execution_class(),
            base.transform(),
            base.transform_contract(),
            base.inputs().to_vec(),
            CanonicalParametersId::new(id(31)),
            base.runtime_semantic_profile(),
            base.output_contract(),
            None,
            base.seed(),
        )
        .unwrap(),
        DerivationInvocation::new(
            base.execution_class(),
            base.transform(),
            base.transform_contract(),
            base.inputs().to_vec(),
            base.canonical_parameters(),
            RuntimeSemanticProfileId::new(id(32)),
            base.output_contract(),
            None,
            base.seed(),
        )
        .unwrap(),
        DerivationInvocation::new(
            base.execution_class(),
            base.transform(),
            base.transform_contract(),
            base.inputs().to_vec(),
            base.canonical_parameters(),
            base.runtime_semantic_profile(),
            OutputContractId::new(id(33)),
            None,
            base.seed(),
        )
        .unwrap(),
        DerivationInvocation::new(
            base.execution_class(),
            base.transform(),
            base.transform_contract(),
            base.inputs().to_vec(),
            base.canonical_parameters(),
            base.runtime_semantic_profile(),
            base.output_contract(),
            None,
            Some(DeterministicSeedId::new(id(34))),
        )
        .unwrap(),
    ];
    let base_id = base.identify(&RecordIdentity).unwrap();
    for invocation in changed {
        assert_ne!(base_id, invocation.identify(&RecordIdentity).unwrap());
    }
}

#[test]
fn execution_class_enforces_snapshot_doctrine() {
    assert_eq!(
        DerivationInvocation::new(
            ExecutionClass::Pure,
            TransformId::new(id(6)),
            DerivationContractId::new(id(1)),
            vec![],
            CanonicalParametersId::new(id(2)),
            RuntimeSemanticProfileId::new(id(3)),
            OutputContractId::new(id(4)),
            Some(SnapshotId::new(id(5))),
            None,
        ),
        Err(DerivationModelError::PureInvocationHasSnapshot)
    );
    assert_eq!(
        DerivationInvocation::new(
            ExecutionClass::SnapshotBound,
            TransformId::new(id(6)),
            DerivationContractId::new(id(1)),
            vec![],
            CanonicalParametersId::new(id(2)),
            RuntimeSemanticProfileId::new(id(3)),
            OutputContractId::new(id(4)),
            None,
            None,
        ),
        Err(DerivationModelError::SnapshotBoundInvocationMissingSnapshot)
    );
}

#[test]
fn canonical_decoder_rejects_wrong_reference_semantics() {
    let invocation = invocation(ExecutionClass::Pure);
    let record = invocation.to_object_record().unwrap();
    let mut references = record.references().to_vec();
    let first = &references[0];
    references[0] = ObjectReference::new(
        first.label().clone(),
        first.target(),
        ReferenceKind::Evidence,
    );
    let tampered = ObjectRecord::new(
        ObjectKind::DerivationInvocation,
        ObjectFormatVersion::V1,
        record.canonical_bytes().to_vec(),
        references,
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    assert_eq!(
        DerivationInvocation::from_object_record(&tampered),
        Err(DerivationModelError::InvalidReferenceKind)
    );
}

#[test]
fn canonical_decoders_reject_optional_reference_mask_disagreement() {
    let profile_record = profile().to_object_record().unwrap();
    let profile_without_presence = ObjectRecord::new(
        ObjectKind::RuntimeSemanticProfile,
        ObjectFormatVersion::V1,
        vec![0],
        profile_record.references().to_vec(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    assert_eq!(
        RuntimeSemanticProfile::from_object_record(&profile_without_presence),
        Err(DerivationModelError::InvalidOptionMask)
    );

    let invocation_record = invocation(ExecutionClass::Pure).to_object_record().unwrap();
    let invocation_without_seed_presence = ObjectRecord::new(
        ObjectKind::DerivationInvocation,
        ObjectFormatVersion::V1,
        vec![ExecutionClass::Pure.code(), 0],
        invocation_record.references().to_vec(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    assert_eq!(
        DerivationInvocation::from_object_record(&invocation_without_seed_presence),
        Err(DerivationModelError::InvalidOptionMask)
    );
}

#[test]
fn derivation_evidence_round_trips_and_validates_its_exact_invocation() {
    let invocation = invocation(ExecutionClass::Pure);
    let evidence = evidence(ExecutionClass::Pure);
    let record = evidence.to_object_record().unwrap();
    assert_eq!(
        DerivationEvidence::from_object_record(&record),
        Ok(evidence.clone())
    );
    assert_eq!(
        evidence.identify(&RecordIdentity),
        Ok(RecordIdentity.identify(&record))
    );
    assert_eq!(
        evidence.validate_invocation(&invocation, &RecordIdentity),
        Ok(())
    );
    assert_eq!(record.references()[0].kind(), ReferenceKind::Owns);
    assert!(
        record
            .references()
            .iter()
            .filter(|reference| reference.label().as_bytes().starts_with(b"20-output/"))
            .all(|reference| reference.kind() == ReferenceKind::Derived)
    );
}

#[test]
fn derivation_evidence_rejects_drift_from_its_invocation() {
    let base = invocation(ExecutionClass::Pure);
    let changed = DerivationInvocation::new(
        base.execution_class(),
        TransformId::new(id(99)),
        base.transform_contract(),
        base.inputs().to_vec(),
        base.canonical_parameters(),
        base.runtime_semantic_profile(),
        base.output_contract(),
        base.snapshot(),
        base.seed(),
    )
    .unwrap();
    assert_eq!(
        evidence(ExecutionClass::Pure).validate_invocation(&changed, &RecordIdentity),
        Err(DerivationEvidenceError::InvocationMismatch)
    );
}

#[test]
fn derivation_evidence_rejects_optional_mask_disagreement() {
    let record = evidence(ExecutionClass::Pure).to_object_record().unwrap();
    let without_verifier_presence = ObjectRecord::new(
        ObjectKind::DerivationEvidence,
        ObjectFormatVersion::V1,
        vec![ExecutionClass::Pure.code(), 0],
        record.references().to_vec(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    assert_eq!(
        DerivationEvidence::from_object_record(&without_verifier_presence),
        Err(DerivationEvidenceError::InvalidOptionMask)
    );
}
