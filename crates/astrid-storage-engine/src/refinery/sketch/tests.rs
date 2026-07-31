use astrid_storage_content::{ChunkingProfile, build_content};
use astrid_storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectIdentity, ObjectReference, PlacementEpoch,
    ReferenceKind, ReferenceLabel, World,
};

use crate::{RefineryResourceBudget, RefinerySnapshotId};

use super::*;

#[derive(Clone, Copy)]
struct TestIdentity;

impl ObjectIdentity for TestIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        let mut hasher =
            blake3::Hasher::new_derive_key("astrid principal store object identity v1");
        hasher.update(&record.kind().code().to_le_bytes());
        hasher.update(&record.format_version().get().to_le_bytes());
        hasher.update(
            &u128::try_from(record.canonical_bytes().len())
                .unwrap()
                .to_le_bytes(),
        );
        hasher.update(record.canonical_bytes());
        hasher.update(&record.logical_bytes().to_le_bytes());
        hasher.update(&[record.class().code()]);
        hasher.update(
            &u128::try_from(record.references().len())
                .unwrap()
                .to_le_bytes(),
        );
        for reference in record.references() {
            hasher.update(
                &u128::try_from(reference.label().as_bytes().len())
                    .unwrap()
                    .to_le_bytes(),
            );
            hasher.update(reference.label().as_bytes());
            hasher.update(reference.target().as_bytes());
            hasher.update(&[reference.kind().code()]);
        }
        ObjectId::new(*hasher.finalize().as_bytes())
    }
}

fn sample_size(value: u16) -> SketchSampleSize {
    SketchSampleSize::new(value).unwrap()
}

fn descriptor(width: SketchScoreWidth, samples: u16) -> BottomKSketchDescriptor {
    BottomKSketchDescriptor::new(width, sample_size(samples))
}

fn context(bytes_read: u64, retained_output_bytes: u64) -> RefineryBatchContext {
    RefineryBatchContext::new(
        RefinerySnapshotId::new(ObjectId::new([31; 32])),
        PlacementEpoch::new(7),
        RefineryResourceBudget::new(
            u64::MAX,
            u128::MAX,
            bytes_read,
            u64::MAX,
            u64::MAX,
            retained_output_bytes,
        ),
        None,
    )
}

fn unlimited_context() -> RefineryBatchContext {
    context(u64::MAX, u64::MAX)
}

fn deterministic_bytes(length: usize) -> Vec<u8> {
    let mut state = 0x4d59_5df4_d0f3_3173_u64;
    (0..length)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 37).to_le_bytes()[0]
        })
        .collect()
}

#[test]
fn accumulator_never_grows_beyond_its_initial_reservation() {
    let mut accumulator =
        BottomKAccumulator::new(descriptor(SketchScoreWidth::Bits256, 8)).unwrap();
    let reserved = accumulator.scores.capacity();
    assert!(reserved >= 8);
    for value in 0_u16..1_024 {
        accumulator.observe(&value.to_le_bytes()).unwrap();
        assert!(accumulator.scores.len() <= 8);
        assert_eq!(accumulator.scores.capacity(), reserved);
    }
}

fn replace_canonical(record: &ObjectRecord, canonical: Vec<u8>) -> ObjectRecord {
    ObjectRecord::new(
        record.kind(),
        record.format_version(),
        canonical,
        record.references().to_vec(),
        record.logical_bytes(),
        record.class(),
    )
    .unwrap()
}

fn only_output(outputs: &[ProposedRefineryOutput]) -> &ObjectRecord {
    assert_eq!(outputs.len(), 1);
    outputs[0].record()
}

#[test]
fn descriptor_is_canonical_and_pins_every_algorithm_choice() {
    let descriptor = descriptor(SketchScoreWidth::Bits128, 64);
    let record = descriptor.record().unwrap();
    assert_eq!(decode_descriptor(&record), Ok(descriptor));

    let mut trailing = record.canonical_bytes().to_vec();
    trailing.push(0);
    assert_eq!(
        decode_descriptor(&replace_canonical(&record, trailing)),
        Err(BottomKSketchError::NonCanonicalRecord)
    );

    let mut altered = record.canonical_bytes().to_vec();
    let byte = altered.last_mut().unwrap();
    *byte ^= 1;
    assert_eq!(
        decode_descriptor(&replace_canonical(&record, altered)),
        Err(BottomKSketchError::NonCanonicalRecord)
    );
}

#[test]
fn measured_astrid_profile_is_128_bits_by_256_samples() {
    assert_eq!(
        BottomKSketchDescriptor::ASTRID_V1.score_width(),
        SketchScoreWidth::Bits128
    );
    assert_eq!(BottomKSketchDescriptor::ASTRID_V1.sample_size().get(), 256);
    assert_eq!(
        decode_descriptor(&BottomKSketchDescriptor::ASTRID_V1.record().unwrap()),
        Ok(BottomKSketchDescriptor::ASTRID_V1)
    );
}

#[test]
fn score_construction_has_a_frozen_golden_vector() {
    let mut accumulator =
        BottomKAccumulator::new(descriptor(SketchScoreWidth::Bits256, 1)).unwrap();
    accumulator.observe(b"hello").unwrap();
    assert_eq!(
        accumulator.scores,
        vec![[
            0x86, 0xbe, 0xe6, 0x1c, 0x26, 0x2f, 0xaa, 0xef, 0xa6, 0xa1, 0x06, 0xed, 0x68, 0x97,
            0x97, 0x1b, 0x1f, 0x05, 0x57, 0xe5, 0xd7, 0x40, 0xeb, 0xf7, 0x60, 0x10, 0xb7, 0x77,
            0xfc, 0xf4, 0xde, 0x7a,
        ]]
    );
}

#[test]
fn sketch_is_order_independent_and_recomputable() {
    let built = build_content(
        &TestIdentity,
        ChunkingProfile::ASTRID_V1,
        &deterministic_bytes(3 * 1024 * 1024),
    )
    .unwrap();
    let descriptor = descriptor(SketchScoreWidth::Bits128, 16);
    let first = build_bottom_k_sketch(
        &TestIdentity,
        descriptor,
        unlimited_context(),
        built.descriptor().file(),
        built.records(),
    )
    .unwrap();
    let mut reversed = built.records().to_vec();
    reversed.reverse();
    let second = build_bottom_k_sketch(
        &TestIdentity,
        descriptor,
        unlimited_context(),
        built.descriptor().file(),
        &reversed,
    )
    .unwrap();
    assert_eq!(first, second);

    let descriptor_record = descriptor.record().unwrap();
    let verified = verify_bottom_k_sketch(
        &TestIdentity,
        &descriptor_record,
        only_output(&first),
        built.descriptor().file(),
        built.records(),
    )
    .unwrap();
    assert_eq!(verified.source(), built.descriptor());
    assert_eq!(verified.unique_chunk_objects(), built.unique_chunks());
    assert_eq!(verified.scores().len(), 16);
    assert!(verified.scores().windows(2).all(|pair| pair[0] < pair[1]));
    assert!(
        verified
            .scores()
            .iter()
            .all(|score| score[16..].iter().all(|byte| *byte == 0))
    );
    assert_eq!(only_output(&first).kind(), ObjectKind::Derived);
    assert_eq!(
        only_output(&first)
            .references()
            .iter()
            .map(ObjectReference::kind)
            .collect::<Vec<_>>(),
        [ReferenceKind::Evidence, ReferenceKind::Evidence]
    );
}

#[test]
fn interruption_emits_nothing_and_restart_rebuilds_identically() {
    let built = build_content(
        &TestIdentity,
        ChunkingProfile::ASTRID_V1,
        &deterministic_bytes(2 * 1024 * 1024),
    )
    .unwrap();
    let descriptor = descriptor(SketchScoreWidth::Bits128, 16);
    let descriptor_id =
        RefineryPassDescriptorId::new(TestIdentity.identify(&descriptor.record().unwrap()));
    let mut pass = BottomKPass::new(descriptor, descriptor_id, built.descriptor()).unwrap();
    pass.begin(unlimited_context()).unwrap();
    let mut interrupted_outputs = RefineryProposalSink::new();
    for (id, record) in &built.records()[..built.records().len() / 2] {
        pass.observe(
            VerifiedRefineryObject::from_engine(*id, record),
            &mut interrupted_outputs,
        )
        .unwrap();
    }
    assert!(interrupted_outputs.into_outputs().is_empty());
    assert_eq!(pass.checkpoint(), None);

    let restarted = run_refinery_observer(
        &TestIdentity,
        &mut pass,
        unlimited_context(),
        built.records(),
    )
    .unwrap();
    let direct = build_bottom_k_sketch(
        &TestIdentity,
        descriptor,
        unlimited_context(),
        built.descriptor().file(),
        built.records(),
    )
    .unwrap();
    assert_eq!(restarted, direct);
}

#[test]
fn advisory_records_do_not_change_authoritative_exports() {
    let built = build_content(
        &TestIdentity,
        ChunkingProfile::ASTRID_V1,
        &deterministic_bytes(1024 * 1024),
    )
    .unwrap();
    let descriptor = BottomKSketchDescriptor::ASTRID_V1;
    let outputs = build_bottom_k_sketch(
        &TestIdentity,
        descriptor,
        unlimited_context(),
        built.descriptor().file(),
        built.records(),
    )
    .unwrap();
    let mut world = World::<()>::new();
    for (id, record) in built.records() {
        world.insert_object(*id, record.clone()).unwrap();
    }
    let commit = ObjectRecord::new(
        ObjectKind::Commit,
        ObjectFormatVersion::V1,
        b"bottom-k export fixture".to_vec(),
        vec![ObjectReference::owns(
            ReferenceLabel::new(b"content".to_vec()),
            built.descriptor().file(),
        )],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let commit_id = TestIdentity.identify(&commit);
    world.insert_object(commit_id, commit).unwrap();
    let before = world.export_closure(commit_id).unwrap();

    let descriptor_record = descriptor.record().unwrap();
    world
        .insert_object(TestIdentity.identify(&descriptor_record), descriptor_record)
        .unwrap();
    for proposal in outputs {
        let record = proposal.record().clone();
        world
            .insert_object(TestIdentity.identify(&record), record)
            .unwrap();
    }
    assert_eq!(world.export_closure(commit_id).unwrap(), before);
}

#[test]
fn empty_and_small_files_have_exact_sample_semantics() {
    let empty = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &[]).unwrap();
    let small = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, b"one chunk").unwrap();
    for (built, expected) in [(&empty, 0_usize), (&small, 1)] {
        let descriptor = descriptor(SketchScoreWidth::Bits256, 64);
        let output = build_bottom_k_sketch(
            &TestIdentity,
            descriptor,
            unlimited_context(),
            built.descriptor().file(),
            built.records(),
        )
        .unwrap();
        let verified = verify_bottom_k_sketch(
            &TestIdentity,
            &descriptor.record().unwrap(),
            only_output(&output),
            built.descriptor().file(),
            built.records(),
        )
        .unwrap();
        assert_eq!(verified.scores().len(), expected);
    }
}

#[test]
fn exact_closure_rejects_substitution_omission_duplication_and_extras() {
    let built = build_content(
        &TestIdentity,
        ChunkingProfile::ASTRID_V1,
        &deterministic_bytes(1024 * 1024),
    )
    .unwrap();
    let descriptor = descriptor(SketchScoreWidth::Bits128, 8);

    let mut substituted = built.records().to_vec();
    substituted[0].0 = ObjectId::new([77; 32]);
    assert!(matches!(
        build_bottom_k_sketch(
            &TestIdentity,
            descriptor,
            unlimited_context(),
            built.descriptor().file(),
            &substituted,
        ),
        Err(BottomKSketchError::ObjectIdentityMismatch(_))
    ));

    let mut missing = built.records().to_vec();
    let removable = missing
        .iter()
        .position(|(id, _)| *id != built.descriptor().file())
        .unwrap();
    let missing_id = missing.remove(removable).0;
    assert_eq!(
        build_bottom_k_sketch(
            &TestIdentity,
            descriptor,
            unlimited_context(),
            built.descriptor().file(),
            &missing,
        ),
        Err(BottomKSketchError::MissingObject(missing_id))
    );

    let mut duplicate = built.records().to_vec();
    duplicate.push(duplicate[0].clone());
    assert!(matches!(
        build_bottom_k_sketch(
            &TestIdentity,
            descriptor,
            unlimited_context(),
            built.descriptor().file(),
            &duplicate,
        ),
        Err(BottomKSketchError::DuplicateObject(_))
    ));

    let unrelated = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"unrelated".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let mut extra = built.records().to_vec();
    extra.push((TestIdentity.identify(&unrelated), unrelated));
    assert!(matches!(
        build_bottom_k_sketch(
            &TestIdentity,
            descriptor,
            unlimited_context(),
            built.descriptor().file(),
            &extra,
        ),
        Err(BottomKSketchError::ExtraneousObject(_))
    ));
}

#[test]
fn budget_exhaustion_returns_no_partial_sketch() {
    let built = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, b"bounded work").unwrap();
    let descriptor = descriptor(SketchScoreWidth::Bits256, 8);
    assert_eq!(
        build_bottom_k_sketch(
            &TestIdentity,
            descriptor,
            context(0, u64::MAX),
            built.descriptor().file(),
            built.records(),
        ),
        Err(BottomKSketchError::ResourceBudgetExceeded)
    );
    assert_eq!(
        build_bottom_k_sketch(
            &TestIdentity,
            descriptor,
            context(u64::MAX, 0),
            built.descriptor().file(),
            built.records(),
        ),
        Err(BottomKSketchError::ResourceBudgetExceeded)
    );
}

#[test]
fn verification_rejects_any_changed_result() {
    let built = build_content(
        &TestIdentity,
        ChunkingProfile::ASTRID_V1,
        b"immutable source",
    )
    .unwrap();
    let descriptor = descriptor(SketchScoreWidth::Bits256, 8);
    let descriptor_record = descriptor.record().unwrap();
    let outputs = build_bottom_k_sketch(
        &TestIdentity,
        descriptor,
        unlimited_context(),
        built.descriptor().file(),
        built.records(),
    )
    .unwrap();
    let output = only_output(&outputs);
    let mut changed = output.canonical_bytes().to_vec();
    *changed.last_mut().unwrap() ^= 1;
    assert_eq!(
        verify_bottom_k_sketch(
            &TestIdentity,
            &descriptor_record,
            &replace_canonical(output, changed),
            built.descriptor().file(),
            built.records(),
        ),
        Err(BottomKSketchError::RecomputedSketchMismatch)
    );
}
