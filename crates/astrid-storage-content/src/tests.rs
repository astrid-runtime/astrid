use std::cell::Cell;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::hash::Hasher;

use astrid_storage_model::{
    ObjectClass, ObjectId, ObjectIdentity, ObjectKind, ObjectRecord, ObjectReference,
    ReferenceKind, ReferenceLabel,
};

use crate::{
    CONTENT_LABEL, ChunkingProfile, ContentError, ContentReadError, ContentSource, FORMAT_VERSION,
    build_content, describe_content, encode_file_header, read_content, read_content_range,
};

#[derive(Clone, Copy)]
struct TestIdentity;

impl ObjectIdentity for TestIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        let mut identity = [0_u8; 32];
        for lane in 0..4_usize {
            let mut hasher = DefaultHasher::new();
            hasher.write_usize(lane);
            hasher.write(&record.kind().code().to_le_bytes());
            hasher.write(&record.format_version().get().to_le_bytes());
            hasher.write(&(record.canonical_bytes().len() as u128).to_le_bytes());
            hasher.write(record.canonical_bytes());
            hasher.write(&record.logical_bytes().to_le_bytes());
            hasher.write_u8(match record.class() {
                ObjectClass::Data => 0,
                ObjectClass::Metadata => 1,
            });
            hasher.write(&(record.references().len() as u128).to_le_bytes());
            for reference in record.references() {
                hasher.write(&(reference.label().as_bytes().len() as u128).to_le_bytes());
                hasher.write(reference.label().as_bytes());
                hasher.write(reference.target().as_bytes());
                hasher.write_u8(match reference.kind() {
                    ReferenceKind::Owns => 0,
                    ReferenceKind::Evidence => 1,
                    ReferenceKind::Lineage => 2,
                    ReferenceKind::Derived => 3,
                });
            }
            let start = lane.saturating_mul(8);
            identity[start..start.saturating_add(8)]
                .copy_from_slice(&hasher.finish().to_le_bytes());
        }
        ObjectId::new(identity)
    }
}

struct MapSource {
    records: BTreeMap<ObjectId, ObjectRecord>,
    loads: Cell<usize>,
}

impl MapSource {
    fn new(records: &[(ObjectId, ObjectRecord)]) -> Self {
        Self {
            records: records.iter().cloned().collect(),
            loads: Cell::new(0),
        }
    }
}

impl ContentSource for MapSource {
    type Error = Infallible;

    fn load_content_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, Self::Error> {
        self.loads.set(self.loads.get().saturating_add(1));
        Ok(self.records.get(&id).cloned())
    }
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

fn manual_content(profile: ChunkingProfile, chunks: &[Vec<u8>]) -> (ObjectId, MapSource) {
    assert!(!chunks.is_empty());
    assert!(chunks.len() <= 128);
    let identity = TestIdentity;
    let mut records = BTreeMap::new();
    let mut children = Vec::new();
    for bytes in chunks {
        let record = ObjectRecord::new(
            ObjectKind::Chunk,
            FORMAT_VERSION,
            bytes.clone(),
            Vec::new(),
            0,
            ObjectClass::Data,
        )
        .unwrap();
        let id = identity.identify(&record);
        records.insert(id, record);
        children.push((id, bytes.len() as u64));
    }
    let content = if let [(only, _)] = children.as_slice() {
        *only
    } else {
        let logical_bytes = children
            .iter()
            .map(|(_, length)| length)
            .try_fold(0_u64, |total, length| total.checked_add(*length))
            .unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u16::try_from(children.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(&logical_bytes.to_le_bytes());
        bytes.extend_from_slice(&(children.len() as u64).to_le_bytes());
        let references = children
            .iter()
            .enumerate()
            .map(|(index, (id, length))| {
                bytes.extend_from_slice(&length.to_le_bytes());
                bytes.extend_from_slice(&1_u64.to_le_bytes());
                ObjectReference::owns(
                    ReferenceLabel::new(u16::try_from(index).unwrap().to_be_bytes().to_vec()),
                    *id,
                )
            })
            .collect();
        let tree = ObjectRecord::new(
            ObjectKind::ChunkTree,
            FORMAT_VERSION,
            bytes,
            references,
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let id = identity.identify(&tree);
        records.insert(id, tree);
        id
    };
    let logical_bytes = chunks
        .iter()
        .map(Vec::len)
        .try_fold(0_u64, |total, length| total.checked_add(length as u64))
        .unwrap();
    let file = ObjectRecord::new(
        ObjectKind::File,
        FORMAT_VERSION,
        encode_file_header(profile, logical_bytes, chunks.len() as u64),
        vec![ObjectReference::owns(
            ReferenceLabel::new(CONTENT_LABEL.to_vec()),
            content,
        )],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let file_id = identity.identify(&file);
    records.insert(file_id, file);
    (
        file_id,
        MapSource {
            records,
            loads: Cell::new(0),
        },
    )
}

#[test]
fn empty_small_and_large_content_round_trip() {
    for bytes in [
        Vec::new(),
        b"hello principal store".to_vec(),
        deterministic_bytes(3 * 1024 * 1024),
    ] {
        let built = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &bytes).unwrap();
        let source = MapSource::new(built.records());
        let descriptor = describe_content(&source, built.descriptor().file()).unwrap();
        assert_eq!(descriptor.logical_bytes(), bytes.len() as u64);
        assert_eq!(
            read_content(&source, built.descriptor().file()).unwrap(),
            bytes
        );
    }
}

#[test]
fn exact_ranges_cross_chunk_and_tree_boundaries() {
    let bytes = deterministic_bytes(5 * 1024 * 1024);
    let built = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &bytes).unwrap();
    let source = MapSource::new(built.records());
    for (offset, length) in [
        (0_u64, 1_u64),
        (15_997, 220_003),
        (2_000_000, 1_000_000),
        (bytes.len() as u64, 0),
    ] {
        let start = usize::try_from(offset).unwrap();
        let end = usize::try_from(offset + length).unwrap();
        assert_eq!(
            read_content_range(&source, built.descriptor().file(), offset, length).unwrap(),
            bytes[start..end]
        );
    }
}

#[test]
fn range_reads_skip_unrelated_chunks() {
    let bytes = deterministic_bytes(8 * 1024 * 1024);
    let built = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &bytes).unwrap();
    let source = MapSource::new(built.records());
    let selected = read_content_range(&source, built.descriptor().file(), 4_000_000, 32).unwrap();
    assert_eq!(selected, bytes[4_000_000..4_000_032]);
    assert!(
        source.loads.get() < built.records().len() / 4,
        "range read loaded {} of {} objects",
        source.loads.get(),
        built.records().len()
    );
}

#[test]
fn identical_and_repeated_content_reuses_objects() {
    let bytes = vec![0_u8; 2 * 1024 * 1024];
    let first = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &bytes).unwrap();
    let second = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &bytes).unwrap();
    assert_eq!(first, second);
    assert!(first.descriptor().chunk_count() > first.unique_chunks());
    assert_eq!(first.unique_chunks(), 1);
}

#[test]
fn insertion_reuses_the_unchanged_content_defined_chunks() {
    let original = deterministic_bytes(8 * 1024 * 1024);
    let mut edited = original.clone();
    edited.splice(3_000_000..3_000_000, [0x55; 4096]);
    let before = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &original).unwrap();
    let after = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &edited).unwrap();
    let before_chunks: BTreeSet<_> = before
        .records()
        .iter()
        .filter(|(_, record)| record.kind() == ObjectKind::Chunk)
        .map(|(id, _)| *id)
        .collect();
    let after_chunks: BTreeSet<_> = after
        .records()
        .iter()
        .filter(|(_, record)| record.kind() == ObjectKind::Chunk)
        .map(|(id, _)| *id)
        .collect();
    let shared = before_chunks.intersection(&after_chunks).count();
    assert!(
        shared.saturating_mul(100) >= before_chunks.len().saturating_mul(90),
        "only {shared} of {} original chunks survived a local insertion",
        before_chunks.len()
    );
}

#[test]
fn profile_identity_is_deterministic_and_seeded() {
    let bytes = deterministic_bytes(1024 * 1024);
    let first = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &bytes).unwrap();
    let second = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &bytes).unwrap();
    assert_eq!(first.descriptor(), second.descriptor());
    let boundaries: Vec<_> = fastcdc::v2020::FastCDC::with_level_and_seed(
        &bytes,
        16 * 1024,
        64 * 1024,
        256 * 1024,
        fastcdc::v2020::Normalization::Level1,
        0,
    )
    .map(|chunk| chunk.length)
    .collect();
    assert_eq!(
        boundaries,
        vec![
            94_129, 73_623, 28_537, 107_508, 87_622, 224_123, 45_882, 98_297, 40_690, 69_224,
            121_633, 57_308,
        ]
    );
    assert_eq!(first.descriptor().chunk_count(), boundaries.len() as u64);
    let seeded = ChunkingProfile::fastcdc_v2020(16 * 1024, 64 * 1024, 256 * 1024, 7).unwrap();
    let alternate = build_content(&TestIdentity, seeded, &bytes).unwrap();
    assert_ne!(first.descriptor().file(), alternate.descriptor().file());
    assert_eq!(
        read_content(
            &MapSource::new(alternate.records()),
            alternate.descriptor().file()
        )
        .unwrap(),
        bytes
    );

    let zeros = build_content(
        &TestIdentity,
        ChunkingProfile::ASTRID_V1,
        &vec![0_u8; 1024 * 1024],
    )
    .unwrap();
    assert_eq!(zeros.descriptor().chunk_count(), 4);
    assert_eq!(zeros.unique_chunks(), 1);
}

#[test]
fn whole_object_threshold_matches_the_measured_profile_policy() {
    let profile = ChunkingProfile::fastcdc_v2020(64, 256, 1024, 0).unwrap();
    for length in [1, 63, 64, 256, 1024] {
        let bytes = deterministic_bytes(length);
        let built = build_content(&TestIdentity, profile, &bytes).unwrap();
        assert_eq!(built.descriptor().chunk_count(), 1, "length {length}");
        assert_eq!(
            built
                .records()
                .iter()
                .filter(|(_, record)| record.kind() == ObjectKind::Chunk)
                .count(),
            1,
            "length {length}"
        );
    }
    let above_threshold =
        build_content(&TestIdentity, profile, &deterministic_bytes(1025)).unwrap();
    assert!(above_threshold.descriptor().chunk_count() > 1);

    let (file, source) = manual_content(profile, &[vec![1; 64], vec![2; 64]]);
    assert!(matches!(
        describe_content(&source, file),
        Err(ContentReadError::Content(ContentError::InvalidObject {
            object,
            detail: "file chunk count violates the whole-object threshold",
        })) if object == file
    ));
}

#[test]
fn declared_profile_bounds_reject_adversarial_chunk_shapes() {
    let profile = ChunkingProfile::fastcdc_v2020(64, 256, 1024, 0).unwrap();
    for chunks in [
        vec![vec![1; 63], vec![2; 962]],
        vec![vec![1; 64], vec![2; 1025]],
    ] {
        let (file, source) = manual_content(profile, &chunks);
        assert!(matches!(
            read_content(&source, file),
            Err(ContentReadError::Content(ContentError::InvalidObject {
                detail: "content shape violates the declared chunking profile",
                ..
            }))
        ));
        assert_eq!(
            source.loads.get(),
            2,
            "profile-invalid child metadata should fail before loading chunks"
        );
    }

    let expected = [vec![1; 1024], vec![2; 1]].concat();
    let (file, source) = manual_content(profile, &[vec![1; 1024], vec![2; 1]]);
    assert_eq!(read_content(&source, file).unwrap(), expected);
}

#[test]
fn malformed_and_missing_content_fail_closed() {
    let bytes = deterministic_bytes(1024 * 1024);
    let built = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &bytes).unwrap();
    let mut source = MapSource::new(built.records());
    let missing = *source
        .records
        .iter()
        .find(|(_, record)| record.kind() == ObjectKind::Chunk)
        .unwrap()
        .0;
    source.records.remove(&missing);
    assert!(matches!(
        read_content(&source, built.descriptor().file()),
        Err(ContentReadError::Content(ContentError::MissingObject(id))) if id == missing
    ));

    let mut source = MapSource::new(built.records());
    let file = built.descriptor().file();
    let original = source.records.get(&file).unwrap();
    let mut header = original.canonical_bytes().to_vec();
    header[32..40].copy_from_slice(&(built.descriptor().chunk_count() + 1).to_le_bytes());
    let malformed = ObjectRecord::new(
        ObjectKind::File,
        original.format_version(),
        header,
        original.references().to_vec(),
        original.logical_bytes(),
        original.class(),
    )
    .unwrap();
    source.records.insert(file, malformed);
    assert!(matches!(
        read_content(&source, file),
        Err(ContentReadError::Content(
            ContentError::InvalidObject { object, .. }
        )) if object != file
    ));
}

#[test]
fn invalid_profiles_and_ranges_are_rejected() {
    assert!(matches!(
        ChunkingProfile::fastcdc_v2020(1024, 1024, 4096, 0),
        Err(ContentError::InvalidProfile(_))
    ));
    let bytes = b"range".to_vec();
    let built = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &bytes).unwrap();
    let source = MapSource::new(built.records());
    assert!(matches!(
        read_content_range(&source, built.descriptor().file(), 4, 2),
        Err(ContentReadError::Content(
            ContentError::RangeOutOfBounds { .. }
        ))
    ));
}
