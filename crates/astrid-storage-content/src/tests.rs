use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;

use astrid_storage_model::{
    ObjectClass, ObjectId, ObjectIdentity, ObjectKind, ObjectRecord, ReferenceKind,
};

use crate::{
    ChunkingProfile, ContentError, ContentReadError, ContentSource, build_content,
    describe_content, read_content, read_content_range,
};

#[derive(Clone, Copy)]
struct TestIdentity;

impl ObjectIdentity for TestIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        let mut hasher = blake3::Hasher::new_derive_key("astrid content DAG tests v1");
        hasher.update(&record.kind().code().to_le_bytes());
        hasher.update(&record.format_version().get().to_le_bytes());
        hasher.update(&(record.canonical_bytes().len() as u128).to_le_bytes());
        hasher.update(record.canonical_bytes());
        hasher.update(&record.logical_bytes().to_le_bytes());
        hasher.update(&[match record.class() {
            ObjectClass::Data => 0,
            ObjectClass::Metadata => 1,
        }]);
        hasher.update(&(record.references().len() as u128).to_le_bytes());
        for reference in record.references() {
            hasher.update(&(reference.label().as_bytes().len() as u128).to_le_bytes());
            hasher.update(reference.label().as_bytes());
            hasher.update(reference.target().as_bytes());
            hasher.update(&[match reference.kind() {
                ReferenceKind::Owns => 0,
                ReferenceKind::Evidence => 1,
                ReferenceKind::Lineage => 2,
                ReferenceKind::Derived => 3,
            }]);
        }
        ObjectId::new(*hasher.finalize().as_bytes())
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
            (state >> 37) as u8
        })
        .collect()
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
        assert_eq!(
            read_content_range(&source, built.descriptor().file(), offset, length).unwrap(),
            bytes[offset as usize..(offset + length) as usize]
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
