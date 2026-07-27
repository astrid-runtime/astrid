//! Tests for the native durable principal-state engine.
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Barrier};
use std::thread;

use super::*;

#[derive(Clone, Copy, Debug)]
struct TestIdentity;

const TEST_IDENTITY_SCHEME: IdentityScheme = match IdentityScheme::new(u16::MAX, 1) {
    Some(scheme) => scheme,
    None => unreachable!(),
};

impl ObjectIdentity for TestIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        let mut hasher = blake3::Hasher::new_derive_key("astrid durable engine test identity v1");
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

impl PersistentObjectIdentity for TestIdentity {
    fn scheme(&self) -> IdentityScheme {
        TEST_IDENTITY_SCHEME
    }
}

#[derive(Clone, Copy, Debug)]
struct ConstantIdentity;

impl ObjectIdentity for ConstantIdentity {
    fn identify(&self, _record: &ObjectRecord) -> ObjectId {
        ObjectId::new([42; 32])
    }
}

impl PersistentObjectIdentity for ConstantIdentity {
    fn scheme(&self) -> IdentityScheme {
        TEST_IDENTITY_SCHEME
    }
}

#[derive(Clone, Copy, Debug)]
struct Utf8Codec;

impl PrincipalCodec<String> for Utf8Codec {
    fn encode(&self, principal: &String) -> Vec<u8> {
        principal.as_bytes().to_vec()
    }

    fn decode(&self, bytes: &[u8]) -> Option<String> {
        std::str::from_utf8(bytes).ok().map(str::to_owned)
    }
}

#[derive(Debug)]
struct FailAt(FaultPoint);

impl FaultInjector for FailAt {
    fn should_fail(&self, point: FaultPoint) -> bool {
        point == self.0
    }
}

type TestEngine = DurableEngine<String, TestIdentity, Utf8Codec>;

fn limits() -> RecoveryLimits {
    RecoveryLimits::new(1024 * 1024).unwrap()
}

fn label(bytes: &[u8]) -> ReferenceLabel {
    ReferenceLabel::new(bytes.to_vec())
}

fn open(path: &Path) -> TestEngine {
    DurableEngine::open(path, TestIdentity, Utf8Codec, limits()).unwrap()
}

fn open_with_fault(path: &Path, point: FaultPoint) -> TestEngine {
    DurableEngine::open_with_faults(
        path,
        TestIdentity,
        Utf8Codec,
        limits(),
        Arc::new(FailAt(point)),
    )
    .unwrap()
}

fn transaction(
    principal: &str,
    expected: Option<RootState>,
    payload: &[u8],
) -> (ObjectId, RootTransaction<String>) {
    let identity = TestIdentity;
    let leaf = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        payload.to_vec(),
        Vec::new(),
        u64::try_from(payload.len()).unwrap(),
        ObjectClass::Data,
    )
    .unwrap();
    let leaf_id = identity.identify(&leaf);
    let commit = ObjectRecord::new(
        ObjectKind::Commit,
        ObjectFormatVersion::V1,
        payload.to_vec(),
        vec![ObjectReference::owns(label(b"state"), leaf_id)],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let commit_id = identity.identify(&commit);
    (
        commit_id,
        RootTransaction::new(
            principal.to_owned(),
            expected,
            commit_id,
            vec![(leaf_id, leaf), (commit_id, commit)],
        ),
    )
}

fn append_partial_header(path: &Path, magic: [u8; 8]) {
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(&magic[..5]).unwrap();
    file.sync_data().unwrap();
}

fn append_torn_payload(path: &Path, magic: [u8; 8]) {
    let payload = b"incomplete";
    let payload_len = u64::try_from(payload.len()).unwrap();
    let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
    header[..8].copy_from_slice(&magic);
    header[8..10].copy_from_slice(&FRAME_VERSION.to_le_bytes());
    header[12..20].copy_from_slice(&payload_len.to_le_bytes());
    header[CHECKSUM_START..].copy_from_slice(&frame_checksum(magic, payload_len, payload));
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(&header).unwrap();
    file.write_all(&payload[..3]).unwrap();
    file.sync_data().unwrap();
}

fn append_orphan_object(path: &Path) -> u64 {
    let valid_len = std::fs::metadata(path).unwrap().len();
    let record = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        b"uncommitted tail".to_vec(),
        Vec::new(),
        16,
        ObjectClass::Data,
    )
    .unwrap();
    let id = TestIdentity.identify(&record);
    let payload = encode_object_frame(TEST_IDENTITY_SCHEME, id, &record).unwrap();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let location = append_frame(&mut file, ARENA_MAGIC, &payload).unwrap();
    assert_eq!(location.offset, valid_len);
    file.sync_data().unwrap();
    valid_len
}

fn frame_end(path: &Path, offset: u64) -> u64 {
    let mut file = File::open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
    file.read_exact(&mut header).unwrap();
    let payload_len = u64::from_le_bytes(header[12..20].try_into().unwrap());
    offset
        .checked_add(FRAME_HEADER_LEN)
        .and_then(|value| value.checked_add(payload_len))
        .unwrap()
}

fn flip_byte(path: &Path, offset: u64) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut byte = [0_u8; 1];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0x80;
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_data().unwrap();
}

#[test]
fn object_frame_round_trips_binary_typed_records() {
    let target = ObjectId::new([9; 32]);
    let record = ObjectRecord::new(
        ObjectKind::PrincipalState,
        ObjectFormatVersion::new(7).unwrap(),
        vec![0, 255, 19],
        vec![
            ObjectReference::new(
                ReferenceLabel::new(vec![0, 1]),
                target,
                ReferenceKind::Evidence,
            ),
            ObjectReference::new(
                ReferenceLabel::new(vec![255]),
                ObjectId::new([10; 32]),
                ReferenceKind::Lineage,
            ),
        ],
        83,
        ObjectClass::Metadata,
    )
    .unwrap();
    let id = TestIdentity.identify(&record);

    let encoded = encode_object_frame(TEST_IDENTITY_SCHEME, id, &record).unwrap();
    let decoded = decode_object_frame(&encoded, TEST_IDENTITY_SCHEME).unwrap();

    assert_eq!(decoded, (id, record));
}

#[test]
fn object_frame_tags_own_and_reference_identities() {
    let target = ObjectId::new([9; 32]);
    let record = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        Vec::new(),
        vec![ObjectReference::new(
            label(b"x"),
            target,
            ReferenceKind::Evidence,
        )],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let id = TestIdentity.identify(&record);
    let encoded = encode_object_frame(TEST_IDENTITY_SCHEME, id, &record).unwrap();

    assert_eq!(
        &encoded[..8],
        &[255, 255, 1, 0, 32, 0, 0, 0],
        "the object identity carries algorithm, construction, and digest length"
    );
    assert_eq!(&encoded[8..40], id.as_bytes());
    let reference_identity = 69 + 8 + 1;
    assert_eq!(
        &encoded[reference_identity..reference_identity + 8],
        &[255, 255, 1, 0, 32, 0, 0, 0],
        "reference targets carry their own identity envelope"
    );
    assert_eq!(
        &encoded[reference_identity + 8..reference_identity + 40],
        target.as_bytes()
    );
}

#[test]
fn root_frame_tags_expected_and_replacement_identities() {
    let expected = RootState {
        generation: RootGeneration::new(3),
        commit: ObjectId::new([3; 32]),
    };
    let replacement = RootState {
        generation: RootGeneration::new(4),
        commit: ObjectId::new([4; 32]),
    };
    let encoded =
        encode_root_record(TEST_IDENTITY_SCHEME, b"a", Some(expected), replacement).unwrap();
    let expected_identity = 8 + 1 + 1 + 8;
    let replacement_identity = expected_identity + 40 + 8;

    for offset in [expected_identity, replacement_identity] {
        assert_eq!(&encoded[offset..offset + 8], &[255, 255, 1, 0, 32, 0, 0, 0]);
    }
}

#[test]
fn identity_digest_length_is_framed_not_fixed_by_the_wire() {
    let (_, transaction) = transaction("alice", None, b"extensible");
    let (id, record) = transaction.records().first().unwrap();
    let mut encoded = encode_object_frame(TEST_IDENTITY_SCHEME, *id, record).unwrap();
    encoded[4..8].copy_from_slice(&48_u32.to_le_bytes());
    encoded.splice(40..40, [0_u8; 16]);

    assert_eq!(
        decode_object_frame(&encoded, TEST_IDENTITY_SCHEME),
        Err("identity digest length does not match the supported scheme")
    );
}

#[test]
fn decoder_rejects_zero_and_unknown_identity_tags() {
    let (_, transaction) = transaction("alice", None, b"tagged");
    let (id, record) = transaction.records().first().unwrap();
    let encoded = encode_object_frame(TEST_IDENTITY_SCHEME, *id, record).unwrap();
    let mut zero = encoded.clone();
    zero[..2].copy_from_slice(&0_u16.to_le_bytes());
    let mut unknown = encoded;
    unknown[..2].copy_from_slice(&1_u16.to_le_bytes());

    assert_eq!(
        decode_object_frame(&zero, TEST_IDENTITY_SCHEME),
        Err("identity tag fields must be non-zero")
    );
    assert_eq!(
        decode_object_frame(&unknown, TEST_IDENTITY_SCHEME),
        Err("unsupported identity algorithm or construction version")
    );
}

#[test]
fn object_frame_rejects_zero_schema_version() {
    let (_, transaction) = transaction("alice", None, b"versioned");
    let (id, record) = transaction
        .records()
        .iter()
        .find(|(_, record)| record.kind() == ObjectKind::Commit)
        .unwrap();
    let mut encoded = encode_object_frame(TEST_IDENTITY_SCHEME, *id, record).unwrap();
    encoded[42..44].copy_from_slice(&0_u16.to_le_bytes());

    assert_eq!(
        decode_object_frame(&encoded, TEST_IDENTITY_SCHEME),
        Err("object-format version must be non-zero")
    );
}

#[test]
fn standalone_bootstrap_object_is_durable_and_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let record = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"format specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();

    let (id, inserted) = engine.persist_standalone_object(&record).unwrap();
    let (_, repeated) = engine.persist_standalone_object(&record).unwrap();
    assert_eq!(inserted, InsertOutcome::Inserted);
    assert_eq!(repeated, InsertOutcome::AlreadyPresent);
    assert_eq!(engine.object(id).unwrap(), Some(record.clone()));
    drop(engine);

    let reopened = open(directory.path());
    assert_eq!(reopened.object(id).unwrap(), Some(record));
    assert_eq!(reopened.object_count().unwrap(), 1);
}

#[test]
fn standalone_bootstrap_object_cannot_own_principal_state() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let record = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        Vec::new(),
        vec![ObjectReference::owns(
            label(b"state"),
            ObjectId::new([1; 32]),
        )],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();

    assert!(matches!(
        engine.persist_standalone_object(&record),
        Err(DurableError::BootstrapObjectOwnsState)
    ));
    assert_eq!(engine.object_count().unwrap(), 0);
}

#[test]
fn commit_flush_reopen_rebuilds_index_and_root() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (commit, transaction) = transaction("alice", None, b"durable");

    let outcome = engine.commit(transaction).unwrap();
    assert_eq!(outcome.objects_inserted(), 2);
    assert_eq!(outcome.root().commit, commit);
    engine.flush().unwrap();
    drop(engine);

    let reopened = open(directory.path());
    assert_eq!(
        reopened.root(&"alice".to_owned()).unwrap(),
        Some(outcome.root())
    );
    assert_eq!(reopened.object_count().unwrap(), 2);
    assert_eq!(
        reopened
            .snapshot(&"alice".to_owned())
            .unwrap()
            .unwrap()
            .records()
            .len(),
        2
    );
}

#[test]
fn every_exposed_fault_recovers_old_or_new_complete_root() {
    for point in [
        FaultPoint::AfterObjectAppend,
        FaultPoint::AfterObjectFlush,
        FaultPoint::AfterCommitAppend,
        FaultPoint::AfterCommitFlush,
        FaultPoint::BeforeRootCas,
        FaultPoint::AfterRootCas,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let initial = open(directory.path());
        let (_, first) = transaction("alice", None, b"before");
        let old = initial.commit(first).unwrap().root();
        drop(initial);

        let interrupted = open_with_fault(directory.path(), point);
        let (new_commit, update) = transaction("alice", Some(old), b"after");
        assert!(matches!(
            interrupted.commit(update),
            Err(DurableError::FaultInjected(actual)) if actual == point
        ));
        assert!(matches!(
            interrupted.snapshot(&"alice".to_owned()),
            Err(DurableError::RequiresRecovery)
        ));
        assert!(matches!(
            interrupted.root(&"alice".to_owned()),
            Err(DurableError::RequiresRecovery)
        ));
        assert!(matches!(
            interrupted.object_count(),
            Err(DurableError::RequiresRecovery)
        ));
        drop(interrupted);

        let recovered = open(directory.path());
        let visible = recovered.root(&"alice".to_owned()).unwrap().unwrap();
        if point == FaultPoint::AfterRootCas {
            assert_eq!(
                visible,
                RootState {
                    generation: RootGeneration::new(1),
                    commit: new_commit,
                },
                "point {point:?}"
            );
        } else {
            assert_eq!(visible, old, "point {point:?}");
        }
        assert!(recovered.snapshot(&"alice".to_owned()).unwrap().is_some());
    }
}

#[test]
fn truncated_arena_tail_is_removed_without_changing_root() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    let root = engine.commit(transaction).unwrap().root();
    drop(engine);
    let arena = directory.path().join(ARENA_FILE);
    let valid_len = std::fs::metadata(&arena).unwrap().len();
    append_partial_header(&arena, ARENA_MAGIC);

    let recovered = open(directory.path());

    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(root));
    assert_eq!(std::fs::metadata(arena).unwrap().len(), valid_len);
}

#[test]
fn truncated_root_payload_is_removed_without_changing_root() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    let root = engine.commit(transaction).unwrap().root();
    drop(engine);
    let journal = directory.path().join(ROOT_FILE);
    let valid_len = std::fs::metadata(&journal).unwrap().len();
    append_torn_payload(&journal, ROOT_MAGIC);

    let recovered = open(directory.path());

    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(root));
    assert_eq!(std::fs::metadata(journal).unwrap().len(), valid_len);
}

#[test]
fn complete_magic_corruption_at_tail_is_truncated() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    let root = engine.commit(transaction).unwrap().root();
    drop(engine);
    let arena = directory.path().join(ARENA_FILE);
    let valid_len = append_orphan_object(&arena);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&arena)
        .unwrap();
    file.seek(SeekFrom::Start(valid_len)).unwrap();
    file.write_all(&[0]).unwrap();
    file.sync_data().unwrap();
    drop(file);

    let recovered = open(directory.path());

    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(root));
    assert_eq!(std::fs::metadata(arena).unwrap().len(), valid_len);
}

#[test]
fn complete_checksum_corruption_at_tail_is_truncated() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    let root = engine.commit(transaction).unwrap().root();
    drop(engine);
    let arena = directory.path().join(ARENA_FILE);
    let valid_len = append_orphan_object(&arena);
    let tail_len = std::fs::metadata(&arena).unwrap().len();
    flip_byte(&arena, tail_len.saturating_sub(1));

    let recovered = open(directory.path());

    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(root));
    assert_eq!(std::fs::metadata(arena).unwrap().len(), valid_len);
}

#[test]
fn rooted_checksum_corruption_at_arena_tail_still_fails_closure_validation() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    let root = engine.commit(transaction).unwrap().root();
    drop(engine);
    let arena = directory.path().join(ARENA_FILE);
    let commit_offset = frame_end(&arena, 0);
    let tail_len = std::fs::metadata(&arena).unwrap().len();
    flip_byte(&arena, tail_len.saturating_sub(1));

    assert!(matches!(
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
        Err(DurableError::RecoveryModel {
            file: ROOT_FILE,
            source: ModelError::MissingObject(missing),
            ..
        }) if missing == root.commit
    ));
    assert_eq!(std::fs::metadata(arena).unwrap().len(), commit_offset);
}

#[test]
fn invalid_root_journal_tail_rolls_back_to_the_last_durable_root() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, first) = transaction("alice", None, b"before");
    let old = engine.commit(first).unwrap().root();
    let (_, second) = transaction("alice", Some(old), b"after");
    engine.commit(second).unwrap();
    drop(engine);
    let journal = directory.path().join(ROOT_FILE);
    let second_offset = frame_end(&journal, 0);
    let tail_len = std::fs::metadata(&journal).unwrap().len();
    flip_byte(&journal, tail_len.saturating_sub(1));

    let recovered = open(directory.path());

    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(old));
    assert_eq!(std::fs::metadata(journal).unwrap().len(), second_offset);
}

#[test]
fn interior_checksum_corruption_is_fatal_not_silently_truncated() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    engine.commit(transaction).unwrap();
    drop(engine);
    let arena = directory.path().join(ARENA_FILE);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(arena)
        .unwrap();
    file.seek(SeekFrom::Start(FRAME_HEADER_LEN + 33)).unwrap();
    let mut byte = [0_u8; 1];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0x80;
    file.seek(SeekFrom::Start(FRAME_HEADER_LEN + 33)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_data().unwrap();
    drop(file);

    assert!(matches!(
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
        Err(DurableError::Corrupt {
            file: ARENA_FILE,
            detail: "frame checksum mismatch",
            ..
        })
    ));
}

#[test]
fn interior_magic_corruption_is_fatal_not_silently_truncated() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    engine.commit(transaction).unwrap();
    drop(engine);
    let arena = directory.path().join(ARENA_FILE);
    let original_len = std::fs::metadata(&arena).unwrap().len();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&arena)
        .unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&[0]).unwrap();
    file.sync_data().unwrap();
    drop(file);

    assert!(matches!(
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
        Err(DurableError::Corrupt {
            file: ARENA_FILE,
            offset: 0,
            detail: "frame magic mismatch",
        })
    ));
    assert_eq!(std::fs::metadata(arena).unwrap().len(), original_len);
}

#[test]
fn live_snapshot_reads_indexed_objects_lazily_from_the_arena() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    engine.commit(transaction).unwrap();

    let arena = directory.path().join(ARENA_FILE);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(arena)
        .unwrap();
    file.seek(SeekFrom::Start(FRAME_HEADER_LEN + 33)).unwrap();
    let mut byte = [0_u8; 1];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0x80;
    file.seek(SeekFrom::Start(FRAME_HEADER_LEN + 33)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_data().unwrap();

    assert!(matches!(
        engine.snapshot(&"alice".to_owned()),
        Err(DurableError::Corrupt {
            file: ARENA_FILE,
            detail: "frame checksum mismatch",
            ..
        })
    ));
}

#[test]
fn recovery_reports_root_journal_model_failure_with_offset() {
    let directory = tempfile::tempdir().unwrap();
    drop(open(directory.path()));
    let journal = directory.path().join(ROOT_FILE);
    let payload = encode_root_record(
        TEST_IDENTITY_SCHEME,
        b"alice",
        None,
        RootState {
            generation: RootGeneration::INITIAL,
            commit: ObjectId::new([99; 32]),
        },
    )
    .unwrap();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(journal)
        .unwrap();
    append_frame(&mut file, ROOT_MAGIC, &payload).unwrap();
    file.sync_data().unwrap();
    drop(file);

    assert!(matches!(
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
        Err(DurableError::RecoveryModel {
            file: ROOT_FILE,
            offset: 0,
            source: ModelError::MissingObject(_),
        })
    ));
}

#[test]
fn recovery_never_accepts_an_identity_collision() {
    let directory = tempfile::tempdir().unwrap();
    drop(open(directory.path()));
    let first = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        b"first".to_vec(),
        Vec::new(),
        5,
        ObjectClass::Data,
    )
    .unwrap();
    let second = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        b"second".to_vec(),
        Vec::new(),
        6,
        ObjectClass::Data,
    )
    .unwrap();
    let id = ObjectId::new([42; 32]);
    let arena = directory.path().join(ARENA_FILE);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(arena)
        .unwrap();
    append_frame(
        &mut file,
        ARENA_MAGIC,
        &encode_object_frame(TEST_IDENTITY_SCHEME, id, &first).unwrap(),
    )
    .unwrap();
    append_frame(
        &mut file,
        ARENA_MAGIC,
        &encode_object_frame(TEST_IDENTITY_SCHEME, id, &second).unwrap(),
    )
    .unwrap();
    file.sync_data().unwrap();
    drop(file);

    assert!(matches!(
        DurableEngine::open(
            directory.path(),
            ConstantIdentity,
            Utf8Codec,
            limits()
        ),
        Err(DurableError::RecoveryModel {
            file: ARENA_FILE,
            source: ModelError::ObjectCollision(object),
            ..
        }) if object == id
    ));
}

#[test]
fn recovery_rejects_oversized_declaration_before_allocating_payload() {
    let directory = tempfile::tempdir().unwrap();
    drop(open(directory.path()));
    let arena = directory.path().join(ARENA_FILE);
    let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
    header[..8].copy_from_slice(&ARENA_MAGIC);
    header[8..10].copy_from_slice(&FRAME_VERSION.to_le_bytes());
    header[12..20].copy_from_slice(&1024_u64.to_le_bytes());
    let mut file = OpenOptions::new().append(true).open(arena).unwrap();
    file.write_all(&header).unwrap();
    file.sync_data().unwrap();
    drop(file);
    let tiny = RecoveryLimits::new(64).unwrap();

    assert!(matches!(
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, tiny),
        Err(DurableError::FrameTooLarge {
            file: ARENA_FILE,
            offset: 0,
            declared: 1024,
            limit: 64,
        })
    ));
}

#[test]
fn stale_root_conflict_appends_no_bytes_and_does_not_poison() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, first) = transaction("alice", None, b"first");
    let installed = engine.commit(first).unwrap().root();
    let arena = directory.path().join(ARENA_FILE);
    let journal = directory.path().join(ROOT_FILE);
    let before = (
        std::fs::metadata(&arena).unwrap().len(),
        std::fs::metadata(&journal).unwrap().len(),
    );
    let (_, stale) = transaction("alice", None, b"stale");

    assert!(matches!(
        engine.commit(stale),
        Err(DurableError::Model(ModelError::RootConflict { .. }))
    ));
    assert_eq!(
        before,
        (
            std::fs::metadata(arena).unwrap().len(),
            std::fs::metadata(journal).unwrap().len(),
        )
    );
    assert_eq!(engine.root(&"alice".to_owned()).unwrap(), Some(installed));
    assert!(engine.snapshot(&"alice".to_owned()).unwrap().is_some());
}

#[test]
fn concurrent_genesis_has_one_durable_winner() {
    let directory = tempfile::tempdir().unwrap();
    let engine = Arc::new(open(directory.path()));
    let barrier = Arc::new(Barrier::new(9));
    let mut handles = Vec::new();
    for value in 0_u8..8 {
        let engine = Arc::clone(&engine);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let (_, transaction) = transaction("alice", None, &[value]);
            barrier.wait();
            engine.commit(transaction)
        }));
    }
    barrier.wait();

    let mut successes = 0;
    for handle in handles {
        match handle.join().unwrap() {
            Ok(_) => successes += 1,
            Err(DurableError::Model(ModelError::RootConflict { .. })) => {},
            Err(error) => panic!("unexpected commit error: {error}"),
        }
    }
    assert_eq!(successes, 1);
    let root = engine.root(&"alice".to_owned()).unwrap().unwrap();
    drop(engine);

    let recovered = open(directory.path());
    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(root));
}

#[test]
fn second_writer_cannot_open_the_same_store() {
    let directory = tempfile::tempdir().unwrap();
    let first = open(directory.path());

    assert!(matches!(
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
        Err(DurableError::LockHeld(_))
    ));

    drop(first);
    assert!(DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()).is_ok());
}

#[test]
fn explicit_close_releases_files_while_engine_references_remain() {
    let directory = tempfile::tempdir().unwrap();
    let engine = Arc::new(open(directory.path()));
    let retained = Arc::clone(&engine);

    engine.close().unwrap();
    engine.close().unwrap();
    assert!(matches!(retained.object_count(), Err(DurableError::Closed)));

    let reopened = open(directory.path());
    assert_eq!(reopened.object_count().unwrap(), 0);
}

#[test]
fn configured_frame_boundary_rejects_before_writing() {
    let directory = tempfile::tempdir().unwrap();
    let tiny = RecoveryLimits::new(64).unwrap();
    let engine = DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, tiny).unwrap();
    let (_, transaction) = transaction("alice", None, b"too large");

    assert!(matches!(
        engine.commit(transaction),
        Err(DurableError::FrameTooLarge {
            file: ARENA_FILE,
            limit: 64,
            ..
        })
    ));
    assert_eq!(engine.object_count().unwrap(), 0);
    assert!(engine.snapshot(&"alice".to_owned()).unwrap().is_none());
    assert_eq!(
        std::fs::metadata(directory.path().join(ARENA_FILE))
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        std::fs::metadata(directory.path().join(ROOT_FILE))
            .unwrap()
            .len(),
        0
    );
}
