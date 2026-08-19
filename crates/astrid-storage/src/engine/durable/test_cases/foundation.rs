// Tests for the native durable principal-state engine.
use std::io::{Read, Seek, SeekFrom, Write};
use std::fs::File;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use super::*;

#[derive(Clone, Copy, Debug)]
pub(super) struct TestIdentity;

pub(super) const TEST_IDENTITY_SCHEME: IdentityScheme = match IdentityScheme::new(u16::MAX, 1) {
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

#[derive(Clone, Debug)]
struct BlockingIdentity {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

impl ObjectIdentity for BlockingIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        self.entered.wait();
        self.release.wait();
        TestIdentity.identify(record)
    }
}

impl PersistentObjectIdentity for BlockingIdentity {
    fn scheme(&self) -> IdentityScheme {
        TEST_IDENTITY_SCHEME
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Utf8Codec;

impl PrincipalCodec<String> for Utf8Codec {
    fn encode(&self, principal: &String) -> Vec<u8> {
        principal.as_bytes().to_vec()
    }

    fn decode(&self, bytes: &[u8]) -> Option<String> {
        std::str::from_utf8(bytes).ok().map(str::to_owned)
    }
}

#[derive(Clone, Copy, Debug)]
struct U64Codec;

impl PrincipalCodec<u64> for U64Codec {
    fn encode(&self, principal: &u64) -> Vec<u8> {
        principal.to_le_bytes().to_vec()
    }

    fn decode(&self, bytes: &[u8]) -> Option<u64> {
        <[u8; 8]>::try_from(bytes).ok().map(u64::from_le_bytes)
    }
}

#[derive(Debug)]
struct FailAt(FaultPoint);

impl FaultInjector for FailAt {
    fn should_fail(&self, point: FaultPoint) -> bool {
        point == self.0
    }
}

#[derive(Debug)]
struct RecoveryIoFailures {
    remaining: AtomicUsize,
    attempts: AtomicUsize,
}

impl RecoveryIoFailures {
    fn new(failures: usize) -> Self {
        Self {
            remaining: AtomicUsize::new(failures),
            attempts: AtomicUsize::new(0),
        }
    }
}

#[derive(Debug)]
struct RecoveryFlushFailure {
    point: FaultPoint,
    remaining: AtomicUsize,
    observed: Mutex<Vec<FaultPoint>>,
}

impl RecoveryFlushFailure {
    fn once(point: FaultPoint) -> Self {
        Self {
            point,
            remaining: AtomicUsize::new(1),
            observed: Mutex::new(Vec::new()),
        }
    }

    fn observed(&self) -> Vec<FaultPoint> {
        self.observed.lock().clone()
    }
}

impl FaultInjector for RecoveryFlushFailure {
    fn should_fail(&self, point: FaultPoint) -> bool {
        if matches!(
            point,
            FaultPoint::BeforeInProcessRecoveryArenaFlush
                | FaultPoint::BeforeInProcessRecoveryRootFlush
        ) {
            self.observed.lock().push(point);
        }
        point == self.point
            && self
                .remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
    }
}

impl FaultInjector for RecoveryIoFailures {
    fn should_fail(&self, point: FaultPoint) -> bool {
        if point != FaultPoint::BeforeInProcessRecoveryOpen {
            return false;
        }
        self.attempts.fetch_add(1, Ordering::Relaxed);
        self.remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
    }
}

pub(super) type TestEngine = DurableEngine<String, TestIdentity, Utf8Codec>;

pub(super) fn limits() -> RecoveryLimits {
    RecoveryLimits::new(1024 * 1024).unwrap()
}

fn label(bytes: &[u8]) -> ReferenceLabel {
    ReferenceLabel::new(bytes.to_vec())
}

pub(super) fn open(path: &Path) -> TestEngine {
    DurableEngine::open(path, TestIdentity, Utf8Codec, limits()).unwrap()
}

#[test]
fn physical_frame_discriminants_are_stable() {
    assert_eq!(ARENA_MAGIC, *b"ASTOBJ1\0");
    assert_eq!(ROOT_MAGIC, *b"ASTROOT\0");
    assert_eq!(INDEX_MAGIC, *b"ASTIDX1\0");
    assert_eq!(FRAME_VERSION, 1);
    assert_eq!(FRAME_HEADER_LEN, 52);
    assert_eq!(FRAME_HEADER_LEN_USIZE, 52);
    assert_eq!(CHECKSUM_START, 20);
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

pub(super) fn open_with_cache(path: &Path, controller: ObjectCacheController) -> TestEngine {
    let principal_capacity =
        ObjectCacheCapacity::Bounded(std::num::NonZeroU64::new(1024 * 1024).unwrap());
    DurableEngine::open_with_object_cache(
        path,
        TestIdentity,
        Utf8Codec,
        limits(),
        ObjectCacheConfig::new(controller, Arc::new(move |_: &String| principal_capacity)),
    )
    .unwrap()
}

pub(super) fn transaction(
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

pub(super) fn flip_byte(path: &Path, offset: u64) {
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
