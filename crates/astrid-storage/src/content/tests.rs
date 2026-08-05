use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use astrid_storage_engine::{
    CommitOutcome, DurableEngine, IdentityScheme, InMemoryEngine, PersistentObjectIdentity,
    PrincipalCodec, PrincipalProjectionEngine, PrincipalProjectionError, ProjectionCacheEntry,
    ProjectionCacheKey, RecoveryLimits, RootTransaction,
};
use astrid_storage_model::{
    InsertOutcome, ModelError, ObjectClass, ObjectId, ObjectIdentity, ObjectKind, ObjectRecord,
    ObjectReference, ReferenceKind, ReferenceLabel, RootState,
};
use fastcdc::v2020::{FastCDC, Normalization};
use parking_lot::RwLock;

use super::{
    BulkIngestPolicy, ContentChangeCache, ContentIngest, ContentName, ContentNameError,
    ContentObservation, PrincipalContentError, PrincipalContentStore, SourceEpoch,
    SourceFingerprint, SourceObservation, SourceScopeId, StableSourceId,
};
use crate::StorageError;
use crate::kv::{KvStore, TreeKvStore};
use crate::principal_graph::PRINCIPAL_GRAPH_VERSION;

#[derive(Clone, Copy)]
struct TestIdentity;

impl ObjectIdentity for TestIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        let mut hasher = blake3::Hasher::new_derive_key("astrid content store tests v1");
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

const TEST_IDENTITY_SCHEME: IdentityScheme = match IdentityScheme::new(u16::MAX, 7) {
    Some(scheme) => scheme,
    None => unreachable!(),
};

impl PersistentObjectIdentity for TestIdentity {
    fn scheme(&self) -> IdentityScheme {
        TEST_IDENTITY_SCHEME
    }
}

#[derive(Clone, Copy)]
struct Utf8Codec;

impl PrincipalCodec<String> for Utf8Codec {
    fn encode(&self, principal: &String) -> Vec<u8> {
        principal.as_bytes().to_vec()
    }

    fn decode(&self, bytes: &[u8]) -> Option<String> {
        std::str::from_utf8(bytes).ok().map(str::to_owned)
    }
}

type Engine = InMemoryEngine<String, TestIdentity>;
type TestProjectionKey = (String, ObjectId, ProjectionCacheKey);
type TestProjectionMap = BTreeMap<TestProjectionKey, ProjectionCacheEntry>;

#[test]
fn projection_engine_trait_remains_object_safe() {
    let engine = Engine::new(TestIdentity);
    let erased: &dyn PrincipalProjectionEngine<String> = &engine;
    assert!(
        erased
            .current_root(&"object-safety".to_owned())
            .unwrap()
            .is_none()
    );
}

struct ConflictOnceEngine {
    inner: Engine,
    conflict: AtomicBool,
}

impl ConflictOnceEngine {
    fn new() -> Self {
        Self {
            inner: Engine::new(TestIdentity),
            conflict: AtomicBool::new(true),
        }
    }
}

impl PrincipalProjectionEngine<String> for ConflictOnceEngine {
    fn identify_object(&self, record: &ObjectRecord) -> ObjectId {
        self.inner.identify(record)
    }

    fn stage_object(
        &self,
        record: ObjectRecord,
    ) -> Result<(ObjectId, InsertOutcome), PrincipalProjectionError> {
        self.inner.put_object(record).map_err(Into::into)
    }

    fn current_root(
        &self,
        principal: &String,
    ) -> Result<Option<RootState>, PrincipalProjectionError> {
        Ok(self.inner.root(principal))
    }

    fn load_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, PrincipalProjectionError> {
        Ok(self.inner.object(id))
    }

    fn commit_root(
        &self,
        transaction: RootTransaction<String>,
    ) -> Result<CommitOutcome, PrincipalProjectionError> {
        if self.conflict.swap(false, Ordering::SeqCst) {
            return Err(ModelError::RootConflict {
                expected: transaction.expected(),
                actual: self.inner.root(transaction.principal()),
            }
            .into());
        }
        self.inner.commit(transaction).map_err(Into::into)
    }

    fn flush_projection(&self) -> Result<(), PrincipalProjectionError> {
        Ok(())
    }
}

struct CountingEngine {
    inner: Engine,
    object_loads: AtomicUsize,
    projection_cache: RwLock<TestProjectionMap>,
}

impl CountingEngine {
    fn new() -> Self {
        Self {
            inner: Engine::new(TestIdentity),
            object_loads: AtomicUsize::new(0),
            projection_cache: RwLock::new(BTreeMap::new()),
        }
    }

    fn reset_object_loads(&self) {
        self.object_loads.store(0, Ordering::SeqCst);
    }

    fn object_loads(&self) -> usize {
        self.object_loads.load(Ordering::SeqCst)
    }

    fn clear_projection_cache(&self) {
        self.projection_cache.write().clear();
    }
}

impl PrincipalProjectionEngine<String> for CountingEngine {
    fn identify_object(&self, record: &ObjectRecord) -> ObjectId {
        self.inner.identify(record)
    }

    fn stage_object(
        &self,
        record: ObjectRecord,
    ) -> Result<(ObjectId, InsertOutcome), PrincipalProjectionError> {
        self.inner.put_object(record).map_err(Into::into)
    }

    fn current_root(
        &self,
        principal: &String,
    ) -> Result<Option<RootState>, PrincipalProjectionError> {
        Ok(self.inner.root(principal))
    }

    fn load_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, PrincipalProjectionError> {
        self.object_loads.fetch_add(1, Ordering::SeqCst);
        Ok(self.inner.object(id))
    }

    fn load_projection_cache(
        &self,
        principal: &String,
        object: ObjectId,
        key: ProjectionCacheKey,
    ) -> Option<ProjectionCacheEntry> {
        self.projection_cache
            .read()
            .get(&(principal.clone(), object, key))
            .cloned()
    }

    fn retain_projection_cache(
        &self,
        principal: &String,
        object: ObjectId,
        key: ProjectionCacheKey,
        value: ProjectionCacheEntry,
    ) -> bool {
        self.projection_cache
            .write()
            .insert((principal.clone(), object, key), value);
        true
    }

    fn discard_projection_cache(
        &self,
        principal: &String,
        object: ObjectId,
        key: ProjectionCacheKey,
    ) -> bool {
        self.projection_cache
            .write()
            .remove(&(principal.clone(), object, key))
            .is_some()
    }

    fn commit_root(
        &self,
        transaction: RootTransaction<String>,
    ) -> Result<CommitOutcome, PrincipalProjectionError> {
        self.inner.commit(transaction).map_err(Into::into)
    }

    fn flush_projection(&self) -> Result<(), PrincipalProjectionError> {
        Ok(())
    }
}

fn bytes(length: usize) -> Vec<u8> {
    let mut state = 0x8f3f_73b5_cf1c_9ade_u64;
    (0..length)
        .map(|_| {
            state = state
                .wrapping_mul(2_862_933_555_777_941_757)
                .wrapping_add(3_037_000_493);
            (state >> 29).to_le_bytes()[0]
        })
        .collect()
}

#[test]
fn content_name_is_a_typed_validation_boundary() {
    let parsed: ContentName = "models/site.bin".parse().unwrap();
    assert_eq!(parsed.as_str(), "models/site.bin");
    assert_eq!(parsed.to_string(), "models/site.bin");
    assert_eq!(String::from(parsed), "models/site.bin");
    assert_eq!(ContentName::new(""), Err(ContentNameError::Empty));
    assert_eq!(
        ContentName::new("bad\0name"),
        Err(ContentNameError::ContainsNull)
    );
    assert!(matches!(
        ContentName::from_bytes(&[0xff]),
        Err(PrincipalContentError::InvalidName(
            ContentNameError::InvalidUtf8
        ))
    ));
}

struct CountingReader {
    bytes: Vec<u8>,
    offset: usize,
    bytes_read: Arc<AtomicUsize>,
}

impl Read for CountingReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let length = output
            .len()
            .min(self.bytes.len().saturating_sub(self.offset));
        if length == 0 {
            return Ok(0);
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or(io::Error::other("test reader position overflow"))?;
        output[..length].copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        self.bytes_read.fetch_add(length, Ordering::SeqCst);
        Ok(length)
    }
}

struct RendezvousReader {
    bytes: Vec<u8>,
    offset: usize,
    first_read: Arc<Barrier>,
}

impl Read for RendezvousReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.offset == 0 {
            self.first_read.wait();
        }
        let length = output
            .len()
            .min(self.bytes.len().saturating_sub(self.offset));
        if length == 0 {
            return Ok(0);
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or(io::Error::other("test reader position overflow"))?;
        output[..length].copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        Ok(length)
    }
}

struct FailAfter {
    bytes: Vec<u8>,
    offset: usize,
    limit: usize,
}

impl Read for FailAfter {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.offset >= self.limit {
            return Err(io::Error::other("injected streaming source failure"));
        }
        let length = output
            .len()
            .min(self.limit.saturating_sub(self.offset))
            .min(self.bytes.len().saturating_sub(self.offset));
        if length == 0 {
            return Ok(0);
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or(io::Error::other("test reader position overflow"))?;
        output[..length].copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        Ok(length)
    }
}

#[test]
fn named_content_round_trips_lists_ranges_and_deletes() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let owner = "alice".to_owned();
    let name = ContentName::new("models/site.bin").unwrap();
    let value = bytes(2 * 1024 * 1024);
    let outcome = store.put(&owner, &name, &value).unwrap();
    assert!(outcome.objects_inserted() > 3);
    assert_eq!(store.read(&owner, &name).unwrap(), Some(value.clone()));
    assert_eq!(
        store.read_range(&owner, &name, 999_000, 12_345).unwrap(),
        Some(value[999_000..1_011_345].to_vec())
    );
    assert_eq!(
        store.list(&owner).unwrap(),
        vec![super::ContentEntry::new(
            name.clone(),
            outcome.descriptor().file(),
            value.len() as u64,
        )]
    );
    assert!(store.delete(&owner, &name).unwrap());
    assert!(!store.delete(&owner, &name).unwrap());
    assert_eq!(store.read(&owner, &name).unwrap(), None);
}

#[test]
fn open_read_handle_remains_on_its_authorized_generation() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(engine);
    let owner = "alice".to_owned();
    let name = ContentName::new("models/current.bin").unwrap();
    let original = bytes(2 * 1024 * 1024);
    let replacement = bytes(1024 * 1024);
    let first = store.put(&owner, &name, &original).unwrap();
    let handle = store.open_read(&owner, &name).unwrap().unwrap();

    assert_eq!(handle.descriptor(), first.descriptor());
    assert_eq!(handle.principal_root(), first.principal_root());
    assert_eq!(
        handle.read_range(999_000, 12_345).unwrap(),
        original[999_000..1_011_345]
    );

    store.put(&owner, &name, &replacement).unwrap();
    assert_eq!(handle.read().unwrap(), original);
    assert_eq!(store.read(&owner, &name).unwrap(), Some(replacement));

    assert!(store.delete(&owner, &name).unwrap());
    assert_eq!(handle.read_range(17, 4096).unwrap(), original[17..4113]);
    assert!(store.open_read(&owner, &name).unwrap().is_none());
}

#[test]
fn verified_handle_reuse_survives_an_unrelated_root_commit() {
    let engine = Arc::new(CountingEngine::new());
    let writer = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let reader = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let owner = "alice".to_owned();
    let name = ContentName::new("models/stable.bin").unwrap();
    let value = bytes(2 * 1024 * 1024);
    writer.put(&owner, &name, &value).unwrap();
    let handle = reader.open_read(&owner, &name).unwrap().unwrap();

    writer
        .put(
            &owner,
            &ContentName::new("state/unrelated.bin").unwrap(),
            b"unrelated root movement",
        )
        .unwrap();
    assert_ne!(
        Some(handle.principal_root()),
        engine.current_root(&owner).unwrap()
    );
    assert_eq!(handle.read().unwrap(), value);

    engine.reset_object_loads();
    assert_eq!(
        handle.read_range(999_000, 12_345).unwrap(),
        value[999_000..1_011_345]
    );
    let verified_loads = engine.object_loads();

    engine.clear_projection_cache();
    let uncached = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let uncached_handle = uncached.open_read(&owner, &name).unwrap().unwrap();
    engine.reset_object_loads();
    assert_eq!(
        uncached_handle.read_range(999_000, 12_345).unwrap(),
        value[999_000..1_011_345]
    );
    let validating_loads = engine.object_loads();

    assert!(
        verified_loads < validating_loads,
        "verified handle loaded {verified_loads} objects; validating handle loaded {validating_loads}"
    );
}

#[test]
fn range_edge_proofs_are_principal_scoped_and_remain_safe_for_open_handles() {
    let engine = Arc::new(CountingEngine::new());
    let writer = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let reader = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let alice = "alice".to_owned();
    let bob = "bob".to_owned();
    let name = ContentName::new("models/shared.bin").unwrap();
    let value = bytes(8 * 1024 * 1024);
    writer.put(&alice, &name, &value).unwrap();
    writer.put(&bob, &name, &value).unwrap();
    engine.clear_projection_cache();
    let alice_handle = reader.open_read(&alice, &name).unwrap().unwrap();
    let bob_handle = reader.open_read(&bob, &name).unwrap().unwrap();
    let offset = 4_000_000_u64;
    let length = 64 * 1024_u64;
    let start = usize::try_from(offset).unwrap();
    let end = usize::try_from(offset + length).unwrap();

    engine.reset_object_loads();
    assert_eq!(
        alice_handle.read_range(offset, length).unwrap(),
        value[start..end]
    );
    let alice_first = engine.object_loads();

    engine.reset_object_loads();
    assert_eq!(
        alice_handle.read_range(offset, length).unwrap(),
        value[start..end]
    );
    let alice_reused = engine.object_loads();
    assert!(
        alice_reused < alice_first,
        "reused range loaded {alice_reused} objects; first validation loaded {alice_first}"
    );

    engine.reset_object_loads();
    assert_eq!(
        bob_handle.read_range(offset, length).unwrap(),
        value[start..end]
    );
    assert!(
        engine.object_loads() >= alice_first,
        "Bob reused Alice's verification evidence"
    );

    assert!(reader.delete(&alice, &name).unwrap());
    engine.reset_object_loads();
    assert_eq!(
        alice_handle.read_range(offset, length).unwrap(),
        value[start..end]
    );
    assert!(
        engine.object_loads() <= alice_reused,
        "an authorized open handle lost governed immutable evidence after catalog deletion"
    );
}

#[test]
fn one_shot_reads_reuse_the_current_decoded_header() {
    let engine = Arc::new(CountingEngine::new());
    let writer = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let reader = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let owner = "alice".to_owned();
    let name = ContentName::new("catalog/target.bin").unwrap();
    let value = bytes(2 * 1024 * 1024);
    writer.put(&owner, &name, &value).unwrap();
    for index in 0..64 {
        writer
            .put(
                &owner,
                &ContentName::new(format!("catalog/other-{index}.bin")).unwrap(),
                format!("value-{index}").as_bytes(),
            )
            .unwrap();
    }

    engine.reset_object_loads();
    assert_eq!(
        reader.read_range(&owner, &name, 999_000, 12_345).unwrap(),
        Some(value[999_000..1_011_345].to_vec())
    );
    let first_loads = engine.object_loads();

    engine.reset_object_loads();
    assert_eq!(
        reader.read_range(&owner, &name, 999_000, 12_345).unwrap(),
        Some(value[999_000..1_011_345].to_vec())
    );
    let cached_loads = engine.object_loads();
    assert!(
        cached_loads < first_loads,
        "cached one-shot read loaded {cached_loads} objects; first read loaded {first_loads}"
    );

    writer
        .put(
            &owner,
            &ContentName::new("catalog/new-generation.bin").unwrap(),
            b"new root generation",
        )
        .unwrap();
    engine.reset_object_loads();
    assert_eq!(
        reader.read_range(&owner, &name, 999_000, 12_345).unwrap(),
        Some(value[999_000..1_011_345].to_vec())
    );
    let next_generation_loads = engine.object_loads();
    assert!(
        next_generation_loads > cached_loads,
        "new generation loaded {next_generation_loads} objects; cached generation loaded {cached_loads}"
    );
}

#[test]
fn streamed_content_matches_slice_identity_and_round_trips() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(engine);
    let value = bytes(2 * 1024 * 1024);
    let streamed = store
        .put_streaming(
            &"alice".to_owned(),
            &ContentName::new("streamed").unwrap(),
            value.as_slice(),
        )
        .unwrap();
    let sliced = store
        .put(
            &"bob".to_owned(),
            &ContentName::new("sliced").unwrap(),
            &value,
        )
        .unwrap();

    assert_eq!(streamed.descriptor(), sliced.descriptor());
    assert_eq!(
        store
            .read(&"alice".to_owned(), &ContentName::new("streamed").unwrap())
            .unwrap(),
        Some(value)
    );
    assert!(sliced.objects_inserted() < streamed.objects_inserted());
}

#[test]
fn streamed_content_survives_durable_engine_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let owner = "alice".to_owned();
    let name = ContentName::new("durable").unwrap();
    let value = bytes(2 * 1024 * 1024);
    let engine = Arc::new(
        DurableEngine::open(
            directory.path(),
            TestIdentity,
            Utf8Codec,
            RecoveryLimits::new(1024 * 1024).unwrap(),
        )
        .unwrap(),
    );
    let store = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let outcome = store
        .put_streaming(&owner, &name, value.as_slice())
        .unwrap();
    assert_eq!(store.read(&owner, &name).unwrap(), Some(value.clone()));
    drop(store);
    drop(engine);

    let reopened = Arc::new(
        DurableEngine::open(
            directory.path(),
            TestIdentity,
            Utf8Codec,
            RecoveryLimits::new(1024 * 1024).unwrap(),
        )
        .unwrap(),
    );
    let store = PrincipalContentStore::from_engine(reopened);
    assert_eq!(
        store.describe(&owner, &name).unwrap(),
        Some(outcome.descriptor())
    );
    assert_eq!(store.read(&owner, &name).unwrap(), Some(value));
}

#[test]
fn cold_range_after_reopen_rejects_a_tampered_neighbour_chunk() {
    let directory = tempfile::tempdir().unwrap();
    let owner = "alice".to_owned();
    let name = ContentName::new("durable-neighbour").unwrap();
    let value = bytes(8 * 1024 * 1024);
    let profile = astrid_storage_content::ChunkingProfile::ASTRID_V1;
    let chunks: Vec<_> = FastCDC::with_level_and_seed(
        &value,
        usize::try_from(profile.minimum_bytes()).unwrap(),
        usize::try_from(profile.average_bytes()).unwrap(),
        usize::try_from(profile.maximum_bytes()).unwrap(),
        Normalization::Level1,
        profile.gear_seed(),
    )
    .collect();
    assert!(chunks.len() >= 3);
    let selected = chunks.len() / 2;
    let target = &chunks[selected];
    let neighbour = &chunks[selected - 1];

    let engine = Arc::new(
        DurableEngine::open(
            directory.path(),
            TestIdentity,
            Utf8Codec,
            RecoveryLimits::new(1024 * 1024).unwrap(),
        )
        .unwrap(),
    );
    let store = PrincipalContentStore::from_engine(Arc::clone(&engine));
    store.put(&owner, &name, &value).unwrap();
    drop(store);
    drop(engine);

    let reopened = Arc::new(
        DurableEngine::open(
            directory.path(),
            TestIdentity,
            Utf8Codec,
            RecoveryLimits::new(1024 * 1024).unwrap(),
        )
        .unwrap(),
    );
    let store = PrincipalContentStore::from_engine(reopened);
    let arena_path = directory.path().join("objects.arena");
    let arena = std::fs::read(&arena_path).unwrap();
    let neighbour_end = neighbour.offset.checked_add(neighbour.length).unwrap();
    let neighbour_bytes = &value[neighbour.offset..neighbour_end];
    let needle = &neighbour_bytes[..64];
    let matches: Vec<_> = arena
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == needle).then_some(offset))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "test neighbour prefix must identify exactly one arena payload"
    );
    let corrupt_offset = matches[0].saturating_add(17);
    let mut arena = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&arena_path)
        .unwrap();
    arena
        .seek(SeekFrom::Start(u64::try_from(corrupt_offset).unwrap()))
        .unwrap();
    let mut byte = [0_u8; 1];
    arena.read_exact(&mut byte).unwrap();
    byte[0] ^= 0x80;
    arena
        .seek(SeekFrom::Start(u64::try_from(corrupt_offset).unwrap()))
        .unwrap();
    arena.write_all(&byte).unwrap();
    arena.sync_data().unwrap();

    let range_offset = u64::try_from(target.offset.saturating_add(8)).unwrap();
    let error = store
        .read_range(&owner, &name, range_offset, 32)
        .unwrap_err();
    assert!(
        error.to_string().contains("checksum"),
        "unexpected cold tamper error: {error}"
    );
}

#[test]
fn streaming_source_failure_stages_only_unreachable_objects() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let owner = "alice".to_owned();
    let source = FailAfter {
        bytes: bytes(8 * 1024 * 1024),
        offset: 0,
        limit: 6 * 1024 * 1024,
    };

    let error = store
        .put_streaming(&owner, &ContentName::new("broken").unwrap(), source)
        .unwrap_err();
    assert!(matches!(&error, PrincipalContentError::ContentSource(_)));
    assert!(
        std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<io::Error>()
            .is_some()
    );
    assert_eq!(engine.root(&owner), None);
    assert!(engine.object_count() > 0);
    assert!(store.list(&owner).unwrap().is_empty());
}

#[test]
fn root_conflict_retries_publication_without_rereading_the_source() {
    let engine = Arc::new(ConflictOnceEngine::new());
    let store = PrincipalContentStore::from_engine(engine);
    let value = bytes(2 * 1024 * 1024);
    let bytes_read = Arc::new(AtomicUsize::new(0));
    let source = CountingReader {
        bytes: value.clone(),
        offset: 0,
        bytes_read: Arc::clone(&bytes_read),
    };
    let owner = "alice".to_owned();
    let name = ContentName::new("retry").unwrap();

    store.put_streaming(&owner, &name, source).unwrap();

    assert_eq!(bytes_read.load(Ordering::SeqCst), value.len());
    assert_eq!(store.read(&owner, &name).unwrap(), Some(value));
}

#[test]
fn streaming_batch_publishes_every_name_under_one_root() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let owner = "alice".to_owned();
    let alpha = bytes(2 * 1024 * 1024);
    let middle = bytes(257 * 1024);
    let zeta = b"last in canonical order".to_vec();

    let outcome = store
        .put_streaming_batch(
            &owner,
            [
                ContentIngest::new(ContentName::new("zeta").unwrap(), zeta.as_slice()),
                ContentIngest::new(ContentName::new("alpha").unwrap(), alpha.as_slice()),
                ContentIngest::new(ContentName::new("middle").unwrap(), middle.as_slice()),
            ],
        )
        .unwrap();

    assert_eq!(outcome.principal_root().generation.get(), 0);
    assert_eq!(
        outcome
            .entries()
            .iter()
            .map(|entry| entry.name().as_str())
            .collect::<Vec<_>>(),
        ["alpha", "middle", "zeta"]
    );
    for (name, expected) in [("alpha", alpha), ("middle", middle), ("zeta", zeta)] {
        assert_eq!(
            store
                .read(&owner, &ContentName::new(name).unwrap())
                .unwrap(),
            Some(expected)
        );
    }
}

#[test]
fn streaming_batch_honors_explicit_source_parallelism() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(engine);
    let first_read = Arc::new(Barrier::new(2));
    let source = |value| RendezvousReader {
        bytes: value,
        offset: 0,
        first_read: Arc::clone(&first_read),
    };

    let outcome = store
        .put_streaming_batch_with_policy(
            &"alice".to_owned(),
            [
                ContentIngest::new(
                    ContentName::new("first").unwrap(),
                    source(bytes(1024 * 1024)),
                ),
                ContentIngest::new(
                    ContentName::new("second").unwrap(),
                    source(bytes(1024 * 1024 + 1)),
                ),
            ],
            BulkIngestPolicy::new(NonZeroUsize::new(2).unwrap()),
        )
        .unwrap();

    assert_eq!(outcome.entries().len(), 2);
}

fn source_fingerprint(
    path: &str,
    logical_bytes: u64,
    modified_nanoseconds: i128,
) -> SourceFingerprint {
    SourceFingerprint::new(
        SourceScopeId::new([0x11; 32]),
        PathBuf::from(path),
        logical_bytes,
        modified_nanoseconds,
        StableSourceId::new([0x22; 16]),
        SourceEpoch::new([0x33; 32]),
    )
}

#[test]
fn trusted_change_token_reuses_a_byte_verified_descriptor_without_reading() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(engine);
    let cache = ContentChangeCache::new(NonZeroU64::new(1024 * 1024).unwrap());
    let value = bytes(2 * 1024 * 1024);
    let fingerprint = source_fingerprint("/workspace/model.bin", value.len() as u64, 42);
    let observation = SourceObservation::trusted(fingerprint);
    let first_reads = Arc::new(AtomicUsize::new(0));
    let first = CountingReader {
        bytes: value.clone(),
        offset: 0,
        bytes_read: Arc::clone(&first_reads),
    };
    let name = ContentName::new("model.bin").unwrap();

    let first_outcome = store
        .put_streaming_batch_with_change_cache(
            &"alice".to_owned(),
            [ContentIngest::new(name.clone(), first).with_observation(observation.clone())],
            BulkIngestPolicy::new(NonZeroUsize::MIN),
            &cache,
        )
        .unwrap();
    assert_eq!(first_reads.load(Ordering::SeqCst), value.len());
    assert_eq!(
        first_outcome.entries()[0].observation(),
        ContentObservation::BytesObserved
    );

    let repeated_reads = Arc::new(AtomicUsize::new(0));
    let repeated = CountingReader {
        bytes: value,
        offset: 0,
        bytes_read: Arc::clone(&repeated_reads),
    };
    let repeated_outcome = store
        .put_streaming_batch_with_change_cache(
            &"alice".to_owned(),
            [ContentIngest::new(name, repeated).with_observation(observation)],
            BulkIngestPolicy::new(NonZeroUsize::MIN),
            &cache,
        )
        .unwrap();

    assert_eq!(repeated_reads.load(Ordering::SeqCst), 0);
    assert_eq!(
        repeated_outcome.entries()[0].observation(),
        ContentObservation::ChangeTokenObserved
    );
    assert_eq!(cache.entry_count(), 1);
    assert!(cache.retained_bytes() > 0);
}

#[test]
fn change_token_never_crosses_chunking_profiles() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(engine);
    let cache = ContentChangeCache::new(NonZeroU64::new(1024 * 1024).unwrap());
    let value = bytes(2 * 1024 * 1024);
    let observation = SourceObservation::trusted(source_fingerprint(
        "/workspace/profile.bin",
        value.len() as u64,
        42,
    ));
    let name = ContentName::new("profile.bin").unwrap();
    store
        .put_streaming_batch_with_change_cache(
            &"alice".to_owned(),
            [ContentIngest::new(name.clone(), value.as_slice())
                .with_observation(observation.clone())],
            BulkIngestPolicy::new(NonZeroUsize::MIN),
            &cache,
        )
        .unwrap();

    let alternate = super::ChunkingProfile::fastcdc_v2020(
        8 * 1024,
        32 * 1024,
        128 * 1024,
        super::ChunkingProfile::ASTRID_V1.gear_seed(),
    )
    .unwrap();
    let bytes_read = Arc::new(AtomicUsize::new(0));
    let outcome = store
        .put_streaming_batch_with_change_cache(
            &"alice".to_owned(),
            [ContentIngest::with_profile(
                name,
                CountingReader {
                    bytes: value.clone(),
                    offset: 0,
                    bytes_read: Arc::clone(&bytes_read),
                },
                alternate,
            )
            .with_observation(observation)],
            BulkIngestPolicy::new(NonZeroUsize::MIN),
            &cache,
        )
        .unwrap();

    assert_eq!(bytes_read.load(Ordering::SeqCst), value.len());
    assert_eq!(outcome.entries()[0].descriptor().profile(), alternate);
    assert_eq!(
        outcome.entries()[0].observation(),
        ContentObservation::BytesObserved
    );
}

#[test]
fn change_cache_entry_missing_from_this_engine_falls_back_to_source_bytes() {
    let cache = ContentChangeCache::new(NonZeroU64::new(1024 * 1024).unwrap());
    let value = bytes(512 * 1024);
    let observation = SourceObservation::trusted(source_fingerprint(
        "/workspace/reopened-elsewhere.bin",
        value.len() as u64,
        73,
    ));
    let first = PrincipalContentStore::from_engine(Arc::new(Engine::new(TestIdentity)));
    first
        .put_streaming_batch_with_change_cache(
            &"alice".to_owned(),
            [
                ContentIngest::new(ContentName::new("first").unwrap(), value.as_slice())
                    .with_observation(observation.clone()),
            ],
            BulkIngestPolicy::new(NonZeroUsize::MIN),
            &cache,
        )
        .unwrap();

    let second = PrincipalContentStore::from_engine(Arc::new(Engine::new(TestIdentity)));
    let bytes_read = Arc::new(AtomicUsize::new(0));
    second
        .put_streaming_batch_with_change_cache(
            &"alice".to_owned(),
            [ContentIngest::new(
                ContentName::new("second").unwrap(),
                CountingReader {
                    bytes: value.clone(),
                    offset: 0,
                    bytes_read: Arc::clone(&bytes_read),
                },
            )
            .with_observation(observation)],
            BulkIngestPolicy::new(NonZeroUsize::MIN),
            &cache,
        )
        .unwrap();

    assert_eq!(bytes_read.load(Ordering::SeqCst), value.len());
}

#[test]
fn untrusted_or_changed_metadata_never_skips_source_bytes() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(engine);
    let cache = ContentChangeCache::new(NonZeroU64::new(1024 * 1024).unwrap());
    let value = bytes(1024 * 1024);
    let name = ContentName::new("source.bin").unwrap();
    let trusted = SourceObservation::trusted(source_fingerprint(
        "/imports/source.bin",
        value.len() as u64,
        7,
    ));
    store
        .put_streaming_batch_with_change_cache(
            &"alice".to_owned(),
            [ContentIngest::new(name.clone(), value.as_slice()).with_observation(trusted)],
            BulkIngestPolicy::new(NonZeroUsize::MIN),
            &cache,
        )
        .unwrap();

    for observation in [
        SourceObservation::untrusted(source_fingerprint(
            "/imports/source.bin",
            value.len() as u64,
            7,
        )),
        SourceObservation::trusted(source_fingerprint(
            "/imports/source.bin",
            value.len() as u64,
            8,
        )),
    ] {
        let bytes_read = Arc::new(AtomicUsize::new(0));
        let reader = CountingReader {
            bytes: value.clone(),
            offset: 0,
            bytes_read: Arc::clone(&bytes_read),
        };
        let outcome = store
            .put_streaming_batch_with_change_cache(
                &"alice".to_owned(),
                [ContentIngest::new(name.clone(), reader).with_observation(observation)],
                BulkIngestPolicy::new(NonZeroUsize::MIN),
                &cache,
            )
            .unwrap();

        assert_eq!(bytes_read.load(Ordering::SeqCst), value.len());
        assert_eq!(
            outcome.entries()[0].observation(),
            ContentObservation::BytesObserved
        );
    }
}

#[test]
fn untrusted_metadata_never_consumes_change_cache_capacity() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(engine);
    let cache = ContentChangeCache::new(NonZeroU64::new(1024 * 1024).unwrap());
    let value = bytes(128 * 1024);
    let observation = SourceObservation::untrusted(source_fingerprint(
        "/imports/untrusted.bin",
        value.len() as u64,
        9,
    ));

    store
        .put_streaming_batch_with_change_cache(
            &"alice".to_owned(),
            [
                ContentIngest::new(ContentName::new("untrusted").unwrap(), value.as_slice())
                    .with_observation(observation),
            ],
            BulkIngestPolicy::new(NonZeroUsize::MIN),
            &cache,
        )
        .unwrap();

    assert_eq!(cache.entry_count(), 0);
    assert_eq!(cache.retained_bytes(), 0);
}

#[test]
fn change_cache_capacity_is_a_retention_limit_not_an_ingest_limit() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(engine);
    let cache = ContentChangeCache::new(NonZeroU64::MIN);
    let value = bytes(128 * 1024);
    let observation = SourceObservation::trusted(source_fingerprint(
        "/workspace/too-large-for-cache.bin",
        value.len() as u64,
        1,
    ));

    store
        .put_streaming_batch_with_change_cache(
            &"alice".to_owned(),
            [
                ContentIngest::new(ContentName::new("first").unwrap(), value.as_slice())
                    .with_observation(observation.clone()),
            ],
            BulkIngestPolicy::new(NonZeroUsize::MIN),
            &cache,
        )
        .unwrap();
    assert_eq!(cache.entry_count(), 0);
    assert_eq!(cache.retained_bytes(), 0);

    let bytes_read = Arc::new(AtomicUsize::new(0));
    store
        .put_streaming_batch_with_change_cache(
            &"alice".to_owned(),
            [ContentIngest::new(
                ContentName::new("second").unwrap(),
                CountingReader {
                    bytes: value.clone(),
                    offset: 0,
                    bytes_read: Arc::clone(&bytes_read),
                },
            )
            .with_observation(observation)],
            BulkIngestPolicy::new(NonZeroUsize::MIN),
            &cache,
        )
        .unwrap();

    assert_eq!(bytes_read.load(Ordering::SeqCst), value.len());
}

#[test]
fn failed_batch_never_teaches_the_change_cache() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(engine);
    let cache = ContentChangeCache::new(NonZeroU64::new(1024 * 1024).unwrap());
    let value = bytes(2 * 1024 * 1024);
    let observation = SourceObservation::trusted(source_fingerprint(
        "/workspace/interrupted.bin",
        value.len() as u64,
        11,
    ));

    let error = store
        .put_streaming_batch_with_change_cache(
            &"alice".to_owned(),
            [ContentIngest::new(
                ContentName::new("interrupted").unwrap(),
                FailAfter {
                    bytes: value.clone(),
                    offset: 0,
                    limit: value.len() / 2,
                },
            )
            .with_observation(observation.clone())],
            BulkIngestPolicy::new(NonZeroUsize::MIN),
            &cache,
        )
        .unwrap_err();
    assert!(matches!(error, PrincipalContentError::ContentSource(_)));
    assert_eq!(cache.entry_count(), 0);

    let bytes_read = Arc::new(AtomicUsize::new(0));
    store
        .put_streaming_batch_with_change_cache(
            &"alice".to_owned(),
            [ContentIngest::new(
                ContentName::new("recovered").unwrap(),
                CountingReader {
                    bytes: value.clone(),
                    offset: 0,
                    bytes_read: Arc::clone(&bytes_read),
                },
            )
            .with_observation(observation)],
            BulkIngestPolicy::new(NonZeroUsize::MIN),
            &cache,
        )
        .unwrap();
    assert_eq!(bytes_read.load(Ordering::SeqCst), value.len());
}

#[test]
fn streaming_batch_rejects_duplicate_names_before_reading() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(engine);
    let bytes_read = Arc::new(AtomicUsize::new(0));
    let source = || CountingReader {
        bytes: bytes(1024),
        offset: 0,
        bytes_read: Arc::clone(&bytes_read),
    };
    let name = ContentName::new("same").unwrap();

    let error = store
        .put_streaming_batch(
            &"alice".to_owned(),
            [
                ContentIngest::new(name.clone(), source()),
                ContentIngest::new(name.clone(), source()),
            ],
        )
        .unwrap_err();

    assert!(matches!(error, PrincipalContentError::DuplicateBatchName(found) if found == name));
    assert_eq!(bytes_read.load(Ordering::SeqCst), 0);
}

#[test]
fn streaming_batch_source_failure_publishes_nothing() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let owner = "alice".to_owned();
    let first = FailAfter {
        bytes: bytes(2 * 1024 * 1024),
        offset: 0,
        limit: usize::MAX,
    };
    let second = FailAfter {
        bytes: bytes(8 * 1024 * 1024),
        offset: 0,
        limit: 3 * 1024 * 1024,
    };

    let error = store
        .put_streaming_batch(
            &owner,
            [
                ContentIngest::new(ContentName::new("first").unwrap(), first),
                ContentIngest::new(ContentName::new("second").unwrap(), second),
            ],
        )
        .unwrap_err();

    assert!(matches!(error, PrincipalContentError::ContentSource(_)));
    assert_eq!(engine.root(&owner), None);
    assert!(store.list(&owner).unwrap().is_empty());
}

#[test]
fn streaming_batch_root_conflict_does_not_reread_sources() {
    let engine = Arc::new(ConflictOnceEngine::new());
    let store = PrincipalContentStore::from_engine(engine);
    let first = bytes(2 * 1024 * 1024);
    let second = bytes(3 * 1024 * 1024);
    let bytes_read = Arc::new(AtomicUsize::new(0));
    let reader = |value: Vec<u8>| CountingReader {
        bytes: value,
        offset: 0,
        bytes_read: Arc::clone(&bytes_read),
    };

    store
        .put_streaming_batch(
            &"alice".to_owned(),
            [
                ContentIngest::new(ContentName::new("first").unwrap(), reader(first.clone())),
                ContentIngest::new(ContentName::new("second").unwrap(), reader(second.clone())),
            ],
        )
        .unwrap();

    assert_eq!(
        bytes_read.load(Ordering::SeqCst),
        first.len() + second.len()
    );
}

#[test]
fn principals_and_aliases_share_physical_objects_but_not_logical_usage() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let value = bytes(4 * 1024 * 1024);
    let alice = "alice".to_owned();
    let bob = "bob".to_owned();
    let first = store
        .put(&alice, &ContentName::new("first").unwrap(), &value)
        .unwrap();
    let second = store
        .put(&bob, &ContentName::new("copy").unwrap(), &value)
        .unwrap();
    assert_eq!(first.descriptor().file(), second.descriptor().file());
    assert!(
        second.objects_inserted() < first.objects_inserted() / 4,
        "second principal inserted {} objects after first inserted {}",
        second.objects_inserted(),
        first.objects_inserted()
    );

    store
        .put(&alice, &ContentName::new("alias").unwrap(), &value)
        .unwrap();
    assert_eq!(
        engine.principal_usage(&alice).unwrap().logical_bytes,
        (value.len() as u64) * 2
    );
    assert_eq!(
        engine.principal_usage(&bob).unwrap().logical_bytes,
        value.len() as u64
    );
}

#[test]
fn aliases_cannot_turn_deduplication_into_free_quota() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let quota = Arc::new(|_: &String| Ok(Some(150_u64)));
    let store = PrincipalContentStore::from_engine_with_quota(engine, quota);
    let owner = "alice".to_owned();
    let value = vec![7_u8; 100];
    store
        .put(&owner, &ContentName::new("one").unwrap(), &value)
        .unwrap();
    assert!(matches!(
        store.put(&owner, &ContentName::new("two").unwrap(), &value),
        Err(PrincipalContentError::QuotaExceeded {
            used: 206,
            limit: 150
        })
    ));
}

#[tokio::test]
async fn kv_and_content_share_one_principal_quota_and_root() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let quota = Arc::new(|_: &String| Ok(Some(128_u64)));
    let content = PrincipalContentStore::from_engine_with_quota(Arc::clone(&engine), quota.clone());
    let kv = TreeKvStore::<String, TestIdentity, _, _>::from_engine_with_quota(
        Arc::clone(&engine),
        |namespace: &str| Ok(namespace.to_owned()),
        quota,
    );
    kv.set("alice", "key", vec![1_u8; 64]).await.unwrap();
    assert!(matches!(
        content.put(
            &"alice".to_owned(),
            &ContentName::new("blob").unwrap(),
            &[2_u8; 64]
        ),
        Err(PrincipalContentError::QuotaExceeded { .. })
    ));

    content
        .put(
            &"alice".to_owned(),
            &ContentName::new("small").unwrap(),
            &[3_u8; 16],
        )
        .unwrap();
    assert_eq!(kv.get("alice", "key").await.unwrap(), Some(vec![1_u8; 64]));
    assert_eq!(
        content
            .read(&"alice".to_owned(), &ContentName::new("small").unwrap())
            .unwrap(),
        Some(vec![3_u8; 16])
    );
}

#[tokio::test]
async fn kv_growth_accounts_for_existing_content() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let quota = Arc::new(|_: &String| Ok(Some(128_u64)));
    let content = PrincipalContentStore::from_engine_with_quota(Arc::clone(&engine), quota.clone());
    let kv = TreeKvStore::<String, TestIdentity, _, _>::from_engine_with_quota(
        engine,
        |namespace: &str| Ok(namespace.to_owned()),
        quota,
    );
    content
        .put(
            &"alice".to_owned(),
            &ContentName::new("blob").unwrap(),
            &[3_u8; 64],
        )
        .unwrap();
    assert!(kv.set("alice", "key", vec![1_u8; 64]).await.is_err());
    assert_eq!(
        content
            .read(&"alice".to_owned(), &ContentName::new("blob").unwrap())
            .unwrap(),
        Some(vec![3_u8; 64])
    );
}

#[tokio::test]
async fn content_write_revalidates_kv_quota_instead_of_trusting_the_head() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let kv = TreeKvStore::<String, TestIdentity, _, _>::from_engine(
        Arc::clone(&engine),
        |namespace: &str| Ok(namespace.to_owned()),
    );
    kv.set("alice", "key", vec![1_u8; 64]).await.unwrap();
    publish_forged_kv_quota(engine.as_ref(), &"alice".to_owned());

    let content = PrincipalContentStore::from_engine(engine);
    assert!(matches!(
        content.put(
            &"alice".to_owned(),
            &ContentName::new("blob").unwrap(),
            &[2_u8; 16]
        ),
        Err(PrincipalContentError::InvalidGraph {
            detail: "invalid KV component accounting",
            ..
        })
    ));
}

fn publish_forged_kv_quota(engine: &Engine, principal: &String) {
    let root = engine.root(principal).unwrap();
    let commit = engine.object(root.commit).unwrap();
    let state_id = commit
        .reference(&ReferenceLabel::new(b"state".to_vec()))
        .unwrap()
        .target();
    let state = engine.object(state_id).unwrap();
    let kv_id = state
        .reference(&ReferenceLabel::new(b"kv".to_vec()))
        .unwrap()
        .target();
    let kv = engine.object(kv_id).unwrap();
    let mut bytes = kv.canonical_bytes().to_vec();
    bytes[25..33].copy_from_slice(&0_u64.to_le_bytes());
    let forged_kv = ObjectRecord::new(
        ObjectKind::NamespaceMap,
        PRINCIPAL_GRAPH_VERSION,
        bytes,
        kv.references().to_vec(),
        kv.logical_bytes(),
        ObjectClass::Metadata,
    )
    .unwrap();
    let forged_kv_id = engine.identify(&forged_kv);
    let forged_state = ObjectRecord::new(
        ObjectKind::PrincipalState,
        PRINCIPAL_GRAPH_VERSION,
        Vec::new(),
        vec![ObjectReference::owns(
            ReferenceLabel::new(b"kv".to_vec()),
            forged_kv_id,
        )],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let forged_state_id = engine.identify(&forged_state);
    let forged_commit = ObjectRecord::new(
        ObjectKind::Commit,
        PRINCIPAL_GRAPH_VERSION,
        Vec::new(),
        vec![
            ObjectReference::new(
                ReferenceLabel::new(b"parent".to_vec()),
                root.commit,
                ReferenceKind::Lineage,
            ),
            ObjectReference::owns(ReferenceLabel::new(b"state".to_vec()), forged_state_id),
        ],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let forged_commit_id = engine.identify(&forged_commit);
    engine
        .commit(RootTransaction::new(
            principal.clone(),
            Some(root),
            forged_commit_id,
            vec![
                (forged_kv_id, forged_kv),
                (forged_state_id, forged_state),
                (forged_commit_id, forged_commit),
            ],
        ))
        .unwrap();
}

#[test]
fn concurrent_catalog_updates_retry_the_shared_root_cas() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = Arc::new(PrincipalContentStore::from_engine(engine));
    let mut workers = Vec::new();
    for index in 0..8 {
        let store = Arc::clone(&store);
        workers.push(std::thread::spawn(move || {
            store
                .put(
                    &"alice".to_owned(),
                    &ContentName::new(format!("blob-{index}")).unwrap(),
                    &bytes(128 * 1024 + index),
                )
                .unwrap();
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(store.list(&"alice".to_owned()).unwrap().len(), 8);
}

#[test]
fn principal_content_error_preserves_nested_sources() {
    let error = PrincipalContentError::Content(astrid_storage_content::ContentError::Model(
        ModelError::ArithmeticOverflow,
    ));
    let content_source = std::error::Error::source(&error).unwrap();
    let content_error = content_source
        .downcast_ref::<astrid_storage_content::ContentError>()
        .unwrap();
    let model_source = std::error::Error::source(content_error).unwrap();

    assert_eq!(
        model_source.downcast_ref::<ModelError>(),
        Some(&ModelError::ArithmeticOverflow)
    );

    let quota = PrincipalContentError::QuotaPolicy(StorageError::Connection(
        "policy service unavailable".to_owned(),
    ));
    assert!(
        std::error::Error::source(&quota)
            .unwrap()
            .downcast_ref::<StorageError>()
            .is_some()
    );
}
