use std::io::{self, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use astrid_storage_engine::{
    CommitOutcome, DurableEngine, IdentityScheme, InMemoryEngine, PersistentObjectIdentity,
    PrincipalCodec, PrincipalProjectionEngine, PrincipalProjectionError, RecoveryLimits,
    RootTransaction,
};
use astrid_storage_model::{
    InsertOutcome, ModelError, ObjectClass, ObjectId, ObjectIdentity, ObjectRecord, ReferenceKind,
    RootState,
};

use super::{ContentName, PrincipalContentError, PrincipalContentStore};
use crate::kv::{KvStore, TreeKvStore};

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
fn streaming_source_failure_stages_only_unreachable_objects() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let owner = "alice".to_owned();
    let source = FailAfter {
        bytes: bytes(8 * 1024 * 1024),
        offset: 0,
        limit: 6 * 1024 * 1024,
    };

    assert!(matches!(
        store.put_streaming(&owner, &ContentName::new("broken").unwrap(), source),
        Err(PrincipalContentError::ContentSource(_))
    ));
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
}
