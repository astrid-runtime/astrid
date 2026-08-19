use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::engine::{
    CommitOutcome, InMemoryEngine, KvProjectionEngine, KvProjectionError, ReadyKvRoot,
    RootSnapshot, RootTransaction,
};
use crate::kv::principal::KvPrincipalResolver;
use crate::kv::{KvReadCacheConfig, KvStore, TreeKvStore};
use crate::principal_state::Blake3ObjectIdentityV1;
use crate::storage_model::{ObjectId, ObjectRecord, RootState};
use crate::{StorageError, StorageResult};

#[derive(Clone, Copy)]
struct Resolver;

impl KvPrincipalResolver<String> for Resolver {
    fn resolve(&self, namespace: &str) -> StorageResult<String> {
        namespace
            .split_once(":capsule:")
            .map(|(principal, _)| principal.to_owned())
            .ok_or_else(|| StorageError::InvalidKey("test namespace has no owner".to_owned()))
    }
}

struct CountingEngine {
    inner: InMemoryEngine<String, Blake3ObjectIdentityV1>,
    object_loads: AtomicU64,
}

impl CountingEngine {
    fn new() -> Self {
        Self {
            inner: InMemoryEngine::new(Blake3ObjectIdentityV1),
            object_loads: AtomicU64::new(0),
        }
    }

    fn object_loads(&self) -> u64 {
        self.object_loads.load(Ordering::Acquire)
    }
}

impl KvProjectionEngine<String> for CountingEngine {
    fn identify_kv_object(&self, record: &ObjectRecord) -> ObjectId {
        self.inner.identify(record)
    }

    fn current_kv_root(&self, principal: &String) -> Result<Option<RootState>, KvProjectionError> {
        Ok(self.inner.root(principal))
    }

    fn current_kv_root_if_ready(&self, principal: &String) -> Option<ReadyKvRoot> {
        Some(ReadyKvRoot::new(self.inner.root(principal)))
    }

    fn load_kv_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, KvProjectionError> {
        self.object_loads.fetch_add(1, Ordering::AcqRel);
        Ok(self.inner.object(id))
    }

    fn snapshot_kv_root(
        &self,
        principal: &String,
    ) -> Result<Option<RootSnapshot>, KvProjectionError> {
        self.inner.snapshot(principal).map_err(Into::into)
    }

    fn commit_kv_root(
        &self,
        transaction: RootTransaction<String>,
    ) -> Result<CommitOutcome, KvProjectionError> {
        self.inner.commit(transaction).map_err(Into::into)
    }

    fn flush_kv(&self) -> Result<(), KvProjectionError> {
        Ok(())
    }
}

#[tokio::test]
async fn repeated_point_read_uses_root_scoped_hot_value() {
    let engine = Arc::new(CountingEngine::new());
    let store = TreeKvStore::<String, Blake3ObjectIdentityV1, Resolver, _>::from_engine(
        Arc::clone(&engine),
        Resolver,
    )
    .with_read_cache(KvReadCacheConfig::default());
    store
        .set("alice:capsule:test", "answer", vec![42; 128])
        .await
        .unwrap();

    assert_eq!(
        store.get("alice:capsule:test", "answer").await.unwrap(),
        Some(vec![42; 128])
    );
    let warmed_loads = engine.object_loads();
    assert!(warmed_loads > 0);

    for _ in 0..64 {
        assert_eq!(
            store.get("alice:capsule:test", "answer").await.unwrap(),
            Some(vec![42; 128])
        );
    }
    assert_eq!(engine.object_loads(), warmed_loads);

    store.reclaim_read_cache();
    assert_eq!(
        store.get("alice:capsule:test", "answer").await.unwrap(),
        Some(vec![42; 128])
    );
    assert!(engine.object_loads() > warmed_loads);
}

#[tokio::test]
async fn hot_value_never_crosses_root_or_principal_boundaries() {
    let engine = Arc::new(InMemoryEngine::new(Blake3ObjectIdentityV1));
    let alice_reader = TreeKvStore::<String, Blake3ObjectIdentityV1, Resolver, _>::from_engine(
        Arc::clone(&engine),
        Resolver,
    )
    .with_read_cache(KvReadCacheConfig::default());
    let independent_writer =
        TreeKvStore::<String, Blake3ObjectIdentityV1, Resolver, _>::from_engine(
            Arc::clone(&engine),
            Resolver,
        );

    alice_reader
        .set("alice:capsule:test", "key", b"old".to_vec())
        .await
        .unwrap();
    assert_eq!(
        alice_reader.get("alice:capsule:test", "key").await.unwrap(),
        Some(b"old".to_vec())
    );
    assert_eq!(
        alice_reader.get("bob:capsule:test", "key").await.unwrap(),
        None
    );

    independent_writer
        .set("alice:capsule:test", "key", b"new".to_vec())
        .await
        .unwrap();
    independent_writer
        .set("bob:capsule:test", "key", b"bob".to_vec())
        .await
        .unwrap();

    assert_eq!(
        alice_reader.get("alice:capsule:test", "key").await.unwrap(),
        Some(b"new".to_vec())
    );
    assert_eq!(
        alice_reader.get("bob:capsule:test", "key").await.unwrap(),
        Some(b"bob".to_vec())
    );
}

#[tokio::test]
async fn owner_purge_reclaims_only_that_owners_hot_entries() {
    let engine = Arc::new(CountingEngine::new());
    let store = TreeKvStore::<String, Blake3ObjectIdentityV1, Resolver, _>::from_engine(
        Arc::clone(&engine),
        Resolver,
    )
    .with_read_cache(KvReadCacheConfig::default());

    store
        .set("alice:capsule:test", "key", b"alice".to_vec())
        .await
        .unwrap();
    store
        .set("bob:capsule:test", "key", b"bob".to_vec())
        .await
        .unwrap();
    assert_eq!(
        store.get("alice:capsule:test", "key").await.unwrap(),
        Some(b"alice".to_vec())
    );
    assert_eq!(
        store.get("bob:capsule:test", "key").await.unwrap(),
        Some(b"bob".to_vec())
    );

    assert_eq!(store.clear_owner(&"alice".to_owned()).unwrap(), 1);
    let loads_after_purge = engine.object_loads();
    assert_eq!(
        store.get("bob:capsule:test", "key").await.unwrap(),
        Some(b"bob".to_vec())
    );
    assert_eq!(engine.object_loads(), loads_after_purge);
    assert_eq!(store.get("alice:capsule:test", "key").await.unwrap(), None);
    assert!(engine.object_loads() > loads_after_purge);
}
