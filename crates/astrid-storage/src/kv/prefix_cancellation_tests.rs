//! Cancellation must stop parsing a native scan once its caller is gone.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use super::tree_tests::{Resolver, TestIdentity};
use super::{KvStore, ScopedKvStore, TreeKvStore};
use crate::engine::{
    CommitOutcome, InMemoryEngine, KvProjectionEngine, KvProjectionError, RootSnapshot,
    RootTransaction,
};
use crate::identity::{IdentityStore, KvIdentityStore};
use crate::storage_model::{ObjectClass, ObjectId, ObjectKind, ObjectRecord, RootState};

type Pause = (mpsc::Sender<()>, mpsc::Receiver<()>);

struct PausingReader {
    inner: InMemoryEngine<String, TestIdentity>,
    pause: Mutex<Option<Pause>>,
    value_reads: AtomicUsize,
}

impl KvProjectionEngine<String> for PausingReader {
    fn identify_kv_object(&self, record: &ObjectRecord) -> ObjectId {
        self.inner.identify(record)
    }
    fn current_kv_root(&self, principal: &String) -> Result<Option<RootState>, KvProjectionError> {
        Ok(self.inner.root(principal))
    }
    fn load_kv_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, KvProjectionError> {
        let record = self.inner.object(id);
        let pause = self.pause.lock().unwrap().take();
        if let Some((entered, release)) = pause {
            entered.send(()).unwrap();
            release.recv_timeout(Duration::from_secs(10)).unwrap();
        }
        if record.as_ref().is_some_and(|record| {
            record.kind() == ObjectKind::KvLeaf && record.class() == ObjectClass::Data
        }) {
            self.value_reads.fetch_add(1, Ordering::Relaxed);
        }
        Ok(record)
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_identity_prefix_scan_stops_reading_values() {
    let engine = Arc::new(PausingReader {
        inner: InMemoryEngine::new(TestIdentity),
        pause: Mutex::new(None),
        value_reads: AtomicUsize::new(0),
    });
    let backend = Arc::new(
        TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(engine.clone(), Resolver),
    );
    let namespace = "alice:capsule:identity";
    let reader = KvIdentityStore::new(ScopedKvStore::new(backend.clone(), namespace).unwrap());
    let user = reader.create_user(Some("target")).await.unwrap();
    for index in 0..32 {
        reader
            .link(
                "service",
                &format!("row-{index:04}"),
                user.id,
                &"x".repeat(2048),
            )
            .await
            .unwrap();
    }
    backend.checkpoint_for_test("alice".to_owned()).unwrap();
    // Warm header validation before counting the actual range's value reads.
    backend
        .get(namespace, "link/service/row-0000")
        .await
        .unwrap();
    engine.value_reads.store(0, Ordering::Relaxed);
    let baseline_refs = Arc::strong_count(&engine);
    let (entered, arrived) = mpsc::channel();
    let (release, released) = mpsc::channel();
    *engine.pause.lock().unwrap() = Some((entered, released));
    let query = tokio::spawn(async move { reader.list_links(user.id).await });
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(10)).unwrap())
        .await
        .unwrap();
    query.abort();
    assert!(query.await.unwrap_err().is_cancelled());
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while Arc::strong_count(&engine) != baseline_refs {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        engine.value_reads.load(Ordering::Relaxed) <= 1,
        "canceled scan kept reconstructing unrelated values"
    );
}
