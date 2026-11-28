//! Force a replacement between the conditional predicate and root publication.

use std::sync::{Arc, Barrier, mpsc};

use super::tree_tests::{Resolver, TestIdentity};
use super::{KvStore, TreeKvStore};
use crate::engine::{
    CommitOutcome, InMemoryEngine, KvProjectionEngine, KvProjectionError, RootSnapshot,
    RootTransaction,
};
use crate::storage_model::{ObjectId, ObjectRecord, RootState};

struct PausingEngine {
    inner: InMemoryEngine<String, TestIdentity>,
    pause: std::sync::Mutex<Option<mpsc::Sender<()>>>,
    resume: Barrier,
}

impl KvProjectionEngine<String> for PausingEngine {
    fn identify_kv_object(&self, record: &ObjectRecord) -> ObjectId {
        self.inner.identify(record)
    }
    fn current_kv_root(&self, principal: &String) -> Result<Option<RootState>, KvProjectionError> {
        Ok(self.inner.root(principal))
    }
    fn load_kv_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, KvProjectionError> {
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
        let pause = self.pause.lock().unwrap().take();
        if let Some(sender) = pause {
            sender.send(()).unwrap();
            self.resume.wait();
        }
        self.inner.commit(transaction).map_err(Into::into)
    }
    fn flush_kv(&self) -> Result<(), KvProjectionError> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_conflict_rechecks_delete_predicate_after_replacement() {
    check_conflicting_update(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_conflict_rechecks_swap_predicate_after_replacement() {
    check_conflicting_update(true).await;
}

async fn check_conflicting_update(swap: bool) {
    let engine = Arc::new(PausingEngine {
        inner: InMemoryEngine::new(TestIdentity),
        pause: std::sync::Mutex::new(None),
        resume: Barrier::new(2),
    });
    let store = Arc::new(
        TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(engine.clone(), Resolver),
    );
    let namespace = "alice:capsule:identity";
    store.set(namespace, "key", b"old".to_vec()).await.unwrap();
    let (sender, receiver) = mpsc::channel();
    *engine.pause.lock().unwrap() = Some(sender);
    let contender = store.clone();
    let pending = tokio::spawn(async move {
        if swap {
            contender
                .compare_and_swap(namespace, "key", Some(b"old"), b"candidate".to_vec())
                .await
        } else {
            contender
                .compare_and_delete(namespace, "key", b"old".to_vec())
                .await
        }
        .unwrap()
    });
    tokio::task::spawn_blocking(move || {
        receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
    })
    .await
    .unwrap();
    let writer =
        TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(engine.clone(), Resolver);
    let replacement = writer.set(namespace, "key", b"replacement".to_vec()).await;
    engine.resume.wait();
    replacement.unwrap();
    assert!(!pending.await.unwrap());
    assert_eq!(
        store.get(namespace, "key").await.unwrap(),
        Some(b"replacement".to_vec())
    );
}
