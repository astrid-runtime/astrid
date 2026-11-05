//! Delayed historical readers must not evict current checkpoint validation.

use super::*;
use std::sync::{Mutex, mpsc};
use std::time::Duration;

struct HeadReadGate {
    object: ObjectId,
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
}

struct CheckpointCommitGate {
    entered: mpsc::SyncSender<RootState>,
    release: mpsc::Receiver<()>,
}

struct GatedEngine {
    measured: MeasuringEngine,
    gate: Mutex<Option<HeadReadGate>>,
    committed_checkpoint: Mutex<Option<CheckpointCommitGate>>,
}

impl GatedEngine {
    fn new() -> Self {
        Self {
            measured: MeasuringEngine::new(),
            gate: Mutex::new(None),
            committed_checkpoint: Mutex::new(None),
        }
    }

    fn gate_once(&self, object: ObjectId) -> (mpsc::Receiver<()>, mpsc::SyncSender<()>) {
        let (entered, receiver) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(1);
        let mut gate = self.gate.lock().unwrap();
        assert!(gate.is_none());
        *gate = Some(HeadReadGate {
            object,
            entered,
            release: released,
        });
        (receiver, release)
    }

    // Arm immediately before the explicitly owned checkpoint, after seed admission.
    fn gate_next_checkpoint_commit(&self) -> (mpsc::Receiver<RootState>, mpsc::SyncSender<()>) {
        let (entered, receiver) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(1);
        let mut gate = self.committed_checkpoint.lock().unwrap();
        assert!(gate.is_none());
        *gate = Some(CheckpointCommitGate {
            entered,
            release: released,
        });
        (receiver, release)
    }

    fn pause_committed_checkpoint(&self, root: RootState) {
        let gate = self.committed_checkpoint.lock().unwrap().take();
        if let Some(gate) = gate {
            // Underlying admission already returned: no engine/cache/gate lock
            // is held while newer foreground operations publish their roots.
            gate.entered.send(root).unwrap();
            gate.release.recv_timeout(Duration::from_secs(30)).unwrap();
        }
    }

    fn wait_if_gated(&self, object: ObjectId) {
        let gate = {
            let mut gate = self.gate.lock().unwrap();
            if gate.as_ref().is_some_and(|gate| gate.object == object) {
                gate.take()
            } else {
                None
            }
        };
        if let Some(gate) = gate {
            // No engine/cache/gate mutex remains held across this explicit interleaving.
            gate.entered.send(()).unwrap();
            gate.release.recv_timeout(Duration::from_secs(30)).unwrap();
        }
    }
}

impl KvProjectionEngine<String> for GatedEngine {
    fn identify_kv_object(&self, record: &ObjectRecord) -> ObjectId {
        self.measured.identify_kv_object(record)
    }

    fn current_kv_root(&self, principal: &String) -> Result<Option<RootState>, KvProjectionError> {
        self.measured.current_kv_root(principal)
    }

    fn load_kv_object(&self, object: ObjectId) -> Result<Option<ObjectRecord>, KvProjectionError> {
        self.wait_if_gated(object);
        self.measured.load_kv_object(object)
    }

    fn snapshot_kv_root(
        &self,
        principal: &String,
    ) -> Result<Option<RootSnapshot>, KvProjectionError> {
        self.measured.snapshot_kv_root(principal)
    }

    fn commit_kv_root(
        &self,
        transaction: RootTransaction<String>,
    ) -> Result<CommitOutcome, KvProjectionError> {
        let outcome = self.measured.commit_kv_root(transaction)?;
        self.pause_committed_checkpoint(outcome.root());
        Ok(outcome)
    }

    fn flush_kv(&self) -> Result<(), KvProjectionError> {
        self.measured.flush_kv()
    }
}

type GatedStore = TreeKvStore<String, TestIdentity, Resolver, GatedEngine>;

struct SnapshotRead {
    release: Option<mpsc::SyncSender<()>>,
    reader: Option<std::thread::JoinHandle<StorageResult<Option<Vec<u8>>>>>,
}

impl SnapshotRead {
    fn finish(mut self) -> StorageResult<Option<Vec<u8>>> {
        self.release.take().unwrap().send(()).unwrap();
        self.reader.take().unwrap().join().unwrap()
    }
}

impl Drop for SnapshotRead {
    fn drop(&mut self) {
        // Release and join the owned reader even when a writer assertion fails.
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[tokio::test]
async fn delayed_snapshot_read_cannot_evict_newer_checkpoint_validation() {
    let owner = "alice".to_owned();
    let namespace = "alice:capsule:ownership";
    let engine = Arc::new(GatedEngine::new());
    // Remain below automatic checkpoint admission; only explicit real checkpoints run.
    let mut seed = 0x12ab_56cd_90ef_3412;
    let original: Vec<u8> = (0..512 * 1024)
        .map(|_| next(&mut seed).to_le_bytes()[0])
        .collect();
    let mut replacement = original.clone();
    replacement[200_000..204_096].fill(0x55);
    let checkpoint_a = {
        let initial = GatedStore::from_engine(Arc::clone(&engine), Resolver);
        initial
            .set(namespace, "graph", original.clone())
            .await
            .unwrap();
        assert!(initial.checkpoint_for_test(owner.clone()).unwrap());
        initial.cached_checkpoint_for_test(&owner)
    };
    let head_a = checkpoint_a.0.expect("checkpoint A must have a head");
    assert!(checkpoint_a.1.is_some());
    // A fresh adapter is genuinely cold; no fake cache insertion/clearing causes the miss.
    let store = Arc::new(GatedStore::from_engine(Arc::clone(&engine), Resolver));
    let (entered, release) = engine.gate_once(head_a);
    let reader_store = Arc::clone(&store);
    let reader = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(reader_store.get(namespace, "graph"))
    });
    let reader = SnapshotRead {
        release: Some(release),
        reader: Some(reader),
    };
    // This bounded receive is a failure deadline, not the race trigger. The one-shot gate
    // proves the reader captured root A and is paused before decoding its NamespaceMap.
    entered.recv_timeout(Duration::from_secs(30)).unwrap();
    store
        .set(namespace, "graph", replacement.clone())
        .await
        .unwrap();
    assert!(store.checkpoint_for_test(owner.clone()).unwrap());
    let root_b = engine.measured.inner.root(&owner).unwrap();
    let checkpoint_b = store.cached_checkpoint_for_test(&owner);
    assert_ne!(checkpoint_b.0, checkpoint_a.0);
    assert_ne!(checkpoint_b.1, checkpoint_a.1);
    assert!(checkpoint_b.0.is_some() && checkpoint_b.1.is_some());
    assert_eq!(reader.finish().unwrap(), Some(original));
    assert_eq!(engine.measured.inner.root(&owner), Some(root_b));
    let after_old_reader = store.cached_checkpoint_for_test(&owner);
    engine
        .measured
        .loaded_chunk_bytes
        .store(0, Ordering::Relaxed);
    assert_eq!(
        store.get(namespace, "graph").await.unwrap(),
        Some(replacement.clone())
    );
    let loaded = engine.measured.loaded_chunk_bytes.load(Ordering::Relaxed);
    assert_eq!(
        after_old_reader, checkpoint_b,
        "historical read replaced B's validation; next B read loaded {loaded} chunk bytes"
    );
    assert_eq!(
        loaded,
        replacement.len() as u64,
        "a warm checkpoint read must traverse content once, without a discarded validating read"
    );
    assert_eq!(engine.measured.inner.root(&owner), Some(root_b));
    store.close().await.unwrap();
}

struct CheckpointPublication {
    release: Option<mpsc::SyncSender<()>>,
    worker: Option<std::thread::JoinHandle<StorageResult<bool>>>,
}

impl CheckpointPublication {
    fn finish(mut self) -> StorageResult<bool> {
        self.release.take().unwrap().send(()).unwrap();
        self.worker.take().unwrap().join().unwrap()
    }
}

impl Drop for CheckpointPublication {
    fn drop(&mut self) {
        // Unblock and join the owned checkpoint even if a B assertion unwinds.
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[tokio::test]
async fn delayed_successful_checkpoint_cannot_evict_newer_checkpoint_validation() {
    let owner = "alice".to_owned();
    let namespace = "alice:capsule:ownership";
    let engine = Arc::new(GatedEngine::new());
    let store = Arc::new(GatedStore::from_engine(Arc::clone(&engine), Resolver));
    // Below automatic checkpoint threshold: A is the sole commit after arming.
    let mut seed = 0x12ab_56cd_90ef_3412;
    let original: Vec<u8> = (0..512 * 1024)
        .map(|_| next(&mut seed).to_le_bytes()[0])
        .collect();
    let mut replacement = original.clone();
    replacement[200_000..204_096].fill(0x55);
    store.set(namespace, "graph", original).await.unwrap();
    let seed_root = engine.measured.inner.root(&owner).unwrap();
    let (entered, release) = engine.gate_next_checkpoint_commit();
    let checkpoint_store = Arc::clone(&store);
    let checkpoint_owner = owner.clone();
    let worker = std::thread::spawn(move || checkpoint_store.checkpoint_for_test(checkpoint_owner));
    let checkpoint = CheckpointPublication {
        release: Some(release),
        worker: Some(worker),
    };
    // Notification is sent only after real A admission succeeds and its lock
    // is released; return to the adapter's cache publisher remains gated.
    let root_a = entered.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_ne!(root_a, seed_root);
    assert_eq!(engine.measured.inner.root(&owner), Some(root_a));
    store
        .set(namespace, "graph", replacement.clone())
        .await
        .unwrap();
    assert!(store.checkpoint_for_test(owner.clone()).unwrap());
    let root_b = engine.measured.inner.root(&owner).unwrap();
    let checkpoint_b = store.cached_checkpoint_for_test(&owner);
    assert_ne!(root_b, root_a);
    assert!(checkpoint_b.0.is_some() && checkpoint_b.1.is_some());
    assert!(
        checkpoint.finish().unwrap(),
        "A committed successfully before B"
    );
    assert_eq!(engine.measured.inner.root(&owner), Some(root_b));
    let after_delayed_a = store.cached_checkpoint_for_test(&owner);
    engine
        .measured
        .loaded_chunk_bytes
        .store(0, Ordering::Relaxed);
    assert_eq!(
        store.get(namespace, "graph").await.unwrap(),
        Some(replacement.clone())
    );
    let loaded = engine.measured.loaded_chunk_bytes.load(Ordering::Relaxed);
    assert_eq!(
        after_delayed_a, checkpoint_b,
        "late successful A checkpoint evicted B validation; B get loaded {loaded} bytes"
    );
    assert_eq!(
        loaded,
        replacement.len() as u64,
        "B read must traverse chunks once"
    );
    assert_eq!(engine.measured.inner.root(&owner), Some(root_b));
    store.close().await.unwrap();
}
