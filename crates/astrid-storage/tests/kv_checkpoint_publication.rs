//! Real checkpoint publication must preserve validation and avoid a second content audit.
#![cfg(not(target_family = "wasm"))]

use astrid_storage::engine::{
    CommitOutcome, DurableEngine, DurableEnginePolicy, InMemoryEngine, KvIdentitySession,
    KvProjectionEngine, KvProjectionError, PrincipalCodec, ReadyKvRoot, RecoveryLimits,
    RootSnapshot, RootTransaction, TransactionWalPolicy,
};
use astrid_storage::principal_state::Blake3ObjectIdentityV1;
use astrid_storage::storage_model::{ObjectId, ObjectKind, ObjectRecord, RootState};
use astrid_storage::{KvStore, StorageResult, TreeKvStore};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

#[test]
fn public_transactions_keep_their_original_auto_traits() {
    fn original_traits<T: Send + Sync + std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
    original_traits::<RootTransaction<String>>();
}

struct Gate {
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
}
#[derive(Clone, Copy, Debug)]
enum Authority {
    Same,
    Foreign,
    Untrusted,
    Cloned,
}
struct Engine<E> {
    mode: Authority,
    foreign: InMemoryEngine<String, Blake3ObjectIdentityV1>,
    inner: E,
    gate: Mutex<Option<Gate>>,
    loaded: AtomicU64,
}
impl<E> Engine<E> {
    fn count(&self, r: &ObjectRecord) {
        if r.kind() == ObjectKind::Chunk {
            self.loaded
                .fetch_add(r.canonical_bytes().len() as u64, Ordering::Relaxed);
        }
    }
}
impl<E: KvProjectionEngine<String>> KvProjectionEngine<String> for Engine<E> {
    fn identify_kv_object(&self, r: &ObjectRecord) -> ObjectId {
        self.inner.identify_kv_object(r)
    }
    fn kv_identity_session(&self) -> Option<KvIdentitySession<'_>> {
        match self.mode {
            Authority::Same | Authority::Cloned => self.inner.kv_identity_session(),
            Authority::Foreign => self.foreign.kv_identity_session(),
            Authority::Untrusted => None,
        }
    }
    fn current_kv_root(&self, p: &String) -> Result<Option<RootState>, KvProjectionError> {
        self.inner.current_kv_root(p)
    }
    fn current_kv_root_if_ready(&self, p: &String) -> Option<ReadyKvRoot> {
        self.inner.current_kv_root_if_ready(p)
    }
    fn load_kv_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, KvProjectionError> {
        let r = self.inner.load_kv_object(id)?;
        if let Some(ref r) = r {
            self.count(r);
        }
        Ok(r)
    }
    fn load_kv_object_for(
        &self,
        p: &String,
        id: ObjectId,
    ) -> Result<Option<ObjectRecord>, KvProjectionError> {
        let r = self.inner.load_kv_object_for(p, id)?;
        if let Some(ref r) = r {
            self.count(r);
        }
        Ok(r)
    }
    fn load_shared_kv_object_for(
        &self,
        p: &String,
        id: ObjectId,
    ) -> Result<Option<Arc<ObjectRecord>>, KvProjectionError> {
        let r = self.inner.load_shared_kv_object_for(p, id)?;
        if let Some(ref r) = r {
            self.count(r);
        }
        Ok(r)
    }
    fn snapshot_kv_root(&self, p: &String) -> Result<Option<RootSnapshot>, KvProjectionError> {
        self.inner.snapshot_kv_root(p)
    }
    fn commit_kv_root(
        &self,
        t: RootTransaction<String>,
    ) -> Result<CommitOutcome, KvProjectionError> {
        let checkpoint = t.records().iter().any(|(_, r)| {
            r.kind() == ObjectKind::NamespaceMap && r.canonical_bytes().first() == Some(&0)
        });
        let t = if matches!(self.mode, Authority::Cloned) {
            t.clone()
        } else {
            t
        };
        let result = self.inner.commit_kv_root(t)?;
        if checkpoint {
            let gate = self.gate.lock().unwrap().take();
            if let Some(g) = gate {
                g.entered.send(()).unwrap();
                g.release.recv_timeout(Duration::from_secs(30)).unwrap();
            }
        }
        Ok(result)
    }
    fn flush_kv(&self) -> Result<(), KvProjectionError> {
        self.inner.flush_kv()
    }
    fn close_kv(&self) -> Result<(), KvProjectionError> {
        self.inner.close_kv()
    }
}
struct Release(Option<mpsc::SyncSender<()>>);
impl Drop for Release {
    fn drop(&mut self) {
        if let Some(s) = self.0.take() {
            let _ = s.send(());
        }
    }
}
fn owner(s: &str) -> StorageResult<String> {
    s.split_once(":capsule:")
        .map(|(p, _)| p.to_owned())
        .ok_or_else(|| astrid_storage::StorageError::InvalidKey("missingowner".into()))
}
fn payload() -> Vec<u8> {
    let mut x = 0x12ab_56cd_90ef_3412u64;
    (0..8 * 1024 * 1024)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}
const AUTHORITIES: [Authority; 4] = [
    Authority::Same,
    Authority::Foreign,
    Authority::Untrusted,
    Authority::Cloned,
];

#[tokio::test(flavor = "multi_thread")]
async fn committed_checkpoint_validation_is_published_only_for_native_authority() {
    for mode in AUTHORITIES {
        exercise(InMemoryEngine::new(Blake3ObjectIdentityV1), mode).await;
    }
}

struct Codec;
impl PrincipalCodec<String> for Codec {
    fn encode(&self, principal: &String) -> Vec<u8> {
        principal.as_bytes().to_vec()
    }
    fn decode(&self, bytes: &[u8]) -> Option<String> {
        String::from_utf8(bytes.to_vec()).ok()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn durable_checkpoint_publication_obeys_authority_and_survives_reopen() {
    for wal_enabled in [false, true] {
        for mode in AUTHORITIES {
            let directory = tempfile::tempdir().unwrap();
            let policy = || {
                if wal_enabled {
                    DurableEnginePolicy::default().with_transaction_wal(
                        TransactionWalPolicy::enabled(std::num::NonZeroU64::MAX),
                    )
                } else {
                    DurableEnginePolicy::default()
                }
            };
            let open = || {
                DurableEngine::open_with_policy(
                    directory.path(),
                    Blake3ObjectIdentityV1,
                    Codec,
                    RecoveryLimits::process_addressable(),
                    policy(),
                )
                .unwrap()
            };
            exercise(open(), mode).await;
            let reopened = Arc::new(open());
            let store =
                TreeKvStore::<String, Blake3ObjectIdentityV1, _, _>::from_engine(reopened, owner);
            assert_eq!(
                store.get("alice:capsule:test", "value").await.unwrap(),
                Some(payload())
            );
            store.close().await.unwrap();
        }
    }
}

async fn exercise<E: KvProjectionEngine<String> + 'static>(inner: E, mode: Authority) {
    let (entered, recv) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let release = Release(Some(release));
    let engine = Arc::new(Engine {
        mode,
        foreign: InMemoryEngine::new(Blake3ObjectIdentityV1),
        inner,
        gate: Mutex::new(Some(Gate {
            entered,
            release: released,
        })),
        loaded: AtomicU64::new(0),
    });
    let store =
        TreeKvStore::<String, Blake3ObjectIdentityV1, _, _>::from_engine(engine.clone(), owner);
    let bytes = payload();
    store
        .set("alice:capsule:test", "value", bytes.clone())
        .await
        .unwrap();
    recv.recv_timeout(Duration::from_secs(30)).unwrap();
    engine.loaded.store(0, Ordering::Relaxed);
    let got = store
        .get("alice:capsule:test", "value")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, bytes);
    let window = engine.loaded.load(Ordering::Relaxed);
    drop(release);
    let start = Instant::now();
    while Arc::strong_count(&engine) != 2 {
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::task::yield_now().await;
    }
    engine.loaded.store(0, Ordering::Relaxed);
    let got = store
        .get("alice:capsule:test", "value")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, bytes);
    let warm = engine.loaded.load(Ordering::Relaxed);
    store.close().await.unwrap();
    println!(
        "{{\"value_bytes\":{},\"committed_before_cache_publication_chunk_bytes\":{},\"after_cache_publication_chunk_bytes\":{},\"exact_payload\":true}}",
        bytes.len(),
        window,
        warm
    );
    let passes = if matches!(mode, Authority::Same) {
        1
    } else {
        2
    };
    assert_eq!(
        window,
        u64::try_from(bytes.len())
            .unwrap()
            .checked_mul(passes)
            .unwrap(),
        "publication authority {mode:?}: incorrect full content traversal count"
    );
    assert_eq!(
        warm,
        bytes.len() as u64,
        "warm certified read must load chunks once"
    );
}
