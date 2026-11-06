//! Public-client regression coverage for engine-bound KV identities.
#![cfg(not(target_family = "wasm"))]
use astrid_storage::engine::{
    CommitOutcome, DurableEngine, DurableEnginePolicy, IdentityScheme, InMemoryEngine,
    KvIdentitySession, KvProjectionEngine, KvProjectionError, PersistentObjectIdentity,
    PrincipalCodec, RecoveryLimits, RootSnapshot, RootTransaction, TransactionWalPolicy,
};
use astrid_storage::principal_state::Blake3ObjectIdentityV1;
use astrid_storage::storage_model::{
    ModelError, ObjectId, ObjectIdentity, ObjectKind, ObjectRecord, RootState,
};
use astrid_storage::{KvStore, StorageResult, TreeKvStore};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Clone)]
struct CountingIdentity(Arc<AtomicU64>);
impl ObjectIdentity for CountingIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        if record.kind() == ObjectKind::Chunk {
            self.0
                .fetch_add(record.canonical_bytes().len() as u64, Ordering::Relaxed);
        }
        Blake3ObjectIdentityV1.identify(record)
    }
}
impl PersistentObjectIdentity for CountingIdentity {
    fn scheme(&self) -> IdentityScheme {
        Blake3ObjectIdentityV1.scheme()
    }
}
struct Codec;
impl PrincipalCodec<String> for Codec {
    fn encode(&self, p: &String) -> Vec<u8> {
        p.as_bytes().to_vec()
    }
    fn decode(&self, b: &[u8]) -> Option<String> {
        String::from_utf8(b.to_vec()).ok()
    }
}
#[derive(Clone, Copy, Debug)]
enum Mode {
    Trusted,
    Fallback,
    Clone,
    LyingTrusted,
    LyingFallback,
    ChangingGetter,
}
struct Client<E> {
    inner: E,
    mode: Mode,
    sessions: AtomicU64,
    commits: AtomicU64,
}
impl<E: KvProjectionEngine<String>> KvProjectionEngine<String> for Client<E> {
    fn identify_kv_object(&self, r: &ObjectRecord) -> ObjectId {
        if matches!(self.mode, Mode::LyingTrusted | Mode::LyingFallback)
            && r.kind() == ObjectKind::Chunk
        {
            // A reversible transformation preserves distinct chunk identities,
            // reaching engine admission instead of failing local deduplication.
            let mut forged = *self.inner.identify_kv_object(r).as_bytes();
            forged[0] ^= 0x80;
            ObjectId::new(forged)
        } else {
            self.inner.identify_kv_object(r)
        }
    }
    fn kv_identity_session(&self) -> Option<KvIdentitySession<'_>> {
        let call = self.sessions.fetch_add(1, Ordering::Relaxed);
        if matches!(self.mode, Mode::Fallback | Mode::LyingFallback)
            || matches!(self.mode, Mode::ChangingGetter) && call != 0
        {
            None
        } else {
            self.inner.kv_identity_session()
        }
    }
    fn current_kv_root(&self, p: &String) -> Result<Option<RootState>, KvProjectionError> {
        self.inner.current_kv_root(p)
    }
    fn load_kv_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, KvProjectionError> {
        self.inner.load_kv_object(id)
    }
    fn snapshot_kv_root(&self, p: &String) -> Result<Option<RootSnapshot>, KvProjectionError> {
        self.inner.snapshot_kv_root(p)
    }
    fn commit_kv_root(
        &self,
        tx: RootTransaction<String>,
    ) -> Result<CommitOutcome, KvProjectionError> {
        self.commits.fetch_add(1, Ordering::Relaxed);
        let expected_mismatch = matches!(self.mode, Mode::LyingFallback).then(|| {
            let (declared, record) = tx
                .records()
                .iter()
                .find(|(_, record)| record.kind() == ObjectKind::Chunk)
                .unwrap();
            (*declared, Blake3ObjectIdentityV1.identify(record))
        });
        let outcome = if matches!(self.mode, Mode::Clone) {
            self.inner.commit_kv_root(tx.clone())
        } else {
            self.inner.commit_kv_root(tx)
        };
        if let Some((expected_declared, expected_computed)) = expected_mismatch {
            assert!(matches!(&outcome, Err(KvProjectionError::Model(
                ModelError::ObjectIdentityMismatch { declared, computed }
            )) if *declared == expected_declared && *computed == expected_computed));
        }
        outcome
    }

    fn flush_kv(&self) -> Result<(), KvProjectionError> {
        self.inner.flush_kv()
    }
    fn close_kv(&self) -> Result<(), KvProjectionError> {
        self.inner.close_kv()
    }
}
fn owner(namespace: &str) -> StorageResult<String> {
    namespace
        .split_once(":capsule:")
        .map(|(owner, _)| owner.to_owned())
        .ok_or_else(|| {
            astrid_storage::StorageError::InvalidKey("namespace has no owner".to_owned())
        })
}
fn payload() -> Vec<u8> {
    let mut x = 0x12ab_56cd_90ef_3412_u64;
    (0..512 * 1024)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}
async fn exercise<E: KvProjectionEngine<String> + 'static>(
    inner: E,
    identity: CountingIdentity,
    mode: Mode,
    wal_enabled: bool,
) {
    let engine = Arc::new(Client {
        inner,
        mode,
        sessions: AtomicU64::new(0),
        commits: AtomicU64::new(0),
    });
    let store =
        TreeKvStore::<String, CountingIdentity, _, _>::from_engine(Arc::clone(&engine), owner);
    let bytes = payload();
    let result = store
        .set("alice:capsule:test", "value", bytes.clone())
        .await;
    assert_eq!(
        engine.commits.load(Ordering::Relaxed),
        1,
        "the public write must reach admission"
    );
    if matches!(mode, Mode::LyingFallback) {
        assert!(
            result.is_err(),
            "forged untrusted identities must be rejected"
        );
        assert_eq!(
            engine.inner.current_kv_root(&"alice".to_owned()).unwrap(),
            None
        );
    } else {
        result.unwrap();
        assert_eq!(
            engine.sessions.load(Ordering::Relaxed),
            1,
            "one session capture for the write context"
        );
        // This payload is below the checkpoint byte threshold. Wait for any
        // owned background store references before reading admission counters.
        let start = Instant::now();
        while Arc::strong_count(&engine) != 2 {
            assert!(start.elapsed() < Duration::from_secs(30));
            tokio::task::yield_now().await;
        }
        let admission_passes: u64 = if matches!(mode, Mode::Fallback | Mode::Clone) {
            2
        } else {
            1
        };
        // WAL overlay installation decodes and verifies its encoded frames
        // independently. This test does not waive that verification.
        let factor = admission_passes.strict_add(u64::from(wal_enabled));
        assert_eq!(
            identity.0.load(Ordering::Relaxed),
            (bytes.len() as u64).strict_mul(factor),
            "mode {mode:?}"
        );
        assert_eq!(
            store
                .get("alice:capsule:test", "value")
                .await
                .unwrap()
                .as_deref(),
            Some(bytes.as_slice())
        );
    }
    store.close().await.unwrap();
}
#[tokio::test]
async fn external_wrapper_cannot_forge_or_preserve_cloned_identity_proof() {
    for mode in [
        Mode::Trusted,
        Mode::Fallback,
        Mode::Clone,
        Mode::LyingTrusted,
        Mode::LyingFallback,
        Mode::ChangingGetter,
    ] {
        let identity = CountingIdentity(Arc::new(AtomicU64::new(0)));
        exercise(
            InMemoryEngine::<String, _>::new(identity.clone()),
            identity,
            mode,
            false,
        )
        .await;
    }
}
#[tokio::test]
async fn durable_admission_obeys_the_same_external_identity_boundary() {
    for wal_enabled in [false, true] {
        for mode in [
            Mode::Trusted,
            Mode::Fallback,
            Mode::Clone,
            Mode::LyingTrusted,
            Mode::LyingFallback,
            Mode::ChangingGetter,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let identity = CountingIdentity(Arc::new(AtomicU64::new(0)));
            let policy = || {
                if wal_enabled {
                    DurableEnginePolicy::default().with_transaction_wal(
                        TransactionWalPolicy::enabled(std::num::NonZeroU64::MAX),
                    )
                } else {
                    DurableEnginePolicy::default()
                }
            };
            let inner = DurableEngine::open_with_policy(
                dir.path(),
                identity.clone(),
                Codec,
                RecoveryLimits::process_addressable(),
                policy(),
            )
            .unwrap();
            exercise(inner, identity.clone(), mode, wal_enabled).await;
            let reopened = Arc::new(
                DurableEngine::open_with_policy(
                    dir.path(),
                    identity,
                    Codec,
                    RecoveryLimits::process_addressable(),
                    policy(),
                )
                .unwrap(),
            );
            let store = TreeKvStore::<String, CountingIdentity, _, _>::from_engine(
                Arc::clone(&reopened),
                owner,
            );
            let value = store.get("alice:capsule:test", "value").await.unwrap();
            assert_eq!(
                value,
                if matches!(mode, Mode::LyingFallback) {
                    None
                } else {
                    Some(payload())
                }
            );
            store.close().await.unwrap();
        }
    }
}
