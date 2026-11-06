//! Failed durability admission must never publish disposable KV validation.
use crate::engine::{
    DurableEngine, DurableEnginePolicy, FaultInjector, FaultPoint, PrincipalCodec, RecoveryLimits,
    TransactionWalPolicy,
};
use crate::principal_state::Blake3ObjectIdentityV1;
use crate::volume::HostedFileVolume;
use crate::{KvStore, TreeKvStore};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

struct Codec;
impl PrincipalCodec<String> for Codec {
    fn encode(&self, principal: &String) -> Vec<u8> {
        principal.as_bytes().to_vec()
    }
    fn decode(&self, bytes: &[u8]) -> Option<String> {
        String::from_utf8(bytes.to_vec()).ok()
    }
}
struct FailAdmission {
    point: FaultPoint,
    armed: AtomicBool,
}
impl FaultInjector for FailAdmission {
    fn should_fail(&self, point: FaultPoint) -> bool {
        point == self.point && self.armed.swap(false, Ordering::SeqCst)
    }
}
fn owner(namespace: &str) -> crate::StorageResult<String> {
    (namespace == "test")
        .then(|| "alice".to_owned())
        .ok_or_else(|| crate::StorageError::InvalidKey("unknown namespace".to_owned()))
}

#[tokio::test]
async fn failed_durable_admission_does_not_publish_checkpoint_validation() {
    for point in [
        FaultPoint::AfterRootCas,
        FaultPoint::BeforeIndexCachePublication,
        FaultPoint::AfterWalPublication,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let volume = HostedFileVolume::open(directory.path().join("store.volume")).unwrap();
        let policy = || {
            if point == FaultPoint::AfterWalPublication {
                DurableEnginePolicy::default()
                    .with_transaction_wal(TransactionWalPolicy::enabled(std::num::NonZeroU64::MAX))
            } else {
                DurableEnginePolicy::default()
            }
        };
        let faults = Arc::new(FailAdmission {
            point,
            armed: AtomicBool::new(false),
        });
        let engine = Arc::new(
            DurableEngine::open_volume_with_faults(
                volume.clone(),
                Blake3ObjectIdentityV1,
                Codec,
                RecoveryLimits::process_addressable(),
                policy(),
                faults.clone(),
            )
            .unwrap(),
        );
        let store =
            TreeKvStore::<String, Blake3ObjectIdentityV1, _, _>::from_engine(engine.clone(), owner);
        let bytes = vec![42; 512 * 1024];
        store.set("test", "value", bytes.clone()).await.unwrap();
        let principal = "alice".to_owned();
        assert!(store.delta_depth_for_test(principal.clone()).unwrap() > 0);
        let before = store.cached_checkpoint_for_test(&principal);
        assert!(before.0.is_some());
        assert!(before.1.is_none());
        faults.armed.store(true, Ordering::SeqCst);
        assert!(
            store.checkpoint_for_test(principal.clone()).is_err(),
            "{point:?}"
        );
        assert!(
            !faults.armed.load(Ordering::SeqCst),
            "fault was not reached: {point:?}"
        );
        assert_eq!(
            store.cached_checkpoint_for_test(&principal),
            before,
            "{point:?}"
        );
        // A failed durability boundary intentionally poisons the live engine;
        // recovery belongs to a fresh open, not a successful close assertion.
        assert!(store.close().await.is_err());
        drop(store);
        drop(engine);
        let reopened = Arc::new(
            DurableEngine::open_volume(
                volume.clone(),
                Blake3ObjectIdentityV1,
                Codec,
                RecoveryLimits::process_addressable(),
                policy(),
            )
            .unwrap(),
        );
        let store =
            TreeKvStore::<String, Blake3ObjectIdentityV1, _, _>::from_engine(reopened, owner);
        assert_eq!(
            store.get("test", "value").await.unwrap(),
            Some(bytes),
            "{point:?}"
        );
        store.close().await.unwrap();
    }
}
