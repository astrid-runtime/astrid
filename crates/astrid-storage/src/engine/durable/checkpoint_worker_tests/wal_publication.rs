//! WAL fold, reset and index publication share the physical failure fence.

use std::num::NonZeroU64;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::engine::durable::checkpoint_worker::SharedRepresentationStore;
use crate::engine::durable::tests::{TestIdentity, Utf8Codec, limits, transaction};
use crate::engine::durable::{
    DurableEnginePolicy, FaultInjector, FaultPoint, LIFECYCLE_REQUIRES_RECOVERY,
    TransactionWalPolicy,
};
use crate::volume::{AstridVolume, HostedFileVolume};

use super::{
    BlockNextGenerationMetadata, Engine, GATE_BOUND, PrepareGate, activated_volume_engine,
};

#[derive(Default)]
struct PanicAtWalIndex {
    armed: AtomicBool,
    observed: AtomicBool,
    physical_held: AtomicBool,
    physical: Mutex<Option<SharedRepresentationStore>>,
}

impl FaultInjector for PanicAtWalIndex {
    fn should_fail(&self, point: FaultPoint) -> bool {
        if point == FaultPoint::BeforeIndexCachePublication
            && self.armed.swap(false, Ordering::SeqCst)
        {
            let shared = self.physical.lock().unwrap().as_ref().unwrap().clone();
            self.physical_held
                .store(shared.try_lock().is_none(), Ordering::SeqCst);
            self.observed.store(true, Ordering::SeqCst);
            panic!("injected WAL index-publication panic after canonical fold");
        }
        false
    }
}

fn grow_folded_metadata_until_eligible(engine: &Engine) {
    let mut previous = engine.root(&"alice".to_owned()).unwrap();
    for sequence in 0_u64..2048 {
        let (_, txn) = transaction("alice", previous, &sequence.to_le_bytes());
        previous = Some(engine.commit(txn).unwrap().root());
        engine.flush().unwrap();
        let inner = engine.inner.lock();
        let shared = inner.representations.as_ref().unwrap();
        if shared.lock().should_checkpoint_representations_metadata() {
            return;
        }
    }
    panic!("fixture must make representation history checkpoint-eligible");
}

#[test]
fn wal_fold_index_panic_poison_precedes_physical_release_with_pending_checkpoint() {
    let directory = tempfile::tempdir().unwrap();
    let preparation = PrepareGate::new();
    let volume: Arc<dyn AstridVolume> = BlockNextGenerationMetadata::wrap(
        HostedFileVolume::open(directory.path().join("wal-publication.volume")).unwrap(),
        Arc::clone(&preparation),
    );
    let initialized = activated_volume_engine(Arc::clone(&volume));
    initialized.close().unwrap();
    drop(initialized);
    let faults = Arc::new(PanicAtWalIndex::default());
    let policy = DurableEnginePolicy::default().with_transaction_wal(
        TransactionWalPolicy::enabled(NonZeroU64::new(u64::MAX).unwrap()),
    );
    let engine = Engine::open_volume_with_faults(
        Arc::clone(&volume),
        TestIdentity,
        Utf8Codec,
        limits(),
        policy,
        Arc::clone(&faults) as Arc<dyn FaultInjector>,
    )
    .unwrap();
    let shared = engine
        .inner
        .lock()
        .representations
        .as_ref()
        .unwrap()
        .clone();
    *faults.physical.lock().unwrap() = Some(shared);
    let release_preparation = preparation.arm();
    grow_folded_metadata_until_eligible(&engine);
    engine.maybe_schedule_representation_checkpoint().unwrap();
    assert!(preparation.wait_entered(GATE_BOUND));
    let previous = engine.root(&"alice".to_owned()).unwrap();
    let (_, txn) = transaction("alice", previous, b"durable-WAL-before-fold-panic");
    let committed = engine.commit(txn).unwrap().root();
    // Keep the real scheduled worker out of the physical mutex during the
    // ownership probe: otherwise try_lock could observe the worker's lock
    // instead of the foreground fold's. It remains pending on publication.
    let arbiter = engine.checkpoint_arbiter_for_test();
    let exclusion = arbiter.lock();
    drop(release_preparation);
    faults.armed.store(true, Ordering::SeqCst);
    let failed = catch_unwind(AssertUnwindSafe(|| engine.flush()));
    assert!(
        failed.is_err(),
        "the public flush must reach the injected panic"
    );
    assert!(faults.observed.load(Ordering::SeqCst));
    assert!(
        faults.physical_held.load(Ordering::SeqCst),
        "WAL fold/reset/index publication must retain physical custody at failure"
    );
    assert_eq!(
        engine.lifecycle_for_test().load(Ordering::Acquire),
        LIFECYCLE_REQUIRES_RECOVERY
    );
    drop(exclusion);
    assert!(engine.close().is_err());
    drop(faults.physical.lock().unwrap().take());
    let reopened = activated_volume_engine(volume);
    assert_eq!(reopened.root(&"alice".to_owned()).unwrap(), Some(committed));
    assert!(reopened.object(committed.commit).unwrap().is_some());
    reopened.close().unwrap();
}
