//! Successful publication should not require an immediate physical reread.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::super::format::{FRAME_CHECKSUM_PASSES, encode_object_frame, frame_checksum};
use super::super::tests::{TestIdentity, Utf8Codec, limits, transaction};
use super::super::{
    ARENA_MAGIC, DurableEngine, DurableEnginePolicy, LIFECYCLE_REQUIRES_RECOVERY, LIFECYCLE_USABLE,
    ObjectCacheConfig, PersistentObjectIdentity, TransactionWalPolicy,
};
use super::commit_cache::PublishedCommitPayload;
use crate::engine::{ObjectCacheCapacity, ObjectCacheController, ObjectCacheMemoryBudget};

type Engine = DurableEngine<String, TestIdentity, Utf8Codec>;

fn fixture() -> (tempfile::TempDir, Engine, PublishedCommitPayload) {
    let directory = tempfile::tempdir().unwrap();
    let engine = Engine::open_with_object_cache(
        directory.path(),
        TestIdentity,
        Utf8Codec,
        limits(),
        ObjectCacheConfig::bounded(NonZeroU64::new(1024 * 1024).unwrap()),
    )
    .unwrap();
    let (id, transaction) = transaction("alice", None, b"published commit");
    let record = transaction
        .records()
        .iter()
        .find(|(object, _)| *object == id)
        .unwrap()
        .1
        .clone();
    let root = engine.commit(transaction).unwrap().root();
    let inner = engine.inner.lock();
    let payload = PublishedCommitPayload {
        root,
        arena_generation: inner.arena_generation,
        location: inner.index.get(&id).copied().unwrap(),
        payload: encode_object_frame(TestIdentity.scheme(), id, &record)
            .unwrap()
            .into(),
    };
    drop(inner);
    engine.object_cache.clear();
    (directory, engine, payload)
}

fn admit(engine: &Engine, payload: PublishedCommitPayload) {
    engine.warm_published_commits(BTreeMap::from([("alice".to_owned(), payload)]));
}

fn assert_refused(engine: &Engine, payload: PublishedCommitPayload) {
    let id = payload.root.commit;
    admit(engine, payload);
    assert!(engine.object_cache.get(&"alice".to_owned(), id).is_none());
    assert_eq!(engine.lifecycle.load(Ordering::Acquire), LIFECYCLE_USABLE);
    assert!(!engine.inner.lock().poisoned);
}

#[test]
fn published_commit_association_avoids_an_immediate_arena_reread() {
    let directory = tempfile::tempdir().unwrap();
    let engine = DurableEngine::open_with_object_cache(
        directory.path(),
        TestIdentity,
        Utf8Codec,
        limits(),
        ObjectCacheConfig::bounded(NonZeroU64::new(1024 * 1024).unwrap()),
    )
    .unwrap();
    let (id, transaction) = transaction("alice", None, b"published commit");
    let committed = engine.commit(transaction).unwrap();
    assert_eq!(committed.root().commit, id);
    let before = engine.object_cache_stats();
    FRAME_CHECKSUM_PASSES.with(|passes| passes.set(0));
    assert!(
        engine
            .shared_object_for(&"alice".to_owned(), id)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        FRAME_CHECKSUM_PASSES.with(Cell::get),
        0,
        "a just-published, verified commit should already be associated"
    );
    let after = engine.object_cache_stats();
    assert_eq!(after.misses, before.misses);
    assert_eq!(after.hits, before.hits + 1);
    engine.close().unwrap();
}

#[test]
fn pending_wal_commit_keeps_its_existing_memory_read_path() {
    let directory = tempfile::tempdir().unwrap();
    let policy = DurableEnginePolicy::new(
        super::GroupCommitPolicy::immediate(),
        super::super::RecoveryRetryPolicy::default(),
        ObjectCacheConfig::bounded(NonZeroU64::new(1024 * 1024).unwrap()),
    )
    .with_transaction_wal(TransactionWalPolicy::enabled(
        NonZeroU64::new(1024 * 1024).unwrap(),
    ));
    let engine =
        Engine::open_with_policy(directory.path(), TestIdentity, Utf8Codec, limits(), policy)
            .unwrap();
    let (id, transaction) = transaction("alice", None, b"WAL commit");
    engine.commit(transaction).unwrap();
    assert_eq!(engine.object_cache_stats().resident_objects, 0);
    assert!(!engine.inner.lock().index.contains_key(&id));
    assert!(engine.inner.lock().pending_wal.get_object(&id).is_some());
    let before = engine.object_cache_stats();
    FRAME_CHECKSUM_PASSES.with(|passes| passes.set(0));
    assert!(
        engine
            .shared_object_for(&"alice".to_owned(), id)
            .unwrap()
            .is_some()
    );
    let after = engine.object_cache_stats();
    assert_eq!(FRAME_CHECKSUM_PASSES.with(Cell::get), 0);
    assert_eq!(after.misses, before.misses + 1);
    assert_eq!(after.hits, before.hits);
    engine.close().unwrap();
}

#[test]
fn publication_still_succeeds_when_either_cache_budget_refuses() {
    let configs = [
        ObjectCacheConfig::disabled(),
        ObjectCacheConfig::bounded(NonZeroU64::new(1).unwrap()),
        ObjectCacheConfig::new(
            ObjectCacheController::new(ObjectCacheCapacity::Unbounded),
            Arc::new(|_: &String| ObjectCacheCapacity::Disabled),
        ),
    ];
    for cache in configs {
        let directory = tempfile::tempdir().unwrap();
        let engine = Engine::open_with_object_cache(
            directory.path(),
            TestIdentity,
            Utf8Codec,
            limits(),
            cache,
        )
        .unwrap();
        let (id, transaction) = transaction("alice", None, b"budget refusal");
        engine.commit(transaction).unwrap();
        assert!(
            engine
                .shared_object_for(&"alice".to_owned(), id)
                .unwrap()
                .is_some()
        );
        assert_eq!(engine.object_cache_stats().resident_objects, 0);
        engine.close().unwrap();
    }
}

#[test]
fn published_payload_refuses_wire_identity_canonical_identity_and_index_disagreement() {
    for mutation in 0..5 {
        let (_directory, engine, mut payload) = fixture();
        match mutation {
            0 => payload.location.checksum[0] ^= 1,
            1 => payload.location.payload_len += 1,
            _ => {
                let (other_id, other) = transaction("alice", None, b"different record");
                let record = &other
                    .records()
                    .iter()
                    .find(|(id, _)| *id == other_id)
                    .unwrap()
                    .1;
                let wire_id = if mutation == 2 {
                    other_id
                } else {
                    payload.root.commit
                };
                let mut bytes =
                    encode_object_frame(TestIdentity.scheme(), wire_id, record).unwrap();
                if mutation == 4 {
                    bytes.push(0);
                }
                let location = &mut payload.location;
                location.payload_len = u64::try_from(bytes.len()).unwrap();
                location.checksum = frame_checksum(ARENA_MAGIC, location.payload_len, &bytes);
                payload.payload = bytes.into();
            },
        }
        assert_refused(&engine, payload);
        engine.close().unwrap();
    }
}

#[test]
fn delayed_publication_payload_does_not_cross_an_arena_generation() {
    let (_directory, engine, payload) = fixture();
    let generation = payload.arena_generation;
    engine.inner.lock().arena_generation = generation + 1;
    assert_refused(&engine, payload);
    engine.inner.lock().arena_generation = generation;
    engine.close().unwrap();
}

#[test]
fn delayed_publication_payload_requires_live_membership_and_latest_owner_root() {
    let (_directory, engine, payload) = fixture();
    let id = payload.root.commit;
    let location = engine.inner.lock().index.remove(&id).unwrap();
    assert_refused(&engine, payload);
    engine.inner.lock().index.insert(id, location);
    engine.close().unwrap();

    let (_directory, engine, payload) = fixture();
    let (_, next) = transaction("alice", Some(payload.root), b"new owner root");
    engine.commit(next).unwrap();
    engine.object_cache.clear();
    assert_refused(&engine, payload);
    engine.close().unwrap();
}

#[test]
fn publication_cache_admission_never_waits_on_the_writer() {
    let (_directory, engine, payload) = fixture();
    let id = payload.root.commit;
    let writer = engine.inner.lock();
    admit(&engine, payload);
    drop(writer);
    assert!(engine.object_cache.get(&"alice".to_owned(), id).is_none());
    engine.close().unwrap();
}

#[test]
fn publication_cache_admission_never_recovers_or_revives_a_closed_engine() {
    let (_directory, engine, payload) = fixture();
    engine.close().unwrap();
    admit(&engine, payload);
    assert_eq!(engine.object_cache_stats().resident_objects, 0);

    let (_directory, engine, payload) = fixture();
    engine.mark_requires_recovery(&mut engine.inner.lock());
    admit(&engine, payload);
    assert_eq!(
        engine.lifecycle.load(Ordering::Acquire),
        LIFECYCLE_REQUIRES_RECOVERY
    );
    assert!(engine.inner.lock().poisoned);
    assert_eq!(engine.object_cache_stats().resident_objects, 0);
    assert!(matches!(
        engine.close(),
        Err(super::super::DurableError::RequiresRecovery)
    ));
}

struct PanickingAdmission(AtomicBool);

impl ObjectCacheMemoryBudget for PanickingAdmission {
    fn capacity(&self) -> ObjectCacheCapacity {
        ObjectCacheCapacity::Unbounded
    }
    fn ensure_capacity(&self, _required: u64) -> ObjectCacheCapacity {
        assert!(
            !self.0.load(Ordering::Acquire),
            "injected budget callback panic"
        );
        self.capacity()
    }
}

#[test]
fn optional_cache_callback_panic_cannot_poison_a_durable_receipt() {
    let directory = tempfile::tempdir().unwrap();
    let budget = Arc::new(PanickingAdmission(AtomicBool::new(false)));
    let cache = ObjectCacheConfig::new(
        ObjectCacheController::governed(Arc::clone(&budget) as Arc<dyn ObjectCacheMemoryBudget>),
        Arc::new(|_: &String| ObjectCacheCapacity::Unbounded),
    );
    let engine =
        Engine::open_with_object_cache(directory.path(), TestIdentity, Utf8Codec, limits(), cache)
            .unwrap();
    budget.0.store(true, Ordering::Release);
    let (id, transaction) = transaction("alice", None, b"durable despite cache panic");
    let committed = engine.commit(transaction).unwrap();
    assert_eq!(committed.root().commit, id);
    assert_eq!(engine.lifecycle.load(Ordering::Acquire), LIFECYCLE_USABLE);
    assert!(!engine.inner.lock().poisoned);
    budget.0.store(false, Ordering::Release);
    assert!(
        engine
            .shared_object_for(&"alice".to_owned(), id)
            .unwrap()
            .is_some()
    );
    engine.close().unwrap();
}

#[test]
fn one_owner_batch_only_warms_its_final_root() {
    let directory = tempfile::tempdir().unwrap();
    let engine = Engine::open_with_object_cache(
        directory.path(),
        TestIdentity,
        Utf8Codec,
        limits(),
        ObjectCacheConfig::bounded(NonZeroU64::new(1024 * 1024).unwrap()),
    )
    .unwrap();
    let (first, initial) = transaction("alice", None, b"first root");
    let expected = crate::storage_model::RootState {
        generation: crate::storage_model::RootGeneration::INITIAL,
        commit: first,
    };
    let (second, next) = transaction("alice", Some(expected), b"second root");
    let receipts = [
        Arc::new(super::CommitReceipt::default()),
        Arc::new(super::CommitReceipt::default()),
    ];
    let batch = [initial, next]
        .into_iter()
        .zip(&receipts)
        .map(|(transaction, receipt)| super::QueuedCommit {
            transaction,
            receipt: Arc::clone(receipt),
            observer: None,
        })
        .collect();
    engine.process_commit_batch(batch);
    for receipt in receipts {
        assert!(matches!(
            receipt.wait(),
            super::ReceiptAction::Complete(Ok(_))
        ));
    }
    let owner = "alice".to_owned();
    assert!(engine.object_cache.get(&owner, first).is_none());
    assert!(engine.object_cache.get(&owner, second).is_some());
    assert_eq!(engine.object_cache_stats().resident_objects, 1);
    engine.close().unwrap();
}

struct FailFrontier;

impl super::super::FaultInjector for FailFrontier {
    fn should_fail(&self, point: super::super::FaultPoint) -> bool {
        point == super::super::FaultPoint::AfterObjectFlush
    }
}

#[test]
fn failed_durable_publication_never_warms_prepared_payloads() {
    let directory = tempfile::tempdir().unwrap();
    let policy = DurableEnginePolicy::new(
        super::GroupCommitPolicy::immediate(),
        super::super::RecoveryRetryPolicy::default(),
        ObjectCacheConfig::bounded(NonZeroU64::new(1024 * 1024).unwrap()),
    );
    let engine = Engine::open_with_options(
        directory.path(),
        TestIdentity,
        Utf8Codec,
        limits(),
        super::super::EngineOpenOptions {
            policy,
            faults: Arc::new(FailFrontier),
        },
    )
    .unwrap();
    let (_, transaction) = transaction("alice", None, b"publication fails");
    assert!(engine.commit(transaction).is_err());
    assert_eq!(engine.object_cache_stats().resident_objects, 0);
}
