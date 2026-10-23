use std::num::NonZeroU64;
use std::sync::Arc;

use super::super::tests::{TestIdentity, Utf8Codec, limits, open, transaction};
use super::super::{
    DurableEngine, DurableEnginePolicy, DurableError, FaultInjector, FaultPoint, GroupCommitPolicy,
    ObjectCacheConfig, RecoveryRetryPolicy, TransactionWalPolicy,
};
use crate::storage_model::{ModelError, RootGeneration};

#[test]
fn exact_root_removal_survives_reopen_without_a_tombstone() {
    let directory = tempfile::tempdir().unwrap();
    let owner = "alice".to_owned();
    let peer = "bob".to_owned();
    let engine = open(directory.path());
    let (_, initial) = transaction(&owner, None, b"shared objects");
    let root = engine.commit(initial).unwrap().root;
    let (_, other) = transaction(&peer, None, b"shared objects");
    let peer_root = engine.commit(other).unwrap().root;
    let (_, update) = transaction(&owner, Some(root), b"second generation");
    let latest = engine.commit(update).unwrap().root;
    assert!(matches!(
        engine.remove_root(&owner, root),
        Err(DurableError::Model(ModelError::RootConflict { .. }))
    ));
    assert_eq!(engine.remove_root(&owner, latest).unwrap(), latest);
    assert!(engine.root(&owner).unwrap().is_none());
    assert!(engine.root_if_ready(&owner).unwrap().get().is_none());
    assert!(
        !engine
            .roots()
            .unwrap()
            .iter()
            .any(|(principal, _)| principal == &owner)
    );
    assert!(!engine.published_roots.entries.load().contains_key(&owner));
    assert_eq!(engine.root(&peer).unwrap(), Some(peer_root));
    assert!(engine.object(root.commit).unwrap().is_some());
    assert!(matches!(
        engine.remove_root(&owner, latest),
        Err(DurableError::Model(ModelError::RootConflict {
            actual: None,
            ..
        }))
    ));
    engine.close().unwrap();
    let engine = open(directory.path());
    assert!(engine.root(&owner).unwrap().is_none());
    assert_eq!(engine.root(&peer).unwrap(), Some(peer_root));
    let (_, recreate) = transaction(&owner, None, b"new identity scope");
    assert_eq!(
        engine.commit(recreate).unwrap().root.generation,
        RootGeneration::INITIAL
    );
}

#[test]
fn pending_wal_is_folded_before_root_removal_and_cannot_resurrect() {
    let directory = tempfile::tempdir().unwrap();
    let owner = "alice".to_owned();
    let policy = || {
        DurableEnginePolicy::new(
            GroupCommitPolicy::immediate(),
            RecoveryRetryPolicy::immediate(),
            ObjectCacheConfig::disabled(),
        )
        .with_transaction_wal(TransactionWalPolicy::enabled(
            NonZeroU64::new(u64::MAX).unwrap(),
        ))
    };
    let engine = DurableEngine::open_with_policy(
        directory.path(),
        TestIdentity,
        Utf8Codec,
        limits(),
        policy(),
    )
    .unwrap();
    let (_, first) = transaction(&owner, None, b"pending first");
    let first = engine.commit(first).unwrap().root;
    let (_, second) = transaction(&owner, Some(first), b"pending second");
    let second = engine.commit(second).unwrap().root;
    assert!(!engine.inner.lock().pending_wal.roots().is_empty());
    engine.remove_root(&owner, second).unwrap();
    assert!(engine.inner.lock().pending_wal.roots().is_empty());
    drop(engine);
    let engine = DurableEngine::open_with_policy(
        directory.path(),
        TestIdentity,
        Utf8Codec,
        limits(),
        policy(),
    )
    .unwrap();
    assert!(engine.root(&owner).unwrap().is_none());
    engine.flush().unwrap();
    engine.close().unwrap();
    let engine = open(directory.path());
    assert!(engine.root(&owner).unwrap().is_none());
}

#[derive(Debug)]
struct FailAt(FaultPoint);
impl FaultInjector for FailAt {
    fn should_fail(&self, point: FaultPoint) -> bool {
        point == self.0
    }
}

#[test]
fn interrupted_root_removal_recovers_exact_durable_frontier() {
    for point in [FaultPoint::BeforeRootCas, FaultPoint::AfterRootCas] {
        let directory = tempfile::tempdir().unwrap();
        let owner = "alice".to_owned();
        let engine = open(directory.path());
        let (_, initial) = transaction(&owner, None, b"crash boundary");
        let root = engine.commit(initial).unwrap().root;
        engine.close().unwrap();
        let engine = DurableEngine::open_with_faults(
            directory.path(),
            TestIdentity,
            Utf8Codec,
            limits(),
            Arc::new(FailAt(point)),
        )
        .unwrap();
        assert!(
            matches!(engine.remove_root(&owner, root), Err(DurableError::FaultInjected(actual)) if actual == point)
        );
        assert!(engine.root_if_ready(&owner).is_none());
        drop(engine);
        let engine = open(directory.path());
        assert_eq!(
            engine.root(&owner).unwrap(),
            (point == FaultPoint::BeforeRootCas).then_some(root)
        );
    }
}
