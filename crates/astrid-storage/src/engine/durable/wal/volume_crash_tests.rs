//! Volume-backed crash and recovery regressions for the transaction WAL.

use std::num::NonZeroU64;
use std::sync::Arc;

use crate::engine::durable::tests::{
    TestIdentity, Utf8Codec, limits, transaction as kv_transaction,
};
use crate::engine::durable::{
    DurableEngine, DurableEnginePolicy, DurableError, FaultInjector, FaultPoint, GroupCommitPolicy,
    ObjectCacheConfig, RecoveryRetryPolicy, TransactionWalPolicy, WAL_FILE,
};
use crate::volume::{AstridVolume, HostedFileVolume, VolumeRegion};

#[derive(Debug)]
struct FailAt(FaultPoint);

impl FaultInjector for FailAt {
    fn should_fail(&self, point: FaultPoint) -> bool {
        point == self.0
    }
}

fn wal_policy() -> DurableEnginePolicy<String> {
    DurableEnginePolicy::new(
        GroupCommitPolicy::immediate(),
        RecoveryRetryPolicy::immediate(),
        ObjectCacheConfig::disabled(),
    )
    .with_transaction_wal(TransactionWalPolicy::enabled(
        NonZeroU64::new(u64::MAX).unwrap(),
    ))
}

fn disabled_wal_policy() -> DurableEnginePolicy<String> {
    DurableEnginePolicy::new(
        GroupCommitPolicy::immediate(),
        RecoveryRetryPolicy::immediate(),
        ObjectCacheConfig::disabled(),
    )
    .with_transaction_wal(TransactionWalPolicy::disabled())
}

fn open_volume(
    directory: &tempfile::TempDir,
) -> (
    Arc<dyn AstridVolume>,
    DurableEngine<String, TestIdentity, Utf8Codec>,
) {
    let volume_path = directory.path().join("astrid.volume");
    let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&volume_path).unwrap();
    let engine = DurableEngine::open_volume(
        Arc::clone(&volume),
        TestIdentity,
        Utf8Codec,
        limits(),
        wal_policy(),
    )
    .unwrap();
    (volume, engine)
}

#[test]
fn after_wal_publication_crash_replays_committed_visibility() {
    let directory = tempfile::tempdir().unwrap();
    let volume_path = directory.path().join("astrid.volume");
    let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&volume_path).unwrap();
    let engine = DurableEngine::open_volume_with_faults(
        Arc::clone(&volume),
        TestIdentity,
        Utf8Codec,
        limits(),
        wal_policy(),
        Arc::new(FailAt(FaultPoint::AfterWalPublication)),
    )
    .unwrap();
    let (commit, tx) = kv_transaction("alice", None, b"published-before-fold");
    let error = engine.commit(tx).unwrap_err();
    assert!(matches!(
        error,
        DurableError::FaultInjected(FaultPoint::AfterWalPublication)
    ));
    drop(engine);

    let engine =
        DurableEngine::open_volume(volume, TestIdentity, Utf8Codec, limits(), wal_policy())
            .unwrap();
    assert_eq!(
        engine.root(&"alice".to_owned()).unwrap().unwrap().commit,
        commit
    );
    assert!(engine.object(commit).unwrap().is_some());
}

#[test]
fn volume_crash_reopen_keeps_committed_wal_visible() {
    let directory = tempfile::tempdir().unwrap();
    let (volume, engine) = open_volume(&directory);
    let (commit, tx) = kv_transaction("alice", None, b"crash-reopen");
    engine.commit(tx).unwrap();
    drop(engine);

    let engine =
        DurableEngine::open_volume(volume, TestIdentity, Utf8Codec, limits(), wal_policy())
            .unwrap();
    assert_eq!(
        engine.root(&"alice".to_owned()).unwrap().unwrap().commit,
        commit
    );
    assert!(engine.object(commit).unwrap().is_some());
}

#[test]
fn torn_wal_tail_on_volume_stays_invisible() {
    let directory = tempfile::tempdir().unwrap();
    let (volume, engine) = open_volume(&directory);
    let (first_commit, first) = kv_transaction("alice", None, b"durable-first");
    let first_root = engine.commit(first).unwrap().root();
    let wal = VolumeRegion::new(WAL_FILE).unwrap();
    let first_len = volume.region_len(&wal).unwrap();
    assert!(first_len > 0);

    let (second_commit, second) = kv_transaction("alice", Some(first_root), b"torn-second");
    engine.commit(second).unwrap();
    let second_len = volume.region_len(&wal).unwrap();
    assert!(second_len > first_len);
    drop(engine);

    let torn_len = first_len + (second_len - first_len) / 2;
    volume.set_region_len(&wal, torn_len).unwrap();
    volume.sync().unwrap();

    let engine =
        DurableEngine::open_volume(volume, TestIdentity, Utf8Codec, limits(), wal_policy())
            .unwrap();
    assert_eq!(
        engine.root(&"alice".to_owned()).unwrap().unwrap().commit,
        first_commit
    );
    assert!(engine.object(first_commit).unwrap().is_some());
    assert!(engine.object(second_commit).unwrap().is_none());
}

#[test]
fn disabled_wal_policy_still_replays_published_volume_wal() {
    let directory = tempfile::tempdir().unwrap();
    let (volume, engine) = open_volume(&directory);
    let (commit, tx) = kv_transaction("alice", None, b"keep-after-disable");
    engine.commit(tx).unwrap();
    drop(engine);

    let engine = DurableEngine::open_volume(
        Arc::clone(&volume),
        TestIdentity,
        Utf8Codec,
        limits(),
        disabled_wal_policy(),
    )
    .unwrap();
    assert_eq!(
        engine.root(&"alice".to_owned()).unwrap().unwrap().commit,
        commit
    );
    assert!(engine.object(commit).unwrap().is_some());

    let (next, next_tx) = kv_transaction(
        "alice",
        engine.root(&"alice".to_owned()).unwrap(),
        b"legacy-after",
    );
    let next_root = engine.commit(next_tx).unwrap().root();
    assert_eq!(next_root.commit, next);
    engine.close().unwrap();
    drop(engine);

    let engine = DurableEngine::open_volume(
        volume,
        TestIdentity,
        Utf8Codec,
        limits(),
        disabled_wal_policy(),
    )
    .unwrap();
    assert_eq!(
        engine.root(&"alice".to_owned()).unwrap().unwrap().commit,
        next
    );
}

#[test]
fn disabled_wal_volume_commit_survives_reopen_from_on_disk_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let volume_path = directory.path().join("astrid.volume");
    let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&volume_path).unwrap();
    let engine = DurableEngine::open_volume(
        Arc::clone(&volume),
        TestIdentity,
        Utf8Codec,
        limits(),
        disabled_wal_policy(),
    )
    .unwrap();
    let (commit, tx) = kv_transaction("alice", None, b"legacy-barrier");
    engine.commit(tx).unwrap();
    let snapshot = directory.path().join("snapshot.volume");
    std::fs::copy(&volume_path, &snapshot).unwrap();
    drop(engine);
    drop(volume);

    let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&snapshot).unwrap();
    let engine = DurableEngine::open_volume(
        volume,
        TestIdentity,
        Utf8Codec,
        limits(),
        disabled_wal_policy(),
    )
    .unwrap();
    assert_eq!(
        engine.root(&"alice".to_owned()).unwrap().unwrap().commit,
        commit
    );
    assert!(engine.object(commit).unwrap().is_some());
}

#[test]
fn wal_enabled_volume_commit_survives_reopen_from_on_disk_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let volume_path = directory.path().join("astrid.volume");
    let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&volume_path).unwrap();
    let engine = DurableEngine::open_volume(
        Arc::clone(&volume),
        TestIdentity,
        Utf8Codec,
        limits(),
        wal_policy(),
    )
    .unwrap();
    let (commit, tx) = kv_transaction("alice", None, b"wal-barrier");
    engine.commit(tx).unwrap();
    let snapshot = directory.path().join("snapshot.volume");
    std::fs::copy(&volume_path, &snapshot).unwrap();
    drop(engine);
    drop(volume);

    let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&snapshot).unwrap();
    let engine =
        DurableEngine::open_volume(volume, TestIdentity, Utf8Codec, limits(), wal_policy())
            .unwrap();
    assert_eq!(
        engine.root(&"alice".to_owned()).unwrap().unwrap().commit,
        commit
    );
    assert!(engine.object(commit).unwrap().is_some());
}
