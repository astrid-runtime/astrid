//! Retirement transfers exclusive authority rather than reopening the store.
use super::super::tests::{TestIdentity, Utf8Codec, limits, open, transaction};
use super::*;

#[test]
fn handoff_preserves_history_and_closes_retained_engine() {
    let directory = tempfile::tempdir().unwrap();
    let engine = Arc::new(open(directory.path()));
    let principal = "agent".to_owned();
    let mut root = None;
    let mut commits = Vec::new();
    for value in 0_u8..64 {
        let (commit, transaction) = transaction(&principal, root, &[value]);
        root = Some(engine.commit(transaction).unwrap().root());
        commits.push(commit);
    }
    let count = engine.object_count().unwrap();
    let transferred = engine.handoff_for_retirement().unwrap();
    assert_eq!(transferred.root(&principal).unwrap(), root);
    assert_eq!(transferred.object_count().unwrap(), count);
    for commit in &commits {
        assert!(transferred.object(*commit).unwrap().is_some());
        assert!(matches!(engine.object(*commit), Err(DurableError::Closed)));
    }
    assert!(matches!(engine.root(&principal), Err(DurableError::Closed)));
    let (_, rejected) = transaction(&principal, root, b"old handle");
    assert!(engine.commit(rejected).is_err());
    engine.close().unwrap();
    drop(engine);
    probe_lock(directory.path(), true);
    transferred.close().unwrap();
    probe_lock(directory.path(), false);
    let reopened = open(directory.path());
    assert_eq!(reopened.root(&principal).unwrap(), root);
    assert_eq!(reopened.object_count().unwrap(), count);
    for commit in commits {
        assert!(reopened.object(commit).unwrap().is_some());
    }
}

fn probe_lock(path: &std::path::Path, blocked: bool) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "engine::durable::retirement::tests::child_checks_exclusive_store_lock",
            "--nocapture",
        ])
        .env("ASTRID_TEST_RETIREMENT_STORE", path)
        .env(
            "ASTRID_TEST_RETIREMENT_BLOCKED",
            if blocked { "yes" } else { "no" },
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn child_checks_exclusive_store_lock() {
    let Some(path) = std::env::var_os("ASTRID_TEST_RETIREMENT_STORE") else {
        return;
    };
    let opened = DurableEngine::open(&path, TestIdentity, Utf8Codec, limits());
    let blocked = std::env::var("ASTRID_TEST_RETIREMENT_BLOCKED").unwrap() == "yes";
    assert_eq!(opened.is_err(), blocked);
}

#[test]
fn stager_holding_inner_causes_immediate_refusal_without_queue_deadlock() {
    let directory = tempfile::tempdir().unwrap();
    let engine = Arc::new(open(directory.path()));
    let inner = engine.inner.lock();
    let (sender, receiver) = std::sync::mpsc::channel();
    let other = Arc::clone(&engine);
    let worker = std::thread::spawn(move || {
        sender
            .send(other.handoff_for_retirement().is_err())
            .unwrap();
    });
    let refused = receiver.recv_timeout(std::time::Duration::from_secs(5));
    drop(inner);
    worker.join().unwrap();
    assert!(
        refused.unwrap(),
        "handoff waited while holding the commit queue"
    );
    let (_, transaction) = transaction("agent", None, b"still writable");
    engine.commit(transaction).unwrap();
    engine.handoff_for_retirement().unwrap().close().unwrap();
}

#[test]
fn prepared_batch_cannot_cross_retirement_authority() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("agent", None, b"prepared before retirement");
    let batch = engine
        .prepare_objects_for_projection(
            transaction
                .records()
                .iter()
                .map(|(_, record)| record.clone())
                .collect(),
            None,
        )
        .unwrap();
    let transferred = engine.handoff_for_retirement().unwrap();
    assert!(
        transferred
            .stage_prepared_for_projection(batch, None)
            .is_err()
    );
    transferred.close().unwrap();
}

#[test]
fn handoff_flushes_pending_wal_before_transferring_authority() {
    use super::super::{
        DurableEnginePolicy, GroupCommitPolicy, ObjectCacheConfig, RecoveryRetryPolicy,
        TransactionWalPolicy,
    };
    let directory = tempfile::tempdir().unwrap();
    let policy = DurableEnginePolicy::new(
        GroupCommitPolicy::immediate(),
        RecoveryRetryPolicy::immediate(),
        ObjectCacheConfig::disabled(),
    )
    .with_transaction_wal(TransactionWalPolicy::enabled(
        std::num::NonZeroU64::new(u64::MAX).unwrap(),
    ));
    let engine = DurableEngine::open_with_policy(
        directory.path(),
        TestIdentity,
        Utf8Codec,
        limits(),
        policy,
    )
    .unwrap();
    let (commit, transaction) = transaction("agent", None, b"pending WAL state");
    let root = engine.commit(transaction).unwrap().root();
    let transferred = engine.handoff_for_retirement().unwrap();
    assert_eq!(transferred.root(&"agent".to_owned()).unwrap(), Some(root));
    assert!(transferred.object(commit).unwrap().is_some());
    engine.close().unwrap();
    probe_lock(directory.path(), true);
    transferred.close().unwrap();
    let reopened = open(directory.path());
    assert_eq!(reopened.root(&"agent".to_owned()).unwrap(), Some(root));
    assert!(reopened.object(commit).unwrap().is_some());
}

#[test]
fn failed_handoff_flush_keeps_lock_and_recoverable_old_authority() {
    use super::super::{FaultInjector, FaultPoint};
    use std::sync::atomic::AtomicBool;
    struct Switch(AtomicBool);
    impl FaultInjector for Switch {
        fn should_fail(&self, point: FaultPoint) -> bool {
            point == FaultPoint::BeforeIndexCachePublication && self.0.load(Ordering::Acquire)
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let faults = Arc::new(Switch(AtomicBool::new(false)));
    let engine = DurableEngine::open_with_faults(
        directory.path(),
        TestIdentity,
        Utf8Codec,
        limits(),
        faults.clone(),
    )
    .unwrap();
    let (commit, transaction) = transaction("agent", None, b"recover after handoff failure");
    let root = engine.commit(transaction).unwrap().root();
    faults.0.store(true, Ordering::Release);
    assert!(engine.handoff_for_retirement().is_err());
    assert!(engine.inner.lock().poisoned);
    probe_lock(directory.path(), true);
    faults.0.store(false, Ordering::Release);
    assert_eq!(engine.root(&"agent".to_owned()).unwrap(), Some(root));
    assert!(engine.object(commit).unwrap().is_some());
    let transferred = engine.handoff_for_retirement().unwrap();
    engine.close().unwrap();
    probe_lock(directory.path(), true);
    transferred.close().unwrap();
}
