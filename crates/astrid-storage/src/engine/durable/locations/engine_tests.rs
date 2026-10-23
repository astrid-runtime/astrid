//! Full engine admission, restart and scratch-repair regressions.

use super::super::tests::{TestIdentity, Utf8Codec, limits, transaction};
use super::super::{DurableEngine, DurableEnginePolicy, EngineOpenOptions, NoFaults};
use super::super::{DurableError, TransactionWalPolicy};
use super::LocationIndexMemoryBudget;
use crate::engine::{GroupCommitPolicy, ObjectCacheConfig, RecoveryRetryPolicy};
use crate::storage_model::ObjectIdentity as _;
use crate::storage_model::{ObjectClass, ObjectFormatVersion, ObjectKind, ObjectRecord};
use std::num::NonZeroU64;

fn open(path: &std::path::Path) -> DurableEngine<String, TestIdentity, Utf8Codec> {
    open_with_wal(path, TransactionWalPolicy::disabled())
}

fn open_with_wal(
    path: &std::path::Path,
    wal: TransactionWalPolicy,
) -> DurableEngine<String, TestIdentity, Utf8Codec> {
    let budget = LocationIndexMemoryBudget::new(NonZeroU64::new(80 * 8).unwrap()).unwrap();
    DurableEngine::open_with_options(
        path,
        TestIdentity,
        Utf8Codec,
        limits(),
        EngineOpenOptions {
            policy: DurableEnginePolicy::new(
                GroupCommitPolicy::default(),
                RecoveryRetryPolicy::immediate(),
                ObjectCacheConfig::disabled(),
            )
            .with_location_index_memory(budget)
            .with_transaction_wal(wal),
            faults: std::sync::Arc::new(NoFaults),
        },
    )
    .unwrap()
}

#[test]
fn spilled_location_index_restarts_with_all_roots_and_historical_objects_intact() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (commit, root) = transaction("alice", None, b"durable root with cold locators");
    engine.commit(root).unwrap();
    let mut history = Vec::new();
    for number in 0..160_u64 {
        let record = ObjectRecord::new(
            ObjectKind::Evidence,
            ObjectFormatVersion::V1,
            number.to_le_bytes().to_vec(),
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let (id, _) = engine.persist_standalone_object(&record).unwrap();
        history.push((id, record));
        assert!(engine.inner.lock().index.resident_entries() < 8);
    }
    let count = engine.object_count().unwrap();
    let smaller = LocationIndexMemoryBudget::new(NonZeroU64::new(80 * 2).unwrap()).unwrap();
    engine.set_location_index_memory(smaller).unwrap();
    assert!(engine.inner.lock().index.resident_capacity_bytes() <= 160);
    for (id, record) in &history {
        assert_eq!(engine.object(*id).unwrap(), Some(record.clone()));
    }
    engine.close().unwrap();
    assert_eq!(engine.inner.lock().index.resident_capacity_bytes(), 0);
    let reopened = open(directory.path());
    assert_eq!(reopened.object_count().unwrap(), count);
    assert_eq!(
        reopened.root(&"alice".to_owned()).unwrap().unwrap().commit,
        commit
    );
    for (id, record) in &history {
        assert_eq!(reopened.object(*id).unwrap(), Some(record.clone()));
    }
    assert!(reopened.inner.lock().index.resident_entries() < 8);
    reopened.inner.lock().index.truncate_test_run();
    // A cold read must discover the damaged accelerator. It must error rather
    // than claim an acknowledged object is missing.
    let mut observed = false;
    for (id, _) in &history {
        match reopened.object(*id) {
            Err(_) => {
                observed = true;
                break;
            },
            Ok(value) => assert!(value.is_some()),
        }
    }
    assert!(observed);
    assert!(reopened.recover_if_required().unwrap());
    assert!(!reopened.recover_if_required().unwrap());
    for (id, record) in history {
        assert_eq!(reopened.object(id).unwrap(), Some(record));
    }
    assert_eq!(
        reopened.root(&"alice".to_owned()).unwrap().unwrap().commit,
        commit
    );
}

#[test]
fn location_index_memory_target_is_positive_finite_and_holds_a_complete_entry() {
    assert!(LocationIndexMemoryBudget::new(NonZeroU64::new(1).unwrap()).is_err());
    assert!(LocationIndexMemoryBudget::new(NonZeroU64::new(u64::MAX).unwrap()).is_err());
    let minimum = LocationIndexMemoryBudget::new(
        NonZeroU64::new(LocationIndexMemoryBudget::MIN_BYTES).unwrap(),
    )
    .unwrap();
    assert_eq!(minimum.entries().get(), 1);
    assert!(LocationIndexMemoryBudget::default().entries().get() > 1);
}

fn seed_spilled_history(
    engine: &DurableEngine<String, TestIdentity, Utf8Codec>,
) -> Vec<(super::ObjectId, ObjectRecord)> {
    (0..24_u64)
        .map(|number| {
            let record = ObjectRecord::new(
                ObjectKind::Evidence,
                ObjectFormatVersion::V1,
                number.to_le_bytes().to_vec(),
                Vec::new(),
                0,
                ObjectClass::Metadata,
            )
            .unwrap();
            let (id, _) = engine.persist_standalone_object(&record).unwrap();
            (id, record)
        })
        .collect()
}

fn assert_poisoned_and_recover_history(
    engine: &DurableEngine<String, TestIdentity, Utf8Codec>,
    history: &[(super::ObjectId, ObjectRecord)],
) {
    assert!(engine.inner.lock().poisoned);
    assert!(engine.recover_if_required().unwrap());
    assert!(!engine.inner.lock().poisoned);
    for (id, record) in history {
        assert_eq!(engine.object(*id).unwrap(), Some(record.clone()));
    }
}

#[test]
fn standalone_locator_failure_after_durable_append_returns_error_and_recovers_object() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let mut history = seed_spilled_history(&engine);
    let record = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"persisted before scratch failure".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let id = TestIdentity.identify(&record);
    let arena = directory.path().join(super::super::ARENA_FILE);
    let before = std::fs::metadata(&arena).unwrap().len();
    engine.inner.lock().index.damage_run_after_inserts(0);
    assert!(engine.persist_standalone_object(&record).is_err());
    assert!(std::fs::metadata(&arena).unwrap().len() > before);
    history.push((id, record));
    assert_poisoned_and_recover_history(&engine, &history);
}

#[test]
fn mid_group_locator_failure_returns_error_after_durable_root_and_recovers() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let history = seed_spilled_history(&engine);
    let (commit, tx) = transaction("alice", None, b"group persisted before locator install");
    let before_count = engine.inner.lock().index.len();
    let roots = directory.path().join(super::super::ROOT_FILE);
    let before = std::fs::metadata(&roots).unwrap().len();
    engine.inner.lock().index.damage_run_after_inserts(1);
    assert!(engine.commit(tx).is_err(), "no successful commit receipt");
    assert_eq!(engine.inner.lock().index.len(), before_count + 1);
    assert!(std::fs::metadata(&roots).unwrap().len() > before);
    assert_poisoned_and_recover_history(&engine, &history);
    assert_eq!(
        engine.root(&"alice".to_owned()).unwrap().unwrap().commit,
        commit
    );
    assert!(engine.object(commit).unwrap().is_some());
}

#[test]
fn checkpoint_iteration_scratch_corruption_poison_and_recovery_preserve_history() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let history = seed_spilled_history(&engine);
    engine.inner.lock().index.truncate_test_run();
    // No object lookup observes the corruption before production checkpointing.
    assert!(!engine.inner.lock().poisoned);
    assert!(engine.flush().is_err());
    assert_poisoned_and_recover_history(&engine, &history);
    engine.flush().unwrap();
    engine.close().unwrap();
    let reopened = open(directory.path());
    for (id, record) in history {
        assert_eq!(reopened.object(id).unwrap(), Some(record));
    }
}

#[test]
fn wal_checkpoint_mid_install_scratch_failure_replays_acknowledged_root() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open_with_wal(
        directory.path(),
        TransactionWalPolicy::enabled(NonZeroU64::new(u64::MAX).unwrap()),
    );
    let history = seed_spilled_history(&engine);
    let (commit, tx) = transaction("alice", None, b"acknowledged WAL survives scratch failure");
    let root = engine.commit(tx).unwrap().root();
    let before_count = engine.inner.lock().index.len();
    engine.inner.lock().index.damage_run_after_inserts(1);
    assert!(engine.flush().is_err());
    assert_eq!(engine.inner.lock().index.len(), before_count + 1);
    assert_poisoned_and_recover_history(&engine, &history);
    assert_eq!(engine.root(&"alice".to_owned()).unwrap(), Some(root));
    assert!(engine.object(commit).unwrap().is_some());
    engine.close().unwrap();
    // Turning off new WAL writes must still replay the acknowledged history.
    let reopened = open(directory.path());
    assert_eq!(reopened.root(&"alice".to_owned()).unwrap(), Some(root));
    assert!(reopened.object(commit).unwrap().is_some());
}

#[test]
fn retirement_transfers_spilled_locator_files_and_releases_old_owner() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let history = seed_spilled_history(&engine);
    let transferred = engine.handoff_for_retirement().unwrap();
    assert_eq!(engine.inner.lock().index.resident_capacity_bytes(), 0);
    for (id, record) in history {
        assert!(matches!(engine.object(id), Err(DurableError::Closed)));
        assert!(transferred.inner.lock().index.closure_proven(id).unwrap());
        assert_eq!(transferred.object(id).unwrap(), Some(record));
    }
    transferred.close().unwrap();
}

#[test]
fn proof_install_failure_immediately_fences_standalone_and_staged_publication() {
    for standalone in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let engine = open(directory.path());
        engine
            .set_location_index_memory(
                LocationIndexMemoryBudget::new(
                    NonZeroU64::new(LocationIndexMemoryBudget::MIN_BYTES).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let mut history = seed_spilled_history(&engine);
        let record = ObjectRecord::new(
            ObjectKind::Evidence,
            ObjectFormatVersion::V1,
            b"proof failure after location admission".to_vec(),
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let id = TestIdentity.identify(&record);
        engine.inner.lock().index.damage_run_after_inserts(1);
        let result = if standalone {
            engine.persist_standalone_object(&record)
        } else {
            engine.stage_object(&record)
        };
        assert!(result.is_err(), "proof write cannot acknowledge success");
        assert_eq!(
            engine.lifecycle.load(std::sync::atomic::Ordering::Acquire),
            super::super::LIFECYCLE_REQUIRES_RECOVERY,
            "cached reads must observe the fence before another lock"
        );
        history.push((id, record));
        assert_poisoned_and_recover_history(&engine, &history);
    }
}

#[test]
fn wal_closure_proofs_fold_into_locators_and_recover_with_the_same_root() {
    use super::super::proofs::ClosureProofLookup as _;
    let directory = tempfile::tempdir().unwrap();
    let engine = open_with_wal(
        directory.path(),
        TransactionWalPolicy::enabled(NonZeroU64::new(u64::MAX).unwrap()),
    );
    let (commit, tx) = transaction("alice", None, b"pending proof ownership");
    let root = engine.commit(tx).unwrap().root();
    assert!(engine.inner.lock().proofs().proven(&commit).unwrap());
    engine.flush().unwrap();
    assert!(engine.inner.lock().pending_wal.is_empty());
    assert!(engine.inner.lock().index.closure_proven(commit).unwrap());
    engine.close().unwrap();
    let reopened = open(directory.path());
    assert_eq!(reopened.root(&"alice".to_owned()).unwrap(), Some(root));
    assert!(reopened.inner.lock().proofs().proven(&commit).unwrap());
}

fn activate_test_catalogue(engine: &DurableEngine<String, TestIdentity, Utf8Codec>) {
    let specification = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"reverse locator recovery specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (id, _) = engine.persist_standalone_object(&specification).unwrap();
    engine
        .ensure_direct_representation_catalogue(id, &[id])
        .unwrap();
}

#[test]
fn reverse_admission_failure_after_publication_immediately_fences_and_recovers() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    activate_test_catalogue(&engine);
    let mut history = seed_spilled_history(&engine);
    let record = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"canonical object before reverse admission failure".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let id = TestIdentity.identify(&record);
    engine
        .inner
        .lock()
        .representations
        .as_mut()
        .unwrap()
        .damage_reverse_run_after_inserts(0);
    assert!(engine.persist_standalone_object(&record).is_err());
    assert_eq!(
        engine.lifecycle.load(std::sync::atomic::Ordering::Acquire),
        super::super::LIFECYCLE_REQUIRES_RECOVERY
    );
    history.push((id, record));
    assert_poisoned_and_recover_history(&engine, &history);
}

#[test]
fn retirement_keeps_reverse_custody_and_recovers_corrupt_scratch() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    activate_test_catalogue(&engine);
    let history = seed_spilled_history(&engine);
    let transferred = engine.handoff_for_retirement().unwrap();
    for (id, _) in &history {
        assert!(
            transferred
                .inner
                .lock()
                .representations
                .as_ref()
                .unwrap()
                .contains_direct(*id)
                .unwrap()
        );
    }
    transferred
        .inner
        .lock()
        .representations
        .as_ref()
        .unwrap()
        .truncate_reverse_test_run();
    assert!(
        transferred
            .inner
            .lock()
            .representations
            .as_ref()
            .unwrap()
            .contains_direct(history[0].0)
            .is_err()
    );
    assert!(transferred.recover_if_required().unwrap());
    assert!(!transferred.recover_if_required().unwrap());
    for (id, record) in &history {
        assert_eq!(transferred.object(*id).unwrap(), Some(record.clone()));
    }
    transferred.close().unwrap();
    let reopened = open(directory.path());
    for (id, record) in history {
        assert_eq!(reopened.object(id).unwrap(), Some(record));
    }
}
