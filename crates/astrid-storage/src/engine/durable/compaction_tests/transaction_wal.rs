//! Pending transaction WAL interactions with proof-audited compaction.

use super::*;

fn wal_policy() -> DurableEnginePolicy<String> {
    DurableEnginePolicy::new(
        GroupCommitPolicy::immediate(),
        RecoveryRetryPolicy::immediate(),
        ObjectCacheConfig::disabled(),
    )
    .with_transaction_wal(TransactionWalPolicy::enabled(
        std::num::NonZeroU64::new(u64::MAX).unwrap(),
    ))
}

fn open_backend(directory: &Path, volume: bool) -> TestEngine {
    if volume {
        let volume =
            crate::volume::HostedFileVolume::open(directory.join("astrid.volume")).unwrap();
        TestEngine::open_volume(volume, TestIdentity, Utf8Codec, limits(), wal_policy()).unwrap()
    } else {
        TestEngine::open_with_policy(directory, TestIdentity, Utf8Codec, limits(), wal_policy())
            .unwrap()
    }
}

#[test]
fn wal_compaction_drops_unreachable_overlay_before_later_fold() {
    for volume in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        assert_wal_retirement(directory.path(), volume);
    }
}

fn assert_wal_retirement(directory: &Path, volume: bool) {
    let engine = open_backend(directory, volume);
    let (_, retained) = two_versions(&engine);
    engine.flush().unwrap();
    let (discarded, transaction) = transaction("alice", Some(retained), b"unreachable-wal");
    let discarded_ids = transaction
        .records()
        .iter()
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    let transient = engine.commit(transaction).unwrap().root();
    let restored = engine
        .commit(RootTransaction::new(
            "alice".to_owned(),
            Some(transient),
            retained.commit,
            Vec::new(),
        ))
        .unwrap()
        .root();
    assert_eq!(restored.commit, retained.commit);
    assert!(
        engine
            .inner
            .lock()
            .pending_wal
            .get_object(&discarded)
            .is_some()
    );
    assert!(!engine.inner.lock().index.contains_key(&discarded));
    let policy_record = evidence(b"retain-current-roots");
    let authorization = plan(
        &engine,
        retention(&engine, &policy_record, []),
        policy_record,
    );
    assert!(authorization.facts().condemned().contains(&discarded));
    assert!(
        engine
            .inner
            .lock()
            .pending_wal
            .get_object(&discarded)
            .is_some()
    );
    assert!(!engine.inner.lock().index.contains_key(&discarded));
    let report = engine.compact(&authorization).unwrap();
    assert!(engine.inner.lock().pending_wal.is_empty());
    for id in &discarded_ids {
        assert!(
            engine.object(*id).unwrap().is_none(),
            "compaction left unreachable WAL object {id:?}"
        );
    }
    assert_eq!(
        u64::try_from(engine.object_count().unwrap()).unwrap(),
        report.objects_after()
    );
    engine.flush().unwrap();
    for id in &discarded_ids {
        assert!(
            engine.object(*id).unwrap().is_none(),
            "WAL fold resurrected compacted object {id:?}"
        );
    }
    engine.close().unwrap();
    let reopened = open_backend(directory, volume);
    assert_eq!(reopened.root(&"alice".to_owned()).unwrap(), Some(restored));
    for id in discarded_ids {
        assert!(
            reopened.object(id).unwrap().is_none(),
            "recovery resurrected compacted object {id:?}"
        );
    }
    reopened.close().unwrap();
}

#[test]
fn wal_compaction_preserves_wal_only_current_root() {
    for volume in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let engine = open_backend(directory.path(), volume);
        let (_, previous) = two_versions(&engine);
        engine.flush().unwrap();
        let (commit, transaction) = transaction("alice", Some(previous), b"live-wal-root");
        let records = transaction.records().to_vec();
        let current = engine.commit(transaction).unwrap().root();
        let policy = evidence(b"retain-current-roots");
        let authorization = plan(&engine, retention(&engine, &policy, []), policy);
        assert!(
            engine
                .inner
                .lock()
                .pending_wal
                .get_object(&commit)
                .is_some()
        );
        assert!(!engine.inner.lock().index.contains_key(&commit));
        engine.compact(&authorization).unwrap();
        for (id, record) in &records {
            assert_eq!(engine.object(*id).unwrap().as_ref(), Some(record));
        }
        engine.flush().unwrap();
        engine.close().unwrap();
        let reopened = open_backend(directory.path(), volume);
        assert_eq!(reopened.root(&"alice".to_owned()).unwrap(), Some(current));
        for (id, record) in records {
            assert_eq!(reopened.object(id).unwrap(), Some(record));
        }
        reopened.close().unwrap();
    }
}

#[test]
fn wal_compaction_fact_capture_is_nonmutating_and_checkpoint_stable() {
    for volume in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let engine = open_backend(directory.path(), volume);
        two_versions(&engine);
        let pending_objects = engine.inner.lock().pending_wal.objects().count();
        assert!(pending_objects > 0);
        let policy = evidence(b"retain-current-roots");
        let retention = retention(&engine, &policy, []);
        let authorization = plan(&engine, retention.clone(), policy);
        assert_eq!(
            engine.inner.lock().pending_wal.objects().count(),
            pending_objects
        );
        assert_eq!(engine.inner.lock().index.len(), 0);
        engine.flush().unwrap();
        assert_eq!(
            engine.capture_compaction_facts(&retention).unwrap(),
            *authorization.facts()
        );
        engine.compact(&authorization).unwrap();
        engine.close().unwrap();
    }
}

#[test]
fn wal_compaction_rejects_stale_plan_without_losing_new_commit() {
    for volume in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let engine = open_backend(directory.path(), volume);
        let (_, previous) = two_versions(&engine);
        let policy = evidence(b"retain-current-roots");
        let authorization = plan(&engine, retention(&engine, &policy, []), policy);
        let (_, transaction) = transaction("alice", Some(previous), b"after-proof");
        let records = transaction.records().to_vec();
        let current = engine.commit(transaction).unwrap().root();
        assert!(matches!(
            engine.compact(&authorization),
            Err(DurableError::CompactionSnapshotChanged)
        ));
        assert_eq!(engine.root(&"alice".to_owned()).unwrap(), Some(current));
        for (id, record) in &records {
            assert_eq!(engine.object(*id).unwrap().as_ref(), Some(record));
        }
        assert!(engine.pending_compaction_evidence().unwrap().is_empty());
        engine.close().unwrap();
        let reopened = open_backend(directory.path(), volume);
        assert_eq!(reopened.root(&"alice".to_owned()).unwrap(), Some(current));
        for (id, record) in records {
            assert_eq!(reopened.object(id).unwrap(), Some(record));
        }
        reopened.close().unwrap();
    }
}

#[test]
fn wal_compaction_recovers_at_each_publication_boundary_with_catalogue() {
    let directory_points = [
        FaultPoint::AfterCompactionFilesFlush,
        FaultPoint::AfterCompactionEvidencePrepare,
        FaultPoint::AfterCompactionIntentFlush,
        FaultPoint::AfterCompactionArenaBackup,
        FaultPoint::AfterCompactionArenaPromote,
        FaultPoint::AfterCompactionRootsBackup,
        FaultPoint::AfterCompactionRootsPromote,
        FaultPoint::AfterCompactionDirectoryFlush,
        FaultPoint::AfterCompactionRepresentationRebase,
        FaultPoint::AfterCompactionEvidenceReady,
        FaultPoint::BeforeCompactionIntentRemoval,
    ];
    for volume in [false, true] {
        let points = if volume {
            &[
                FaultPoint::AfterCompactionEvidencePrepare,
                FaultPoint::AfterCompactionArenaPromote,
            ][..]
        } else {
            &directory_points[..]
        };
        for point in points {
            for recover_in_process in [false, true] {
                assert_wal_crash_recovers(volume, *point, recover_in_process);
            }
        }
    }
}

fn assert_wal_crash_recovers(volume: bool, point: FaultPoint, recover_in_process: bool) {
    let directory = tempfile::tempdir().unwrap();
    let faults: Arc<dyn FaultInjector> = Arc::new(FailAt(point));
    let engine = if volume {
        TestEngine::open_volume_with_faults(
            crate::volume::HostedFileVolume::open(directory.path().join("astrid.volume")).unwrap(),
            TestIdentity,
            Utf8Codec,
            limits(),
            wal_policy(),
            faults,
        )
    } else {
        TestEngine::open_with_options(
            directory.path(),
            TestIdentity,
            Utf8Codec,
            limits(),
            EngineOpenOptions {
                policy: wal_policy(),
                faults,
            },
        )
    }
    .unwrap();
    let (specification, _) = engine
        .persist_standalone_object(&evidence(b"physical-format"))
        .unwrap();
    engine
        .ensure_direct_representation_catalogue(specification, &[specification])
        .unwrap();
    let (obsolete, current) = two_versions(&engine);
    assert!(!engine.inner.lock().pending_wal.is_empty());
    let current_record = engine.object(current.commit).unwrap().unwrap();
    let policy = evidence(b"retain-current-roots");
    let authorization = plan(&engine, retention(&engine, &policy, []), policy);
    assert!(matches!(
        engine.compact(&authorization),
        Err(DurableError::FaultInjected(actual)) if actual == point
    ));
    let committed = if volume {
        point == FaultPoint::AfterCompactionArenaPromote
    } else {
        !matches!(
            point,
            FaultPoint::AfterCompactionFilesFlush | FaultPoint::AfterCompactionEvidencePrepare
        )
    };
    if recover_in_process {
        assert_eq!(engine.root(&"alice".to_owned()).unwrap(), Some(current));
        assert_eq!(
            engine.object(current.commit).unwrap(),
            Some(current_record.clone())
        );
        assert_eq!(engine.object(obsolete.commit).unwrap().is_none(), committed);
    }
    drop(engine);
    let recovered = open_backend(directory.path(), volume);
    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(current));
    assert_eq!(
        recovered.object(current.commit).unwrap(),
        Some(current_record)
    );
    assert_eq!(
        recovered.object(obsolete.commit).unwrap().is_none(),
        committed
    );
    if !committed {
        recovered.compact(&authorization).unwrap();
    }
    recovered.flush().unwrap();
    assert!(recovered.object(obsolete.commit).unwrap().is_none());
    recovered.close().unwrap();
    let reopened = open_backend(directory.path(), volume);
    assert_eq!(reopened.root(&"alice".to_owned()).unwrap(), Some(current));
    assert!(reopened.object(current.commit).unwrap().is_some());
    assert!(reopened.object(obsolete.commit).unwrap().is_none());
    reopened.close().unwrap();
}

#[derive(Debug, Default)]
struct FailNextIndexPublication(std::sync::atomic::AtomicBool);

impl FaultInjector for FailNextIndexPublication {
    fn should_fail(&self, point: FaultPoint) -> bool {
        point == FaultPoint::BeforeIndexCachePublication
            && self.0.swap(false, std::sync::atomic::Ordering::SeqCst)
    }
}

#[test]
fn wal_compaction_checkpoint_failure_recovers_before_retry() {
    let directory = tempfile::tempdir().unwrap();
    let faults = Arc::new(FailNextIndexPublication::default());
    let engine = TestEngine::open_with_options(
        directory.path(),
        TestIdentity,
        Utf8Codec,
        limits(),
        EngineOpenOptions {
            policy: wal_policy(),
            faults: faults.clone(),
        },
    )
    .unwrap();
    let (obsolete, current) = two_versions(&engine);
    let policy = evidence(b"retain-current-roots");
    let authorization = plan(&engine, retention(&engine, &policy, []), policy);
    faults.0.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        engine.compact(&authorization),
        Err(DurableError::FaultInjected(
            FaultPoint::BeforeIndexCachePublication
        ))
    ));
    assert_eq!(engine.root(&"alice".to_owned()).unwrap(), Some(current));
    assert!(engine.object(current.commit).unwrap().is_some());
    assert!(engine.object(obsolete.commit).unwrap().is_some());
    assert!(engine.pending_compaction_evidence().unwrap().is_empty());
    engine.compact(&authorization).unwrap();
    engine.flush().unwrap();
    assert!(engine.object(obsolete.commit).unwrap().is_none());
    engine.close().unwrap();
    let recovered = open_backend(directory.path(), false);
    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(current));
    assert!(recovered.object(current.commit).unwrap().is_some());
    assert!(recovered.object(obsolete.commit).unwrap().is_none());
    recovered.close().unwrap();
}
