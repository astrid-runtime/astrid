//! Closed engine handles release disposable views without changing disk authority.

use std::num::NonZeroU64;
use std::sync::Arc;

use crate::engine::durable::tests::{TestIdentity, Utf8Codec, limits, open, transaction};
use crate::engine::durable::{
    DurableEngine, DurableEnginePolicy, DurableError, TransactionWalPolicy,
};
use crate::storage_model::{ObjectClass, ObjectFormatVersion, ObjectKind, ObjectRecord};

fn assert_metadata_released(engine: &DurableEngine<String, TestIdentity, Utf8Codec>) {
    let inner = engine.inner.lock();
    assert!(
        inner.index.is_empty(),
        "closed handles retain historical locators"
    );
    assert_eq!(inner.index.resident_capacity_bytes(), 0);
    assert!(inner.roots_by_principal.is_empty());
    assert!(inner.pending_direct_objects.is_empty());
    assert_eq!(inner.pending_index_locations.capacity(), 0);
    assert!(inner.pending_wal.is_empty());
    assert!(engine.published_roots.entries.load().is_empty());
    assert!(engine.root_if_ready(&"alice".to_owned()).is_none());
}

#[test]
fn retained_closed_engine_releases_history_and_reopens_identical_authority() {
    let directory = tempfile::tempdir().unwrap();
    let engine = Arc::new(open(directory.path()));
    let retained = Arc::clone(&engine);
    let (commit, transaction) = transaction("alice", None, b"acknowledged root");
    engine.commit(transaction).unwrap();
    let mut history = Vec::new();
    for index in 0..128_u64 {
        let record = ObjectRecord::new(
            ObjectKind::Evidence,
            ObjectFormatVersion::V1,
            index.to_le_bytes().to_vec(),
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let (id, _) = engine.persist_standalone_object(&record).unwrap();
        history.push((id, record));
    }
    let count = engine.object_count().unwrap();
    assert!(!engine.inner.lock().index.is_empty());
    assert!(!engine.published_roots.entries.load().is_empty());

    engine.close().unwrap();
    assert_metadata_released(&retained);
    retained.close().unwrap();
    assert!(matches!(retained.object_count(), Err(DurableError::Closed)));

    let reopened = open(directory.path());
    assert_eq!(reopened.object_count().unwrap(), count);
    assert_eq!(
        reopened.root(&"alice".to_owned()).unwrap().unwrap().commit,
        commit
    );
    for (id, record) in history {
        assert_eq!(reopened.object(id).unwrap(), Some(record));
    }
}

#[test]
fn failed_close_discards_pending_views_but_replays_acknowledged_wal() {
    let directory = tempfile::tempdir().unwrap();
    let policy = || {
        DurableEnginePolicy::default().with_transaction_wal(TransactionWalPolicy::enabled(
            NonZeroU64::new(u64::MAX).unwrap(),
        ))
    };
    let engine = Arc::new(
        DurableEngine::open_with_policy(
            directory.path(),
            TestIdentity,
            Utf8Codec,
            limits(),
            policy(),
        )
        .unwrap(),
    );
    let (commit, transaction) = transaction("alice", None, b"durable WAL authority");
    engine.commit(transaction).unwrap();
    let count = engine.object_count().unwrap();
    {
        let mut inner = engine.inner.lock();
        assert!(!inner.pending_wal.is_empty());
        engine.mark_requires_recovery(&mut inner);
    }

    assert!(matches!(
        engine.close(),
        Err(DurableError::RequiresRecovery)
    ));
    assert_metadata_released(&engine);
    engine.close().unwrap();

    let reopened = DurableEngine::open_with_policy(
        directory.path(),
        TestIdentity,
        Utf8Codec,
        limits(),
        policy(),
    )
    .unwrap();
    assert_eq!(reopened.object_count().unwrap(), count);
    assert_eq!(
        reopened.root(&"alice".to_owned()).unwrap().unwrap().commit,
        commit
    );
    assert!(reopened.object(commit).unwrap().is_some());
}
