//! Public durable writes checkpoint physical metadata without deleting history.

use std::sync::Arc;

use crate::engine::durable::representations::RepresentationStore;
use crate::engine::durable::tests::{TestIdentity, Utf8Codec, limits, transaction};
use crate::engine::durable::{DurableEngine, DurableEnginePolicy, RecoveryLimits};
use crate::storage_model::{ObjectClass, ObjectFormatVersion, ObjectKind, ObjectRecord};
use crate::volume::{AstridVolume, HostedFileVolume};

type Engine = DurableEngine<String, TestIdentity, Utf8Codec>;

fn evidence(payload: Vec<u8>) -> ObjectRecord {
    ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        payload,
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap()
}

fn activated_engine(volume: Arc<dyn AstridVolume>) -> Engine {
    let engine = DurableEngine::open_volume(
        volume,
        TestIdentity,
        Utf8Codec,
        limits(),
        DurableEnginePolicy::default(),
    )
    .unwrap();
    let specification = evidence(b"physical format specification".to_vec());
    let (id, _) = engine.persist_standalone_object(&specification).unwrap();
    engine
        .ensure_direct_representation_catalogue(id, &[id])
        .unwrap();
    engine
}

#[test]
fn engine_commit_auto_checkpoints_representation_and_survives_close_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("engine.volume");
    let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&path).unwrap();
    let engine = activated_engine(Arc::clone(&volume));
    let before = engine
        .inner
        .lock()
        .representations
        .as_ref()
        .unwrap()
        .journal_generation;
    let mut expected = None;
    let mut history = Vec::new();
    for sequence in 0_u64..1024 {
        let mut payload = sequence.to_le_bytes().to_vec();
        payload.extend([b'x'; 256]);
        let (commit, txn) = transaction("alice", expected, &payload);
        expected = Some(engine.commit(txn).unwrap().root());
        history.push((commit, payload));
        if engine
            .inner
            .lock()
            .representations
            .as_ref()
            .unwrap()
            .journal_generation
            > before
        {
            break;
        }
    }
    engine.close().unwrap();
    engine.close().unwrap();
    drop(engine);

    let store = RepresentationStore::open_volume(&volume, RecoveryLimits::process_addressable())
        .unwrap()
        .unwrap();
    let current = store.journal_generation;
    assert!(
        current > before,
        "ordinary commits must advance CURRENT: {before} -> {current}; frames={}, resident_nodes={}",
        store.map_frame_count(),
        store.resident_map_node_count()
    );
    let regions = volume.list_regions("representations/generations/").unwrap();
    assert!(!regions.is_empty());
    assert!(
        regions.iter().all(|region| {
            region
                .as_str()
                .strip_prefix("representations/generations/")
                .and_then(|suffix| suffix.split_once('/'))
                .is_some_and(|(generation, _)| {
                    u64::from_str_radix(generation, 16).ok() == Some(current)
                })
        }),
        "obsolete generations must reclaim toward CURRENT-only: {regions:?}"
    );
    drop(store);
    drop(volume);

    let reopened: Arc<dyn AstridVolume> = HostedFileVolume::open(&path).unwrap();
    let engine = DurableEngine::open_volume(
        reopened,
        TestIdentity,
        Utf8Codec,
        limits(),
        DurableEnginePolicy::default(),
    )
    .unwrap();
    assert_eq!(engine.root(&"alice".to_owned()).unwrap(), expected);
    // Physical generations are disposable; all previously committed logical
    // objects and their owned leaves remain authenticated and readable.
    for (id, payload) in history {
        let object = engine
            .object(id)
            .unwrap()
            .expect("historical commit remains readable");
        assert_eq!(object.canonical_bytes(), payload);
        for reference in object.owning_references() {
            let leaf = engine
                .object(reference)
                .unwrap()
                .expect("owned history remains readable");
            assert_eq!(leaf.canonical_bytes(), payload);
        }
    }
    engine.close().unwrap();
}

#[test]
fn engine_close_without_commits_does_not_reclaim_fat_representation_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("fat-close.volume")).unwrap();
    let engine = activated_engine(Arc::clone(&volume));
    // Standalone publications use the real object arena and representation
    // frontier, without invoking the ordinary root-commit maintenance path.
    for sequence in 0_u64..1024 {
        engine
            .persist_standalone_object(&evidence(sequence.to_le_bytes().to_vec()))
            .unwrap();
        if engine
            .inner
            .lock()
            .representations
            .as_ref()
            .unwrap()
            .should_checkpoint_representations_metadata()
        {
            break;
        }
    }
    let (before_len, before_generation) = {
        let inner = engine.inner.lock();
        let store = inner.representations.as_ref().unwrap();
        assert!(
            store.should_checkpoint_representations_metadata(),
            "fixture must contain reclaimable history: frames={}, resident_nodes={}",
            store.map_frame_count(),
            store.resident_map_node_count()
        );
        (
            store.metadata.metadata().unwrap().len(),
            store.journal_generation,
        )
    };
    engine.close().unwrap();
    engine.close().unwrap();
    drop(engine);
    let reopened = RepresentationStore::open_volume(&volume, RecoveryLimits::process_addressable())
        .unwrap()
        .unwrap();
    assert_eq!(reopened.metadata.metadata().unwrap().len(), before_len);
    assert_eq!(reopened.journal_generation, before_generation);
}

#[test]
fn post_publication_checkpoint_failure_poison_fences_the_engine_until_recovery() {
    use super::adoption_tests::SyncFailOnceVolume;
    let directory = tempfile::tempdir().unwrap();
    let inner: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("checkpoint-poison.volume")).unwrap();
    let failing = Arc::new(SyncFailOnceVolume::new(inner));
    let volume: Arc<dyn AstridVolume> = failing.clone();
    let engine = activated_engine(volume);
    failing.arm_next_sync_failure();
    let mut expected = None;
    let mut committed = None;
    let mut observed_poison = false;
    for sequence in 0_u64..1024 {
        let payload = sequence.to_le_bytes().to_vec();
        let (commit, txn) = transaction("alice", expected, &payload);
        expected = Some(engine.commit(txn).unwrap().root());
        committed = Some((commit, payload));
        if engine.inner.lock().poisoned {
            observed_poison = true;
            break;
        }
    }
    assert!(
        observed_poison,
        "automatic maintenance must surface the injected failure"
    );
    // Public access must cross recovery before using the acknowledged durable tip.
    assert_eq!(engine.root(&"alice".to_owned()).unwrap(), expected);
    assert!(!engine.inner.lock().poisoned);
    let (commit, payload) = committed.unwrap();
    assert_eq!(
        engine.object(commit).unwrap().unwrap().canonical_bytes(),
        payload
    );
    engine.close().unwrap();
}
