use super::*;
use crate::storage_model::RootGeneration;
use std::sync::mpsc;
use std::time::Duration;

#[test]
fn cache_contention_never_blocks_admission_or_partially_publishes() {
    for lock_trees in [false, true] {
        let cache = Arc::new(KvValidationCache::<String>::default());
        let commit = ObjectId::new([7; 32]);
        let publication = KvCheckpointPublication::new(
            Arc::clone(&cache),
            "alice".to_owned(),
            commit,
            Projection::empty(),
            TreeValidation::EMPTY,
            cache.memo_epoch(),
        );
        let projections = (!lock_trees).then(|| cache.projections.lock());
        let trees = lock_trees.then(|| cache.trees.lock());
        let (finished, receive) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let retired = publication.try_publish(RootState {
                generation: RootGeneration::INITIAL,
                commit,
            });
            finished.send(retired.is_none()).unwrap();
        });
        // Release and join even if a regression waits on either cache lock.
        let result = receive.recv_timeout(Duration::from_secs(30));
        drop(trees);
        drop(projections);
        worker.join().unwrap();
        assert!(result.unwrap());
        assert!(cache.projections.lock().is_empty());
        assert!(cache.trees.lock().is_empty());
    }
}

#[test]
fn mismatched_commit_cannot_publish_a_checkpoint_certificate() {
    let cache = Arc::new(KvValidationCache::<String>::default());
    let publication = KvCheckpointPublication::new(
        Arc::clone(&cache),
        "alice".to_owned(),
        ObjectId::new([7; 32]),
        Projection::empty(),
        TreeValidation::EMPTY,
        cache.memo_epoch(),
    );
    assert!(
        publication
            .try_publish(RootState {
                generation: RootGeneration::INITIAL,
                commit: ObjectId::new([8; 32]),
            })
            .is_none()
    );
    assert!(cache.projections.lock().is_empty());
    assert!(cache.trees.lock().is_empty());
}

#[test]
fn admitted_checkpoint_cannot_publish_after_no_op_owner_forget() {
    let cache = Arc::new(KvValidationCache::<String>::default());
    let owner = "retiring".to_owned();
    let commit = ObjectId::new([7; 32]);
    let publication = KvCheckpointPublication::new(
        Arc::clone(&cache),
        owner.clone(),
        commit,
        Projection::empty(),
        TreeValidation::EMPTY,
        cache.memo_epoch(),
    );
    let catalogs = parking_lot::Mutex::new(std::collections::BTreeMap::new());
    cache.forget_owner(&owner, &catalogs);
    assert!(
        publication
            .try_publish(RootState {
                generation: RootGeneration::INITIAL,
                commit
            })
            .is_none()
    );
    assert!(cache.projections.lock().is_empty());
    assert!(cache.trees.lock().is_empty());
}

#[cfg(not(target_family = "wasm"))]
#[test]
fn only_issuing_durable_engine_publishes_the_sealed_checkpoint() {
    use crate::engine::{DurableEngine, RecoveryLimits};
    use crate::kv::tree_tests::Utf8Codec;
    use crate::principal_state::Blake3ObjectIdentityV1;
    use crate::storage_model::{ObjectClass, ObjectFormatVersion, ObjectKind, ObjectRecord};

    let open = |dir: &std::path::Path| {
        DurableEngine::open(
            dir,
            Blake3ObjectIdentityV1,
            Utf8Codec,
            RecoveryLimits::process_addressable(),
        )
        .unwrap()
    };
    let issuer_dir = tempfile::tempdir().unwrap();
    let peer_dir = tempfile::tempdir().unwrap();
    let issuer = open(issuer_dir.path());
    let peer = open(peer_dir.path());
    let owner = "alice".to_owned();
    let session = issuer.captured_identity_session();
    let record = ObjectRecord::new(
        ObjectKind::Commit,
        ObjectFormatVersion::V1,
        vec![],
        vec![],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let id = session.identify(&record);
    let cache = Arc::new(KvValidationCache::default());
    let sealed = || {
        session
            .seal_transaction(owner.clone(), None, id, vec![(id, record.clone())])
            .with_kv_checkpoint_publication(|declared_owner, declared_commit| {
                KvCheckpointPublication::new(
                    Arc::clone(&cache),
                    declared_owner.clone(),
                    declared_commit,
                    Projection::empty(),
                    TreeValidation::EMPTY,
                    cache.memo_epoch(),
                )
            })
    };
    let peer_root = peer.commit(sealed()).unwrap().root();
    assert_eq!(peer_root.commit, id);
    assert!(cache.projections.lock().is_empty());
    assert!(cache.trees.lock().is_empty());

    let issuer_root = issuer.commit(sealed()).unwrap().root();
    assert_eq!(issuer_root, peer_root);
    assert!(cache.projections.lock().contains_key(&owner));
    assert!(cache.trees.lock().contains_key(&owner));
}
