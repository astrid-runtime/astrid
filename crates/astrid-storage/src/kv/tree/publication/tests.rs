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
