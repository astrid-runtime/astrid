//! Completion of a pre-retirement read must not recreate cache ownership.

use super::super::tests::{open_with_cache, transaction};
use super::super::{ObjectCacheCapacity, ObjectCacheController};

#[test]
fn decoded_read_completed_after_root_removal_remains_uncached() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open_with_cache(
        directory.path(),
        ObjectCacheController::new(ObjectCacheCapacity::Unbounded),
    );
    let owner = "alice".to_owned();
    let (_, transaction) = transaction(&owner, None, b"immutable read lease");
    let root = engine.commit(transaction).unwrap().root();
    // Capture precisely the validated record and generation that an arena
    // read can hold while it releases the engine lock to perform I/O.
    let record = engine.object(root.commit).unwrap().unwrap();
    let generation = engine.inner.lock().arena_generation;
    assert!(engine.object_for(&owner, root.commit).unwrap().is_some());
    assert!(engine.object_cache_principal_charge(&owner) > 0);
    engine.remove_root(&owner, root).unwrap();
    assert_eq!(engine.object_cache_principal_charge(&owner), 0);

    let completed = engine
        .retain_loaded_object_if_current(&owner, root.commit, generation, record.clone())
        .unwrap()
        .unwrap();
    assert_eq!(*completed, record);
    assert_eq!(
        engine.object_cache_principal_charge(&owner),
        0,
        "completion of a pre-retirement read recreated cache ownership"
    );
    assert!(engine.root(&owner).unwrap().is_none());
    engine.close().unwrap();
}
