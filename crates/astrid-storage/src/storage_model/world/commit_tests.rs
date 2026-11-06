use std::cell::Cell;
use std::sync::{Arc, Barrier};

use super::World;
use parking_lot::RwLock;

use crate::engine::{InMemoryEngine, KvProjectionEngine, RootTransaction};
use crate::principal_state::Blake3ObjectIdentityV1;
use crate::storage_model::{
    ModelError, ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord,
    ObjectReference, ReferenceLabel, RootGeneration, RootState,
};

thread_local! {
    static CLOSURE_WALKS: Cell<Option<usize>> = const { Cell::new(None) };
    static CLOSURE_PAUSE: Cell<Option<(Arc<Barrier>, Arc<Barrier>)>> = const { Cell::new(None) };
}

pub(super) fn record_closure_walk() {
    CLOSURE_WALKS.with(|count| {
        count.set(count.get().map(|walks| walks.strict_add(1)));
    });
    if let Some((entered, release)) = CLOSURE_PAUSE.take() {
        entered.wait();
        release.wait();
    }
}

struct ResetWalks;

impl Drop for ResetWalks {
    fn drop(&mut self) {
        CLOSURE_WALKS.set(None);
        CLOSURE_PAUSE.set(None);
    }
}

fn observed<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    assert!(CLOSURE_WALKS.replace(Some(0)).is_none());
    let reset = ResetWalks;
    let result = operation();
    let count = CLOSURE_WALKS.get().unwrap();
    drop(reset);
    (result, count)
}

fn commit_for(payload: &[u8], leaf: ObjectId) -> ObjectRecord {
    ObjectRecord::new(
        ObjectKind::Commit,
        ObjectFormatVersion::V1,
        payload.to_vec(),
        vec![ObjectReference::owns(
            ReferenceLabel::new(b"state".to_vec()),
            leaf,
        )],
        0,
        ObjectClass::Metadata,
    )
    .unwrap()
}

#[test]
fn engine_commit_validates_its_complete_closure_once() {
    let engine = InMemoryEngine::new(Blake3ObjectIdentityV1);
    let leaf = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        b"immutable payload".to_vec(),
        Vec::new(),
        17,
        ObjectClass::Data,
    )
    .unwrap();
    let leaf_id = engine.identify(&leaf);
    let commit = commit_for(b"first", leaf_id);
    let commit_id = engine.identify(&commit);
    let (result, walks) = observed(|| {
        engine.commit(RootTransaction::new(
            "alice",
            None,
            commit_id,
            vec![(leaf_id, leaf), (commit_id, commit)],
        ))
    });
    let first = result.unwrap();
    assert_eq!(walks, 1, "commit repeated its complete owning-closure walk");
    assert_eq!(first.objects_inserted(), 2);
    assert_eq!(engine.root(&"alice"), Some(first.root()));

    let commit = commit_for(b"second", leaf_id);
    let commit_id = engine.identify(&commit);
    let (result, walks) = observed(|| {
        engine.commit(RootTransaction::new(
            "alice",
            Some(first.root()),
            commit_id,
            vec![(commit_id, commit)],
        ))
    });
    let second = result.unwrap();
    assert_eq!(walks, 1, "resident objects caused another closure walk");
    assert_eq!(second.objects_inserted(), 1);
    assert_eq!(engine.root(&"alice"), Some(second.root()));
    assert_eq!(
        second.root().generation,
        first.root().generation.checked_next().unwrap()
    );
    let (result, walks) = observed(|| {
        engine.commit(RootTransaction::new(
            "alice",
            Some(second.root()),
            first.root().commit,
            Vec::new(),
        ))
    });
    let restored = result.unwrap();
    assert_eq!(walks, 1, "resident-only retarget repeated its closure walk");
    assert_eq!(restored.objects_inserted(), 0);
    assert_eq!(restored.root().commit, first.root().commit);
    assert_eq!(
        restored.root().generation,
        second.root().generation.checked_next().unwrap()
    );
}

#[test]
fn rejected_owned_commits_preserve_objects_and_roots() {
    let root = ObjectId::new([1; 32]);
    let missing = ObjectId::new([2; 32]);
    let unrelated = ObjectId::new([3; 32]);
    let chunk = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        b"resident".to_vec(),
        Vec::new(),
        8,
        ObjectClass::Data,
    )
    .unwrap();
    let valid = commit_for(b"valid", unrelated);
    let incomplete = commit_for(b"incomplete", missing);
    let cyclic = commit_for(b"cycle", root);
    let cases = [
        (vec![(root, incomplete)], ModelError::MissingObject(missing)),
        (vec![(root, cyclic)], ModelError::ObjectCycle(root)),
        (
            vec![(root, valid.clone()), (missing, chunk.clone())],
            ModelError::ExtraneousImportObject(missing),
        ),
        (
            vec![(root, chunk.clone())],
            ModelError::RootNotCommit {
                object: root,
                actual: ObjectKind::Chunk,
            },
        ),
        (
            vec![(root, valid.clone()), (unrelated, valid.clone())],
            ModelError::ObjectCollision(unrelated),
        ),
        (
            vec![(root, valid), (root, commit_for(b"other", unrelated))],
            ModelError::ObjectCollision(root),
        ),
    ];
    for (records, error) in cases {
        let world = RwLock::new(World::new());
        world
            .write()
            .insert_object(unrelated, chunk.clone())
            .unwrap();
        assert_eq!(
            World::commit_closure_owned(world.upgradable_read(), "alice", None, root, records)
                .map(|(_guard, root, inserted)| (root, inserted)),
            Err(error)
        );
        assert_eq!(world.read().root(&"alice"), None);
        assert_eq!(world.read().object_count(), 1);
        assert_eq!(world.read().object(unrelated), Some(&chunk));
        assert_eq!(world.read().object(root), None);
    }
}

#[test]
fn owned_commit_checks_conflict_and_overflow_before_root_validation() {
    let mut world = World::new();
    let root = ObjectId::new([1; 32]);
    let actual = RootState {
        generation: RootGeneration::new(u64::MAX),
        commit: root,
    };
    // Set the otherwise unreachable terminal generation to exercise the
    // production overflow boundary without billions of root publications.
    world.roots.insert("alice", actual);
    let world = RwLock::new(world);
    assert_eq!(
        World::commit_closure_owned(world.upgradable_read(), "alice", None, root, Vec::new())
            .map(|(_guard, root, inserted)| (root, inserted)),
        Err(ModelError::RootConflict {
            expected: None,
            actual: Some(actual)
        }),
    );
    assert_eq!(
        World::commit_closure_owned(
            world.upgradable_read(),
            "alice",
            Some(actual),
            root,
            Vec::new()
        )
        .map(|(_guard, root, inserted)| (root, inserted)),
        Err(ModelError::ArithmeticOverflow),
    );
    assert_eq!(world.read().root(&"alice"), Some(actual));
    assert_eq!(world.read().object_count(), 0);
}

#[test]
fn standalone_root_swap_still_validates_resident_closure() {
    let mut world = World::new();
    let root = ObjectId::new([1; 32]);
    let missing = ObjectId::new([2; 32]);
    world
        .insert_object(root, commit_for(b"incomplete", missing))
        .unwrap();
    let (result, walks) = observed(|| world.compare_and_swap_root("alice", None, root));
    assert_eq!(result, Err(ModelError::MissingObject(missing)));
    assert_eq!(walks, 1);
    assert_eq!(world.root(&"alice"), None);
    assert_eq!(world.object_count(), 1);
}

#[test]
fn engine_commit_keeps_current_root_readable_during_closure_validation() {
    let engine = Arc::new(InMemoryEngine::new(Blake3ObjectIdentityV1));
    let leaf = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        b"value".to_vec(),
        Vec::new(),
        5,
        ObjectClass::Data,
    )
    .unwrap();
    let leaf_id = engine.identify(&leaf);
    let commit = commit_for(b"first", leaf_id);
    let commit_id = engine.identify(&commit);
    let initial = engine
        .commit(RootTransaction::new(
            "alice",
            None,
            commit_id,
            vec![(leaf_id, leaf), (commit_id, commit)],
        ))
        .unwrap()
        .root();
    let commit = commit_for(b"second", leaf_id);
    let commit_id = engine.identify(&commit);
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let worker = {
        let engine = Arc::clone(&engine);
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        std::thread::spawn(move || {
            let _reset = ResetWalks;
            CLOSURE_PAUSE.set(Some((entered, release)));
            engine.commit(RootTransaction::new(
                "alice",
                Some(initial),
                commit_id,
                vec![(commit_id, commit)],
            ))
        })
    };
    entered.wait();
    let captured = engine
        .current_kv_root_if_ready(&"alice")
        .map(crate::engine::ReadyKvRoot::get);
    // Release and join before asserting: a RED result must not leave the
    // validation thread blocked behind the test's own pause.
    release.wait();
    let published = worker.join().unwrap().unwrap().root();
    assert_eq!(
        captured,
        Some(Some(initial)),
        "closure validation blocked the root reader"
    );
    assert_eq!(published.commit, commit_id);
    assert_eq!(
        published.generation,
        initial.generation.checked_next().unwrap()
    );
    assert_eq!(engine.root(&"alice"), Some(published));
}
