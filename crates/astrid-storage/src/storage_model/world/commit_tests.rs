use std::cell::Cell;

use super::World;

use crate::engine::{InMemoryEngine, RootTransaction};
use crate::principal_state::Blake3ObjectIdentityV1;
use crate::storage_model::{
    ModelError, ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord,
    ObjectReference, ReferenceLabel, RootGeneration, RootState,
};

thread_local! {
    static CLOSURE_WALKS: Cell<Option<usize>> = const { Cell::new(None) };
}

pub(super) fn record_closure_walk() {
    CLOSURE_WALKS.with(|count| {
        count.set(count.get().map(|walks| walks.strict_add(1)));
    });
}

struct ResetWalks;

impl Drop for ResetWalks {
    fn drop(&mut self) {
        CLOSURE_WALKS.set(None);
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
        let mut world = World::new();
        world.insert_object(unrelated, chunk.clone()).unwrap();
        assert_eq!(
            world.commit_closure_owned("alice", None, root, records),
            Err(error)
        );
        assert_eq!(world.root(&"alice"), None);
        assert_eq!(world.object_count(), 1);
        assert_eq!(world.object(unrelated), Some(&chunk));
        assert_eq!(world.object(root), None);
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
    assert_eq!(
        world.commit_closure_owned("alice", None, root, Vec::new()),
        Err(ModelError::RootConflict {
            expected: None,
            actual: Some(actual)
        }),
    );
    assert_eq!(
        world.commit_closure_owned("alice", Some(actual), root, Vec::new()),
        Err(ModelError::ArithmeticOverflow),
    );
    assert_eq!(world.root(&"alice"), Some(actual));
    assert_eq!(world.object_count(), 0);
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
