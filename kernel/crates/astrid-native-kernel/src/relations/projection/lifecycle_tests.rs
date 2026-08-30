//! Retirement and bounded metadata regressions for the live projection path.

use super::{ProjectionStore, ReaderLease};
use crate::ipc::DomainToken;
use crate::relations::types::{
    MAX_OBJECT_OBSERVATIONS, MAX_RELATION_ROWS, ObjectKind, ObjectRef, ObjectToken,
    ProjectionError, ReclaimOutcome, Relation, RelationChange,
};

fn reader(store: &mut ProjectionStore, slot: u64, generation: u64) -> ReaderLease {
    store
        .register_reader(DomainToken::new(slot, generation).unwrap())
        .unwrap()
}

fn endpoint_object(value: u64) -> ObjectRef {
    ObjectRef::new(ObjectKind::Endpoint, ObjectToken::new(value).unwrap())
}

fn endpoint_relation(lease: ReaderLease, value: u64) -> Relation {
    Relation::object(lease.token(), endpoint_object(value))
}

#[test]
fn single_mutation_denies_a_foreign_scope_without_mutation() {
    let mut store = ProjectionStore::empty();
    let authorized = reader(&mut store, 0, 1);
    let foreign = reader(&mut store, 1, 1);
    let relation = endpoint_relation(foreign, 1);

    assert_eq!(
        store.apply_mutation(authorized, RelationChange::Upsert(relation)),
        Err(ProjectionError::Denied)
    );
    assert!(store.snapshot(authorized).unwrap().is_empty());
}

#[test]
fn retirement_preserves_the_old_lease_fold() {
    let mut store = ProjectionStore::empty();
    let old = reader(&mut store, 0, 1);
    let relation = endpoint_relation(old, 1);
    store
        .apply_mutation(old, RelationChange::Upsert(relation))
        .unwrap();
    let base = store.snapshot(old).unwrap();
    let cursor = store.delta_cursor(old).unwrap();

    reader(&mut store, 0, 2);
    assert_eq!(store.retired_delete_count(0), 1);
    let replayed = store.fold(old, base, cursor).unwrap();
    assert_eq!(replayed.epoch(), 2);
    assert!(replayed.is_empty());
    assert_eq!(
        store.snapshot(old).unwrap_err(),
        ProjectionError::ResnapshotRequired
    );
}

#[test]
fn retirement_clears_scope_tombstones_and_reclaims() {
    let mut store = ProjectionStore::empty();
    let old = reader(&mut store, 0, 1);
    let live = reader(&mut store, 1, 1);
    for value in 1..=MAX_RELATION_ROWS as u64 {
        let relation = endpoint_relation(old, value);
        store
            .apply_mutation(old, RelationChange::Upsert(relation))
            .unwrap();
        store
            .apply_mutation(old, RelationChange::Delete(relation.key()))
            .unwrap();
    }
    for value in 1..=MAX_OBJECT_OBSERVATIONS {
        store
            .record_reclaim(
                old,
                endpoint_object(value as u64 + MAX_RELATION_ROWS as u64),
                ReclaimOutcome::ReleaseFailed,
            )
            .unwrap();
    }
    let live_relation = endpoint_relation(live, 1);
    store
        .apply_mutation(live, RelationChange::Upsert(live_relation))
        .unwrap();

    let fresh = reader(&mut store, 0, 2);
    let fresh_relation = endpoint_relation(fresh, MAX_RELATION_ROWS as u64 + 2);
    store
        .apply_mutation(fresh, RelationChange::Upsert(fresh_relation))
        .unwrap();
    assert_eq!(store.snapshot(live).unwrap().len(), 1);
    assert_eq!(store.snapshot(fresh).unwrap().len(), 1);
}

#[test]
fn successful_reclaim_is_accurate_and_replaces_older_generations() {
    let mut store = ProjectionStore::empty();
    let lease = reader(&mut store, 0, 1);
    for value in 1..=MAX_OBJECT_OBSERVATIONS {
        assert!(
            store
                .record_reclaim(
                    lease,
                    endpoint_object(value as u64),
                    ReclaimOutcome::ReleaseFailed,
                )
                .unwrap()
        );
    }

    let reclaimed = endpoint_object(MAX_OBJECT_OBSERVATIONS as u64 + 1);
    assert!(
        store
            .record_reclaim(lease, reclaimed, ReclaimOutcome::Reclaimed)
            .unwrap()
    );
    assert_eq!(
        store
            .reclaim_observation(lease, reclaimed)
            .unwrap()
            .outcome(),
        ReclaimOutcome::Reclaimed
    );
}
