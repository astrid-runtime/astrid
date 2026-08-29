//! Kernel/harness-private regressions for relation projection semantics.

use super::delta::{DeltaCursor, PageCursor};
use super::projection::{
    AuthoritativeBatch, ProjectionStore, ReaderLease, RelationMutation, Snapshot,
};
use super::types::{
    AuthorityObject, CapabilityGeneration, CapabilityInstance, CapabilitySlot, DELTA_RING_ENTRIES,
    DomainProjectionToken, ObjectKind, ObjectRef, ObjectToken, ProjectionError, RELATION_PAGE_ROWS,
    ReclaimOutcome, Relation, RelationChange, RelationKey, RelationRights,
};
use crate::ipc::DomainToken;

fn store() -> ProjectionStore {
    ProjectionStore::empty()
}

fn reader(store: &mut ProjectionStore, slot: u64, generation: u64) -> ReaderLease {
    store
        .register_reader(DomainToken::new(slot, generation).unwrap())
        .unwrap()
}

fn generation(value: u64) -> CapabilityGeneration {
    CapabilityGeneration::new(value).unwrap()
}

fn token(value: u64) -> ObjectToken {
    ObjectToken::new(value).unwrap()
}

fn object(kind: ObjectKind, value: u64) -> ObjectRef {
    ObjectRef::new(kind, token(value))
}

fn capability(lease: ReaderLease, slot: usize, generation_value: u64) -> CapabilityInstance {
    CapabilityInstance::new(
        lease.token(),
        CapabilitySlot::try_new(slot).unwrap(),
        generation(generation_value),
    )
}

fn object_relation(scope: DomainProjectionToken, kind: ObjectKind, value: u64) -> Relation {
    Relation::object(scope, object(kind, value))
}

fn holds_relation(
    lease: ReaderLease,
    slot: usize,
    generation_value: u64,
    object_value: u64,
) -> Relation {
    Relation::holds(
        lease.token(),
        capability(lease, slot, generation_value),
        object(ObjectKind::Endpoint, object_value),
        RelationRights::SEND,
    )
}

fn derive_relation(
    lease: ReaderLease,
    parent: CapabilityInstance,
    child: CapabilityInstance,
) -> Relation {
    Relation::derives(lease.token(), parent, child)
}

fn apply_one(store: &mut ProjectionStore, lease: ReaderLease, relation: Relation) {
    apply_change(store, lease, RelationChange::Upsert(relation)).unwrap();
}

fn apply_change(
    store: &mut ProjectionStore,
    lease: ReaderLease,
    change: RelationChange,
) -> Result<usize, ProjectionError> {
    let mut batch = AuthoritativeBatch::empty();
    batch.push(RelationMutation::new(lease, change))?;
    store.apply(batch)
}

fn fold_base(store: &mut ProjectionStore, lease: ReaderLease) -> (Snapshot, DeltaCursor) {
    let snapshot = store.base_snapshot(lease).unwrap();
    let cursor = store.delta_cursor(lease).unwrap();
    (snapshot, cursor)
}

fn assert_canonical(snapshot: &Snapshot) {
    let mut previous = snapshot.row(0);
    for index in 1..snapshot.len() {
        let current = snapshot.row(index);
        if let (Some(left), Some(right)) = (previous, current) {
            assert!(left.key() < right.key());
        }
        previous = current;
    }
}

#[test]
fn constants_match_the_private_relation_freeze() {
    assert_eq!(RELATION_PAGE_ROWS, 16);
    assert_eq!(DELTA_RING_ENTRIES, 32);
}

#[test]
fn object_capability_and_endpoint_tables_project_without_message_rows() {
    let mut store = store();
    let first = reader(&mut store, 0, 1);
    let second = reader(&mut store, 1, 1);

    apply_one(
        &mut store,
        first,
        object_relation(first.token(), ObjectKind::Domain, 10),
    );
    apply_one(
        &mut store,
        first,
        object_relation(first.token(), ObjectKind::Endpoint, 11),
    );
    apply_one(&mut store, second, holds_relation(second, 3, 7, 11));

    let first_snapshot = store.snapshot(first).unwrap();
    assert_eq!(first_snapshot.len(), 2);
    assert!(first_snapshot.rows().any(|row| row.key()
        == RelationKey::Object {
            scope: first.token(),
            object: object(ObjectKind::Domain, 10),
        }));
    assert!(first_snapshot.rows().any(|row| row.key()
        == RelationKey::Object {
            scope: first.token(),
            object: object(ObjectKind::Endpoint, 11),
        }));

    let second_snapshot = store.snapshot(second).unwrap();
    let held = second_snapshot.rows().next().unwrap();
    assert!(matches!(
        held.state(),
        super::types::RelationState::Holds { rights } if rights == RelationRights::SEND
    ));
    assert_eq!(
        held.key(),
        RelationKey::Holds {
            scope: second.token(),
            capability: capability(second, 3, 7),
            object: object(ObjectKind::Endpoint, 11),
        }
    );

    assert_eq!(AuthorityObject::Message.relation_kind(), None);
    assert_eq!(AuthorityObject::Message.token(), None);
}

#[test]
fn relation_identities_use_full_capability_instances_across_reuse() {
    let mut store = store();
    let source = reader(&mut store, 0, 1);
    let target = reader(&mut store, 1, 1);
    let parent_a = capability(source, 3, 5);
    let parent_b = capability(source, 3, 6);
    let child_a = capability(target, 3, 7);
    let child_b = capability(target, 3, 8);

    apply_one(
        &mut store,
        target,
        derive_relation(target, parent_a, child_a),
    );
    apply_one(
        &mut store,
        target,
        derive_relation(target, parent_b, child_b),
    );

    let snapshot = store.snapshot(target).unwrap();
    assert_eq!(snapshot.len(), 2);
    assert!(snapshot.rows().any(|row| row.key()
        == RelationKey::Derives {
            scope: target.token(),
            parent: parent_a,
            child: child_a,
        }));
    assert!(snapshot.rows().any(|row| row.key()
        == RelationKey::Derives {
            scope: target.token(),
            parent: parent_b,
            child: child_b,
        }));
}

#[test]
fn domain_slot_reuse_clears_the_old_generation_reader() {
    let mut store = store();
    let old = reader(&mut store, 0, 1);
    apply_one(
        &mut store,
        old,
        object_relation(old.token(), ObjectKind::Domain, 1),
    );
    assert_eq!(store.relation_epoch(old).unwrap(), 1);

    let fresh = reader(&mut store, 0, 2);
    assert_eq!(
        store.snapshot(old).unwrap_err(),
        ProjectionError::ResnapshotRequired
    );
    assert_eq!(
        store.delta_cursor(old).unwrap_err(),
        ProjectionError::ResnapshotRequired
    );
    assert_eq!(
        apply_change(
            &mut store,
            old,
            RelationChange::Delete(object_relation(old.token(), ObjectKind::Domain, 1).key()),
        )
        .unwrap_err(),
        ProjectionError::ResnapshotRequired
    );

    let fresh_snapshot = store.snapshot(fresh).unwrap();
    assert_eq!(fresh_snapshot.epoch(), 0);
    assert!(fresh_snapshot.is_empty());
}

#[test]
fn epochs_are_projection_local_and_batches_advance_exactly_once() {
    let mut store = store();
    let first = reader(&mut store, 0, 1);
    let second = reader(&mut store, 1, 1);
    let child = capability(first, 1, 2);

    let mut batch = AuthoritativeBatch::empty();
    for relation in [
        object_relation(first.token(), ObjectKind::Domain, 1),
        object_relation(first.token(), ObjectKind::Endpoint, 2),
        holds_relation(first, 1, 2, 2),
    ] {
        batch
            .push(RelationMutation::new(
                first,
                RelationChange::Upsert(relation),
            ))
            .unwrap();
    }
    batch
        .push(RelationMutation::new(
            first,
            RelationChange::Upsert(derive_relation(first, child, child)),
        ))
        .unwrap();
    assert_eq!(store.apply(batch).unwrap(), 4);
    assert_eq!(store.relation_epoch(first).unwrap(), 1);
    assert_eq!(store.relation_epoch(second).unwrap(), 0);

    apply_one(
        &mut store,
        second,
        object_relation(second.token(), ObjectKind::Domain, 3),
    );
    assert_eq!(store.relation_epoch(first).unwrap(), 1);
    assert_eq!(store.relation_epoch(second).unwrap(), 1);
}

#[test]
fn epoch_overflow_fails_closed_and_does_not_wrap() {
    let mut store = store();
    let lease = reader(&mut store, 0, 1);
    store.force_epoch_overflow(lease).unwrap();

    let result = apply_one_or_error(
        &mut store,
        lease,
        object_relation(lease.token(), ObjectKind::Domain, 1),
    );
    assert_eq!(result, Err(ProjectionError::ResnapshotRequired));
    assert_eq!(store.relation_epoch(lease).unwrap(), u64::MAX);
    assert!(store.snapshot(lease).unwrap().is_empty());
}

fn apply_one_or_error(
    store: &mut ProjectionStore,
    lease: ReaderLease,
    relation: Relation,
) -> Result<(), ProjectionError> {
    apply_change(store, lease, RelationChange::Upsert(relation)).map(|_| ())
}

#[test]
fn deterministic_fold_equals_direct_snapshot_and_rejects_bad_cursors() {
    let mut store = store();
    let lease = reader(&mut store, 0, 1);
    apply_one(
        &mut store,
        lease,
        object_relation(lease.token(), ObjectKind::Endpoint, 1),
    );
    let (base, cursor) = fold_base(&mut store, lease);

    apply_one(
        &mut store,
        lease,
        object_relation(lease.token(), ObjectKind::Domain, 2),
    );
    apply_one(&mut store, lease, holds_relation(lease, 2, 9, 1));
    let revoked = holds_relation(lease, 3, 9, 1);
    apply_one(&mut store, lease, revoked);
    apply_change(&mut store, lease, RelationChange::Delete(revoked.key())).unwrap();

    let direct = store.snapshot(lease).unwrap();
    let replayed = store.fold(lease, base, cursor).unwrap();
    assert_eq!(replayed, direct);
    assert_eq!(replayed.epoch(), 5);
    assert_canonical(&direct);

    assert_eq!(
        store
            .fold(lease, base, DeltaCursor::new(lease.reader_generation(), 0))
            .unwrap_err(),
        ProjectionError::ResnapshotRequired
    );
    assert_eq!(
        store
            .fold(
                lease,
                base,
                DeltaCursor::new(lease.reader_generation() + 1, base.epoch())
            )
            .unwrap_err(),
        ProjectionError::ResnapshotRequired
    );
}

#[test]
fn delta_ring_overflow_requires_a_new_base_and_then_resumes() {
    let mut store = store();
    let lease = reader(&mut store, 0, 1);
    let relation = object_relation(lease.token(), ObjectKind::Endpoint, 1);
    apply_one(&mut store, lease, relation);

    for epoch in 2..=(DELTA_RING_ENTRIES + 2) {
        apply_one(&mut store, lease, relation);
        assert_eq!(store.relation_epoch(lease).unwrap(), epoch as u64);
    }
    assert_eq!(
        store.snapshot(lease).unwrap_err(),
        ProjectionError::ResnapshotRequired
    );

    let (base, cursor) = fold_base(&mut store, lease);
    assert_eq!(base.epoch(), (DELTA_RING_ENTRIES + 2) as u64);
    apply_one(&mut store, lease, relation);
    let replayed = store.fold(lease, base, cursor).unwrap();
    assert_eq!(replayed, store.snapshot(lease).unwrap());
}

#[test]
fn delete_is_once_and_reclaim_failure_cannot_resurrect() {
    let mut store = store();
    let lease = reader(&mut store, 0, 1);
    let endpoint = object(ObjectKind::Endpoint, 7);
    let object_row = Relation::object(lease.token(), endpoint);
    let hold = holds_relation(lease, 2, 4, 7);
    apply_one(&mut store, lease, object_row);
    apply_one(&mut store, lease, hold);

    let mut batch = AuthoritativeBatch::empty();
    batch
        .push(RelationMutation::new(
            lease,
            RelationChange::Delete(hold.key()),
        ))
        .unwrap();
    batch
        .push(RelationMutation::new(
            lease,
            RelationChange::Delete(object_row.key()),
        ))
        .unwrap();
    assert_eq!(store.apply(batch).unwrap(), 2);
    assert_eq!(store.relation_epoch(lease).unwrap(), 3);

    let repeated = AuthoritativeBatch::empty();
    assert_eq!(store.apply(repeated).unwrap(), 0);
    assert_eq!(
        apply_change(&mut store, lease, RelationChange::Delete(hold.key())).unwrap(),
        0
    );
    assert_eq!(store.relation_epoch(lease).unwrap(), 3);
    assert!(store.snapshot(lease).unwrap().is_empty());

    assert!(
        store
            .record_reclaim(lease, token(7), ReclaimOutcome::ReleaseFailed)
            .unwrap()
    );
    assert_eq!(
        store
            .reclaim_observation(lease, token(7))
            .unwrap()
            .outcome(),
        ReclaimOutcome::ReleaseFailed
    );
    assert_eq!(
        apply_one_or_error(&mut store, lease, object_row),
        Err(ProjectionError::Resurrection)
    );
    assert!(store.snapshot(lease).unwrap().is_empty());
}

#[test]
fn reclaim_blocked_is_observable_after_logical_delete() {
    let mut store = store();
    let lease = reader(&mut store, 0, 1);
    let relation = object_relation(lease.token(), ObjectKind::Endpoint, 8);
    apply_one(&mut store, lease, relation);
    apply_change(&mut store, lease, RelationChange::Delete(relation.key())).unwrap();

    assert!(
        store
            .record_reclaim(lease, token(8), ReclaimOutcome::ReclaimBlocked)
            .unwrap()
    );
    assert_eq!(
        store
            .reclaim_observation(lease, token(8))
            .unwrap()
            .outcome(),
        ReclaimOutcome::ReclaimBlocked
    );
    assert!(
        !store
            .record_reclaim(lease, token(8), ReclaimOutcome::ReclaimBlocked)
            .unwrap()
    );
}

#[test]
fn unauthorized_scope_is_denied_without_resnapshot_or_partial_fill() {
    let mut store = store();
    let authorized = reader(&mut store, 0, 1);
    let foreign = reader(&mut store, 1, 1);
    let foreign_relation = object_relation(foreign.token(), ObjectKind::Domain, 4);

    let mut batch = AuthoritativeBatch::empty();
    batch
        .push(RelationMutation::new(
            authorized,
            RelationChange::Upsert(object_relation(authorized.token(), ObjectKind::Endpoint, 3)),
        ))
        .unwrap();
    batch
        .push(RelationMutation::new(
            authorized,
            RelationChange::Upsert(foreign_relation),
        ))
        .unwrap();
    assert_eq!(store.apply(batch).unwrap_err(), ProjectionError::Denied);
    assert_eq!(store.relation_epoch(authorized).unwrap(), 0);
    assert!(store.snapshot(authorized).unwrap().is_empty());

    assert!(DomainToken::new(2, 1).is_none());
    assert_eq!(
        apply_change(
            &mut store,
            authorized,
            RelationChange::Upsert(foreign_relation),
        )
        .unwrap_err(),
        ProjectionError::Denied
    );
}

#[test]
fn pages_are_bounded_and_invalid_cursors_resnapshot() {
    let mut store = store();
    let lease = reader(&mut store, 0, 1);
    for value in 0..RELATION_PAGE_ROWS + 4 {
        apply_one(
            &mut store,
            lease,
            holds_relation(lease, 1, 5, value as u64 + 1),
        );
    }

    let epoch = store.relation_epoch(lease).unwrap();
    let page0 = store
        .snapshot_page(lease, PageCursor::new(1, epoch, 0))
        .unwrap();
    assert_eq!(page0.len(), RELATION_PAGE_ROWS);
    assert!(page0.has_more());
    assert_canonical(&store.snapshot(lease).unwrap());

    let page1 = store
        .snapshot_page(lease, PageCursor::new(1, epoch, 1))
        .unwrap();
    assert_eq!(page1.len(), 4);
    assert!(!page1.has_more());

    assert_eq!(
        store
            .snapshot_page(lease, PageCursor::new(2, epoch, 0))
            .unwrap_err(),
        ProjectionError::ResnapshotRequired
    );
    assert_eq!(
        store
            .snapshot_page(lease, PageCursor::new(1, epoch + 1, 0))
            .unwrap_err(),
        ProjectionError::ResnapshotRequired
    );
    assert_eq!(
        store
            .snapshot_page(lease, PageCursor::new(1, epoch, 5))
            .unwrap_err(),
        ProjectionError::ResnapshotRequired
    );
}
