//! Kernel/harness-private regressions for relation projection semantics.

use super::delta::{DeltaCursor, PageCursor};
use super::projection::{
    AuthoritativeBatch, ProjectionStore, ReaderLease, RelationMutation, Snapshot,
};
use super::types::{
    AuthorityObject, CapabilityGeneration, CapabilityInstance, CapabilitySlot, DELTA_RING_ENTRIES,
    DomainProjectionToken, MAX_RELATION_ROWS, ObjectKind, ObjectRef, ObjectToken, ProjectionError,
    RELATION_PAGE_ROWS, ReaderIdentity, ReclaimOutcome, Relation, RelationChange, RelationKey,
    RelationRights,
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

fn capability(
    lease: ReaderLease,
    slot: usize,
    generation_value: u64,
    object_value: u64,
) -> CapabilityInstance {
    CapabilityInstance::try_new(
        lease.token(),
        CapabilitySlot::try_new(slot).unwrap(),
        object(ObjectKind::Endpoint, object_value),
        generation(generation_value),
    )
    .unwrap()
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
        capability(lease, slot, generation_value, object_value),
        object(ObjectKind::Endpoint, object_value),
        RelationRights::SEND,
    )
    .unwrap()
}

fn hold_with_rights(
    lease: ReaderLease,
    slot: usize,
    generation_value: u64,
    object_value: u64,
    rights: RelationRights,
) -> Relation {
    Relation::holds(
        lease.token(),
        capability(lease, slot, generation_value, object_value),
        object(ObjectKind::Endpoint, object_value),
        rights,
    )
    .unwrap()
}

fn derive_relation(
    lease: ReaderLease,
    parent: CapabilityInstance,
    child: CapabilityInstance,
) -> Relation {
    Relation::derives(lease.token(), parent, child).unwrap()
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
            capability: capability(second, 3, 7, 11),
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
    let parent_a = capability(source, 3, 5, 20);
    let parent_b = capability(source, 3, 6, 20);
    let child_a = capability(target, 3, 7, 20);
    let child_b = capability(target, 3, 8, 20);

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
    let child = capability(first, 1, 2, 2);

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
fn batch_fold_applies_every_visible_change_at_one_projection_epoch() {
    let mut store = store();
    let lease = reader(&mut store, 0, 1);
    let parent = capability(lease, 1, 4, 10);
    let child = capability(lease, 2, 5, 10);

    let mut batch = AuthoritativeBatch::empty();
    batch
        .push(RelationMutation::new(
            lease,
            RelationChange::Upsert(object_relation(lease.token(), ObjectKind::Endpoint, 10)),
        ))
        .unwrap();
    batch
        .push(RelationMutation::new(
            lease,
            RelationChange::Upsert(holds_relation(lease, 1, 4, 10)),
        ))
        .unwrap();
    batch
        .push(RelationMutation::new(
            lease,
            RelationChange::Upsert(derive_relation(lease, parent, child)),
        ))
        .unwrap();

    let (base, cursor) = fold_base(&mut store, lease);
    assert_eq!(store.apply(batch).unwrap(), 3);
    assert_eq!(store.relation_epoch(lease).unwrap(), 1);
    assert_eq!(store.snapshot(lease).unwrap().len(), 3);
    assert_eq!(
        store.fold(lease, base, cursor).unwrap(),
        store.snapshot(lease).unwrap()
    );
}

#[test]
fn cursors_cannot_move_between_readers_with_the_same_generation() {
    let mut store = store();
    let first = reader(&mut store, 0, 1);
    let second = reader(&mut store, 1, 1);
    let first_base = store.base_snapshot(first).unwrap();
    let second_base = store.base_snapshot(second).unwrap();

    apply_one(
        &mut store,
        first,
        object_relation(first.token(), ObjectKind::Endpoint, 1),
    );
    assert_eq!(
        store
            .fold(first, first_base, store.delta_cursor(second).unwrap())
            .unwrap_err(),
        ProjectionError::ResnapshotRequired
    );
    assert_eq!(
        store
            .snapshot_page(first, store.page_cursor(second, 0).unwrap())
            .unwrap_err(),
        ProjectionError::ResnapshotRequired
    );
    assert!(
        store
            .fold(second, second_base, store.delta_cursor(second).unwrap())
            .is_ok()
    );
}

#[test]
fn generation_reuse_retires_rows_without_leaving_them_in_capacity() {
    let mut store = store();
    let old = reader(&mut store, 0, 1);
    let live = reader(&mut store, 1, 1);
    apply_one(
        &mut store,
        old,
        object_relation(old.token(), ObjectKind::Endpoint, 1),
    );
    apply_one(
        &mut store,
        live,
        object_relation(live.token(), ObjectKind::Domain, 2),
    );

    let fresh = reader(&mut store, 0, 2);
    assert_eq!(store.retired_delete_count(0), 1);
    assert_eq!(
        store.snapshot(old).unwrap_err(),
        ProjectionError::ResnapshotRequired
    );
    assert_eq!(store.snapshot(live).unwrap().len(), 1);

    apply_change(
        &mut store,
        live,
        RelationChange::Delete(object_relation(live.token(), ObjectKind::Domain, 2).key()),
    )
    .unwrap();

    for value in 0..MAX_RELATION_ROWS {
        apply_one(
            &mut store,
            fresh,
            holds_relation(fresh, 1, 7, value as u64 + 3),
        );
    }
    let final_base = store.base_snapshot(fresh).unwrap();
    assert_eq!(final_base.len(), MAX_RELATION_ROWS);
    assert_eq!(store.snapshot(fresh).unwrap().len(), MAX_RELATION_ROWS);
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
    let other = reader(&mut store, 1, 1);
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
            .fold(lease, base, store.delta_cursor(other).unwrap())
            .unwrap_err(),
        ProjectionError::ResnapshotRequired
    );
    assert_eq!(
        store
            .fold(
                lease,
                base,
                DeltaCursor::new(
                    ReaderIdentity::new(0, lease.reader_generation() + 1, lease.token()).unwrap(),
                    base.epoch()
                )
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
        let rights = if epoch % 2 == 0 {
            RelationRights::RECV
        } else {
            RelationRights::SEND
        };
        apply_one(&mut store, lease, hold_with_rights(lease, 1, 9, 1, rights));
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
            .record_reclaim(
                lease,
                object(ObjectKind::Endpoint, 7),
                ReclaimOutcome::ReleaseFailed,
            )
            .unwrap()
    );
    assert_eq!(
        store
            .reclaim_observation(lease, object(ObjectKind::Endpoint, 7))
            .unwrap()
            .outcome(),
        ReclaimOutcome::ReleaseFailed
    );
    assert_eq!(
        apply_one_or_error(&mut store, lease, object_row),
        Err(ProjectionError::Resurrection)
    );
    assert_eq!(
        apply_one_or_error(&mut store, lease, hold),
        Err(ProjectionError::Resurrection)
    );
    assert!(store.snapshot(lease).unwrap().is_empty());
}

#[test]
fn logical_deletion_is_a_tombstone_distinct_from_reclaim() {
    let mut store = store();
    let lease = reader(&mut store, 0, 1);
    let relation = object_relation(lease.token(), ObjectKind::Endpoint, 12);
    apply_one(&mut store, lease, relation);
    apply_change(&mut store, lease, RelationChange::Delete(relation.key())).unwrap();

    assert_eq!(
        apply_one_or_error(&mut store, lease, relation),
        Err(ProjectionError::Resurrection)
    );
    assert!(
        store
            .record_reclaim(
                lease,
                object(ObjectKind::Endpoint, 12),
                ReclaimOutcome::ReleaseFailed,
            )
            .unwrap()
    );
}

#[test]
fn derives_and_reclaim_carry_object_kind_identity() {
    let mut store = store();
    let lease = reader(&mut store, 0, 1);
    let parent = capability(lease, 1, 4, 14);
    let child = capability(lease, 2, 5, 14);
    let derivation = derive_relation(lease, parent, child);
    apply_one(&mut store, lease, derivation);
    apply_change(&mut store, lease, RelationChange::Delete(derivation.key())).unwrap();

    assert!(
        store
            .record_reclaim(
                lease,
                object(ObjectKind::Endpoint, 14),
                ReclaimOutcome::ReclaimBlocked,
            )
            .unwrap()
    );
    assert_eq!(
        apply_one_or_error(&mut store, lease, derivation),
        Err(ProjectionError::Resurrection)
    );

    let domain_lease = reader(&mut store, 1, 1);
    assert!(
        store
            .record_reclaim(
                domain_lease,
                object(ObjectKind::Domain, 15),
                ReclaimOutcome::ReleaseFailed,
            )
            .unwrap()
    );
    assert_eq!(
        apply_one_or_error(
            &mut store,
            domain_lease,
            object_relation(domain_lease.token(), ObjectKind::Domain, 15),
        ),
        Err(ProjectionError::Resurrection)
    );
    let endpoint_with_reused_number =
        object_relation(domain_lease.token(), ObjectKind::Endpoint, 15);
    apply_one(&mut store, domain_lease, endpoint_with_reused_number);
}

#[test]
fn relation_constructors_enforce_scoped_capability_and_endpoint_identity() {
    let mut store = store();
    let first = reader(&mut store, 0, 1);
    let second = reader(&mut store, 1, 1);

    assert!(
        CapabilityInstance::try_new(
            first.token(),
            CapabilitySlot::try_new(1).unwrap(),
            object(ObjectKind::Domain, 1),
            generation(2),
        )
        .is_none()
    );
    assert!(
        Relation::holds(
            first.token(),
            capability(second, 1, 2, 3),
            object(ObjectKind::Endpoint, 3),
            RelationRights::SEND,
        )
        .is_none()
    );
    assert!(
        Relation::holds(
            first.token(),
            capability(first, 1, 2, 3),
            object(ObjectKind::Endpoint, 4),
            RelationRights::SEND,
        )
        .is_none()
    );
    assert!(
        Relation::holds(
            first.token(),
            capability(first, 1, 2, 3),
            object(ObjectKind::Domain, 3),
            RelationRights::SEND,
        )
        .is_none()
    );

    let foreign_child = capability(second, 2, 3, 3);
    assert!(Relation::derives(first.token(), capability(first, 1, 2, 3), foreign_child).is_none());
    assert!(
        Relation::derives(
            first.token(),
            capability(first, 1, 2, 3),
            capability(first, 2, 3, 4),
        )
        .is_none()
    );
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
            .record_reclaim(
                lease,
                object(ObjectKind::Endpoint, 8),
                ReclaimOutcome::ReclaimBlocked,
            )
            .unwrap()
    );
    assert_eq!(
        store
            .reclaim_observation(lease, object(ObjectKind::Endpoint, 8))
            .unwrap()
            .outcome(),
        ReclaimOutcome::ReclaimBlocked
    );
    assert!(
        !store
            .record_reclaim(
                lease,
                object(ObjectKind::Endpoint, 8),
                ReclaimOutcome::ReclaimBlocked,
            )
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
        .snapshot_page(lease, store.page_cursor(lease, 0).unwrap())
        .unwrap();
    assert_eq!(page0.len(), RELATION_PAGE_ROWS);
    assert!(page0.has_more());
    assert_canonical(&store.snapshot(lease).unwrap());

    let page1 = store
        .snapshot_page(lease, store.page_cursor(lease, 1).unwrap())
        .unwrap();
    assert_eq!(page1.len(), 4);
    assert!(!page1.has_more());

    assert_eq!(
        store
            .snapshot_page(lease, store.page_cursor(lease, 2).unwrap())
            .unwrap_err(),
        ProjectionError::ResnapshotRequired
    );
    assert_eq!(
        store
            .snapshot_page(
                lease,
                PageCursor::new(store.page_cursor(lease, 0).unwrap().reader, epoch + 1, 0)
            )
            .unwrap_err(),
        ProjectionError::ResnapshotRequired
    );
    assert_eq!(
        store
            .snapshot_page(lease, store.page_cursor(lease, 5).unwrap())
            .unwrap_err(),
        ProjectionError::ResnapshotRequired
    );
}
