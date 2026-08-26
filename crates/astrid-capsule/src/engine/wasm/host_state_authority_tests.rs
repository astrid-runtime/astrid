//! Regressions for HostState-owned semantic-object authority lifecycle.

use std::time::Instant;

use astrid_core::{PrincipalId, PrincipalUid};
use astrid_resource_types::{AuthorityEpoch, ResourceErrorCode, ResourceId, ResourceKind, Rights};

use super::pool::clear_on_return;
use super::test_fixtures::minimal_host_state;
use crate::resource_authority::{AdmissionOptions, Reservation, ResourceScope, RevocationSelector};
use crate::stamp::StampedInvocation;

fn identity(seed: u8) -> ResourceId {
    ResourceId::from_bytes([seed; 32])
}

fn root_rights() -> Rights {
    Rights::from_bits(Rights::READ.bits() | Rights::USE.bits() | Rights::DELEGATE.bits())
        .expect("read, use, and delegate are closed-vocabulary rights")
}

fn scope(identity: ResourceId) -> ResourceScope {
    ResourceScope::singleton(identity)
}

fn reservation(units: u64) -> Reservation {
    Reservation::new(
        astrid_resource_types::AccountId::from_bytes([7u8; 16]),
        astrid_resource_types::BudgetId::from_bytes([11u8; 16]),
        units,
    )
}

fn options(
    rights: Rights,
    expiry: Option<Instant>,
    revocation: Option<RevocationSelector>,
) -> AdmissionOptions {
    AdmissionOptions::new(rights, AuthorityEpoch::INITIAL, expiry, revocation)
}

fn stamp(seed: u8) -> StampedInvocation {
    StampedInvocation::from_trusted_uid(PrincipalUid::from_bytes([seed; 32]))
}

fn event_message(principal: Option<&str>) -> astrid_events::ipc::IpcMessage {
    let message = astrid_events::ipc::IpcMessage::new(
        astrid_events::ipc::Topic::from_raw("some.v1.event"),
        astrid_events::ipc::IpcPayload::RawJson(serde_json::json!({})),
        uuid::Uuid::new_v4(),
    );
    match principal {
        Some(name) => message.with_principal(name.to_string()),
        None => message,
    }
}

fn owner_state(alias: &str) -> (super::HostState, StampedInvocation) {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let principal = PrincipalId::new(alias).expect("fixture principal");
    let uid = state
        .principal_directory
        .uid_for(&principal)
        .expect("registered fixture identity");
    let admission_stamp = StampedInvocation::from_trusted_uid(uid);
    state.principal = principal;
    state.stamped_invocation = Some(admission_stamp.clone());
    (state, admission_stamp)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recv_drains_before_same_principal_stamp_retention() {
    let (mut state, admission_stamp) = owner_state("alice");
    let object = identity(9);
    let handle = state
        .semantic_authorities
        .admit(
            &admission_stamp,
            ResourceKind::SemanticObject,
            object,
            scope(object),
            reservation(8),
            options(root_rights(), None, None),
        )
        .expect("one fixture SemanticObject admits");
    assert_eq!(state.semantic_authorities.tracked_count(), 1);
    assert_eq!(state.semantic_authorities.active_reserved_units(), 8);

    // The repeated alias must not turn into a retention fast path: install a
    // live context only after the previous invocation's table is empty.
    state.install_recv_invocation_context(&event_message(Some("alice")));

    assert!(!state.semantic_authorities.tracks_handle(handle));
    assert_eq!(state.semantic_authorities.tracked_count(), 0);
    assert_eq!(state.semantic_authorities.active_reserved_units(), 0);
    assert_eq!(state.semantic_authorities.released_reserved_units(), 8);
    assert_eq!(state.semantic_authorities.allocated_slot_count(), 0);
    assert_eq!(
        state
            .stamped_invocation
            .as_ref()
            .map(|stamp| stamp.principal()),
        Some(admission_stamp.principal())
    );
}

#[tokio::test]
async fn selector_invalidation_releases_delegated_counter_after_child_first_drain() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let admission_stamp = stamp(1);
    let object = identity(10);
    let selector = RevocationSelector::new(42);
    let parent = state
        .semantic_authorities
        .admit(
            &admission_stamp,
            ResourceKind::SemanticObject,
            object,
            scope(object),
            reservation(10),
            options(root_rights(), None, Some(selector)),
        )
        .expect("parent fixture admits");
    let child = state
        .semantic_authorities
        .attenuate(&admission_stamp, parent, Rights::READ, scope(object), 4)
        .expect("child fixture attenuates the selected parent");
    state
        .semantic_authorities
        .revoke_selector(selector)
        .expect("selector tombstone retains its bounded domain");
    assert_eq!(state.semantic_authorities.tracked_count(), 2);
    assert_eq!(state.semantic_authorities.active_reserved_units(), 10);
    assert_eq!(state.semantic_authorities.released_reserved_units(), 0);

    state.semantic_authorities.prepare_for_replacement();

    assert_eq!(state.semantic_authorities.tracked_count(), 0);
    assert_eq!(state.semantic_authorities.active_reserved_units(), 0);
    assert_eq!(state.semantic_authorities.released_reserved_units(), 10);
    assert_eq!(state.semantic_authorities.allocated_slot_count(), 0);
    assert!(!state.semantic_authorities.tracks_handle(parent));
    assert!(!state.semantic_authorities.tracks_handle(child));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn epoch_invalidation_has_a_dedicated_counter_release_regression() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let admission_stamp = stamp(2);
    let object = identity(11);
    let handle = state
        .semantic_authorities
        .admit(
            &admission_stamp,
            ResourceKind::SemanticObject,
            object,
            scope(object),
            reservation(3),
            options(Rights::READ, None, None),
        )
        .expect("epoch fixture admits");
    let next_epoch = state
        .semantic_authorities
        .advance_authority_epoch()
        .expect("checked epoch advance succeeds");
    assert_ne!(next_epoch, AuthorityEpoch::INITIAL);
    assert_eq!(
        state.semantic_authorities.preflight(
            &admission_stamp,
            handle,
            Rights::READ,
            &scope(object),
            1,
        ),
        Err(ResourceErrorCode::Revoked)
    );

    state.semantic_authorities.prepare_for_replacement();

    assert_eq!(state.semantic_authorities.tracked_count(), 0);
    assert_eq!(state.semantic_authorities.active_reserved_units(), 0);
    assert_eq!(state.semantic_authorities.released_reserved_units(), 3);
    assert_eq!(state.semantic_authorities.allocated_slot_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pool_return_drains_and_resets_in_both_resource_modes() {
    for reset_resources in [false, true] {
        let (mut state, admission_stamp) = owner_state("alice");
        let object = identity(u8::from(reset_resources));
        let _unused_handle = state
            .semantic_authorities
            .admit(
                &admission_stamp,
                ResourceKind::SemanticObject,
                object,
                scope(object),
                reservation(5),
                options(Rights::READ, None, None),
            )
            .expect("pool-state fixture admits");

        clear_on_return(&mut state, reset_resources);

        assert!(state.stamped_invocation.is_none());
        assert_eq!(state.semantic_authorities.tracked_count(), 0);
        assert_eq!(state.semantic_authorities.active_reserved_units(), 0);
        assert_eq!(state.semantic_authorities.released_reserved_units(), 5);
        assert_eq!(state.semantic_authorities.allocated_slot_count(), 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalidated_entries_remain_reclaimable_exactly_once() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let admission_stamp = stamp(3);
    let object = identity(12);
    let handle = state
        .semantic_authorities
        .admit(
            &admission_stamp,
            ResourceKind::SemanticObject,
            object,
            scope(object),
            reservation(6),
            options(Rights::READ, None, None),
        )
        .expect("invalidated-reclaim fixture admits");

    state
        .semantic_authorities
        .revoke(handle)
        .expect("in-place invalidation marks without releasing");
    assert_eq!(
        state.semantic_authorities.preflight(
            &admission_stamp,
            handle,
            Rights::READ,
            &scope(object),
            1,
        ),
        Err(ResourceErrorCode::Revoked)
    );
    assert_eq!(state.semantic_authorities.tracked_count(), 1);
    assert_eq!(state.semantic_authorities.active_reserved_units(), 6);
    assert_eq!(state.semantic_authorities.released_reserved_units(), 0);

    state
        .semantic_authorities
        .reclaim(&admission_stamp, handle)
        .expect("an invalidated entry remains reclaimable by its original stamp");
    assert_eq!(state.semantic_authorities.tracked_count(), 0);
    assert_eq!(state.semantic_authorities.active_reserved_units(), 0);
    assert_eq!(state.semantic_authorities.released_reserved_units(), 6);
    assert_eq!(
        state.semantic_authorities.reclaim(&admission_stamp, handle),
        Err(ResourceErrorCode::StaleGeneration)
    );
    assert_eq!(state.semantic_authorities.released_reserved_units(), 6);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_slot_pressure_fails_closed_and_reuses_reclaimed_slots() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let admission_stamp = stamp(4);
    let mut handles = Vec::new();
    for index in 0..64usize {
        let object = identity(index.try_into().expect("bounded index"));
        let outcome = state.semantic_authorities.admit(
            &admission_stamp,
            ResourceKind::SemanticObject,
            object,
            scope(object),
            reservation(1),
            options(Rights::READ, None, None),
        );
        let Ok(handle) = outcome else {
            panic!(
                "live authority {index} must admit below the bound: {:?}",
                outcome.as_ref().err()
            );
        };
        handles.push(handle);
    }
    assert_eq!(handles.len(), 64);
    assert_eq!(state.semantic_authorities.active_reserved_units(), 64);

    let overflow_identity = identity(64);
    assert_eq!(
        state.semantic_authorities.admit(
            &admission_stamp,
            ResourceKind::SemanticObject,
            overflow_identity,
            scope(overflow_identity),
            reservation(1),
            options(Rights::READ, None, None),
        ),
        Err(ResourceErrorCode::Exhausted)
    );

    for handle in handles.drain(..).rev() {
        state
            .semantic_authorities
            .reclaim(&admission_stamp, handle)
            .expect("each root entry reclaims through its original stamp");
    }
    assert_eq!(state.semantic_authorities.active_reserved_units(), 0);
    assert_eq!(state.semantic_authorities.released_reserved_units(), 64);
    assert_eq!(state.semantic_authorities.allocated_slot_count(), 64);

    let object = identity(u8::MAX - 191);
    let replacement = state
        .semantic_authorities
        .admit(
            &admission_stamp,
            ResourceKind::SemanticObject,
            object,
            scope(object),
            reservation(2),
            options(Rights::READ, None, None),
        )
        .expect("a reclaimed slot becomes reusable within the fixed bound");
    assert_eq!(state.semantic_authorities.allocated_slot_count(), 64);
    assert_eq!(state.semantic_authorities.tracked_count(), 1);
    assert_eq!(state.semantic_authorities.active_reserved_units(), 2);
    assert!(state.semantic_authorities.tracks_handle(replacement));
}

#[tokio::test]
async fn selector_tombstones_are_bounded_and_cleared_on_table_replacement() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    for index in 0..64u64 {
        state
            .semantic_authorities
            .revoke_selector(RevocationSelector::new(index))
            .expect("distinct selector admits below tombstone bound");
    }
    assert_eq!(state.semantic_authorities.revoked_selector_count(), 64);
    assert_eq!(
        state
            .semantic_authorities
            .revoke_selector(RevocationSelector::new(64)),
        Err(ResourceErrorCode::Exhausted)
    );
    state
        .semantic_authorities
        .revoke_selector(RevocationSelector::new(0))
        .expect("an existing tombstone can remain present at capacity");
    assert_eq!(state.semantic_authorities.revoked_selector_count(), 64);

    state.semantic_authorities.prepare_for_replacement();

    assert_eq!(state.semantic_authorities.revoked_selector_count(), 0);
    assert_eq!(state.semantic_authorities.tracked_count(), 0);
    assert_eq!(state.semantic_authorities.active_reserved_units(), 0);
    assert_eq!(state.semantic_authorities.allocated_slot_count(), 0);
}

#[tokio::test]
async fn attenuation_child_respects_live_authority_ceiling() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let admission_stamp = stamp(5);
    let mut roots = Vec::with_capacity(64);
    for index in 0..64usize {
        let object = identity(index.try_into().expect("bounded index"));
        let outcome = state.semantic_authorities.admit(
            &admission_stamp,
            ResourceKind::SemanticObject,
            object,
            scope(object),
            reservation(10),
            options(root_rights(), None, None),
        );
        let Ok(root) = outcome else {
            panic!(
                "live authority {index} must admit below the bound: {:?}",
                outcome.as_ref().err()
            );
        };
        roots.push(root);
    }

    assert_eq!(
        state.semantic_authorities.attenuate(
            &admission_stamp,
            roots[0],
            Rights::READ,
            scope(identity(0)),
            1,
        ),
        Err(ResourceErrorCode::Exhausted)
    );
    assert_eq!(state.semantic_authorities.tracked_count(), 64);
    assert_eq!(state.semantic_authorities.allocated_slot_count(), 64);
    assert_eq!(state.semantic_authorities.active_reserved_units(), 640);
}
