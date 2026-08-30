//! Same-lock regressions driven by the real IPC state machine.

use super::adapter::ProjectionEvidence;
use crate::ipc::test_support::{
    cap_revoke, capability, endpoint_create, install_transfer_message, queued_for, reset, test_lock,
};
use crate::ipc::{
    Capability, DerivationLink, DomainToken, MAX_BUFFER_BYTES, TestCapSlot, bind_peer,
    complete_parked_recv, prepare_domain, relations_projection_fold,
    relations_projection_observation, teardown_domain,
};
use crate::relations::types::RelationKey;
use crate::relations::{DeltaCursor, Snapshot};

fn domain(slot: u64) -> DomainToken {
    DomainToken::new(slot, 1).unwrap()
}

fn linked_transfer(capability: Capability, parent: DomainToken, slot: TestCapSlot) -> Capability {
    Capability {
        parent: Some(DerivationLink {
            domain: parent,
            slot,
        }),
        ..capability
    }
}
#[test]
fn failed_transfer_copyout_does_not_install_stale_waiter() {
    let _guard = test_lock();
    reset();
    let creator = domain(0);
    let peer = domain(1);
    prepare_domain(creator);
    prepare_domain(peer);
    let endpoint = endpoint_create(creator).unwrap();
    assert!(bind_peer(creator, peer).is_ok());
    let root = capability(creator, creator.slot()).unwrap();
    assert!(install_transfer_message(
        peer,
        creator,
        endpoint,
        Some(root)
    ));

    let wire = recv_wire(1);
    let failed_base = observation(peer);
    assert!(complete_parked_recv(peer, &wire, 0, |_| false).is_err());
    let transferred_slot = TestCapSlot::try_new(1).unwrap();
    assert!(capability(peer, transferred_slot).is_none());
    require_fold_from(peer, failed_base.0, failed_base.1);

    let retry_base = observation(peer);
    assert!(complete_parked_recv(peer, &wire, 0, |_| true).is_ok());
    assert!(capability(peer, transferred_slot).is_some());
    let direct = observation(peer).0;
    assert_eq!(direct.rows().count(), retry_base.0.rows().count() + 2);
    assert!(direct.rows().any(|relation| matches!(
        relation.key(),
        RelationKey::Holds { capability, .. } if capability.slot().index() == 1
    )));
    assert!(direct.rows().any(|relation| matches!(
        relation.key(),
        RelationKey::Derives { child, .. } if child.slot().index() == 1
    )));
    require_fold_from(peer, retry_base.0, retry_base.1);
}

fn recv_wire(cap_slot: u16) -> [u8; MAX_BUFFER_BYTES] {
    let mut wire = [0u8; MAX_BUFFER_BYTES];
    wire[8..10].copy_from_slice(&cap_slot.to_le_bytes());
    wire[12..14].copy_from_slice(&4u16.to_le_bytes());
    wire[32] = 7;
    wire
}

#[test]
fn revoked_during_parked_commit_gap_does_not_project_stale_transfer() {
    let _guard = test_lock();
    reset();
    let creator = domain(0);
    let peer = domain(1);
    prepare_domain(creator);
    prepare_domain(peer);
    let endpoint = endpoint_create(creator).unwrap();
    assert!(bind_peer(creator, peer).is_ok());

    let creator_root = capability(creator, creator.slot()).unwrap();
    assert!(install_transfer_message(
        creator,
        creator,
        endpoint,
        Some(creator_root)
    ));
    assert!(
        complete_parked_recv(creator, &recv_wire(1), 0, |_| true).is_ok(),
        "creator anchor keeps the transferred endpoint live through the race"
    );

    let transferred_base = observation(peer);
    let source_slot = TestCapSlot::try_new(0).unwrap();
    let transferred_capability = capability(peer, source_slot).unwrap();
    assert!(install_transfer_message(
        peer,
        peer,
        endpoint,
        Some(transferred_capability)
    ));

    let destination_slot = TestCapSlot::try_new(1).unwrap();
    let wire = recv_wire(1);
    assert!(
        complete_parked_recv(peer, &wire, 0, |_| {
            assert_eq!(cap_revoke(creator, creator.slot()), Ok(3));
            true
        })
        .is_ok()
    );

    assert!(capability(peer, source_slot).is_none());
    assert!(capability(peer, destination_slot).is_none());
    let direct = observation(peer).0;
    assert!(
        !direct.rows().any(|relation| matches!(
            relation.key(),
            RelationKey::Holds { capability, .. } if capability.slot().index() <= 1
        )),
        "no peer Holds row may survive the authoritative revoke"
    );
    assert!(
        !direct.rows().any(|relation| matches!(
            relation.key(),
            RelationKey::Derives { child, .. } if child.slot().index() <= 1
        )),
        "no peer Derives row may survive the authoritative revoke"
    );
    let mut objects = 0;
    let mut holds = 0;
    let mut derives = 0;
    for relation in direct.rows() {
        match relation.key() {
            RelationKey::Object { .. } => objects += 1,
            RelationKey::Holds { .. } => holds += 1,
            RelationKey::Derives { .. } => derives += 1,
        }
    }
    assert_eq!((objects, holds, derives), (2, 0, 0));
    require_fold_from(peer, transferred_base.0, transferred_base.1);
}

#[test]
fn revoked_parent_during_parked_failure_consumes_stale_retry() {
    let _guard = test_lock();
    reset();
    let creator = domain(0);
    let peer = domain(1);
    prepare_domain(creator);
    prepare_domain(peer);
    let endpoint = endpoint_create(creator).unwrap();
    assert!(bind_peer(creator, peer).is_ok());

    let creator_root = capability(creator, creator.slot()).unwrap();
    let parent_anchor = linked_transfer(creator_root, creator, creator.slot());
    assert!(install_transfer_message(
        creator,
        creator,
        endpoint,
        Some(parent_anchor)
    ));
    let anchor_slot = TestCapSlot::try_new(1).unwrap();
    assert!(complete_parked_recv(creator, &recv_wire(1), 0, |_| true).is_ok());
    let parent = capability(creator, anchor_slot).unwrap();

    let queued_base = observation(peer);
    let source_slot = TestCapSlot::try_new(0).unwrap();
    let stale_transfer = linked_transfer(parent, creator, anchor_slot);
    assert!(install_transfer_message(
        peer,
        creator,
        endpoint,
        Some(stale_transfer)
    ));
    let destination_slot = TestCapSlot::try_new(2).unwrap();
    let wire = recv_wire(2);
    assert!(
        complete_parked_recv(peer, &wire, 0, |_| {
            assert_eq!(cap_revoke(creator, anchor_slot), Ok(2));
            false
        })
        .is_err()
    );

    assert_eq!(queued_for(peer), 0);
    assert!(capability(peer, destination_slot).is_none());
    assert!(capability(creator, anchor_slot).is_none());
    assert!(capability(peer, source_slot).is_some());
    assert!(complete_parked_recv(peer, &wire, 0, |_| true).is_err());
    assert_eq!(queued_for(peer), 0);

    let direct = observation(peer).0;
    assert!(direct.rows().any(|relation| matches!(
        relation.key(),
        RelationKey::Holds { capability, .. } if capability.slot().index() == 0
    )));
    assert!(direct.rows().any(|relation| matches!(
        relation.key(),
        RelationKey::Derives { child, .. } if child.slot().index() == 0
    )));
    assert!(!direct.rows().any(|relation| matches!(
        relation.key(),
        RelationKey::Holds { capability, .. } if capability.slot().index() == 2
    )));
    assert!(!direct.rows().any(|relation| matches!(
        relation.key(),
        RelationKey::Derives { child, .. } if child.slot().index() == 2
    )));
    require_fold_from(peer, queued_base.0, queued_base.1);
}

#[test]
fn commit_false_revoke_and_replace_preserves_destination_replacement() {
    let _guard = test_lock();
    reset();
    let creator = domain(0);
    let peer = domain(1);
    prepare_domain(creator);
    prepare_domain(peer);
    let endpoint = endpoint_create(creator).unwrap();
    assert!(bind_peer(creator, peer).is_ok());

    let root_slot = creator.slot();
    let root = capability(creator, root_slot).unwrap();
    let transferred = linked_transfer(root, creator, root_slot);
    assert!(install_transfer_message(
        peer,
        creator,
        endpoint,
        Some(transferred)
    ));

    let rollback_base = observation(peer);
    let destination_slot = TestCapSlot::try_new(1).unwrap();
    let wire = recv_wire(1);
    assert!(
        complete_parked_recv(peer, &wire, 0, |_| {
            assert_eq!(cap_revoke(peer, destination_slot), Ok(1));
            assert!(install_transfer_message(
                peer,
                creator,
                endpoint,
                Some(root)
            ));
            assert!(complete_parked_recv(peer, &wire, 0, |_| true).is_ok());
            false
        })
        .is_err()
    );

    assert_eq!(capability(peer, destination_slot), Some(root));
    assert_eq!(queued_for(peer), 1);
    let direct = observation(peer).0;
    assert!(direct.rows().any(|relation| matches!(
        relation.key(),
        RelationKey::Holds { capability, .. } if capability.slot().index() == 1
    )));
    require_fold_from(peer, rollback_base.0, rollback_base.1);
}

fn require_fold(evidence: ProjectionEvidence) {
    assert!(evidence.fold_matches);
    assert_eq!(evidence.epoch, evidence.fold_epoch);
    assert_eq!(evidence.rows, evidence.fold_rows);
}

fn observation(domain: DomainToken) -> (Snapshot, DeltaCursor) {
    relations_projection_observation(domain).unwrap()
}

fn require_fold_from(domain: DomainToken, base: Snapshot, cursor: DeltaCursor) {
    require_fold(relations_projection_fold(domain, base, cursor).unwrap());
}

#[test]
fn real_ipc_create_transfer_revoke_and_teardown_fold_to_snapshots() {
    let _guard = test_lock();
    reset();
    let creator = domain(0);
    let peer = domain(1);
    prepare_domain(creator);
    prepare_domain(peer);
    let created_base = observation(creator);
    let endpoint = endpoint_create(creator).unwrap();
    require_fold_from(creator, created_base.0, created_base.1);

    let bound_base = observation(peer);
    assert!(bind_peer(creator, peer).is_ok());
    require_fold_from(peer, bound_base.0, bound_base.1);

    let transferred_base = observation(peer);
    let root = capability(creator, creator.slot()).unwrap();
    assert!(install_transfer_message(
        peer,
        creator,
        endpoint,
        Some(root)
    ));
    let wire = recv_wire(1);
    assert!(complete_parked_recv(peer, &wire, 0, |_| true).is_ok());
    require_fold_from(peer, transferred_base.0, transferred_base.1);

    let revoked_base = observation(peer);
    assert_eq!(cap_revoke(creator, creator.slot()), Ok(2));
    require_fold_from(peer, revoked_base.0, revoked_base.1);

    let surviving_base = observation(peer);
    teardown_domain(creator);
    require_fold_from(peer, surviving_base.0, surviving_base.1);

    teardown_domain(peer);
    assert!(relations_projection_observation(peer).is_none());
}
