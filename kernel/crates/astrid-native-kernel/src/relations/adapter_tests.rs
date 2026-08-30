//! Same-lock regressions driven by the real IPC state machine.

use super::adapter::ProjectionEvidence;
use crate::ipc::test_support::{
    cap_revoke, capability, endpoint_create, install_transfer_message, reset, test_lock,
};
use crate::ipc::{
    DomainToken, MAX_BUFFER_BYTES, TestCapSlot, bind_peer, complete_parked_recv, prepare_domain,
    relations_projection_fold, relations_projection_observation, teardown_domain,
};
use crate::relations::types::RelationKey;
use crate::relations::{DeltaCursor, Snapshot};

fn domain(slot: u64) -> DomainToken {
    DomainToken::new(slot, 1).unwrap()
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
