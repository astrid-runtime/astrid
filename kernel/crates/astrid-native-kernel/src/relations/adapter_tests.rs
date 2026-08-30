//! Same-lock regressions driven by the real IPC state machine.

use super::adapter::ProjectionEvidence;
use crate::ipc::test_support::{
    cap_revoke, capability, endpoint_create, install_transfer_message, reset, test_lock,
};
use crate::ipc::{
    DomainToken, MAX_BUFFER_BYTES, bind_peer, complete_parked_recv, prepare_domain,
    relations_projection_evidence, teardown_domain,
};

fn domain(slot: u64) -> DomainToken {
    DomainToken::new(slot, 1).unwrap()
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

#[test]
fn real_ipc_create_transfer_revoke_and_teardown_fold_to_snapshots() {
    let _guard = test_lock();
    reset();
    let creator = domain(0);
    let peer = domain(1);
    prepare_domain(creator);
    prepare_domain(peer);
    require_fold(relations_projection_evidence(creator).unwrap());
    assert_eq!(
        relations_projection_evidence(creator).unwrap(),
        ProjectionEvidence {
            epoch: 1,
            rows: 1,
            fold_epoch: 1,
            fold_rows: 1,
            fold_matches: true,
        }
    );

    let endpoint = endpoint_create(creator).unwrap();
    let created = relations_projection_evidence(creator).unwrap();
    assert_eq!((created.epoch, created.rows), (3, 3));
    require_fold(created);

    assert!(bind_peer(creator, peer).is_ok());
    let bound = relations_projection_evidence(peer).unwrap();
    assert_eq!((bound.epoch, bound.rows), (4, 4));
    require_fold(bound);

    let root = capability(creator, creator.slot()).unwrap();
    assert!(install_transfer_message(
        peer,
        creator,
        endpoint,
        Some(root)
    ));
    let wire = recv_wire(1);
    assert!(complete_parked_recv(peer, &wire, 0, |_| true).is_ok());
    let transferred = relations_projection_evidence(peer).unwrap();
    assert_eq!((transferred.epoch, transferred.rows), (6, 6));
    require_fold(transferred);

    assert_eq!(cap_revoke(creator, creator.slot()), Ok(2));
    let revoked = relations_projection_evidence(peer).unwrap();
    assert_eq!((revoked.epoch, revoked.rows), (8, 4));
    require_fold(revoked);

    teardown_domain(creator);
    let surviving = relations_projection_evidence(peer).unwrap();
    assert_eq!((surviving.epoch, surviving.rows), (8, 4));
    require_fold(surviving);

    teardown_domain(peer);
    assert!(relations_projection_evidence(peer).is_none());
}
