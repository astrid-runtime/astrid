//! Production-path regressions for capability revocation and terminal wakes.

use super::abi::MAX_BUFFER_BYTES;
use super::capability::DOMAIN_SLOTS;
use super::capability::Rights;
use super::error::IpcError;
use super::test_support::{
    capability, domain_blocked, endpoint_create, find, has_waiter, install_blocked,
    install_transfer_message, object_count, park_member, park_peer, peer_parked, peer_status,
    queued_for, reset, send_outcome, test_lock,
};
use super::*;
use crate::platform::TrapFrame;

fn domain(slot: u64) -> DomainToken {
    DomainToken::new(slot, 1).unwrap()
}

fn recv_wire(sender: DomainToken, cap_slot: u16) -> [u8; MAX_BUFFER_BYTES] {
    let mut parsed = abi::MessageBuffer::zeroed();
    parsed.set_message(7, 0, 4, [1u8; abi::MAX_PAYLOAD_BYTES]);
    parsed.set_cap_slot(cap_slot);
    parsed.into_wire(sender)
}

fn revoke(frame_domain: DomainToken, slot: CapSlot) -> Result<u64, IpcError> {
    super::cap_revoke(
        &TrapFrame {
            rdi: u64::from(slot.get()),
            ..TrapFrame::zeroed()
        },
        frame_domain,
    )
    .map(|(_, count)| count)
}

fn receive_transfer(
    recipient: DomainToken,
    sender: DomainToken,
    endpoint: EndpointId,
    parent: Capability,
    install_slot: u16,
) -> Option<Capability> {
    assert!(install_transfer_message(
        recipient,
        sender,
        endpoint,
        Some(parent)
    ));
    let recv_slot = find(recipient, Rights::RECV)?;
    let wire = recv_wire(sender, install_slot);
    super::complete_parked_recv(recipient, &wire, u64::from(recv_slot.get()), |encoded| {
        crate::platform::set_user_memory_for_test(*encoded);
        true
    })
    .ok()?;
    let slot = CapSlot::try_new(usize::from(install_slot)).ok()?;
    capability(recipient, slot)
}

fn derived_transfer(parent: Capability, owner: DomainToken, slot: CapSlot) -> Capability {
    Capability {
        parent: Some(DerivationLink {
            domain: owner,
            slot,
        }),
        ..parent
    }
}

#[test]
fn cap_revoke_removes_grandchild_and_drains_derived_queue() {
    let _guard = test_lock();
    reset();
    let creator = domain(0);
    let child = domain(1);
    prepare_domain(creator);
    prepare_domain(child);

    let endpoint = endpoint_create(creator).unwrap();
    assert!(bind_peer(creator, child).is_ok());
    let root_slot = find(creator, Rights::ALL).unwrap();
    let root = capability(creator, root_slot).unwrap();
    let child_slot_index = 7u16;
    let child_slot = CapSlot::try_new(usize::from(child_slot_index)).unwrap();
    let child_transfer = derived_transfer(root, creator, root_slot);
    let derived_child =
        receive_transfer(child, creator, endpoint, child_transfer, child_slot_index).unwrap();
    assert_eq!(
        derived_child.parent,
        Some(DerivationLink {
            domain: creator,
            slot: root_slot
        })
    );

    let grandchild_slot_index = 1u16;
    let grandchild_slot = CapSlot::try_new(usize::from(grandchild_slot_index)).unwrap();
    let grandchild_transfer = derived_transfer(derived_child, child, child_slot);
    let grandchild = receive_transfer(
        creator,
        child,
        endpoint,
        grandchild_transfer,
        grandchild_slot_index,
    )
    .unwrap();
    assert_eq!(
        grandchild.parent,
        Some(DerivationLink {
            domain: child,
            slot: child_slot
        })
    );
    assert!(capability(child, child_slot).is_some());
    assert!(capability(creator, grandchild_slot).is_some());

    assert!(install_transfer_message(
        creator,
        child,
        endpoint,
        Some(grandchild_transfer)
    ));
    assert_eq!(queued_for(creator), 1);

    assert_eq!(revoke(child, child_slot), Ok(3));
    assert!(capability(child, child_slot).is_none());
    assert!(capability(creator, grandchild_slot).is_none());
    assert_eq!(queued_for(creator), 0);
    assert_eq!(find(child, Rights::RECV), Some(root_slot));
    let teardown = teardown_domain(creator);
    assert_eq!(teardown.capabilities, 2);
    assert_eq!(teardown.queued_messages, 0);
    assert_eq!(find(child, Rights::RECV), None);
    assert_eq!(object_count(), 0);
}

#[test]
fn cap_revoke_terminal_wakes_parked_recv_peer_without_stale_waiter() {
    let _guard = test_lock();
    reset();
    let creator = domain(0);
    let peer = domain(1);
    prepare_domain(creator);
    prepare_domain(peer);

    let endpoint = endpoint_create(creator).unwrap();
    assert!(bind_peer(creator, peer).is_ok());
    assert!(park_member(peer));
    assert!(install_transfer_message(peer, creator, endpoint, None));
    assert!(park_peer(peer, "received"));
    assert!(install_blocked(peer));
    assert_eq!(peer_status(peer), Some("received"));
    assert_eq!(queued_for(peer), 1);
    assert!(domain_blocked(peer));

    let peer_slot = find(peer, Rights::RECV).unwrap();
    assert_eq!(revoke(peer, peer_slot), Ok(1));
    assert_eq!(peer_status(peer), Some("faulted"));
    assert!(peer_parked(peer));
    assert!(domain_blocked(peer));
    assert_eq!(find(peer, Rights::RECV), None);
    assert_eq!(queued_for(peer), 0);
    assert!(!has_waiter(peer));
    assert_eq!(object_count(), 1);
    assert_eq!(
        send_outcome(creator, peer, endpoint),
        Some(SendOutcome::Full)
    );
}

#[test]
fn cap_revoke_appends_revoked_domain_after_surviving_peer_wake() {
    let _guard = test_lock();
    reset();
    let creator = domain(0);
    let peer = domain(1);
    prepare_domain(creator);
    prepare_domain(peer);

    let endpoint = endpoint_create(creator).unwrap();
    assert!(bind_peer(creator, peer).is_ok());
    assert!(park_member(peer));
    assert!(install_transfer_message(peer, creator, endpoint, None));
    assert!(park_peer(peer, "received"));
    assert!(park_peer(creator, "sent"));
    assert!(install_blocked(peer));
    assert!(install_blocked(creator));

    let root_slot = find(creator, Rights::ALL).unwrap();
    assert_eq!(revoke(creator, root_slot), Ok(2));

    assert_eq!(peer_status(peer), Some("faulted"));
    assert_eq!(peer_status(creator), Some("faulted"));
    assert!(peer_parked(peer));
    assert!(peer_parked(creator));
    assert!(domain_blocked(peer));
    assert!(domain_blocked(creator));
    assert!(!has_waiter(peer));
    assert!(!has_waiter(creator));
}

#[test]
fn domain_tokens_reject_slots_outside_the_domain_table() {
    assert!(DomainToken::new(0, 1).is_some());
    assert!(DomainToken::new(1, 1).is_some());
    assert!(DomainToken::new(u64::from(u32::MAX), 1).is_none());
    assert!(DomainToken::new(DOMAIN_SLOTS as u64, 1).is_none());
}
