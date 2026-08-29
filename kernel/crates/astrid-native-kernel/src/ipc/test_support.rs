//! Host-test-only access to the production IPC state machine.

use super::*;

pub(crate) fn reset() {
    *IPC.lock() = IpcState::empty();
    crate::domains::wait::test_support::reset();
}

pub(crate) fn capability(domain: DomainToken, slot: CapSlot) -> Option<Capability> {
    IPC.lock().capabilities[domain.slot().index()].get(domain, slot)
}

pub(crate) fn find(domain: DomainToken, rights: Rights) -> Option<CapSlot> {
    let state = IPC.lock();
    find_slot(&state, domain, rights)
}

pub(crate) fn queued_for(domain: DomainToken) -> usize {
    IPC.lock()
        .objects
        .iter()
        .flatten()
        .map(|object| object.queued_for(domain))
        .sum()
}

pub(crate) fn has_waiter(domain: DomainToken) -> bool {
    IPC.lock()
        .objects
        .iter()
        .flatten()
        .any(|object| object.has_waiter(domain))
}

pub(crate) fn endpoint_create(domain: DomainToken) -> Result<EndpointId, IpcError> {
    let (_, slot) = super::endpoint_create(domain)?;
    EndpointId::try_new(slot as usize).map_err(|_| IpcError::NoSpace)
}

pub(crate) fn park_member(domain: DomainToken) -> bool {
    IPC.lock()
        .objects
        .iter_mut()
        .flatten()
        .any(|object| object.park(domain))
}

pub(crate) fn cap_revoke(domain: DomainToken, slot: CapSlot) -> Result<u64, IpcError> {
    super::cap_revoke(
        &TrapFrame {
            rdi: u64::from(slot.get()),
            ..TrapFrame::zeroed()
        },
        domain,
    )
    .map(|(_, count)| count)
}

pub(crate) fn object_count() -> usize {
    IPC.lock().objects.iter().flatten().count()
}

pub(crate) fn install_transfer_message(
    destination: DomainToken,
    sender: DomainToken,
    endpoint_id: EndpointId,
    transfer: Option<Capability>,
) -> bool {
    let mut state = IPC.lock();
    let Some(object) = state.objects[endpoint_id.index()].as_mut() else {
        return false;
    };
    let payload = [0u8; abi::MAX_PAYLOAD_BYTES];
    matches!(
        object.send(
            sender,
            destination,
            Message::new(sender, 7, payload.len() as u16, payload, transfer),
        ),
        SendOutcome::Delivered | SendOutcome::Ready
    )
}

pub(crate) fn can_send(domain: DomainToken, slot: CapSlot) -> bool {
    let state = IPC.lock();
    endpoint_pair(&state, domain, slot, Rights::SEND).is_ok()
}

pub(crate) fn send_outcome(
    sender: DomainToken,
    destination: DomainToken,
    endpoint_id: EndpointId,
) -> Option<SendOutcome> {
    let mut state = IPC.lock();
    let object = state.objects[endpoint_id.index()].as_mut()?;
    let payload = [0u8; abi::MAX_PAYLOAD_BYTES];
    Some(object.send(
        sender,
        destination,
        Message::new(sender, 8, payload.len() as u16, payload, None),
    ))
}

#[cfg(test)]
mod tests {
    use super::test_support::{
        cap_revoke as support_cap_revoke, capability, endpoint_create, has_waiter,
        install_transfer_message, object_count, park_member, queued_for, reset, send_outcome,
    };
    use super::*;
    use crate::test_lock::LOCK;

    fn domain(slot: u64) -> DomainToken {
        DomainToken::new(slot, 1).unwrap()
    }

    fn recv_wire(sender: DomainToken, cap_slot: u16) -> [u8; abi::MAX_BUFFER_BYTES] {
        let mut parsed = abi::MessageBuffer::zeroed();
        let payload = [1u8; abi::MAX_PAYLOAD_BYTES];
        parsed.set_message(7, 0, 4, payload);
        parsed.set_cap_slot(cap_slot);
        parsed.into_wire(sender)
    }

    #[test]
    fn revoking_last_peer_capability_unbinds_stale_member() {
        let _guard = LOCK.lock();
        reset();
        let creator = domain(0);
        let peer = domain(1);
        prepare_domain(creator);
        prepare_domain(peer);
        endpoint_create(creator).unwrap();
        assert!(bind_peer(creator, peer).is_ok());
        let peer_slot = test_support::find(peer, Rights::RECV).unwrap();
        assert_eq!(support_cap_revoke(peer, peer_slot), Ok(1));
        assert!(capability(peer, peer_slot).is_none());
        let root_slot = test_support::find(creator, Rights::SEND).unwrap();
        assert!(!test_support::can_send(creator, root_slot));
        assert_eq!(queued_for(peer), 0);
        assert_eq!(object_count(), 1);
    }

    #[test]
    fn teardown_revokes_derivation_subtree_and_sender_queue() {
        let _guard = LOCK.lock();
        reset();
        let creator = domain(0);
        let peer = domain(1);
        prepare_domain(creator);
        prepare_domain(peer);
        let endpoint = endpoint_create(creator).unwrap();
        assert!(bind_peer(creator, peer).is_ok());
        assert!(install_transfer_message(peer, creator, endpoint, None));
        let outcome = teardown_domain(creator);
        assert_eq!(outcome.capabilities, 2);
        assert_eq!(outcome.queued_messages, 1);
        assert!(outcome.peer_failures.contains(&Some(peer)));
        assert!(test_support::find(peer, Rights::RECV).is_none());
        assert_eq!(object_count(), 0);
    }

    #[test]
    fn failed_nontransfer_copyout_restores_without_waiter() {
        let _guard = LOCK.lock();
        reset();
        let creator = domain(0);
        let peer = domain(1);
        prepare_domain(creator);
        prepare_domain(peer);
        let endpoint = endpoint_create(creator).unwrap();
        assert!(bind_peer(creator, peer).is_ok());
        assert!(install_transfer_message(peer, creator, endpoint, None));
        let wire = recv_wire(creator, 0);
        let slot = test_support::find(peer, Rights::RECV).unwrap();
        assert!(complete_parked_recv(peer, &wire, u64::from(slot.get()), |_| false).is_err());
        assert_eq!(queued_for(peer), 1);
        assert!(!has_waiter(peer));
    }

    #[test]
    fn failed_transfer_copyout_does_not_install_stale_waiter() {
        let _guard = LOCK.lock();
        reset();
        let creator = domain(0);
        let peer = domain(1);
        prepare_domain(creator);
        prepare_domain(peer);
        let endpoint = endpoint_create(creator).unwrap();
        assert!(bind_peer(creator, peer).is_ok());
        let root_slot = test_support::find(creator, Rights::GRANT).unwrap();
        let transfer = capability(creator, root_slot);
        assert!(park_member(peer));
        assert!(install_transfer_message(peer, creator, endpoint, transfer));
        let wire = recv_wire(creator, 7);
        let slot = test_support::find(peer, Rights::RECV).unwrap();
        assert!(complete_parked_recv(peer, &wire, u64::from(slot.get()), |_| false).is_err());
        assert_eq!(queued_for(peer), 1);
        assert!(!has_waiter(peer));
        assert!(capability(peer, CapSlot::try_new(7).unwrap()).is_none());
        assert_eq!(
            send_outcome(creator, peer, endpoint),
            Some(SendOutcome::Full)
        );
        assert!(!has_waiter(peer));
    }

    #[test]
    fn running_guest_cancel_requires_live_capability_and_is_typed() {
        let _guard = LOCK.lock();
        reset();
        let domain = DomainToken::new(0, 1).unwrap();
        prepare_domain(domain);
        let mut frame = TrapFrame::zeroed();
        frame.rax = 4;
        assert_eq!(
            handle_call(&mut frame, domain),
            SyscallOutcome::Done(IpcError::Busy.as_code(), 0)
        );
        endpoint_create(domain).unwrap();
        assert_eq!(
            handle_call(&mut frame, domain),
            SyscallOutcome::Done(CANCELLED_STATUS, 0)
        );
    }
}
