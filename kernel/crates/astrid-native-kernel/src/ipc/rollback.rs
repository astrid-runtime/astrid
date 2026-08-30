//! Rollback of a received IPC transfer after a failed user-copy commit.

use super::IpcState;
use super::capability::{CapSlot, Capability, DomainToken};
use super::endpoint::Message;

pub(super) fn rollback_recv(
    domain: DomainToken,
    endpoint_id: super::EndpointId,
    message: Message,
    installed: Option<(CapSlot, Capability)>,
) {
    let mut state = super::IPC.lock();
    if let Some((slot, transferred)) = installed {
        let table = &mut state.capabilities[domain.slot().index()];
        if table
            .get(domain, slot)
            .is_some_and(|current| current == transferred)
        {
            table.remove(domain, slot);
        }
    }
    // The destination slot may have been revoked and reused independently of
    // the queued message. The message's own authority is still checked below.
    // A receive is durable only when its authority remains valid. Requeueing a
    // transfer whose parent or endpoint vanished in the commit gap would let a
    // revoked capability return through an apparently ordinary retry.
    if message.transfer().is_none_or(|capability| {
        queued_transfer_authority_valid(&state, message.sender(), capability)
    }) && let Some(object) = state.objects[endpoint_id.index()].as_mut()
    {
        object.restore(domain, message, false);
    }
}

pub(super) fn queued_transfer_authority_valid(
    state: &IpcState,
    sender: DomainToken,
    capability: Capability,
) -> bool {
    let authority_live = match capability.parent {
        Some(parent_link) => {
            let Some(parent) = state.capabilities[parent_link.domain.slot().index()]
                .get(parent_link.domain, parent_link.slot)
            else {
                return false;
            };
            parent.endpoint == capability.endpoint
                && parent.generation == capability.generation
                && parent.rights.contains(capability.rights)
        },
        None => state.capabilities[sender.slot().index()]
            .capability_slots()
            .iter()
            .flatten()
            .any(|held| *held == capability),
    };
    if !authority_live {
        return false;
    }
    state.objects[capability.endpoint.index()]
        .as_ref()
        .is_some_and(|object| {
            object.generation() == capability.generation && object.accepts(sender)
        })
}
