//! Private fixed-capability endpoint IPC for native protection domains.

mod abi;
mod capability;
mod copy;
mod endpoint;
mod error;

use core::num::NonZeroU64;

use spin::Mutex;

use crate::serial;
use crate::trap::TrapFrame;

pub(crate) use abi::MAX_BUFFER_BYTES;
pub(crate) use capability::DomainToken;
use capability::{CapSlot, CapTable, Capability, DerivationLink, Rights};
use endpoint::{Endpoint, Message, SendOutcome};
use error::IpcError;

const _: () = assert!(abi::MAX_BUFFER_BYTES == 96);
const _: () = assert!(abi::CAP_SLOTS_PER_DOMAIN == 8);
const _: () = assert!(abi::ENDPOINT_POOL == 4);
const _: () = assert!(abi::CAP_OBJECT_POOL == 16);
const _: () = assert!(abi::QUEUE_DEPTH == 1);
const _: () = assert!(abi::TRANSFERS_PER_MESSAGE == 1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct EndpointId(u8);

impl EndpointId {
    const fn try_new(value: usize) -> Result<Self, IpcError> {
        if value < abi::ENDPOINT_POOL {
            Ok(Self(value as u8))
        } else {
            Err(IpcError::NoSpace)
        }
    }

    const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ObjectGeneration(NonZeroU64);

impl ObjectGeneration {
    const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub(crate) const fn get(self) -> u64 {
        self.0.get()
    }

    const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Self::new(value.get()),
            None => None,
        }
    }
}

#[derive(Clone, Copy)]
struct IpcState {
    next_object_generation: u64,
    objects: [Option<Endpoint>; abi::ENDPOINT_POOL],
    capabilities: [CapTable; capability::DOMAIN_SLOTS],
}

impl IpcState {
    const fn empty() -> Self {
        Self {
            next_object_generation: 1,
            objects: [None; abi::ENDPOINT_POOL],
            capabilities: [CapTable::unowned(), CapTable::unowned()],
        }
    }
}

static IPC: Mutex<IpcState> = Mutex::new(IpcState::empty());

pub(crate) enum SyscallOutcome {
    Done(u64, u64),
    Block(BlockReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlockReason {
    SendReady,
    RecvEmpty,
}

pub(crate) const VECTOR: u8 = 112;
pub(crate) const FAULTED_STATUS: u64 = IpcError::Faulted.as_code();
pub(crate) const CANCELLED_STATUS: u64 = IpcError::Cancelled.as_code();

#[derive(Clone, Copy)]
pub(crate) struct TeardownOutcome {
    pub(crate) endpoints: usize,
    pub(crate) capabilities: usize,
    pub(crate) queued_messages: usize,
    pub(crate) waiters: [Option<DomainToken>; 2],
}

impl TeardownOutcome {
    pub(crate) const EMPTY: Self = Self {
        endpoints: 0,
        capabilities: 0,
        queued_messages: 0,
        waiters: [None; 2],
    };
}

pub(crate) fn prepare_domain(domain: DomainToken) {
    let mut state = IPC.lock();
    state.capabilities[domain.slot().index()].reset(domain);
}

pub(crate) fn bind_peer(creator: DomainToken, peer: DomainToken) -> Result<(), IpcError> {
    let mut state = IPC.lock();
    let creator_slot = find_slot(&state, creator, Rights::GRANT).ok_or(IpcError::Denied)?;
    let source = state.capabilities[creator.slot().index()]
        .get(creator, creator_slot)
        .ok_or(IpcError::Stale)?;
    let Some(object) = state.objects[source.endpoint.index()].as_mut() else {
        return Err(IpcError::Stale);
    };
    if object.generation() != source.generation || !object.bind(peer) {
        return Err(IpcError::Busy);
    }
    let Some(slot) = state.capabilities[peer.slot().index()].free_slot(peer) else {
        if let Some(object) = state.objects[source.endpoint.index()].as_mut() {
            object.clear_domain(peer);
        }
        return Err(IpcError::NoSpace);
    };
    state.capabilities[peer.slot().index()].install(
        peer,
        slot,
        Capability {
            endpoint: source.endpoint,
            rights: source.rights,
            generation: source.generation,
            parent: Some(DerivationLink {
                domain: creator,
                slot: creator_slot,
            }),
        },
    )
}

pub(crate) fn handle_call(frame: &mut TrapFrame, domain: DomainToken) -> SyscallOutcome {
    let Some(operation) = abi::Operation::decode(frame.rax) else {
        return fault(domain, IpcError::Malformed, None);
    };
    match dispatch(frame, domain, operation) {
        Ok((status, aux)) => {
            let blocks = match operation {
                abi::Operation::Send => status == 0 && aux == SEND_READY_AUX,
                abi::Operation::Recv => status == RECV_BLOCK_STATUS && aux == 1,
                _ => false,
            };
            if blocks {
                if operation == abi::Operation::Send {
                    serial::ev_ipc_op(
                        domain.slot().index() as u64 + 1,
                        domain.generation().get(),
                        operation.as_name(),
                        "ok",
                    );
                }
                let reason = match operation {
                    abi::Operation::Send => BlockReason::SendReady,
                    _ => BlockReason::RecvEmpty,
                };
                return SyscallOutcome::Block(reason);
            }
            serial::ev_ipc_op(
                domain.slot().index() as u64 + 1,
                domain.generation().get(),
                operation.as_name(),
                "ok",
            );
            SyscallOutcome::Done(status, aux)
        },
        Err(error) => fault(domain, error, Some(operation)),
    }
}

fn fault(
    domain: DomainToken,
    error: IpcError,
    operation: Option<abi::Operation>,
) -> SyscallOutcome {
    serial::ev_ipc_op(
        domain.slot().index() as u64 + 1,
        domain.generation().get(),
        operation.map_or("unknown", abi::Operation::as_name),
        error.as_name(),
    );
    SyscallOutcome::Done(error.as_code(), 0)
}

pub(crate) fn complete_parked_recv(
    domain: DomainToken,
    input: &[u8; abi::MAX_BUFFER_BYTES],
    slot: u64,
    commit: impl FnOnce(&mut [u8; abi::MAX_BUFFER_BYTES]) -> bool,
) -> Result<(), ()> {
    let mut parsed = abi::MessageBuffer::parse_recv(input).map_err(|_| ())?;
    let slot = slot_argument(slot).map_err(|_| ())?;
    let mut state = IPC.lock();
    let source = state.capabilities[domain.slot().index()]
        .get(domain, slot)
        .ok_or(())?;
    if !source.rights.contains(Rights::RECV) {
        return Err(());
    }
    let Some(object) = state.objects[source.endpoint.index()].as_mut() else {
        return Err(());
    };
    let Some(message) = object.receive(domain) else {
        return Err(());
    };
    let endpoint_id = source.endpoint;
    let transferred_slot = if message.transfer().is_some() {
        let destination_slot = CapSlot::try_new(usize::from(parsed.cap_slot())).map_err(|_| ())?;
        let capability = message.transfer().ok_or(())?;
        state.capabilities[domain.slot().index()]
            .install(domain, destination_slot, capability)
            .map_err(|_| ())?;
        Some(destination_slot)
    } else {
        None
    };
    parsed.set_message(
        message.tag(),
        u32::from(message.transfer().is_some()) * abi::FLAG_TRANSFER,
        message.payload_len(),
        message.payload(),
    );
    let mut encoded = parsed.into_wire(message.sender());
    let transfer = message.transfer();
    drop(state);
    let committed = commit(&mut encoded);
    if !committed && transfer.is_some() {
        rollback_recv(domain, endpoint_id, message, transfer, transferred_slot);
    }
    committed.then_some(()).ok_or(())
}

const RECV_BLOCK_STATUS: u64 = IpcError::Busy.as_code();
const SEND_READY_AUX: u64 = 1;

fn dispatch(
    frame: &mut TrapFrame,
    domain: DomainToken,
    operation: abi::Operation,
) -> Result<(u64, u64), IpcError> {
    match operation {
        abi::Operation::EndpointCreate => endpoint_create(domain),
        abi::Operation::Send => send(frame, domain),
        abi::Operation::Recv => recv(frame, domain),
        abi::Operation::Cancel => Err(IpcError::Busy),
        abi::Operation::CapRevoke => cap_revoke(frame, domain),
        abi::Operation::CapIdentify => cap_identify(frame, domain),
    }
}

fn endpoint_create(domain: DomainToken) -> Result<(u64, u64), IpcError> {
    let mut state = IPC.lock();
    let generation =
        ObjectGeneration::new(state.next_object_generation).ok_or(IpcError::NoSpace)?;
    let mut endpoint = Endpoint::new(generation);
    if !endpoint.bind(domain) {
        return Err(IpcError::Busy);
    }
    let index = state
        .objects
        .iter()
        .position(|object| object.is_none())
        .ok_or(IpcError::NoSpace)?;
    let slot = state.capabilities[domain.slot().index()]
        .free_slot(domain)
        .ok_or(IpcError::NoSpace)?;
    let id = EndpointId::try_new(index)?;
    state.capabilities[domain.slot().index()].install(
        domain,
        slot,
        Capability {
            endpoint: id,
            rights: Rights::ALL,
            generation,
            parent: None,
        },
    )?;
    state.objects[index] = Some(endpoint);
    state.next_object_generation += 1;
    Ok((0, u64::from(slot.get())))
}

fn send(frame: &TrapFrame, domain: DomainToken) -> Result<(u64, u64), IpcError> {
    let slot = slot_argument(frame.rdi)?;
    if frame.rdx as usize != abi::MAX_BUFFER_BYTES {
        return Err(IpcError::Malformed);
    }
    let mut wire = [0u8; abi::MAX_BUFFER_BYTES];
    if !copy::copy_current_user(frame.rsi, &mut wire, false) {
        return Err(IpcError::Faulted);
    }
    let input = abi::MessageBuffer::parse_send(&wire)?;
    let mut state = IPC.lock();
    let (source, destination, object_generation) =
        endpoint_pair(&state, domain, slot, Rights::SEND)?;
    if input.flags() == abi::FLAG_TRANSFER {
        if !source.rights.contains(Rights::GRANT) {
            return Err(IpcError::Denied);
        }
        let requested = input.requested_rights()?;
        if requested.intersection(source.rights) != requested {
            return Err(IpcError::Denied);
        }
    } else if input.flags() != 0 {
        return Err(IpcError::Malformed);
    }
    let transfer = (input.flags() == abi::FLAG_TRANSFER).then(|| Capability {
        endpoint: source.endpoint,
        rights: input
            .requested_rights()
            .unwrap_or(Rights::SEND)
            .intersection(source.rights),
        generation: object_generation,
        parent: Some(DerivationLink { domain, slot }),
    });
    let message = Message::new(
        domain,
        input.tag(),
        input.payload_len() as u16,
        input.payload(),
        transfer,
    );
    let Some(object) = state.objects[source.endpoint.index()].as_mut() else {
        return Err(IpcError::Stale);
    };
    match object.send(domain, destination, message) {
        SendOutcome::Delivered => Ok((0, abi::MAX_BUFFER_BYTES as u64)),
        SendOutcome::Ready => Ok((0, SEND_READY_AUX)),
        SendOutcome::Full => Err(IpcError::WouldBlock),
    }
}

fn recv(frame: &mut TrapFrame, domain: DomainToken) -> Result<(u64, u64), IpcError> {
    let slot = slot_argument(frame.rdi)?;
    if frame.rdx as usize != abi::MAX_BUFFER_BYTES {
        return Err(IpcError::Malformed);
    }
    let mut wire = [0u8; abi::MAX_BUFFER_BYTES];
    if !copy::copy_current_user(frame.rsi, &mut wire, false) {
        return Err(IpcError::Faulted);
    }
    let mut output = abi::MessageBuffer::parse_recv(&wire)?;
    let mut state = IPC.lock();
    let source = state.capabilities[domain.slot().index()]
        .get(domain, slot)
        .ok_or(IpcError::Stale)?;
    if !source.rights.contains(Rights::RECV) {
        return Err(IpcError::Denied);
    }
    let Some(object) = state.objects[source.endpoint.index()].as_mut() else {
        return Err(IpcError::Stale);
    };
    let Some(message) = object.receive(domain) else {
        if object.park(domain) {
            // Aux 1 distinguishes an intentional empty-queue park from the
            // ordinary Busy terminal without exposing a ninth user status.
            return Ok((RECV_BLOCK_STATUS, 1));
        }
        return Err(IpcError::Busy);
    };
    let endpoint_id = source.endpoint;
    let transferred_slot = if message.transfer().is_some() {
        let destination_slot = CapSlot::try_new(usize::from(output.cap_slot()))?;
        let capability = message.transfer().ok_or(IpcError::Malformed)?;
        state.capabilities[domain.slot().index()].install(domain, destination_slot, capability)?;
        Some(destination_slot)
    } else {
        None
    };
    output.set_message(
        message.tag(),
        u32::from(message.transfer().is_some()) * abi::FLAG_TRANSFER,
        message.payload_len(),
        message.payload(),
    );
    let encoded = output.into_wire(message.sender());
    let transfer = message.transfer();
    drop(state);
    let mut encoded = encoded;
    if !copy::copy_current_user(frame.rsi, &mut encoded, true) {
        rollback_recv(domain, endpoint_id, message, transfer, transferred_slot);
        return Err(IpcError::Faulted);
    }
    Ok((0, abi::MAX_BUFFER_BYTES as u64))
}

fn rollback_recv(
    domain: DomainToken,
    endpoint_id: EndpointId,
    message: Message,
    transfer: Option<Capability>,
    installed: Option<CapSlot>,
) {
    let mut state = IPC.lock();
    if let Some(slot) = installed {
        state.capabilities[domain.slot().index()].remove(domain, slot);
    }
    if transfer.is_some() {
        let restored = Message::new(
            message.sender(),
            message.tag(),
            message.payload_len(),
            message.payload(),
            transfer,
        );
        if let Some(object) = state.objects[endpoint_id.index()].as_mut() {
            object.restore(domain, restored, true);
        }
    }
}

fn cap_revoke(frame: &TrapFrame, domain: DomainToken) -> Result<(u64, u64), IpcError> {
    let slot = slot_argument(frame.rdi)?;
    let mut state = IPC.lock();
    let Some(removed) = state.capabilities[domain.slot().index()].remove(domain, slot) else {
        return Err(IpcError::Stale);
    };
    let mut removed_count = 1usize;
    let parent = DerivationLink { domain, slot };
    for table_index in 0..state.capabilities.len() {
        let Some(owner) = state.capabilities[table_index].owner() else {
            continue;
        };
        for index in 0..abi::CAP_SLOTS_PER_DOMAIN {
            if state.capabilities[table_index]
                .capability_at(index)
                .is_some_and(|capability| is_derived_from(capability.parent, parent))
                && state.capabilities[table_index].remove_index(owner, index)
            {
                removed_count += 1;
            }
        }
    }
    removed_count += revoke_queued_messages(&mut state, parent);
    if endpoint_is_unused(&state, removed.endpoint) {
        reclaim_object(&mut state, removed.endpoint);
    }
    Ok((0, removed_count as u64))
}

fn cap_identify(frame: &mut TrapFrame, domain: DomainToken) -> Result<(u64, u64), IpcError> {
    let slot = slot_argument(frame.rdi)?;
    if frame.rdx as usize != abi::MAX_BUFFER_BYTES {
        return Err(IpcError::Malformed);
    }
    let state = IPC.lock();
    let capability = state.capabilities[domain.slot().index()]
        .get(domain, slot)
        .ok_or(IpcError::Stale)?;
    if !capability.rights.contains(Rights::IDENTIFY) {
        return Err(IpcError::Denied);
    }
    let mut output = abi::MessageBuffer::zeroed();
    output.set_payload_len(16);
    output.payload_mut()[..8].copy_from_slice(&capability.rights.bits().to_le_bytes());
    output.payload_mut()[8..16].copy_from_slice(&capability.generation.get().to_le_bytes());
    let encoded = output.into_wire(domain);
    drop(state);
    let mut encoded = encoded;
    if !copy::copy_current_user(frame.rsi, &mut encoded, true) {
        return Err(IpcError::Faulted);
    }
    Ok((0, abi::MAX_BUFFER_BYTES as u64))
}

pub(crate) fn teardown_domain(domain: DomainToken) -> TeardownOutcome {
    let mut outcome = TeardownOutcome::EMPTY;
    let mut state = IPC.lock();
    outcome.capabilities = state.capabilities[domain.slot().index()].count(domain);
    for index in 0..abi::CAP_SLOTS_PER_DOMAIN {
        state.capabilities[domain.slot().index()].remove_index(domain, index);
    }
    for object_index in 0..state.objects.len() {
        outcome.queued_messages += state.objects[object_index]
            .as_ref()
            .map(|object| object.queued_for(domain))
            .unwrap_or(0);
        let Some(object) = state.objects[object_index].as_mut() else {
            continue;
        };
        let wakes = object.clear_domain(domain);
        for wake in wakes.into_iter().flatten() {
            for slot in &mut outcome.waiters {
                if slot.is_none() {
                    *slot = Some(wake);
                    break;
                }
            }
        }
    }
    let mut object_ids = [None; abi::ENDPOINT_POOL];
    for (index, object) in state.objects.iter().enumerate() {
        if object.is_some()
            && let Ok(id) = EndpointId::try_new(index)
        {
            object_ids[index] = Some(id);
        }
    }
    for id in object_ids.into_iter().flatten() {
        if endpoint_is_unused(&state, id) && reclaim_object(&mut state, id) {
            outcome.endpoints += 1;
        }
    }
    outcome
}

fn reclaim_object(state: &mut IpcState, id: EndpointId) -> bool {
    let Some(object) = state.objects[id.index()].as_mut() else {
        return false;
    };
    let Some(next) = object.generation().next() else {
        return false;
    };
    *object = Endpoint::new(next);
    state.objects[id.index()] = None;
    true
}

fn endpoint_is_unused(state: &IpcState, id: EndpointId) -> bool {
    !state.capabilities.iter().any(|table| {
        (0..abi::CAP_SLOTS_PER_DOMAIN).any(|index| {
            table
                .capability_at(index)
                .is_some_and(|capability| capability.endpoint == id)
        })
    })
}

fn endpoint_pair(
    state: &IpcState,
    domain: DomainToken,
    slot: CapSlot,
    required: Rights,
) -> Result<(Capability, DomainToken, ObjectGeneration), IpcError> {
    let source = state.capabilities[domain.slot().index()]
        .get(domain, slot)
        .ok_or(IpcError::Stale)?;
    if !source.rights.contains(required) {
        return Err(IpcError::Denied);
    }
    let Some(object) = state.objects[source.endpoint.index()].as_ref() else {
        return Err(IpcError::Stale);
    };
    if object.generation() != source.generation || !object.accepts(domain) {
        return Err(IpcError::Stale);
    }
    let Some(destination) = state
        .capabilities
        .iter()
        .filter_map(CapTable::owner)
        .find(|candidate| *candidate != domain && object.accepts(*candidate))
    else {
        return Err(IpcError::Stale);
    };
    Ok((source, destination, source.generation))
}

fn find_slot(state: &IpcState, domain: DomainToken, required: Rights) -> Option<CapSlot> {
    (0..abi::CAP_SLOTS_PER_DOMAIN)
        .map(CapSlot::try_new)
        .find_map(Result::ok)
        .filter(|slot| {
            state.capabilities[domain.slot().index()]
                .get(domain, *slot)
                .is_some_and(|capability| capability.rights.contains(required))
        })
}

fn slot_argument(value: u64) -> Result<CapSlot, IpcError> {
    if value > u64::from(u8::MAX) {
        return Err(IpcError::Malformed);
    }
    CapSlot::try_new(value as usize)
}

fn is_derived_from(parent: Option<DerivationLink>, ancestor: DerivationLink) -> bool {
    parent == Some(ancestor)
}

fn revoke_queued_messages(state: &mut IpcState, parent: DerivationLink) -> usize {
    let mut removed = 0;
    for object_index in 0..state.objects.len() {
        let Some(object) = state.objects[object_index].as_mut() else {
            continue;
        };
        for index in 0..abi::ENDPOINT_POOL.min(2) {
            if object.queue_message(index).is_some_and(|message| {
                is_derived_from(message.transfer().and_then(|cap| cap.parent), parent)
            }) && object.clear_queue(index)
            {
                removed += 1;
            }
        }
    }
    removed
}
