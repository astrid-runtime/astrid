//! On-CPU parking, typed wakeup, and the private IPC trap bridge.

use core::sync::atomic::Ordering;

use spin::Mutex;
#[cfg(not(test))]
use x86_64::VirtAddr;
#[cfg(not(test))]
use x86_64::registers::control::Cr3;

#[cfg(not(test))]
use super::manager::{
    CURRENT, MANAGER, fail_terminal, kernel_cr3_value, resume_stack_end, scheduler_resume,
};
#[cfg(not(test))]
use super::paging::AddressSpace;
use super::types::{DomainGeneration, DomainHandle, DomainId, KERNEL_STACK_TOP};
#[cfg(not(test))]
use crate::gdt;
use crate::ipc;
use crate::serial;
use crate::trap::TrapFrame;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BlockStatus {
    Sent,
    Received,
    Cancelled,
    Faulted,
}

impl BlockStatus {
    const fn as_name(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Sent => "sent",
            Self::Cancelled => "cancelled",
            Self::Faulted => "faulted",
        }
    }
}

#[derive(Clone, Copy)]
struct ParkedDomain {
    handle: DomainHandle,
    root: u64,
    root_flags: u64,
    frame: usize,
    status: BlockStatus,
    user_buffer: u64,
    cap_slot: u64,
    buffer_len: u64,
}

struct CompletionRequest {
    status: u64,
    aux: u64,
}

static PARKED: Mutex<[Option<ParkedDomain>; 2]> = Mutex::new([None, None]);
static COPY_SCRATCH: Mutex<[u8; 96]> = Mutex::new([0; 96]);
static PENDING_COMPLETION: Mutex<Option<CompletionRequest>> = Mutex::new(None);

#[cfg(not(test))]
pub(super) fn current_handle() -> DomainHandle {
    DomainHandle::new(
        DomainId(CURRENT.slot.load(Ordering::SeqCst)),
        DomainGeneration(CURRENT.generation.load(Ordering::SeqCst)),
    )
}

#[cfg(not(test))]
pub(super) fn park_current(frame: &mut TrapFrame, status: BlockStatus) -> ! {
    let handle = current_handle();
    let slot = handle.id().value() as usize;
    let parked = ParkedDomain {
        handle,
        root: CURRENT.root.load(Ordering::SeqCst),
        root_flags: CURRENT.root_flags.load(Ordering::SeqCst),
        frame: frame as *mut TrapFrame as usize,
        status,
        user_buffer: frame.rsi,
        cap_slot: frame.rdi,
        buffer_len: frame.rdx,
    };
    {
        let mut parked_domains = PARKED.lock();
        if parked_domains[slot].is_some() {
            serial::ev_ipc_wake(handle.id().value() + 1, handle.generation().value(), "busy");
            fail_terminal("duplicate_ipc_park");
        }
        parked_domains[slot] = Some(parked);
    }
    if set_domain_blocked(handle).is_err() {
        PARKED.lock()[slot] = None;
        fail_terminal("ipc_block_rejected");
    }
    serial::ev_ipc_park(handle.id().value() + 1, handle.generation().value());
    CURRENT.active.store(false, Ordering::SeqCst);
    CURRENT.root.store(0, Ordering::SeqCst);
    CURRENT.root_flags.store(0, Ordering::SeqCst);
    CURRENT.generation.store(0, Ordering::SeqCst);
    CURRENT.stack_end.store(0, Ordering::SeqCst);
    park_in_kernel_context(resume_stack_end(), kernel_cr3_value());
}

#[cfg(not(test))]
fn set_domain_blocked(handle: DomainHandle) -> Result<(), ()> {
    let mut manager = MANAGER.lock();
    let Some(domain) = manager.valid_domain_mut(handle) else {
        return Err(());
    };
    if domain.state != super::manager::DomainState::Running {
        return Err(());
    }
    domain.state = super::manager::DomainState::Blocked;
    Ok(())
}

pub(super) fn mark_ipc_ready(handle: DomainHandle, status: BlockStatus) {
    let mut parked_domains = PARKED.lock();
    if let Some(parked) = parked_domains[handle.id().value() as usize].as_mut()
        && parked.handle == handle
    {
        parked.status = status;
    }
}

pub(super) fn mark_ipc_cancelled(domain: ipc::DomainToken) -> bool {
    let Some(handle) = domain_handle_token(domain) else {
        return false;
    };
    let mut parked_domains = PARKED.lock();
    let cancelled = parked_domains[handle.id().value() as usize]
        .as_mut()
        .is_some_and(|parked| parked.handle == handle);
    if cancelled && let Some(parked) = parked_domains[handle.id().value() as usize].as_mut() {
        parked.status = BlockStatus::Cancelled;
    }
    cancelled
}

pub(crate) fn clear_parked(handle: DomainHandle) {
    let mut parked_domains = PARKED.lock();
    if parked_domains[handle.id().value() as usize]
        .as_ref()
        .is_some_and(|parked| parked.handle == handle)
    {
        parked_domains[handle.id().value() as usize] = None;
    }
}

pub(super) fn mark_ipc_peer_failed(handle: DomainHandle) {
    let mut parked_domains = PARKED.lock();
    if let Some(parked) = parked_domains[handle.id().value() as usize].as_mut()
        && parked.handle == handle
        && matches!(parked.status, BlockStatus::Received | BlockStatus::Sent)
    {
        parked.status = BlockStatus::Faulted;
    }
}

#[cfg(not(test))]
pub(crate) fn resume_blocked(handle: DomainHandle) -> Result<(), ()> {
    let Some(parked) = PARKED.lock()[handle.id().value() as usize] else {
        return Err(());
    };
    if parked.handle != handle {
        return Err(());
    }
    let (scenario, user_stack, space, token) = {
        let mut manager = MANAGER.lock();
        let Some(domain) = manager.valid_domain_mut(handle) else {
            return Err(());
        };
        if domain.state != super::manager::DomainState::Blocked {
            return Err(());
        }
        domain.state = super::manager::DomainState::Running;
        let stack = domain
            .space
            .as_ref()
            .map(|space| space.user_stack_top())
            .ok_or(())?;
        let space = domain.space.as_ref().ok_or(())? as *const AddressSpace as usize;
        let token = ipc_domain_token(handle).ok_or(())?;
        (domain.scenario, stack, space, token)
    };
    PARKED.lock()[handle.id().value() as usize] = None;
    let (status, aux) = match parked.status {
        BlockStatus::Sent => (0, ipc::MAX_BUFFER_BYTES as u64),
        BlockStatus::Faulted => (ipc::FAULTED_STATUS, 0),
        BlockStatus::Cancelled => (ipc::CANCELLED_STATUS, 0),
        BlockStatus::Received => {
            let space = unsafe { &*(space as *const AddressSpace) };
            match complete_received_payload(
                space,
                parked.user_buffer,
                parked.cap_slot,
                parked.buffer_len,
                token,
            ) {
                Ok(()) => (0, ipc::MAX_BUFFER_BYTES as u64),
                Err(()) => (ipc::FAULTED_STATUS, 0),
            }
        },
    };
    let user_root = parked.root | (parked.root_flags & 0xfff);
    let request = CompletionRequest { status, aux };
    if PENDING_COMPLETION.lock().replace(request).is_some() {
        return Err(());
    }
    gdt::set_privilege_stack(VirtAddr::new(KERNEL_STACK_TOP));
    CURRENT.stack_end.store(user_stack, Ordering::SeqCst);
    CURRENT.slot.store(handle.id().value(), Ordering::SeqCst);
    CURRENT
        .generation
        .store(handle.generation().value(), Ordering::SeqCst);
    CURRENT.ticks.store(0, Ordering::SeqCst);
    CURRENT.quota.store(0, Ordering::SeqCst);
    CURRENT.scenario.store(scenario.value(), Ordering::SeqCst);
    CURRENT.root.store(parked.root, Ordering::SeqCst);
    CURRENT
        .root_flags
        .store(parked.root_flags, Ordering::SeqCst);
    CURRENT.entered.store(true, Ordering::SeqCst);
    CURRENT.active.store(true, Ordering::SeqCst);
    serial::ev_ipc_wake(
        handle.id().value() + 1,
        handle.generation().value(),
        parked.status.as_name(),
    );
    let completed = write_completion_in_domain_context(parked.frame, user_root, kernel_cr3_value());
    if !completed {
        return Err(());
    }
    serial::ev_ipc_resume(handle.id().value() + 1, handle.generation().value());
    resume_user(parked.frame, user_root)
}

#[cfg(not(test))]
fn complete_received_payload(
    space: &AddressSpace,
    address: u64,
    slot: u64,
    buffer_len: u64,
    token: ipc::DomainToken,
) -> Result<(), ()> {
    if buffer_len != ipc::MAX_BUFFER_BYTES as u64 {
        return Err(());
    }
    let mut wire = [0u8; ipc::MAX_BUFFER_BYTES];
    if !space.copy_user(address, &mut wire, false) {
        return Err(());
    }
    ipc::complete_parked_recv(token, &wire, slot, |encoded| {
        space.copy_user(address, encoded, true)
    })
    .map_err(|_| ())
}

#[cfg(not(test))]
unsafe extern "C" fn complete_pending(frame: *mut TrapFrame) -> bool {
    let Some(request) = PENDING_COMPLETION.lock().take() else {
        return false;
    };
    let frame = unsafe { &mut *frame };
    frame.rax = request.status;
    frame.rdx = request.aux;
    frame.vector = 3;
    true
}

#[cfg(not(test))]
#[unsafe(naked)]
extern "C" fn write_completion_in_domain_context(
    frame: usize,
    user_root: u64,
    kernel_root: u64,
) -> bool {
    core::arch::naked_asm!(
        "push rbp",
        "mov rbp, rsp",
        "push r14",
        "push r15",
        "mov r14, rsp",
        "mov r15, rdx",
        "mov cr3, rsi",
        "call {complete}",
        "mov cr3, r15",
        "mov rsp, r14",
        "pop r15",
        "pop r14",
        "pop rbp",
        "ret",
        complete = sym complete_pending,
    );
}

#[cfg(not(test))]
#[unsafe(naked)]
extern "C" fn resume_user(frame: usize, root: u64) -> ! {
    core::arch::naked_asm!(
        "mov cr3, rsi",
        "mov rsp, rdi",
        "pop rax",
        "pop rbx",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "pop rbp",
        "pop r8",
        "pop r9",
        "pop r10",
        "pop r11",
        "pop r12",
        "pop r13",
        "pop r14",
        "pop r15",
        "add rsp, 16",
        "iretq",
    );
}

pub(crate) fn prepare_ipc(domain_slot: u64, generation: u64) -> bool {
    let Some(domain) = ipc::DomainToken::new(domain_slot, generation) else {
        return false;
    };
    ipc::prepare_domain(domain);
    true
}

pub(super) fn ipc_domain_token(handle: DomainHandle) -> Option<ipc::DomainToken> {
    ipc::DomainToken::new(handle.id().value(), handle.generation().value())
}

pub(super) fn domain_handle_token(domain: ipc::DomainToken) -> Option<DomainHandle> {
    Some(DomainHandle::new(
        DomainId(domain.slot().index() as u64),
        DomainGeneration(domain.generation().get()),
    ))
}

pub(crate) fn bind_ipc_peer(
    creator_slot: u64,
    creator_generation: u64,
    peer_slot: u64,
    peer_generation: u64,
) -> bool {
    let Some(creator) = ipc::DomainToken::new(creator_slot, creator_generation) else {
        return false;
    };
    let Some(peer) = ipc::DomainToken::new(peer_slot, peer_generation) else {
        return false;
    };
    ipc::bind_peer(creator, peer).is_ok()
}

pub(crate) fn release_ipc(domain_slot: u64, generation: u64) -> ipc::TeardownOutcome {
    let Some(domain) = ipc::DomainToken::new(domain_slot, generation) else {
        return ipc::TeardownOutcome::EMPTY;
    };
    ipc::teardown_domain(domain)
}

#[cfg(not(test))]
pub(crate) fn copy_current_user(address: u64, buffer: &mut [u8], to_user: bool) -> bool {
    if !CURRENT.active.load(Ordering::SeqCst) {
        return false;
    }
    let expected_root = CURRENT.root.load(Ordering::SeqCst);
    let expected_flags = CURRENT.root_flags.load(Ordering::SeqCst);
    let (root, flags) = Cr3::read();
    if root.start_address().as_u64() != expected_root || flags.bits() != expected_flags {
        return false;
    }
    let manager = MANAGER.lock();
    let handle = current_handle();
    let Some(space) = manager
        .valid_domain(handle)
        .and_then(|domain| domain.space.as_ref())
    else {
        return false;
    };
    let mut scratch = COPY_SCRATCH.lock();
    scratch.copy_from_slice(buffer);
    let (user_root, user_flags) = Cr3::read();
    let user_cr3 = user_root.start_address().as_u64() | (user_flags.bits() & 0xfff);
    // SAFETY: the helper saves the active guarded stack, switches to the
    // existing kernel resume stack for the kernel-only table walk and copy,
    // then restores the exact user CR3 and guarded stack before returning.
    let copied = copy_in_kernel_context(
        space,
        address,
        scratch.as_mut_ptr(),
        buffer.len(),
        usize::from(to_user),
        resume_stack_end(),
        kernel_cr3_value(),
        user_cr3,
    );
    crate::ipc::finish_copy(buffer, scratch.as_slice(), copied, to_user)
}

#[cfg(not(test))]
#[unsafe(naked)]
extern "C" fn park_in_kernel_context(kernel_stack_end: usize, kernel_cr3: u64) -> ! {
    core::arch::naked_asm!(
        "mov rsp, rdi",
        "mov cr3, rsi",
        "call {resume}",
        resume = sym scheduler_resume,
    );
}

#[cfg(not(test))]
unsafe extern "C" fn call_copy_user(
    space: *const AddressSpace,
    address: u64,
    buffer: *mut u8,
    len: usize,
    to_user: usize,
) -> bool {
    // SAFETY: the caller passes the active domain's audited address space and
    // its own fixed-size IPC buffer; no other thread can run on this CPU while
    // interrupts are disabled in the IPC trap gate.
    let buffer = unsafe { core::slice::from_raw_parts_mut(buffer, len) };
    unsafe { (*space).copy_user(address, buffer, to_user != 0) }
}

#[cfg(not(test))]
#[unsafe(naked)]
extern "C" fn copy_in_kernel_context(
    space: *const AddressSpace,
    address: u64,
    buffer: *mut u8,
    len: usize,
    to_user: usize,
    kernel_stack_end: usize,
    kernel_cr3: u64,
    user_cr3: u64,
) -> bool {
    core::arch::naked_asm!(
        "push r15",
        "push r14",
        "push r13",
        "push r12",
        "mov r12, rsp",
        "mov r14, [rsp + 0x28]",
        "mov r15, [rsp + 0x30]",
        "mov cr3, r14",
        "mov rsp, r9",
        "and rsp, -16",
        "sub rsp, 8",
        "call {copy}",
        "mov cr3, r15",
        "mov rsp, r12",
        "pop r12",
        "pop r13",
        "pop r14",
        "pop r15",
        "ret",
        copy = sym call_copy_user,
    );
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn park(
        handle: DomainHandle,
        status: BlockStatus,
        user_buffer: u64,
        cap_slot: u64,
        buffer_len: u64,
    ) {
        PARKED.lock()[handle.id().value() as usize] = Some(ParkedDomain {
            handle,
            root: 0x1000,
            root_flags: 0,
            frame: 0,
            status,
            user_buffer,
            cap_slot,
            buffer_len,
        });
    }

    pub(crate) fn status(handle: DomainHandle) -> Option<BlockStatus> {
        PARKED.lock()[handle.id().value() as usize]
            .as_ref()
            .filter(|parked| parked.handle == handle)
            .map(|parked| parked.status)
    }

    pub(crate) fn parked(handle: DomainHandle) -> bool {
        PARKED.lock()[handle.id().value() as usize]
            .as_ref()
            .is_some_and(|parked| parked.handle == handle)
    }

    pub(crate) fn reset() {
        *PARKED.lock() = [None, None];
        *PENDING_COMPLETION.lock() = None;
    }

    pub(crate) fn all_statuses() -> [Option<BlockStatus>; 2] {
        PARKED
            .lock()
            .map(|parked| parked.map(|parked| parked.status))
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{all_statuses, park, reset, status};
    use super::*;
    use crate::ipc::test_support::{endpoint_create, install_transfer_message, reset as reset_ipc};
    use crate::ipc::{DomainToken, bind_peer, prepare_domain, teardown_domain};
    use crate::test_lock::LOCK;

    fn token(slot: u64) -> DomainToken {
        DomainToken::new(slot, 1).unwrap()
    }

    fn handle(slot: u64) -> DomainHandle {
        DomainHandle::new(DomainId(slot), DomainGeneration(1))
    }

    #[test]
    fn peer_failure_terminals_are_sent_and_received() {
        let _guard = LOCK.lock();
        reset();
        reset_ipc();
        park(handle(0), BlockStatus::Sent, 0, 0, 96);
        park(handle(1), BlockStatus::Received, 0, 0, 96);
        mark_ipc_peer_failed(handle(0));
        mark_ipc_peer_failed(handle(1));
        assert_eq!(
            all_statuses(),
            [Some(BlockStatus::Faulted), Some(BlockStatus::Faulted)]
        );
    }

    #[test]
    fn sender_teardown_reports_and_fails_parked_sent_sender() {
        let _guard = LOCK.lock();
        reset();
        reset_ipc();
        let sender = token(0);
        let receiver = token(1);
        prepare_domain(sender);
        prepare_domain(receiver);
        let endpoint = endpoint_create(sender).unwrap();
        assert!(bind_peer(sender, receiver).is_ok());
        assert!(crate::ipc::test_support::park_member(receiver));
        park(handle(1), BlockStatus::Received, 0, 0, 96);
        assert!(install_transfer_message(receiver, sender, endpoint, None));
        let outcome = teardown_domain(sender);
        assert_eq!(outcome.queued_messages, 1);
        assert!(outcome.peer_failures.contains(&Some(receiver)));
    }

    #[test]
    fn receiver_teardown_finds_parked_sent_sender_without_waiter() {
        let _guard = LOCK.lock();
        reset();
        reset_ipc();
        let sender = token(0);
        let receiver = token(1);
        prepare_domain(sender);
        prepare_domain(receiver);
        let endpoint = endpoint_create(sender).unwrap();
        assert!(bind_peer(sender, receiver).is_ok());
        assert!(crate::ipc::test_support::park_member(receiver));
        park(handle(1), BlockStatus::Received, 0, 0, 96);
        assert!(install_transfer_message(receiver, sender, endpoint, None));
        park(handle(0), BlockStatus::Sent, 0, 0, 96);
        let outcome = teardown_domain(receiver);
        assert_eq!(outcome.peer_failures, [Some(sender), None]);
        mark_ipc_peer_failed(handle(0));
        assert_eq!(status(handle(0)), Some(BlockStatus::Faulted));
    }
}
