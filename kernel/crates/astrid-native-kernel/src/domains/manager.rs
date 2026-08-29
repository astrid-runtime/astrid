//! Typed domain admission, execution, fault containment, and reclamation.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use spin::{Mutex, Once};
use x86_64::VirtAddr;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use astrid_system_generation::ContentId;

use super::paging::AddressSpace;
use super::types::{
    BindError, CODE_BASE, ComponentImage, DomainGeneration, DomainHandle, DomainId,
    DomainPagingError, ENTRYPOINT, KERNEL_STACK_TOP, Outcome, PEER_PROBE, SLOT_CAPACITY, Scenario,
};
use crate::apic;
use crate::gdt;
use crate::ipc;
use crate::memory::FRAME_SIZE;
use crate::serial;
use crate::trap::TrapFrame;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrepareError {
    Bind(BindError),
    Paging(DomainPagingError),
    ResourceCapacity,
    SlotCapacity,
    GenerationExhausted,
    ActiveDomain,
    WrongCr3,
}

impl PrepareError {
    pub(crate) const fn as_reason(self) -> &'static str {
        match self {
            Self::Bind(error) => error.as_reason(),
            Self::Paging(error) => error.as_reason(),
            Self::ResourceCapacity => "resource_capacity",
            Self::SlotCapacity => "slot_capacity",
            Self::GenerationExhausted => "generation_exhausted",
            Self::ActiveDomain => "active_domain",
            Self::WrongCr3 => "wrong_cr3",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CancelError {
    StaleHandle,
    NotPrepared,
    ActiveDomain,
    WrongCr3,
    ReleaseFailed,
}

impl CancelError {
    pub(crate) const fn as_reason(self) -> &'static str {
        match self {
            Self::StaleHandle => "stale_handle",
            Self::NotPrepared => "not_prepared",
            Self::ActiveDomain => "active_domain",
            Self::WrongCr3 => "wrong_cr3",
            Self::ReleaseFailed => "release_failed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DomainIdentity {
    pub(crate) root: u64,
    pub(crate) probe: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReclaimStats {
    expected: u64,
    freed: u64,
}

impl ReclaimStats {
    const fn zero() -> Self {
        Self {
            expected: 0,
            freed: 0,
        }
    }

    const fn exactly_once(self) -> bool {
        self.expected > 0 && self.expected == self.freed
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DomainState {
    Prepared,
    Running,
    Blocked,
    Releasing,
    Reclaimed,
    ReleaseFailed,
}

impl DomainState {
    const fn is_live(self) -> bool {
        matches!(self, Self::Prepared | Self::Running | Self::Blocked)
    }
}

pub(super) struct Domain {
    pub(super) generation: u64,
    pub(super) state: DomainState,
    pub(super) scenario: Scenario,
    quota_ticks: u32,
    pub(super) space: Option<AddressSpace>,
    ipc_enabled: bool,
}

#[derive(Default)]
pub(super) struct Manager {
    slots: [Option<Domain>; SLOT_CAPACITY],
    used_frames: u64,
    last_identity: Option<DomainIdentity>,
}

pub(super) static MANAGER: Mutex<Manager> = Mutex::new(Manager {
    slots: [None, None],
    used_frames: 0,
    last_identity: None,
});

#[derive(Default)]
pub(super) struct Current {
    pub(super) active: AtomicBool,
    pub(super) slot: AtomicU64,
    pub(super) generation: AtomicU64,
    pub(super) root: AtomicU64,
    pub(super) root_flags: AtomicU64,
    pub(super) entered: AtomicBool,
    pub(super) ticks: AtomicU32,
    pub(super) quota: AtomicU32,
    pub(super) scenario: AtomicU64,
    pub(super) stack_end: AtomicU64,
}

pub(super) static CURRENT: Current = Current {
    active: AtomicBool::new(false),
    slot: AtomicU64::new(0),
    generation: AtomicU64::new(0),
    root: AtomicU64::new(0),
    root_flags: AtomicU64::new(0),
    entered: AtomicBool::new(false),
    ticks: AtomicU32::new(0),
    quota: AtomicU32::new(0),
    scenario: AtomicU64::new(0),
    stack_end: AtomicU64::new(0),
};

#[derive(Clone, Copy)]
struct TrapContext {
    slot: u64,
    generation: u64,
    vector: u8,
    error_code: u64,
    rip: u64,
    cs: u64,
    fault_address: u64,
    outcome: Outcome,
}

static TERMINAL_CONTEXT: Mutex<Option<TrapContext>> = Mutex::new(None);

/// The landed #1704 prefix is frozen through this exclusive append boundary.
const IPC_APPEND_OFFSET: u64 = 71;

static KERNEL_CR3: Once<(PhysFrame<Size4KiB>, Cr3Flags)> = Once::new();

static RESUME_STACK_END: AtomicU64 = AtomicU64::new(0);

pub(crate) fn init_kernel_cr3() {
    KERNEL_CR3.call_once(Cr3::read);
}

fn lifecycle_context_error(
    active: bool,
    current: Option<(PhysFrame<Size4KiB>, Cr3Flags)>,
    expected: Option<(PhysFrame<Size4KiB>, Cr3Flags)>,
) -> Option<PrepareError> {
    if active {
        return Some(PrepareError::ActiveDomain);
    }
    let Some(expected) = expected else {
        return Some(PrepareError::WrongCr3);
    };
    (current != Some(expected)).then_some(PrepareError::WrongCr3)
}

fn lifecycle_error() -> Option<PrepareError> {
    lifecycle_context_error(
        CURRENT.active.load(Ordering::SeqCst),
        Some(Cr3::read()),
        KERNEL_CR3.get().copied(),
    )
}

pub(crate) fn init_resume_stack() {
    RESUME_STACK_END.store(aligned_stack_end(), Ordering::SeqCst);
}

pub(super) fn resume_stack_end() -> usize {
    RESUME_STACK_END.load(Ordering::SeqCst) as usize
}

fn aligned_stack_end() -> u64 {
    current_stack_pointer() & !0xf
}

fn current_stack_pointer() -> u64 {
    let pointer;
    // SAFETY: reads the current stack pointer without changing it.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) pointer, options(nomem, preserves_flags));
    }
    pointer
}

fn guest_entry_state_ok(frame: &TrapFrame, scenario: u64) -> bool {
    let (fs, gs) = guest_segment_selectors();
    frame.rdi == scenario
        && [
            frame.rax, frame.rbx, frame.rcx, frame.rdx, frame.rsi, frame.rbp, frame.r8, frame.r9,
            frame.r10, frame.r11, frame.r12, frame.r13, frame.r14, frame.r15,
        ]
        .into_iter()
        .all(|value| value == 0)
        && fs == 0
        && gs == 0
}

fn guest_segment_selectors() -> (u64, u64) {
    let fs: u16;
    let gs: u16;
    // SAFETY: reads the FS/GS selectors without changing state.
    unsafe {
        core::arch::asm!(
            "mov {fs:x}, fs",
            "mov {gs:x}, gs",
            fs = out(reg) fs,
            gs = out(reg) gs,
            options(nomem, preserves_flags)
        );
    }
    (fs as u64, gs as u64)
}

pub(crate) fn kernel_cr3_restored() -> bool {
    KERNEL_CR3
        .get()
        .is_some_and(|expected| Cr3::read() == *expected)
}

pub(super) fn restore_kernel_cr3() {
    let Some((root, flags)) = KERNEL_CR3.get().copied() else {
        fail_terminal("kernel_cr3_missing");
    };
    // SAFETY: this is the kernel root recorded before entering a domain and
    // is restored only after the domain state has left the on-CPU context.
    unsafe { Cr3::write(root, flags) };
}

pub(super) fn kernel_cr3_value() -> u64 {
    let Some((root, flags)) = KERNEL_CR3.get().copied() else {
        fail_terminal("kernel_cr3_missing");
    };
    root.start_address().as_u64() | (flags.bits() & 0xfff)
}

pub(crate) fn prepare(
    raw: &[u8],
    expected_identity: ContentId,
    scenario: Scenario,
) -> Result<DomainHandle, PrepareError> {
    if let Some(error) = lifecycle_error() {
        return Err(error);
    }
    let image = ComponentImage::parse(raw).map_err(PrepareError::Bind)?;
    if image.identity() != expected_identity {
        return Err(PrepareError::Bind(BindError::HashMismatch));
    }
    let mut manager = MANAGER.lock();
    let slot = manager
        .slots
        .iter()
        .position(|slot| {
            slot.as_ref()
                .is_none_or(|domain| domain.state == DomainState::Reclaimed)
        })
        .ok_or(PrepareError::SlotCapacity)?;
    let generation = match manager.slots[slot].as_ref().map(|domain| domain.generation) {
        Some(previous) => previous
            .checked_add(1)
            .ok_or(PrepareError::GenerationExhausted)?,
        None => 1,
    };
    let probe = PEER_PROBE + slot as u64 * FRAME_SIZE;
    let space = AddressSpace::new(image, probe).map_err(PrepareError::Paging)?;
    let needed = space.required_frames();
    if manager.used_frames + needed > super::types::RESOURCE_CAPACITY as u64 {
        let mut space = space;
        space.discard();
        return Err(PrepareError::ResourceCapacity);
    }
    let audit_ok = space.audit();
    let stack_zeroed = space.stack_is_zeroed();
    let probe_zeroed = space.probe_is_zeroed();
    serial::ev_domain_policy(audit_ok, stack_zeroed, probe_zeroed);
    if !audit_ok || !stack_zeroed || !probe_zeroed {
        let mut space = space;
        space.discard();
        return Err(PrepareError::Paging(
            super::types::DomainPagingError::PolicyViolation,
        ));
    }
    manager.used_frames += needed;
    manager.slots[slot] = Some(Domain {
        generation,
        state: DomainState::Prepared,
        scenario,
        quota_ticks: image.quota_ticks(),
        space: Some(space),
        ipc_enabled: matches!(
            scenario,
            Scenario::IpcServer
                | Scenario::IpcClient
                | Scenario::IpcPeerFault
                | Scenario::IpcCancelServer
        ),
    });
    let handle = DomainHandle::new(
        super::types::DomainId(slot as u64),
        super::types::DomainGeneration(generation),
    );
    super::wait::prepare_ipc(handle.id().value(), handle.generation().value());
    serial::ev_domain_audit(needed, true, true, true);
    Ok(handle)
}

pub(crate) fn identity(handle: DomainHandle) -> Option<DomainIdentity> {
    let manager = MANAGER.lock();
    manager.valid_domain(handle).and_then(|domain| {
        let space = domain.space.as_ref()?;
        Some(DomainIdentity {
            root: space.root_phys(),
            probe: space.probe(),
        })
    })
}

pub(crate) fn last_identity() -> Option<DomainIdentity> {
    MANAGER.lock().last_identity
}

pub(crate) fn is_stale(handle: DomainHandle) -> bool {
    MANAGER.lock().valid_domain(handle).is_none()
}

pub(crate) fn generation(handle: DomainHandle) -> Option<u64> {
    MANAGER
        .lock()
        .valid_domain(handle)
        .map(|domain| domain.generation)
}

pub(crate) fn clean_domain_zeroed(handle: DomainHandle) -> bool {
    let manager = MANAGER.lock();
    manager.valid_domain(handle).is_some_and(|domain| {
        domain
            .space
            .as_ref()
            .is_some_and(|space| space.stack_is_zeroed() && space.probe_is_zeroed())
    })
}

pub(crate) fn outstanding_frames() -> u64 {
    MANAGER.lock().used_frames
}

pub(crate) fn peer_is_prepared(handle: DomainHandle) -> bool {
    let index = handle.id().0 as usize;
    MANAGER
        .lock()
        .slots
        .iter()
        .enumerate()
        .any(|(slot, domain)| {
            slot != index
                && domain
                    .as_ref()
                    .is_some_and(|domain| domain.state == DomainState::Prepared)
        })
}

pub(crate) fn start(handle: DomainHandle, scenario: Scenario) -> Result<(), PrepareError> {
    if let Some(error) = lifecycle_error() {
        return Err(error);
    }
    let context = {
        let mut manager = MANAGER.lock();
        let Some(domain) = manager.valid_domain_mut(handle) else {
            return Err(PrepareError::Bind(BindError::NotInstalled));
        };
        if domain.state != DomainState::Prepared || domain.scenario != scenario {
            return Err(PrepareError::Bind(BindError::Malformed));
        }
        let Some(space) = domain.space.as_ref() else {
            return Err(PrepareError::Paging(
                super::types::DomainPagingError::PolicyViolation,
            ));
        };
        if let Some(error) = lifecycle_error() {
            return Err(error);
        }
        let root = space.root_phys();
        let user_stack = space.user_stack_top();
        let quota = domain.quota_ticks;
        let source = space.source_root();
        if Cr3::read() != source {
            return Err(PrepareError::WrongCr3);
        }
        domain.state = DomainState::Running;
        (root, user_stack, quota, scenario)
    };
    let (root, user_end, quota, scenario) = context;
    gdt::set_privilege_stack(VirtAddr::new(KERNEL_STACK_TOP));
    apic::unmask_timer();
    let (_, source_flags) = Cr3::read();
    CURRENT.stack_end.store(user_end, Ordering::SeqCst);
    CURRENT.slot.store(handle.id().0, Ordering::SeqCst);
    CURRENT
        .generation
        .store(handle.generation().0, Ordering::SeqCst);
    CURRENT.ticks.store(0, Ordering::SeqCst);
    CURRENT.quota.store(quota, Ordering::SeqCst);
    CURRENT.scenario.store(scenario.value(), Ordering::SeqCst);
    CURRENT.root.store(root, Ordering::SeqCst);
    CURRENT
        .root_flags
        .store(source_flags.bits(), Ordering::SeqCst);
    CURRENT.entered.store(false, Ordering::SeqCst);
    CURRENT.active.store(true, Ordering::SeqCst);
    serial::ev_domain_started(handle.id().0 + 1, handle.generation().0, scenario.value());
    enter_user(root, user_end, scenario.value());
}

fn enter_user(root: u64, stack: u64, scenario: u64) -> ! {
    let (user_code, user_data) = gdt::user_selectors();
    let user_data = user_data.0 as u64;
    let user_code = user_code.0 as u64;
    // SAFETY: the address space was audited; the TSS has a real guarded RSP0;
    // the user selectors, entry, stack, and quota were validated by admission.
    // Guest GP inputs are explicit: RDI carries the scenario and every other
    // guest-visible GP register and FS/GS selector starts at zero. The entry
    // address is staged through R12 because RBX must be cleared after use.
    unsafe {
        core::arch::asm!(
            "mov rbx, {entry}",
            "mov r12, rbx",
            "mov cr3, rcx",
            "xor eax, eax",
            "xor ebx, ebx",
            "xor edx, edx",
            "xor esi, esi",
            "xor edi, edi",
            "mov edi, r8d",
            "xor ebp, ebp",
            "xor r13d, r13d",
            "xor r14d, r14d",
            "xor r15d, r15d",
            "xor ecx, ecx",
            "mov fs, cx",
            "mov gs, cx",
            "push r9",
            "push r10",
            "push 0x202",
            "push r11",
            "push r12",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            "xor r12d, r12d",
            "xor r8d, r8d",
            "iretq",
            in("rcx") root,
            in("r9") user_data,
            in("r10") stack,
            in("r11") user_code,
            entry = in(reg) CODE_BASE + ENTRYPOINT,
            in("r8") scenario,
            options(noreturn)
        );
    }
}

pub(super) extern "C" fn scheduler_resume() -> ! {
    let stack_end = resume_stack_end();
    // SAFETY: the terminal trap has returned here on the guarded transition
    // stack; no domain frame remains live below this point. Move to the
    // kernel-owned resume stack before re-entering the scheduler.
    unsafe {
        core::arch::asm!(
            "mov rsp, {stack_end}",
            "xor ebp, ebp",
            "call {scheduler}",
            scheduler = sym super::harness::scheduler,
            stack_end = in(reg) stack_end,
            options(noreturn)
        );
    }
}

pub(super) fn fail_terminal(reason: &'static str) -> ! {
    serial::ev_domain_trap_reject(reason);
    serial::ev_domain_harness(false);
    serial::ev_halt(false);
    serial::exit_qemu(false);
}

pub(crate) fn handle_domain_trap(frame: &mut TrapFrame, fault_address: u64) -> bool {
    if !CURRENT.active.load(Ordering::SeqCst) || frame.cs & 3 != 3 {
        return false;
    }
    let expected_root = CURRENT.root.load(Ordering::SeqCst);
    let expected_flags = CURRENT.root_flags.load(Ordering::SeqCst);
    let (current_root, current_flags) = Cr3::read();
    if current_root.start_address().as_u64() != expected_root
        || current_flags.bits() != expected_flags
    {
        serial::ev_domain_trap_reject("cr3_mismatch");
        serial::ev_domain_harness(false);
        serial::ev_halt(false);
        serial::exit_qemu(false);
    }
    if !CURRENT.entered.swap(true, Ordering::SeqCst) {
        let (context_root, context_flags) = Cr3::read();
        let (fs, gs) = guest_segment_selectors();
        let entry_state_ok = guest_entry_state_ok(frame, CURRENT.scenario.load(Ordering::SeqCst));
        serial::ev_domain_entered(
            CURRENT.slot.load(Ordering::SeqCst) + 1,
            CURRENT.generation.load(Ordering::SeqCst),
            frame.cs & 3,
        );
        serial::ev_domain_context(
            CURRENT.slot.load(Ordering::SeqCst) + 1,
            CURRENT.generation.load(Ordering::SeqCst),
            context_root.start_address().as_u64(),
            context_flags.bits(),
            frame.cs & 3,
            fs,
            gs,
        );
        super::harness::record_entry(frame.cs & 3, entry_state_ok);
    }
    let vector = frame.vector as u8;
    if vector == crate::ipc::VECTOR {
        let handle = super::wait::current_handle();
        let Some(domain_token) = super::wait::ipc_domain_token(handle) else {
            fail_terminal("invalid_ipc_domain");
        };
        match ipc::handle_call(frame, domain_token) {
            ipc::SyscallOutcome::Done(status, aux) => {
                frame.rax = status;
                frame.rdx = aux;
                return true;
            },
            ipc::SyscallOutcome::Block(reason) => {
                let status = match reason {
                    ipc::BlockReason::SendReady => super::wait::BlockStatus::Sent,
                    ipc::BlockReason::RecvEmpty => super::wait::BlockStatus::Received,
                };
                super::wait::park_current(frame, status);
            },
        }
    }
    if vector == 14 {
        super::harness::record_fault(fault_address);
    }
    let scenario = CURRENT.scenario.load(Ordering::SeqCst);
    if vector == apic::TIMER_VECTOR && scenario >= Scenario::IpcServer.value() {
        // The landed #1704 dispatch is byte-frozen and has no path for the
        // new scenarios. Timer preemption is the one transition to the
        // appended private-IPC entry that scenarios 0-5 never take.
        apic::eoi();
        frame.rip = CODE_BASE + IPC_APPEND_OFFSET;
        return true;
    }
    let quota = CURRENT.quota.load(Ordering::SeqCst);
    let ipc_scenario = scenario >= Scenario::IpcServer.value();
    let ipc_terminal = vector == 3 && ipc_scenario;
    let outcome = if ipc_terminal {
        Outcome::CleanExit
    } else if vector == 14 && ipc_scenario {
        Outcome::PageFault
    } else if frame.rdi != scenario {
        Outcome::UnexpectedFault
    } else {
        match vector {
            3 => Outcome::CleanExit,
            6 if frame.cs & 3 == 3 => Outcome::InvalidInstruction,
            14 => Outcome::PageFault,
            32 => {
                let ticks = CURRENT.ticks.fetch_add(1, Ordering::SeqCst) + 1;
                if ticks < quota {
                    apic::eoi();
                    return true;
                }
                apic::mask_timer();
                apic::eoi();
                serial::ev_domain_quota(CURRENT.slot.load(Ordering::SeqCst) + 1, ticks);
                Outcome::QuotaExhausted
            },
            _ => Outcome::UnexpectedFault,
        }
    };
    serial::ev_domain_registers(
        CURRENT.slot.load(Ordering::SeqCst) + 1,
        CURRENT.generation.load(Ordering::SeqCst),
        frame.cs & 3,
        frame.rdi,
        frame.rsp,
        frame.rax,
        frame.rbx,
        frame.rcx,
        frame.rdx,
        frame.rsi,
        frame.rbp,
        frame.r8,
        frame.r9,
        frame.r10,
        frame.r11,
        frame.r12,
        frame.r13,
        frame.r14,
        frame.r15,
    );
    let context = TrapContext {
        slot: CURRENT.slot.load(Ordering::SeqCst),
        generation: CURRENT.generation.load(Ordering::SeqCst),
        vector: frame.vector as u8,
        error_code: frame.error_code,
        rip: frame.rip,
        cs: frame.cs,
        fault_address,
        outcome,
    };
    *TERMINAL_CONTEXT.lock() = Some(context);
    switch_to_resume(resume_stack_end());
}

#[unsafe(naked)]
pub(super) extern "C" fn switch_to_resume(stack_end: usize) -> ! {
    core::arch::naked_asm!(
        "mov rsp, rdi",
        "xor ebp, ebp",
        "call {terminal}",
        "ud2",
        terminal = sym domain_terminal,
    );
}

extern "C" fn domain_terminal() -> ! {
    let mut terminal = TERMINAL_CONTEXT.lock();
    let Some(context) = terminal.as_ref().copied() else {
        serial::ev_domain_harness(false);
        serial::ev_halt(false);
        serial::exit_qemu(false);
    };
    let handle = DomainHandle::new(
        super::types::DomainId(context.slot),
        super::types::DomainGeneration(context.generation),
    );
    let stats = MANAGER.lock().terminate(handle, context.outcome, &context);
    CURRENT.active.store(false, Ordering::SeqCst);
    CURRENT.root.store(0, Ordering::SeqCst);
    CURRENT.root_flags.store(0, Ordering::SeqCst);
    if !stats.exactly_once() {
        serial::ev_domain_harness(false);
        serial::ev_halt(false);
        serial::exit_qemu(false);
    }
    *terminal = None;
    drop(terminal);
    super::harness::record_outcome(context.outcome, stats.exactly_once());
    let (kernel_code, kernel_data) = gdt::kernel_selectors();
    let return_stack = resume_stack_end();
    let rip = scheduler_resume as *const () as usize as u64;
    let cs = kernel_code.0 as u64;
    let rflags = 0x002u64;
    let rsp = return_stack as u64;
    let ss = kernel_data.0 as u64;
    // SAFETY: terminal teardown has restored the kernel CR3. All return
    // values are held in registers while moving to the kernel resume stack.
    unsafe {
        core::arch::asm!(
            "mov rsp, {return_stack}",
            "push {ss}",
            "push {rsp}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            return_stack = in(reg) return_stack,
            ss = in(reg) ss,
            rsp = in(reg) rsp,
            rflags = in(reg) rflags,
            cs = in(reg) cs,
            rip = in(reg) rip,
            options(noreturn)
        );
    }
}

pub(crate) fn cancel(handle: DomainHandle) -> Result<(u64, u64), CancelError> {
    MANAGER.lock().cancel_prepared(handle)
}

pub(crate) fn active_lifecycle_guard_rejects(
    handle: DomainHandle,
    scenario: Scenario,
    raw: &[u8],
    expected: ContentId,
) -> bool {
    let frames = outstanding_frames();
    CURRENT.active.store(true, Ordering::SeqCst);
    let prepare_rejected = matches!(
        prepare(raw, expected, scenario),
        Err(PrepareError::ActiveDomain)
    );
    let start_rejected = matches!(start(handle, scenario), Err(PrepareError::ActiveDomain));
    let cancel_rejected = matches!(cancel(handle), Err(CancelError::ActiveDomain));
    CURRENT.active.store(false, Ordering::SeqCst);
    prepare_rejected
        && start_rejected
        && cancel_rejected
        && outstanding_frames() == frames
        && !is_stale(handle)
}

pub(crate) fn generation_overflow_rejects_prepare(raw: &[u8], expected: ContentId) -> bool {
    let frames = outstanding_frames();
    {
        let mut manager = MANAGER.lock();
        if manager.slots[0].is_some() {
            return false;
        }
        manager.slots[0] = Some(Domain {
            generation: u64::MAX,
            state: DomainState::Reclaimed,
            scenario: Scenario::Exit,
            quota_ticks: 0,
            space: None,
            ipc_enabled: false,
        });
    }
    let rejected = matches!(
        prepare(raw, expected, Scenario::Exit),
        Err(PrepareError::GenerationExhausted)
    );
    let mut manager = MANAGER.lock();
    let unchanged = manager.slots[0].as_ref().is_some_and(|domain| {
        domain.generation == u64::MAX && domain.state == DomainState::Reclaimed
    });
    manager.slots[0] = None;
    rejected && unchanged && manager.used_frames == frames
}

impl Manager {
    pub(super) fn valid_domain(&self, handle: DomainHandle) -> Option<&Domain> {
        let slot = self.slots.get(handle.id().0 as usize)?;
        let domain = slot.as_ref()?;
        (domain.generation == handle.generation().0 && domain.state.is_live()).then_some(domain)
    }

    pub(super) fn valid_domain_mut(&mut self, handle: DomainHandle) -> Option<&mut Domain> {
        let slot = self.slots.get_mut(handle.id().0 as usize)?;
        let domain = slot.as_mut()?;
        (domain.generation == handle.generation().0 && domain.state.is_live()).then_some(domain)
    }

    fn release_slot(&mut self, handle: DomainHandle) -> ReclaimStats {
        let Some(slot) = self.slots.get_mut(handle.id().0 as usize) else {
            return ReclaimStats::zero();
        };
        let Some(domain) = slot.as_mut() else {
            return ReclaimStats::zero();
        };
        if domain.generation != handle.generation().0 || !domain.state.is_live() {
            return ReclaimStats::zero();
        }

        let generation = domain.generation;
        let identity = domain.space.as_ref().map(|space| DomainIdentity {
            root: space.root_phys(),
            probe: space.probe(),
        });
        self.last_identity = identity;
        if domain.ipc_enabled {
            let ipc_outcome = super::wait::release_ipc(handle.id().value(), generation);
            serial::ev_ipc_reclaim(
                handle.id().value() + 1,
                generation,
                ipc_outcome.endpoints as u64,
                ipc_outcome.capabilities as u64,
                ipc_outcome.queued_messages as u64,
            );
            for wake in ipc_outcome.waiters.into_iter().flatten() {
                let Some(wake_handle) = super::wait::domain_handle_token(wake) else {
                    fail_terminal("invalid_ipc_wake");
                };
                super::wait::mark_ipc_peer_failed(wake_handle);
            }
        }
        domain.state = DomainState::Releasing;
        let Some(space) = domain.space.as_mut() else {
            domain.state = DomainState::ReleaseFailed;
            return ReclaimStats::zero();
        };
        let status = space.release(DomainId(handle.id().0), DomainGeneration(generation));
        let (expected, freed) = match status {
            super::paging::ReleaseStatus::Released(expected, freed) => (expected, freed),
            super::paging::ReleaseStatus::RestoreFailed => {
                domain.state = DomainState::ReleaseFailed;
                return ReclaimStats::zero();
            },
            super::paging::ReleaseStatus::ReclaimBlocked(expected, freed) => {
                domain.state = DomainState::ReleaseFailed;
                (expected, freed)
            },
        };
        let Some(domain) = slot.as_mut() else {
            return ReclaimStats { expected, freed };
        };
        if expected > 0 && expected == freed {
            domain.state = DomainState::Reclaimed;
            self.used_frames = self.used_frames.saturating_sub(expected);
            serial::ev_domain_reclaimed(
                handle.id().0 + 1,
                domain.generation,
                expected,
                freed,
                freed,
                expected - freed,
            );
            ReclaimStats { expected, freed }
        } else {
            ReclaimStats { expected, freed }
        }
    }

    fn terminate(
        &mut self,
        handle: DomainHandle,
        outcome: Outcome,
        event: &TrapContext,
    ) -> ReclaimStats {
        serial::ev_domain_outcome(
            serial::DomainEventIdentity::new(event.slot + 1, event.generation),
            outcome.name(),
            event.vector,
            event.error_code,
            event.fault_address,
            event.rip,
            event.cs & 3,
        );
        self.release_slot(handle)
    }

    fn cancel_prepared(&mut self, handle: DomainHandle) -> Result<(u64, u64), CancelError> {
        if CURRENT.active.load(Ordering::SeqCst) {
            return Err(CancelError::ActiveDomain);
        }
        let Some(domain) = self.valid_domain(handle) else {
            serial::ev_domain_cancel_rejected(
                handle.id().0 + 1,
                handle.generation().0,
                CancelError::StaleHandle.as_reason(),
            );
            return Err(CancelError::StaleHandle);
        };
        if domain.state == DomainState::Running {
            return Err(CancelError::ActiveDomain);
        }
        if domain.state != DomainState::Prepared && domain.state != DomainState::Blocked {
            serial::ev_domain_cancel_rejected(
                handle.id().0 + 1,
                domain.generation,
                CancelError::NotPrepared.as_reason(),
            );
            return Err(CancelError::NotPrepared);
        }
        let Some(space) = domain.space.as_ref() else {
            return Err(CancelError::NotPrepared);
        };
        let source = space.source_root();
        if KERNEL_CR3.get().is_none_or(|expected| *expected != source) || Cr3::read() != source {
            return Err(CancelError::WrongCr3);
        }
        let generation = domain.generation;
        let blocked = domain.state == DomainState::Blocked;
        serial::ev_domain_cancel_request(handle.id().0 + 1, generation);
        if blocked {
            serial::ev_ipc_wake(handle.id().0 + 1, generation, "cancelled");
            super::wait::mark_ipc_ready(handle, super::wait::BlockStatus::Cancelled);
        }
        let stats = self.release_slot(handle);
        if stats.exactly_once() {
            serial::ev_domain_cancelled(handle.id().0 + 1, generation);
            serial::ev_domain_outcome(
                serial::DomainEventIdentity::new(handle.id().0 + 1, generation),
                Outcome::Cancelled.name(),
                0,
                0,
                0,
                0,
                0,
            );
            Ok((stats.expected, stats.freed))
        } else {
            Err(CancelError::ReleaseFailed)
        }
    }
}
