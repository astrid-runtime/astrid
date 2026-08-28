//! Typed domain admission, execution, fault containment, and reclamation.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use spin::Mutex;
use x86_64::VirtAddr;

use astrid_system_generation::ContentId;

use super::paging::AddressSpace;
use super::types::{
    BindError, CODE_BASE, ComponentImage, DomainHandle, DomainPagingError, ENTRYPOINT,
    KERNEL_STACK_TOP, Outcome, PEER_PROBE, SLOT_CAPACITY, Scenario,
};
use crate::apic;
use crate::gdt;
use crate::memory::FRAME_SIZE;
use crate::serial;
use crate::trap::TrapFrame;
use x86_64::registers::control::Cr3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrepareError {
    Bind(BindError),
    Paging(DomainPagingError),
    ResourceCapacity,
    SlotCapacity,
    GenerationExhausted,
}

impl PrepareError {
    pub(crate) const fn as_reason(self) -> &'static str {
        match self {
            Self::Bind(error) => error.as_reason(),
            Self::Paging(error) => error.as_reason(),
            Self::ResourceCapacity => "resource_capacity",
            Self::SlotCapacity => "slot_capacity",
            Self::GenerationExhausted => "generation_exhausted",
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
    const fn exactly_once(self) -> bool {
        self.expected > 0 && self.expected == self.freed
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DomainState {
    Prepared,
    Running,
    Dying,
    Reclaimed,
}

struct Domain {
    generation: u64,
    state: DomainState,
    scenario: Scenario,
    quota_ticks: u32,
    space: Option<AddressSpace>,
}

#[derive(Default)]
struct Manager {
    slots: [Option<Domain>; SLOT_CAPACITY],
    used_frames: u64,
    last_identity: Option<DomainIdentity>,
}

static MANAGER: Mutex<Manager> = Mutex::new(Manager {
    slots: [None, None],
    used_frames: 0,
    last_identity: None,
});

#[derive(Default)]
struct Current {
    active: AtomicBool,
    slot: AtomicU64,
    generation: AtomicU64,
    entered: AtomicBool,
    ticks: AtomicU32,
    quota: AtomicU32,
    scenario: AtomicU64,
    stack_end: AtomicU64,
}

static CURRENT: Current = Current {
    active: AtomicBool::new(false),
    slot: AtomicU64::new(0),
    generation: AtomicU64::new(0),
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

static RESUME_STACK_END: AtomicU64 = AtomicU64::new(0);

pub(crate) fn init_resume_stack() {
    RESUME_STACK_END.store(aligned_stack_end(), Ordering::SeqCst);
}

fn resume_stack_end() -> usize {
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

pub(crate) fn prepare(
    raw: &[u8],
    expected_identity: ContentId,
    scenario: Scenario,
) -> Result<DomainHandle, PrepareError> {
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
    let probe = PEER_PROBE + slot as u64 * FRAME_SIZE;
    let space = AddressSpace::new(image, probe).map_err(PrepareError::Paging)?;
    let needed = space.required_frames();
    if manager.used_frames + needed > super::types::RESOURCE_CAPACITY as u64 {
        let mut space = space;
        space.release();
        return Err(PrepareError::ResourceCapacity);
    }
    let audit_ok = space.audit();
    let stack_zeroed = space.stack_is_zeroed();
    let probe_zeroed = space.probe_is_zeroed();
    serial::ev_domain_policy(audit_ok, stack_zeroed, probe_zeroed);
    if !audit_ok || !stack_zeroed || !probe_zeroed {
        let mut space = space;
        space.release();
        return Err(PrepareError::Paging(
            super::types::DomainPagingError::PolicyViolation,
        ));
    }
    let generation = match manager.slots[slot].as_ref() {
        Some(previous) => previous
            .generation
            .checked_add(1)
            .ok_or(PrepareError::GenerationExhausted)?,
        None => 1,
    };
    manager.used_frames += needed;
    manager.slots[slot] = Some(Domain {
        generation,
        state: DomainState::Prepared,
        scenario,
        quota_ticks: image.quota_ticks(),
        space: Some(space),
    });
    serial::ev_domain_audit(needed, true, true, true);
    Ok(DomainHandle::new(
        super::types::DomainId(slot as u64),
        super::types::DomainGeneration(generation),
    ))
}

pub(crate) fn identity(handle: DomainHandle) -> Option<DomainIdentity> {
    let manager = MANAGER.lock();
    manager.valid_domain(handle).map(|domain| {
        let space = domain
            .space
            .as_ref()
            .expect("prepared domain has an address space");
        DomainIdentity {
            root: space.root_phys(),
            probe: space.probe(),
        }
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
    let plan = {
        let mut manager = MANAGER.lock();
        let Some(domain) = manager.valid_domain_mut(handle) else {
            return Err(PrepareError::Bind(BindError::NotInstalled));
        };
        if domain.state != DomainState::Prepared || domain.scenario != scenario {
            return Err(PrepareError::Bind(BindError::Malformed));
        }
        let space = domain
            .space
            .as_ref()
            .expect("prepared domain has an address space");
        let root = space.root_phys();
        let user_stack = space.user_stack_top();
        domain.state = DomainState::Running;
        (root, user_stack, domain.quota_ticks, scenario)
    };
    let (root, user_end, quota, scenario) = plan;
    gdt::set_privilege_stack(VirtAddr::new(KERNEL_STACK_TOP));
    apic::unmask_timer();
    CURRENT.stack_end.store(user_end, Ordering::SeqCst);
    CURRENT.slot.store(handle.id().0, Ordering::SeqCst);
    CURRENT
        .generation
        .store(handle.generation().0, Ordering::SeqCst);
    CURRENT.ticks.store(0, Ordering::SeqCst);
    CURRENT.quota.store(quota, Ordering::SeqCst);
    CURRENT.scenario.store(scenario.value(), Ordering::SeqCst);
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
    unsafe {
        core::arch::asm!(
            "mov cr3, {root}",
            "mov rdi, {scenario}",
            "push {user_data}",
            "push {user_stack}",
            "push {rflags}",
            "push {user_code}",
            "push {entry}",
            "iretq",
            root = in(reg) root,
            user_data = in(reg) user_data,
            user_stack = in(reg) stack,
            rflags = in(reg) 0x202u64,
            user_code = in(reg) user_code,
            entry = in(reg) CODE_BASE + ENTRYPOINT,
            scenario = in(reg) scenario,
            options(noreturn)
        );
    }
}

extern "C" fn scheduler_resume() -> ! {
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

pub(crate) fn handle_domain_trap(frame: &mut TrapFrame, fault_address: u64) -> bool {
    if !CURRENT.active.load(Ordering::SeqCst) || frame.cs & 3 != 3 {
        return false;
    }
    if !CURRENT.entered.swap(true, Ordering::SeqCst) {
        serial::ev_domain_entered(
            CURRENT.slot.load(Ordering::SeqCst) + 1,
            CURRENT.generation.load(Ordering::SeqCst),
            frame.cs & 3,
        );
        super::harness::record_entry(frame.cs & 3);
    }
    let vector = frame.vector as u8;
    if vector == 14 {
        super::harness::record_fault(fault_address);
    }
    let quota = CURRENT.quota.load(Ordering::SeqCst);
    let scenario = CURRENT.scenario.load(Ordering::SeqCst);
    let outcome = if frame.rdi != scenario {
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
extern "C" fn switch_to_resume(stack_end: usize) -> ! {
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

pub(crate) fn cancel(handle: DomainHandle) -> (u64, u64) {
    MANAGER.lock().cancel_prepared(handle)
}

impl Manager {
    fn valid_domain(&self, handle: DomainHandle) -> Option<&Domain> {
        let slot = self.slots.get(handle.id().0 as usize)?;
        let domain = slot.as_ref()?;
        (domain.generation == handle.generation().0 && domain.state != DomainState::Reclaimed)
            .then_some(domain)
    }

    fn valid_domain_mut(&mut self, handle: DomainHandle) -> Option<&mut Domain> {
        let slot = self.slots.get_mut(handle.id().0 as usize)?;
        let domain = slot.as_mut()?;
        (domain.generation == handle.generation().0 && domain.state != DomainState::Reclaimed)
            .then_some(domain)
    }

    fn release_slot(&mut self, handle: DomainHandle) -> ReclaimStats {
        let Some(slot) = self.slots.get_mut(handle.id().0 as usize) else {
            return ReclaimStats {
                expected: 0,
                freed: 0,
            };
        };
        let Some(domain) = slot.as_mut() else {
            return ReclaimStats {
                expected: 0,
                freed: 0,
            };
        };
        if !matches!(domain.state, DomainState::Prepared | DomainState::Running) {
            return ReclaimStats {
                expected: 0,
                freed: 0,
            };
        }
        domain.state = DomainState::Dying;
        let identity = domain.space.as_ref().map(|space| DomainIdentity {
            root: space.root_phys(),
            probe: space.probe(),
        });
        self.last_identity = identity;
        let Some(mut space) = domain.space.take() else {
            domain.state = DomainState::Reclaimed;
            return ReclaimStats {
                expected: 0,
                freed: 0,
            };
        };
        let (expected, freed) = space.release();
        let restored = Cr3::read() == space.source_root();
        serial::ev_domain_restore(restored);
        let Some(domain) = slot.as_mut() else {
            unreachable!("the dying domain remains in its slot");
        };
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
    }

    fn terminate(
        &mut self,
        handle: DomainHandle,
        outcome: Outcome,
        event: &TrapContext,
    ) -> ReclaimStats {
        serial::ev_domain_outcome(
            outcome.name(),
            event.vector,
            event.error_code,
            event.fault_address,
            event.rip,
            event.cs & 3,
        );
        self.release_slot(handle)
    }

    fn cancel_prepared(&mut self, handle: DomainHandle) -> (u64, u64) {
        if let Some(domain) = self.valid_domain(handle) {
            serial::ev_domain_cancelled(handle.id().0 + 1, domain.generation);
        }
        serial::ev_domain_outcome(Outcome::Cancelled.name(), 0, 0, 0, 0, 0);
        let stats = self.release_slot(handle);
        (stats.expected, stats.freed)
    }
}
