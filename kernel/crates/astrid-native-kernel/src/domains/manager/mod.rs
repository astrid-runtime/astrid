//! Typed domain admission, execution, fault containment, and reclamation.

use core::sync::atomic::Ordering;

#[cfg(not(test))]
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};

use spin::Mutex;
#[cfg(not(test))]
use spin::Once;
#[cfg(not(test))]
use x86_64::registers::control::{Cr3, Cr3Flags};
#[cfg(not(test))]
use x86_64::structures::paging::{PhysFrame, Size4KiB};

pub(in crate::domains) use self::control::DomainControl;
#[cfg(not(test))]
use super::paging::AddressSpace;
use super::stop::{DomainStop, HostManifestIdentity};
use super::types::{
    BindError, DomainGeneration, DomainHandle, DomainId, DomainPagingError, Outcome, SLOT_CAPACITY,
    Scenario,
};
#[cfg(not(test))]
use super::types::{ComponentImage, PEER_PROBE};
use crate::ipc;
#[cfg(not(test))]
use crate::memory::FRAME_SIZE;
#[cfg(not(test))]
use crate::serial;
use astrid_system_generation::ContentId;

#[cfg(test)]
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepareError {
    Bind(BindError),
    Paging(DomainPagingError),
    ResourceCapacity,
    SlotCapacity,
    GenerationExhausted,
    ActiveDomain,
    WrongCr3,
}

impl PrepareError {
    pub const fn as_reason(self) -> &'static str {
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
pub enum CancelError {
    StaleHandle,
    NotPrepared,
    ActiveDomain,
    WrongCr3,
    ReleaseFailed,
}

impl CancelError {
    pub const fn as_reason(self) -> &'static str {
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
pub struct DomainIdentity {
    pub root: u64,
    pub probe: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReclaimStats {
    expected: u64,
    freed: u64,
    release_complete: bool,
}

impl ReclaimStats {
    const fn zero() -> Self {
        Self {
            expected: 0,
            freed: 0,
            release_complete: false,
        }
    }

    const fn exactly_once(self) -> bool {
        self.expected > 0 && self.expected == self.freed && self.release_complete
    }

    const fn from_parts(
        expected: u64,
        freed: u64,
        stop_requested: bool,
        relation_released: bool,
    ) -> Self {
        Self {
            expected,
            freed,
            release_complete: !stop_requested || relation_released,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainState {
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

pub struct Domain {
    pub generation: u64,
    pub state: DomainState,
    pub scenario: Scenario,
    pub(super) quota_ticks: u32,
    #[cfg(not(test))]
    pub(super) space: Option<AddressSpace>,
    #[cfg(test)]
    pub(super) space: Option<()>,
    pub(super) ipc_enabled: bool,
    pub(super) stop: DomainStop,
    pub(super) control: DomainControl,
}

#[derive(Default)]
pub struct Manager {
    pub(super) slots: [Option<Domain>; SLOT_CAPACITY],
    used_frames: u64,
    last_identity: Option<DomainIdentity>,
}

#[cfg(test)]
static RELATION_RELEASE_FAILURE: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static SPACE_RELEASE_FAILURE: AtomicU8 = AtomicU8::new(0);
#[cfg(test)]
static ADMISSION_RELEASES: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpaceRelease {
    Released(u64, u64),
    MissingSpace,
    RestoreFailed,
    ReclaimBlocked(u64, u64),
}

#[cfg(not(test))]
fn release_space(
    space: &mut AddressSpace,
    id: DomainId,
    generation: DomainGeneration,
) -> SpaceRelease {
    match space.release(id, generation) {
        super::paging::ReleaseStatus::Released(expected, freed) => {
            SpaceRelease::Released(expected, freed)
        },
        super::paging::ReleaseStatus::RestoreFailed => SpaceRelease::RestoreFailed,
        super::paging::ReleaseStatus::ReclaimBlocked(expected, freed) => {
            SpaceRelease::ReclaimBlocked(expected, freed)
        },
    }
}

#[cfg(test)]
fn release_space(_space: &mut (), _id: DomainId, _generation: DomainGeneration) -> SpaceRelease {
    match SPACE_RELEASE_FAILURE.load(Ordering::SeqCst) {
        1 => SpaceRelease::RestoreFailed,
        2 => SpaceRelease::ReclaimBlocked(3, 2),
        _ => SpaceRelease::Released(3, 3),
    }
}

#[cfg(test)]
fn release_ipc_for_release(slot: u64, generation: u64) -> ipc::TeardownOutcome {
    let mut outcome = super::wait::release_ipc(slot, generation);
    if RELATION_RELEASE_FAILURE.load(Ordering::SeqCst) {
        outcome.relation_released = false;
    }
    outcome
}

#[cfg(not(test))]
fn release_ipc_for_release(slot: u64, generation: u64) -> ipc::TeardownOutcome {
    super::wait::release_ipc(slot, generation)
}

#[cfg(not(test))]
fn space_identity(space: &AddressSpace) -> Option<DomainIdentity> {
    Some(DomainIdentity {
        root: space.root_phys(),
        probe: space.probe(),
    })
}

#[cfg(test)]
fn space_identity(_space: &()) -> Option<DomainIdentity> {
    None
}

pub static MANAGER: Mutex<Manager> = Mutex::new(Manager {
    slots: [None, None],
    used_frames: 0,
    last_identity: None,
});

#[cfg(not(test))]
#[derive(Default)]
pub struct Current {
    pub active: AtomicBool,
    pub slot: AtomicU64,
    pub generation: AtomicU64,
    pub root: AtomicU64,
    pub root_flags: AtomicU64,
    pub entered: AtomicBool,
    pub ticks: AtomicU32,
    pub quota: AtomicU32,
    pub scenario: AtomicU64,
    pub stack_end: AtomicU64,
}

#[cfg(not(test))]
pub static CURRENT: Current = Current {
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
pub(super) struct TrapContext {
    slot: u64,
    generation: u64,
    vector: u8,
    error_code: u64,
    rip: u64,
    cs: u64,
    fault_address: u64,
    outcome: Outcome,
}

#[cfg(not(test))]
pub(super) static TERMINAL_CONTEXT: Mutex<Option<TrapContext>> = Mutex::new(None);

/// The landed #1704 prefix is frozen through this exclusive append boundary.
const IPC_APPEND_OFFSET: u64 = 71;
/// Scenario 10 resumes at the end of the unchanged #1704 code prefix.
const IPC_CANCEL_GUEST_APPEND_OFFSET: u64 = 415;

#[cfg(not(test))]
static KERNEL_CR3: Once<(PhysFrame<Size4KiB>, Cr3Flags)> = Once::new();

#[cfg(not(test))]
static RESUME_STACK_END: AtomicU64 = AtomicU64::new(0);

#[cfg(not(test))]
pub fn init_kernel_cr3() {
    KERNEL_CR3.call_once(Cr3::read);
}

#[cfg(not(test))]
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

#[cfg(not(test))]
fn lifecycle_error() -> Option<PrepareError> {
    lifecycle_context_error(
        CURRENT.active.load(Ordering::SeqCst),
        Some(Cr3::read()),
        KERNEL_CR3.get().copied(),
    )
}

#[cfg(not(test))]
pub fn init_resume_stack() {
    RESUME_STACK_END.store(aligned_stack_end(), Ordering::SeqCst);
}

#[cfg(not(test))]
pub fn resume_stack_end() -> usize {
    RESUME_STACK_END.load(Ordering::SeqCst) as usize
}

#[cfg(not(test))]
fn aligned_stack_end() -> u64 {
    current_stack_pointer() & !0xf
}

#[cfg(not(test))]
fn current_stack_pointer() -> u64 {
    let pointer;
    // SAFETY: reads the current stack pointer without changing it.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) pointer, options(nomem, preserves_flags));
    }
    pointer
}

#[cfg(not(test))]
pub fn kernel_cr3_restored() -> bool {
    KERNEL_CR3
        .get()
        .is_some_and(|expected| Cr3::read() == *expected)
}

#[cfg(not(test))]
pub fn kernel_cr3_value() -> u64 {
    let Some((root, flags)) = KERNEL_CR3.get().copied() else {
        fail_terminal("kernel_cr3_missing");
    };
    root.start_address().as_u64() | (flags.bits() & 0xfff)
}

#[cfg(not(test))]
pub fn prepare(
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
        .position(|slot| Manager::slot_is_preparable(slot.as_ref()))
        .ok_or(PrepareError::SlotCapacity)?;
    let generation = match manager.slots[slot].as_ref().map(|domain| domain.generation) {
        Some(previous) => previous
            .checked_add(1)
            .ok_or(PrepareError::GenerationExhausted)?,
        None => 1,
    };
    readiness::clear_slot(super::types::DomainId(slot as u64));
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
                | Scenario::IpcCancelGuest
        ),
        stop: DomainStop::inactive(),
        control: DomainControl::inactive(),
    });
    let handle = DomainHandle::new(
        super::types::DomainId(slot as u64),
        super::types::DomainGeneration(generation),
    );
    super::wait::prepare_ipc(handle.id().value(), handle.generation().value());
    serial::ev_domain_audit(needed, true, true, true);
    Ok(handle)
}

#[cfg(not(test))]
pub fn identity(handle: DomainHandle) -> Option<DomainIdentity> {
    let manager = MANAGER.lock();
    manager.valid_domain(handle).and_then(|domain| {
        let space = domain.space.as_ref()?;
        Some(DomainIdentity {
            root: space.root_phys(),
            probe: space.probe(),
        })
    })
}

#[cfg(not(test))]
pub fn last_identity() -> Option<DomainIdentity> {
    MANAGER.lock().last_identity
}

pub fn is_stale(handle: DomainHandle) -> bool {
    MANAGER.lock().valid_domain(handle).is_none()
}

pub fn generation(handle: DomainHandle) -> Option<u64> {
    MANAGER
        .lock()
        .valid_domain(handle)
        .map(|domain| domain.generation)
}

#[cfg(not(test))]
pub fn clean_domain_zeroed(handle: DomainHandle) -> bool {
    let manager = MANAGER.lock();
    manager.valid_domain(handle).is_some_and(|domain| {
        domain
            .space
            .as_ref()
            .is_some_and(|space| space.stack_is_zeroed() && space.probe_is_zeroed())
    })
}

#[cfg(not(test))]
pub fn outstanding_frames() -> u64 {
    MANAGER.lock().used_frames
}

pub fn peer_is_prepared(handle: DomainHandle) -> bool {
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

mod control;
mod readiness;
#[cfg(test)]
mod readiness_tests;
mod start;
#[cfg(test)]
mod stop_tests;
#[cfg(not(test))]
mod trap;

#[cfg(not(test))]
pub use trap::handle_domain_trap;

#[cfg(not(test))]
pub(in crate::domains) use control::{
    request_returned_stop, stage_returning_trap, switch_to_return,
};
pub(super) use start::StartContext;
#[cfg(not(test))]
pub(super) use start::{enter_running, stage_context, staged_state, start_running};

#[cfg(not(test))]
pub extern "C" fn scheduler_resume() -> ! {
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

#[cfg(not(test))]
pub fn fail_terminal(reason: &'static str) -> ! {
    serial::ev_domain_trap_reject(reason);
    serial::ev_domain_harness(false);
    serial::ev_halt(false);
    serial::exit_qemu(false);
}

#[cfg(not(test))]
pub fn cancel(handle: DomainHandle) -> Result<(u64, u64), CancelError> {
    MANAGER.lock().cancel_prepared(handle)
}

#[cfg(not(test))]
pub fn active_lifecycle_guard_rejects(
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
    let start_rejected = matches!(
        stage_context(handle, scenario),
        Err(PrepareError::ActiveDomain)
    );
    let cancel_rejected = matches!(cancel(handle), Err(CancelError::ActiveDomain));
    CURRENT.active.store(false, Ordering::SeqCst);
    prepare_rejected
        && start_rejected
        && cancel_rejected
        && outstanding_frames() == frames
        && !is_stale(handle)
}

#[cfg(not(test))]
pub fn generation_overflow_rejects_prepare(raw: &[u8], expected: ContentId) -> bool {
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
            stop: DomainStop::inactive(),
            control: DomainControl::inactive(),
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

#[cfg(not(test))]
pub(in crate::domains) fn readiness_post_terminal_closed(handle: DomainHandle) -> bool {
    readiness::observe_current(handle).is_none()
}

impl Manager {
    pub fn valid_domain(&self, handle: DomainHandle) -> Option<&Domain> {
        let slot = self.slots.get(handle.id().0 as usize)?;
        let domain = slot.as_ref()?;
        (domain.generation == handle.generation().0 && domain.state.is_live()).then_some(domain)
    }

    pub fn valid_domain_mut(&mut self, handle: DomainHandle) -> Option<&mut Domain> {
        let slot = self.slots.get_mut(handle.id().0 as usize)?;
        let domain = slot.as_mut()?;
        (domain.generation == handle.generation().0 && domain.state.is_live()).then_some(domain)
    }

    fn releasing_domain_mut(&mut self, handle: DomainHandle) -> Option<&mut Domain> {
        let slot = self.slots.get_mut(handle.id().0 as usize)?;
        let domain = slot.as_mut()?;
        (domain.generation == handle.generation().0 && domain.state == DomainState::Releasing)
            .then_some(domain)
    }

    #[cfg(test)]
    pub(in crate::domains) fn take_running_stop(
        &mut self,
        handle: DomainHandle,
        scenario: Scenario,
    ) -> Result<(), super::stop::StopError> {
        let Some(domain) = self
            .slots
            .get_mut(handle.id().0 as usize)
            .and_then(Option::as_mut)
            .filter(|domain| domain.generation == handle.generation().0)
        else {
            return Err(super::stop::StopError::StateMismatch);
        };
        if domain.state != DomainState::Running {
            return Err(super::stop::StopError::StateMismatch);
        }
        domain.stop.take_timer(handle, scenario)
    }

    pub(in crate::domains) fn completed_running_stop(
        &self,
        handle: DomainHandle,
        component_id: ContentId,
        scenario: Scenario,
    ) -> Option<super::stop::StopObservation<HostManifestIdentity, ContentId>> {
        let domain = self
            .slots
            .get(handle.id().0 as usize)
            .and_then(Option::as_ref)
            .filter(|domain| {
                domain.generation == handle.generation().0 && domain.state == DomainState::Reclaimed
            })?;
        domain
            .stop
            .completed_observation_for(handle, component_id, scenario)
    }

    fn slot_is_preparable(domain: Option<&Domain>) -> bool {
        domain.is_none_or(|domain| domain.state == DomainState::Reclaimed)
    }

    fn release_domain_admission(handle: DomainHandle) {
        #[cfg(test)]
        {
            ADMISSION_RELEASES.fetch_add(1, Ordering::SeqCst);
            let _ = handle;
        }
        #[cfg(not(test))]
        super::admission::release(handle);
    }

    fn stop_taken(&self, handle: DomainHandle) -> bool {
        self.slots
            .get(handle.id().0 as usize)
            .and_then(Option::as_ref)
            .is_some_and(|domain| {
                domain.generation == handle.generation().0
                    && domain.state.is_live()
                    && domain.stop.is_taken()
            })
    }

    fn release_slot(&mut self, handle: DomainHandle) -> ReclaimStats {
        self.release_slot_with_stop(handle, None)
    }

    fn begin_relation_release(
        &mut self,
        handle: DomainHandle,
        stop_context: Option<&TrapContext>,
    ) -> Option<(u64, bool, bool, ipc::TeardownOutcome)> {
        let slot = self.slots.get_mut(handle.id().0 as usize)?;
        let domain = slot.as_mut()?;
        if domain.generation != handle.generation().0 || !domain.state.is_live() {
            return None;
        }

        let generation = domain.generation;
        let stop_requested = domain.stop.is_taken();
        if let Some(_context) = stop_context {
            #[cfg(not(test))]
            serial::ev_domain_outcome(
                serial::DomainEventIdentity::new(_context.slot + 1, _context.generation),
                _context.outcome.name(),
                _context.vector,
                _context.error_code,
                _context.fault_address,
                _context.rip,
                _context.cs & 3,
            );
        }
        let identity = domain.space.as_ref().and_then(space_identity);
        self.last_identity = identity;
        let ipc_outcome = release_ipc_for_release(handle.id().value(), generation);
        let relation_released = ipc_outcome.relation_released;
        if stop_requested {
            #[cfg(not(test))]
            serial::ev_stop_relation_retired(handle.id().0 + 1, generation, relation_released);
        }
        if !relation_released {
            domain.state = DomainState::ReleaseFailed;
            let _ = domain.stop.finish(handle, false);
            return None;
        }
        Some((generation, stop_requested, relation_released, ipc_outcome))
    }

    fn mark_release_wakes(
        &mut self,
        handle: DomainHandle,
        _generation: u64,
        ipc_outcome: ipc::TeardownOutcome,
    ) -> Option<[Option<DomainHandle>; 2]> {
        #[cfg(not(test))]
        serial::ev_ipc_reclaim(
            handle.id().value() + 1,
            _generation,
            ipc_outcome.endpoints as u64,
            ipc_outcome.capabilities as u64,
            ipc_outcome.queued_messages as u64,
        );
        let mut failed_peers = [None; 2];
        for (failed_peer, wake) in failed_peers.iter_mut().zip(
            ipc_outcome
                .waiters
                .into_iter()
                .chain(ipc_outcome.peer_failures)
                .flatten(),
        ) {
            let wake_handle = match super::wait::domain_handle_token(wake) {
                Some(wake_handle) => wake_handle,
                #[cfg(not(test))]
                None => fail_terminal("invalid_ipc_wake"),
                #[cfg(test)]
                None => return None,
            };
            super::wait::mark_ipc_peer_failed(wake_handle);
            *failed_peer = Some(wake_handle);
        }
        super::wait::clear_parked(handle);
        Some(failed_peers)
    }

    fn release_space_for_slot(&mut self, handle: DomainHandle, generation: u64) -> SpaceRelease {
        let Some(slot) = self.slots.get_mut(handle.id().0 as usize) else {
            return SpaceRelease::MissingSpace;
        };
        let Some(domain) = slot.as_mut() else {
            return SpaceRelease::MissingSpace;
        };
        match domain.space.as_mut() {
            Some(space) => {
                release_space(space, DomainId(handle.id().0), DomainGeneration(generation))
            },
            None => SpaceRelease::MissingSpace,
        }
    }

    fn mark_release_failed(&mut self, handle: DomainHandle) {
        if let Some(domain) = self.releasing_domain_mut(handle) {
            domain.state = DomainState::ReleaseFailed;
        }
        if let Some(domain) = self
            .slots
            .get_mut(handle.id().0 as usize)
            .and_then(Option::as_mut)
        {
            let _ = domain.stop.finish(handle, false);
        }
    }

    fn stage_and_release_space(
        &mut self,
        handle: DomainHandle,
        generation: u64,
    ) -> Option<(u64, u64)> {
        if let Some(domain) = self
            .slots
            .get_mut(handle.id().0 as usize)
            .and_then(Option::as_mut)
        {
            domain.state = DomainState::Releasing;
        }
        match self.release_space_for_slot(handle, generation) {
            SpaceRelease::Released(expected, freed) => Some((expected, freed)),
            SpaceRelease::ReclaimBlocked(expected, freed) => {
                self.mark_release_failed(handle);
                Some((expected, freed))
            },
            SpaceRelease::MissingSpace | SpaceRelease::RestoreFailed => {
                self.mark_release_failed(handle);
                None
            },
        }
    }

    fn reclaim_domain_space(
        &mut self,
        handle: DomainHandle,
        expected: u64,
        freed: u64,
        stop_requested: bool,
    ) -> bool {
        if expected == 0 || expected != freed {
            return false;
        }
        let Some(domain) = self
            .slots
            .get_mut(handle.id().0 as usize)
            .and_then(Option::as_mut)
        else {
            return false;
        };
        domain.state = DomainState::Reclaimed;
        self.used_frames = self.used_frames.saturating_sub(expected);
        #[cfg(not(test))]
        serial::ev_domain_reclaimed(
            handle.id().0 + 1,
            domain.generation,
            expected,
            freed,
            freed,
            expected - freed,
        );
        Self::release_domain_admission(handle);
        if stop_requested {
            #[cfg(not(test))]
            serial::ev_stop_admission_released(handle.id().0 + 1, domain.generation, true);
        }
        true
    }

    fn finish_stop_release(
        &mut self,
        handle: DomainHandle,
        stop_requested: bool,
        stats: ReclaimStats,
        failed_release_ok: bool,
    ) {
        if !stop_requested {
            return;
        }
        if let Some(domain) = self
            .slots
            .get_mut(handle.id().0 as usize)
            .and_then(Option::as_mut)
        {
            let _ = domain
                .stop
                .finish(handle, stats.exactly_once() && failed_release_ok);
        }
    }

    fn release_slot_with_stop(
        &mut self,
        handle: DomainHandle,
        stop_context: Option<&TrapContext>,
    ) -> ReclaimStats {
        let Some((generation, stop_requested, relation_released, ipc_outcome)) =
            self.begin_relation_release(handle, stop_context)
        else {
            return ReclaimStats::zero();
        };
        let ipc_enabled = self
            .valid_domain(handle)
            .is_some_and(|domain| domain.ipc_enabled);
        let failed_peers = if ipc_enabled {
            self.mark_release_wakes(handle, generation, ipc_outcome)
        } else {
            Some([None, None])
        };
        let Some(failed_peers) = failed_peers else {
            return ReclaimStats::zero();
        };
        let Some((expected, freed)) = self.stage_and_release_space(handle, generation) else {
            return ReclaimStats::zero();
        };
        let reclaimed = self.reclaim_domain_space(handle, expected, freed, stop_requested);
        let mut failed_release_ok = true;
        if reclaimed {
            for failed_peer in failed_peers.into_iter().flatten() {
                failed_release_ok &= self.release_slot(failed_peer).exactly_once();
            }
        }
        let stats = ReclaimStats::from_parts(expected, freed, stop_requested, relation_released);
        self.finish_stop_release(handle, stop_requested, stats, failed_release_ok);
        stats
    }

    #[cfg(not(test))]
    fn terminate(
        &mut self,
        handle: DomainHandle,
        outcome: Outcome,
        event: &TrapContext,
    ) -> ReclaimStats {
        let stop_requested = self.stop_taken(handle);
        if !stop_requested {
            serial::ev_domain_outcome(
                serial::DomainEventIdentity::new(event.slot + 1, event.generation),
                outcome.name(),
                event.vector,
                event.error_code,
                event.fault_address,
                event.rip,
                event.cs & 3,
            );
        }
        self.release_slot_with_stop(handle, stop_requested.then_some(event))
    }

    #[cfg(not(test))]
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
        let admitted = blocked || domain.state == DomainState::Running;
        if admitted && !readiness::invalidate_for_terminal(handle) {
            return Err(CancelError::NotPrepared);
        }
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
