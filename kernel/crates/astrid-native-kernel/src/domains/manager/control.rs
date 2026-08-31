//! Private execution-control lease for a running native domain.

use astrid_system_generation::ContentId;

#[cfg(not(test))]
use core::sync::atomic::Ordering;
#[cfg(not(test))]
use x86_64::registers::control::Cr3;

use super::super::types::Outcome;
use super::super::types::{DomainHandle, Scenario};
use super::TrapContext;
#[cfg(not(test))]
use super::{CURRENT, MANAGER};
use crate::platform::TrapFrame;
#[cfg(not(test))]
use crate::serial;
#[cfg(not(test))]
use spin::Mutex;

pub(in crate::domains) type HostManifestIdentity = astrid_system_generation::ManifestIdentity;

pub(in crate::domains) type DomainControl = Control<HostManifestIdentity, ContentId>;

#[cfg(not(test))]
static RETURNED_CONTROL: Mutex<Option<ReturnedRun>> = Mutex::new(None);

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ControlError {
    NotAdmitted,
    AlreadyReturned,
    HandleMismatch,
    ManifestMismatch,
    ComponentMismatch,
    ScenarioMismatch,
    ContextMismatch,
    NotReturned,
    AlreadyRequested,
    StateMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReturnedControlError {
    Control(ControlError),
    ActiveDomain,
    WrongCr3,
    ReleaseFailed,
}

impl ReturnedControlError {
    pub(crate) const fn as_reason(self) -> &'static str {
        match self {
            Self::Control(error) => error.as_reason(),
            Self::ActiveDomain => "active_domain",
            Self::WrongCr3 => "wrong_cr3",
            Self::ReleaseFailed => "release_failed",
        }
    }
}

impl ControlError {
    pub(crate) const fn as_reason(self) -> &'static str {
        match self {
            Self::NotAdmitted => "control_not_admitted",
            Self::AlreadyReturned => "control_already_returned",
            Self::HandleMismatch => "control_handle_mismatch",
            Self::ManifestMismatch => "control_manifest_mismatch",
            Self::ComponentMismatch => "control_component_mismatch",
            Self::ScenarioMismatch => "control_scenario_mismatch",
            Self::ContextMismatch => "control_context_mismatch",
            Self::NotReturned => "control_not_returned",
            Self::AlreadyRequested => "control_already_requested",
            Self::StateMismatch => "control_state_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::domains) struct RunTicket<G, C> {
    handle: DomainHandle,
    manifest_identity: G,
    component_id: C,
    scenario: Scenario,
}

impl<G, C> RunTicket<G, C>
where
    G: Copy + PartialEq,
    C: Copy + PartialEq,
{
    fn verify(
        &self,
        handle: DomainHandle,
        manifest_identity: G,
        component_id: C,
        scenario: Scenario,
    ) -> Result<(), ControlError> {
        if self.handle != handle {
            return Err(ControlError::HandleMismatch);
        }
        if self.manifest_identity != manifest_identity {
            return Err(ControlError::ManifestMismatch);
        }
        if self.component_id != component_id {
            return Err(ControlError::ComponentMismatch);
        }
        if self.scenario != scenario {
            return Err(ControlError::ScenarioMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::domains) struct LeaseContext {
    root: u64,
    root_flags: u64,
    source: u64,
    source_flags: u64,
    stack_end: u64,
}

impl LeaseContext {
    pub(in crate::domains) const fn new(
        root: u64,
        root_flags: u64,
        source: u64,
        source_flags: u64,
        stack_end: u64,
    ) -> Self {
        Self {
            root,
            root_flags,
            source,
            source_flags,
            stack_end,
        }
    }

    const fn matches_current(self, root: u64, root_flags: u64) -> bool {
        self.root == root && self.root_flags == root_flags
    }

    const fn matches_stack(self, stack_end: u64) -> bool {
        self.stack_end == stack_end
    }

    const fn matches_kernel(self, source: u64, source_flags: u64) -> bool {
        self.source == source && self.source_flags == source_flags
    }
}

pub(in crate::domains) struct ReturnedRun {
    root: u64,
    root_flags: u64,
    frame: TrapFrame,
}

impl Clone for ReturnedRun {
    fn clone(&self) -> Self {
        Self {
            root: self.root,
            root_flags: self.root_flags,
            frame: copy_frame(&self.frame),
        }
    }
}

impl core::fmt::Debug for ReturnedRun {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ReturnedRun")
            .field("root", &self.root)
            .field("root_flags", &self.root_flags)
            .field("vector", &self.frame.vector)
            .field("rip", &self.frame.rip)
            .field("cs", &self.frame.cs)
            .finish_non_exhaustive()
    }
}

impl PartialEq for ReturnedRun {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
            && self.root_flags == other.root_flags
            && self.frame.vector == other.frame.vector
            && self.frame.rip == other.frame.rip
            && self.frame.cs == other.frame.cs
            && self.frame.rsp == other.frame.rsp
    }
}

impl Eq for ReturnedRun {}

impl ReturnedRun {
    pub(in crate::domains) const fn vector(&self) -> u8 {
        self.frame.vector as u8
    }

    pub(in crate::domains) const fn error_code(&self) -> u64 {
        self.frame.error_code
    }

    pub(in crate::domains) const fn rip(&self) -> u64 {
        self.frame.rip
    }

    pub(in crate::domains) const fn cs(&self) -> u64 {
        self.frame.cs
    }

    #[cfg(test)]
    pub(in crate::domains) const fn fault_address(&self) -> u64 {
        0
    }
}

#[cfg(test)]
impl ReturnedRun {
    pub(in crate::domains) const fn trap_context(&self) -> TrapContext {
        TrapContext {
            slot: 0,
            generation: 0,
            vector: self.frame.vector as u8,
            error_code: self.frame.error_code,
            rip: self.frame.rip,
            cs: self.frame.cs,
            fault_address: 0,
            outcome: Outcome::Cancelled,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Control<G, C> {
    Inactive,
    Admitted(RunTicket<G, C>, LeaseContext),
    Returned(ReturnedRun, RunTicket<G, C>, LeaseContext),
    StopRequested(ReturnedRun, RunTicket<G, C>, LeaseContext),
}

impl<G, C> Control<G, C>
where
    G: Copy + PartialEq,
    C: Copy + PartialEq,
{
    pub(crate) fn return_at_trap(
        self,
        handle: DomainHandle,
        manifest_identity: G,
        component_id: C,
        scenario: Scenario,
        trap: TrapSnapshot<'_>,
    ) -> Result<(Self, ReturnedRun), ControlError> {
        let Self::Admitted(ticket, context) = self else {
            return Err(ControlError::AlreadyReturned);
        };
        ticket.verify(handle, manifest_identity, component_id, scenario)?;
        if scenario != Scenario::RunningStop
            || !context.matches_current(trap.root, trap.root_flags)
            || !context.matches_stack(trap.frame.rsp)
            || trap.frame.cs & 3 != 3
        {
            return Err(ControlError::ContextMismatch);
        }
        let returned = ReturnedRun {
            root: trap.root,
            root_flags: trap.root_flags,
            frame: copy_frame(trap.frame),
        };
        Ok((Self::Returned(returned.clone(), ticket, context), returned))
    }

    pub(crate) fn request_stop(
        self,
        handle: DomainHandle,
        manifest_identity: G,
        component_id: C,
        scenario: Scenario,
        context_guard: ContextGuard,
    ) -> Result<(Self, ReturnedRun), ControlError> {
        let (returned, ticket, context) = match self {
            Self::Returned(returned, ticket, context) => (returned, ticket, context),
            Self::Admitted(_, _) | Self::Inactive => {
                return Err(ControlError::NotReturned);
            },
            Self::StopRequested(_, _, _) => {
                return Err(ControlError::AlreadyRequested);
            },
        };
        ticket.verify(handle, manifest_identity, component_id, scenario)?;
        if scenario != Scenario::RunningStop
            || !context_guard.is_quiescent()
            || !context.matches_current(returned.root, returned.root_flags)
            || !context.matches_kernel(context_guard.source, context_guard.source_flags)
        {
            return Err(ControlError::ContextMismatch);
        }
        Ok((
            Self::StopRequested(returned.clone(), ticket, context),
            returned,
        ))
    }
}

#[derive(Clone, Copy)]
pub(in crate::domains) struct TrapSnapshot<'a> {
    pub(in crate::domains) root: u64,
    pub(in crate::domains) root_flags: u64,
    pub(in crate::domains) frame: &'a TrapFrame,
}

#[derive(Clone, Copy)]
pub(in crate::domains) struct ContextGuard {
    current_root: u64,
    current_flags: u64,
    source: u64,
    source_flags: u64,
}

impl ContextGuard {
    pub(in crate::domains) const fn new(
        current_root: u64,
        current_flags: u64,
        source: u64,
        source_flags: u64,
    ) -> Self {
        Self {
            current_root,
            current_flags,
            source,
            source_flags,
        }
    }

    const fn is_quiescent(self) -> bool {
        self.current_root == 0 && self.current_flags == 0
    }
}

impl<G, C> Control<G, C>
where
    G: Copy + PartialEq,
    C: Copy + PartialEq,
{
    pub(crate) const fn inactive() -> Self {
        Self::Inactive
    }

    pub(crate) fn admit(
        handle: DomainHandle,
        manifest_identity: G,
        component_id: C,
        scenario: Scenario,
        context: LeaseContext,
    ) -> Result<Self, ControlError> {
        if handle.generation().value() == 0 {
            return Err(ControlError::HandleMismatch);
        }
        Ok(Self::Admitted(
            RunTicket {
                handle,
                manifest_identity,
                component_id,
                scenario,
            },
            context,
        ))
    }
}

#[cfg(not(test))]
pub(in crate::domains) fn request_returned_stop(
    handle: DomainHandle,
    component_id: ContentId,
    scenario: Scenario,
) -> Result<ReturnedRun, ReturnedControlError> {
    if scenario != Scenario::RunningStop {
        return Err(ReturnedControlError::Control(
            ControlError::ScenarioMismatch,
        ));
    }
    let manifest_identity = super::super::admission::confirm_start(handle, component_id)
        .map_err(|_| ReturnedControlError::Control(ControlError::ManifestMismatch))?;
    super::MANAGER
        .lock()
        .accept_returned_stop(handle, manifest_identity, component_id, scenario)
}

#[cfg(not(test))]
fn returned_context_error() -> Option<ReturnedControlError> {
    if CURRENT.active.load(Ordering::SeqCst)
        || CURRENT.root.load(Ordering::SeqCst) != 0
        || CURRENT.root_flags.load(Ordering::SeqCst) != 0
    {
        return Some(ReturnedControlError::ActiveDomain);
    }
    let Some(expected) = super::KERNEL_CR3.get().copied() else {
        return Some(ReturnedControlError::WrongCr3);
    };
    (Cr3::read() != expected).then_some(ReturnedControlError::WrongCr3)
}

#[cfg(not(test))]
pub(in crate::domains) fn stage_returning_trap(
    frame: &TrapFrame,
) -> Result<(), ReturnedControlError> {
    let handle = super::super::wait::current_handle();
    let scenario = Scenario::try_from(CURRENT.scenario.load(Ordering::SeqCst))
        .map_err(|_| ReturnedControlError::Control(ControlError::ScenarioMismatch))?;
    let trap = TrapSnapshot {
        root: CURRENT.root.load(Ordering::SeqCst),
        root_flags: CURRENT.root_flags.load(Ordering::SeqCst),
        frame,
    };
    let component_id = {
        let manager = MANAGER.lock();
        manager
            .valid_domain(handle)
            .and_then(|domain| domain.stop.exact_component(handle, scenario))
            .ok_or(ReturnedControlError::Control(ControlError::NotAdmitted))?
    };
    let manifest_identity = super::super::admission::confirm_start(handle, component_id)
        .map_err(|_| ReturnedControlError::Control(ControlError::ManifestMismatch))?;
    let returned = {
        let mut manager = MANAGER.lock();
        let Some(domain) = manager.valid_domain_mut(handle) else {
            return Err(ReturnedControlError::Control(ControlError::NotAdmitted));
        };
        let (control, returned) = domain
            .control
            .clone()
            .return_at_trap(handle, manifest_identity, component_id, scenario, trap)
            .map_err(ReturnedControlError::Control)?;
        domain.control = control;
        returned
    };
    *RETURNED_CONTROL.lock() = Some(returned);
    Ok(())
}

#[cfg(not(test))]
#[unsafe(naked)]
pub(in crate::domains) extern "C" fn switch_to_return(stack_end: usize) -> ! {
    core::arch::naked_asm!(
        "mov rsp, rdi",
        "xor ebp, ebp",
        "call {returned}",
        "ud2",
        returned = sym finish_return,
    );
}

#[cfg(not(test))]
extern "C" fn finish_return() -> ! {
    let Some(_returned) = RETURNED_CONTROL.lock().take() else {
        serial::ev_domain_harness(false);
        serial::ev_halt(false);
        serial::exit_qemu(false);
    };
    let Some(expected) = super::KERNEL_CR3.get().copied() else {
        super::fail_terminal("kernel_cr3_missing");
    };
    // SAFETY: execution is now on the kernel resume stack; the exact kernel
    // root can safely replace the domain's guarded transition root.
    unsafe {
        Cr3::write(expected.0, expected.1);
    }
    CURRENT.active.store(false, Ordering::SeqCst);
    CURRENT.root.store(0, Ordering::SeqCst);
    CURRENT.root_flags.store(0, Ordering::SeqCst);
    super::scheduler_resume()
}

#[cfg(not(test))]
impl super::Manager {
    pub(in crate::domains) fn accept_returned_stop(
        &mut self,
        handle: DomainHandle,
        manifest_identity: HostManifestIdentity,
        component_id: ContentId,
        scenario: Scenario,
    ) -> Result<ReturnedRun, ReturnedControlError> {
        if let Some(error) = returned_context_error() {
            return Err(error);
        }
        let Some((kernel_root, kernel_flags)) = super::KERNEL_CR3.get().copied() else {
            return Err(ReturnedControlError::WrongCr3);
        };
        let returned = {
            let Some(domain) = self.valid_domain_mut(handle) else {
                return Err(ReturnedControlError::Control(ControlError::NotReturned));
            };
            let (control, returned) = domain
                .control
                .clone()
                .request_stop(
                    handle,
                    manifest_identity,
                    component_id,
                    scenario,
                    ContextGuard::new(
                        CURRENT.root.load(Ordering::SeqCst),
                        CURRENT.root_flags.load(Ordering::SeqCst),
                        kernel_root.start_address().as_u64(),
                        kernel_flags.bits(),
                    ),
                )
                .map_err(ReturnedControlError::Control)?;
            domain
                .stop
                .take_timer(handle, scenario)
                .map_err(|_| ReturnedControlError::Control(ControlError::StateMismatch))?;
            serial::ev_stop_requested(handle.id().0 + 1, handle.generation().0);
            domain.control = control;
            returned
        };
        if !self.invalidate_admitted_for_terminal(handle) {
            return Err(ReturnedControlError::ReleaseFailed);
        }
        let event = TrapContext {
            slot: handle.id().0,
            generation: handle.generation().0,
            vector: returned.vector(),
            error_code: returned.error_code(),
            rip: returned.rip(),
            cs: returned.cs(),
            fault_address: 0,
            outcome: Outcome::Cancelled,
        };
        serial::ev_stop_taken(
            handle.id().0 + 1,
            handle.generation().0,
            u64::from(event.vector),
        );
        let stats = self.release_slot_with_stop(handle, Some(&event));
        if stats.exactly_once() {
            serial::ev_stop_current_inactive(handle.id().0 + 1, handle.generation().0);
            serial::ev_stop_completed(handle.id().0 + 1, handle.generation().0, true);
            Ok(returned)
        } else {
            serial::ev_stop_completed(handle.id().0 + 1, handle.generation().0, false);
            Err(ReturnedControlError::ReleaseFailed)
        }
    }
}

fn copy_frame(frame: &TrapFrame) -> TrapFrame {
    TrapFrame {
        rax: frame.rax,
        rbx: frame.rbx,
        rcx: frame.rcx,
        rdx: frame.rdx,
        rsi: frame.rsi,
        rdi: frame.rdi,
        rbp: frame.rbp,
        r8: frame.r8,
        r9: frame.r9,
        r10: frame.r10,
        r11: frame.r11,
        r12: frame.r12,
        r13: frame.r13,
        r14: frame.r14,
        r15: frame.r15,
        vector: frame.vector,
        error_code: frame.error_code,
        rip: frame.rip,
        cs: frame.cs,
        rflags: frame.rflags,
        rsp: frame.rsp,
        ss: frame.ss,
    }
}
