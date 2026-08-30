//! Typed staging and dispatch primitives for one prepared native domain.

#[cfg(not(test))]
use core::sync::atomic::Ordering;

#[cfg(not(test))]
use x86_64::VirtAddr;
#[cfg(not(test))]
use x86_64::registers::control::Cr3;

#[cfg(not(test))]
use super::super::stop::DomainStop;
#[cfg(not(test))]
use super::{CURRENT, DomainState, MANAGER, PrepareError};
#[cfg(not(test))]
use crate::apic;
use crate::domains::types::Scenario;
#[cfg(not(test))]
use crate::domains::types::{
    BindError, CODE_BASE, DomainHandle, DomainPagingError, ENTRYPOINT, KERNEL_STACK_TOP,
};
#[cfg(not(test))]
use crate::gdt;
#[cfg(not(test))]
use crate::serial;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::domains) struct StartContext {
    scenario: Scenario,
    root: u64,
    user_stack: u64,
    quota_ticks: u32,
    source: u64,
}

#[cfg(test)]
impl StartContext {
    pub(in crate::domains) const fn new(
        scenario: Scenario,
        root: u64,
        user_stack: u64,
        quota_ticks: u32,
        source: u64,
    ) -> Self {
        Self {
            scenario,
            root,
            user_stack,
            quota_ticks,
            source,
        }
    }
}

#[cfg(not(test))]
pub(in crate::domains) fn staged_state(
    handle: DomainHandle,
) -> Result<Option<(DomainState, Scenario)>, PrepareError> {
    let manager = MANAGER.lock();
    let Some(domain) = manager
        .slots
        .get(handle.id().0 as usize)
        .and_then(Option::as_ref)
        .filter(|domain| domain.generation == handle.generation().0)
    else {
        return Ok(None);
    };
    Ok(Some((domain.state, domain.scenario)))
}

#[cfg(not(test))]
pub(in crate::domains) fn stage_context(
    handle: DomainHandle,
    scenario: Scenario,
) -> Result<StartContext, PrepareError> {
    if let Some(error) = super::lifecycle_error() {
        return Err(error);
    }
    let manager = MANAGER.lock();
    let Some(domain) = manager.valid_domain(handle) else {
        return Err(PrepareError::Bind(BindError::NotInstalled));
    };
    if domain.state != DomainState::Prepared || domain.scenario != scenario {
        return Err(PrepareError::Bind(BindError::Malformed));
    }
    let Some(space) = domain.space.as_ref() else {
        return Err(PrepareError::Paging(DomainPagingError::PolicyViolation));
    };
    if let Some(error) = super::lifecycle_error() {
        return Err(error);
    }
    let root = space.root_phys();
    let source = space.source_root();
    if Cr3::read() != source {
        return Err(PrepareError::WrongCr3);
    }
    Ok(StartContext {
        scenario,
        root,
        user_stack: space.user_stack_top(),
        quota_ticks: domain.quota_ticks,
        source: source.0.start_address().as_u64(),
    })
}

#[cfg(not(test))]
pub(in crate::domains) fn start_running(
    handle: DomainHandle,
    context: StartContext,
    stop: DomainStop,
    manifest_identity: astrid_system_generation::ManifestIdentity,
    component_id: astrid_system_generation::ContentId,
) -> Result<(), PrepareError> {
    if let Some(error) = super::lifecycle_error() {
        return Err(error);
    }
    {
        let mut manager = MANAGER.lock();
        let Some(domain) = manager.valid_domain_mut(handle) else {
            return Err(PrepareError::Bind(BindError::NotInstalled));
        };
        if domain.state != DomainState::Prepared
            || domain.scenario != context.scenario
            || domain.quota_ticks != context.quota_ticks
        {
            return Err(PrepareError::Bind(BindError::Malformed));
        }
        let Some(space) = domain.space.as_ref() else {
            return Err(PrepareError::Paging(DomainPagingError::PolicyViolation));
        };
        if space.root_phys() != context.root
            || space.user_stack_top() != context.user_stack
            || space.source_root().0.start_address().as_u64() != context.source
        {
            return Err(PrepareError::Bind(BindError::Malformed));
        }
        if Cr3::read().0.start_address().as_u64() != context.source {
            return Err(PrepareError::WrongCr3);
        }
        if let Some(error) = super::lifecycle_error() {
            return Err(error);
        }
        let armed_stop = stop
            .into_armed(handle, manifest_identity, component_id, context.scenario)
            .map_err(|_| PrepareError::Bind(BindError::Malformed))?;
        domain.state = DomainState::Running;
        domain.stop = armed_stop;
        if context.scenario == crate::domains::types::Scenario::RunningStop {
            serial::ev_stop_armed(handle.id().0 + 1, handle.generation().0);
        }
    }
    Ok(())
}

#[cfg(not(test))]
pub(in crate::domains) fn enter_running(handle: DomainHandle, context: StartContext) -> ! {
    let StartContext {
        scenario,
        root,
        user_stack: user_end,
        quota_ticks: quota,
        source: _,
    } = context;
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

#[cfg(not(test))]
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
