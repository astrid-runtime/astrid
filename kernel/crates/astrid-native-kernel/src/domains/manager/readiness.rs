//! Private, admission-bound component-origin readiness evidence.

use spin::Mutex;

use astrid_system_generation::{ContentId, ManifestIdentity};
#[cfg(not(test))]
use core::sync::atomic::Ordering;

#[cfg(not(test))]
use super::super::admission;
use super::super::types::{DomainHandle, DomainId, SLOT_CAPACITY, Scenario};
#[cfg(not(test))]
use super::CURRENT;
use super::DomainState;
#[cfg(not(test))]
use super::MANAGER;
#[cfg(not(test))]
use x86_64::registers::control::Cr3;

pub(super) const RESERVED_VECTOR: u8 = 64;

pub(super) type DomainReadiness = Readiness<ManifestIdentity, ContentId>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReadinessError {
    NotArmed,
    Invalidated,
    AlreadySignaled,
    HandleMismatch,
    ManifestMismatch,
    ComponentMismatch,
    ScenarioMismatch,
    StateMismatch,
    CurrentMismatch,
    LeaseMismatch,
}

impl ReadinessError {
    pub(super) const fn as_reason(self) -> &'static str {
        match self {
            Self::NotArmed => "readiness_not_armed",
            Self::Invalidated => "readiness_invalidated",
            Self::AlreadySignaled => "readiness_already_signaled",
            Self::HandleMismatch => "readiness_handle_mismatch",
            Self::ManifestMismatch => "readiness_manifest_mismatch",
            Self::ComponentMismatch => "readiness_component_mismatch",
            Self::ScenarioMismatch => "readiness_scenario_mismatch",
            Self::StateMismatch => "readiness_state_mismatch",
            Self::CurrentMismatch => "readiness_current_mismatch",
            Self::LeaseMismatch => "readiness_lease_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ReadinessTicket<G, C> {
    handle: DomainHandle,
    manifest_identity: G,
    component_id: C,
    scenario: Scenario,
}

impl<G, C> ReadinessTicket<G, C>
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
    ) -> Result<(), ReadinessError> {
        if self.handle != handle {
            return Err(ReadinessError::HandleMismatch);
        }
        if self.manifest_identity != manifest_identity {
            return Err(ReadinessError::ManifestMismatch);
        }
        if self.component_id != component_id {
            return Err(ReadinessError::ComponentMismatch);
        }
        if self.scenario != scenario {
            return Err(ReadinessError::ScenarioMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ReadinessReceipt<G, C> {
    handle: DomainHandle,
    manifest_identity: G,
    component_id: C,
    scenario: Scenario,
}

impl<G, C> ReadinessReceipt<G, C> {
    #[cfg(test)]
    pub(super) const fn handle(&self) -> DomainHandle {
        self.handle
    }

    #[cfg(test)]
    pub(super) const fn manifest_identity(&self) -> &G {
        &self.manifest_identity
    }

    #[cfg(test)]
    pub(super) const fn component_id(&self) -> &C {
        &self.component_id
    }

    #[cfg(test)]
    pub(super) const fn scenario(&self) -> Scenario {
        self.scenario
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LiveContext {
    cpl: u64,
    root: u64,
    root_flags: u64,
    stack_end: u64,
    kernel_source: u64,
    kernel_flags: u64,
}

impl LiveContext {
    pub(super) const fn new(
        cpl: u64,
        root: u64,
        root_flags: u64,
        stack_end: u64,
        kernel_source: u64,
        kernel_flags: u64,
    ) -> Self {
        Self {
            cpl,
            root,
            root_flags,
            stack_end,
            kernel_source,
            kernel_flags,
        }
    }

    fn matches_lease(self, lease: &LeaseIdentity) -> bool {
        lease.root == self.root
            && lease.root_flags == self.root_flags
            && lease.stack_end == self.stack_end
            && lease.source == self.kernel_source
            && lease.source_flags == self.kernel_flags
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LeaseIdentity {
    root: u64,
    root_flags: u64,
    source: u64,
    source_flags: u64,
    stack_end: u64,
}

impl LeaseIdentity {
    pub(super) const fn new(
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Readiness<G, C> {
    Pending(ReadinessTicket<G, C>, LeaseIdentity),
    Ready(ReadinessTicket<G, C>, ReadinessReceipt<G, C>, LeaseIdentity),
    Invalidated(ReadinessTicket<G, C>, LeaseIdentity),
}

impl<G, C> Readiness<G, C>
where
    G: Copy + PartialEq,
    C: Copy + PartialEq,
{
    pub(super) fn arm(
        handle: DomainHandle,
        manifest_identity: G,
        component_id: C,
        scenario: Scenario,
        lease: LeaseIdentity,
    ) -> Result<Self, ReadinessError> {
        if handle.generation().value() == 0 {
            return Err(ReadinessError::HandleMismatch);
        }
        Ok(Self::Pending(
            ReadinessTicket {
                handle,
                manifest_identity,
                component_id,
                scenario,
            },
            lease,
        ))
    }

    pub(super) fn signal(
        &mut self,
        handle: DomainHandle,
        manifest_identity: G,
        component_id: C,
        scenario: Scenario,
        state: DomainState,
        live: LiveContext,
    ) -> Result<ReadinessReceipt<G, C>, ReadinessError> {
        let Self::Pending(ticket, lease) = self else {
            return Err(match self {
                Self::Ready(_, _, _) => ReadinessError::AlreadySignaled,
                Self::Invalidated(_, _) => ReadinessError::Invalidated,
                Self::Pending(_, _) => ReadinessError::NotArmed,
            });
        };
        ticket.verify(handle, manifest_identity, component_id, scenario)?;
        if state != DomainState::Running {
            return Err(ReadinessError::StateMismatch);
        }
        if live.cpl != 3 || !live.matches_lease(lease) {
            return Err(ReadinessError::LeaseMismatch);
        }
        let receipt = ReadinessReceipt {
            handle: ticket.handle,
            manifest_identity: ticket.manifest_identity,
            component_id: ticket.component_id,
            scenario: ticket.scenario,
        };
        *self = Self::Ready(*ticket, receipt, *lease);
        Ok(receipt)
    }

    pub(super) fn observe(
        &self,
        handle: DomainHandle,
        manifest_identity: G,
        component_id: C,
        state: DomainState,
        live: LiveContext,
    ) -> Option<ReadinessReceipt<G, C>> {
        let Self::Ready(ticket, receipt, lease) = self else {
            return None;
        };
        ticket
            .verify(handle, manifest_identity, component_id, ticket.scenario)
            .ok()?;
        (state == DomainState::Running && live.matches_lease(lease)).then_some(*receipt)
    }

    pub(super) fn invalidate(&mut self, handle: DomainHandle) -> bool {
        let invalidated = match self {
            Self::Pending(ticket, _) | Self::Ready(ticket, _, _) => ticket.handle == handle,
            Self::Invalidated(_, _) => false,
        };
        if invalidated && let Self::Pending(ticket, lease) | Self::Ready(ticket, _, lease) = self {
            *self = Self::Invalidated(*ticket, *lease);
        }
        invalidated
    }

    fn pending_context(&self, handle: DomainHandle) -> Option<(C, Scenario)> {
        let Self::Pending(ticket, _) = self else {
            return None;
        };
        (ticket.handle == handle).then_some((ticket.component_id, ticket.scenario))
    }
}

static READINESS: Mutex<[Option<DomainReadiness>; SLOT_CAPACITY]> = Mutex::new([None, None]);

fn slot_readiness_mut(
    readiness: &mut [Option<DomainReadiness>; SLOT_CAPACITY],
    handle: DomainHandle,
) -> Option<&mut DomainReadiness> {
    let slot = handle.id().0 as usize;
    readiness.get_mut(slot)?.as_mut()
}

pub(super) fn clear_slot(slot: DomainId) {
    let index = slot.0 as usize;
    if let Some(record) = READINESS.lock().get_mut(index) {
        *record = None;
    }
}

pub(super) fn arm(
    handle: DomainHandle,
    manifest_identity: ManifestIdentity,
    component_id: ContentId,
    scenario: Scenario,
    lease: LeaseIdentity,
) -> Result<(), super::PrepareError> {
    let armed = DomainReadiness::arm(handle, manifest_identity, component_id, scenario, lease)
        .map_err(|_| super::PrepareError::Bind(super::super::types::BindError::Malformed))?;
    let slot = handle.id().0 as usize;
    let mut readiness = READINESS.lock();
    let Some(record) = readiness.get_mut(slot) else {
        return Err(super::PrepareError::Bind(
            super::super::types::BindError::NotInstalled,
        ));
    };
    if record.is_some() {
        return Err(super::PrepareError::Bind(
            super::super::types::BindError::Malformed,
        ));
    }
    *record = Some(armed);
    Ok(())
}

pub(super) fn invalidate_for_terminal(handle: DomainHandle) -> bool {
    let mut readiness = READINESS.lock();
    slot_readiness_mut(&mut readiness, handle).is_some_and(|record| record.invalidate(handle))
}

fn pending_signal_context(handle: DomainHandle) -> Result<(ContentId, Scenario), ReadinessError> {
    let readiness = READINESS.lock();
    let Some(record) = readiness
        .get(handle.id().0 as usize)
        .and_then(Option::as_ref)
    else {
        return Err(ReadinessError::NotArmed);
    };
    record
        .pending_context(handle)
        .ok_or(ReadinessError::HandleMismatch)
}

#[cfg(not(test))]
fn current_live(cpl: u64) -> Result<LiveContext, ReadinessError> {
    if !CURRENT.active.load(Ordering::SeqCst) || CURRENT.root.load(Ordering::SeqCst) == 0 {
        return Err(ReadinessError::CurrentMismatch);
    }
    let (actual_root, actual_flags) = Cr3::read();
    if actual_root.start_address().as_u64() != CURRENT.root.load(Ordering::SeqCst)
        || actual_flags.bits() != CURRENT.root_flags.load(Ordering::SeqCst)
    {
        return Err(ReadinessError::CurrentMismatch);
    }
    let Some((kernel_root, kernel_flags)) = super::KERNEL_CR3.get().copied() else {
        return Err(ReadinessError::LeaseMismatch);
    };
    Ok(LiveContext::new(
        cpl,
        CURRENT.root.load(Ordering::SeqCst),
        CURRENT.root_flags.load(Ordering::SeqCst),
        CURRENT.stack_end.load(Ordering::SeqCst),
        kernel_root.start_address().as_u64(),
        kernel_flags.bits(),
    ))
}

#[cfg(not(test))]
pub(super) fn signal_from_trap(
    handle: DomainHandle,
    cpl: u64,
) -> Result<ReadinessReceipt<ManifestIdentity, ContentId>, ReadinessError> {
    current_live(cpl)?;
    let scenario = Scenario::try_from(CURRENT.scenario.load(Ordering::SeqCst))
        .map_err(|_| ReadinessError::ScenarioMismatch)?;
    let (component_id, pending_scenario) = pending_signal_context(handle)?;
    if pending_scenario != scenario {
        return Err(ReadinessError::ScenarioMismatch);
    }
    let manifest_identity = admission::confirm_start(handle, component_id)
        .map_err(|_| ReadinessError::ManifestMismatch)?;
    let live = current_live(cpl)?;

    let manager = MANAGER.lock();
    let Some(domain) = manager.valid_domain(handle) else {
        return Err(ReadinessError::HandleMismatch);
    };
    let state = domain.state;
    let mut readiness = READINESS.lock();
    let readiness_record =
        slot_readiness_mut(&mut readiness, handle).ok_or(ReadinessError::HandleMismatch)?;
    readiness_record.signal(
        handle,
        manifest_identity,
        component_id,
        scenario,
        state,
        live,
    )
}

#[cfg(not(test))]
pub(super) fn observe_current(
    handle: DomainHandle,
) -> Option<ReadinessReceipt<ManifestIdentity, ContentId>> {
    current_live(0).ok()?;
    let scenario = Scenario::try_from(CURRENT.scenario.load(Ordering::SeqCst)).ok()?;
    let (component_id, ready_scenario) = {
        let readiness = READINESS.lock();
        let record = readiness.get(handle.id().0 as usize)?.as_ref()?;
        let Readiness::Ready(ticket, _, _) = record else {
            return None;
        };
        (ticket.component_id, ticket.scenario)
    };
    if ready_scenario != scenario {
        return None;
    }
    let manifest_identity = admission::confirm_start(handle, component_id).ok()?;
    let live = current_live(0).ok()?;

    let manager = MANAGER.lock();
    let domain = manager.valid_domain(handle)?;
    let state = domain.state;
    let readiness = READINESS.lock();
    readiness.get(handle.id().0 as usize)?.as_ref()?.observe(
        handle,
        manifest_identity,
        component_id,
        state,
        live,
    )
}
