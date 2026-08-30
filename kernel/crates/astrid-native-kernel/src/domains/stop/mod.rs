//! Private identity-bound Running-stop scheduler handoff.

use super::types::{DomainHandle, Outcome, Scenario};
use astrid_system_generation::ContentId;
#[cfg(not(test))]
use astrid_system_generation::ManifestIdentity;

#[cfg(not(test))]
use super::manager::{CURRENT, MANAGER, fail_terminal};
#[cfg(not(test))]
use crate::serial;

#[cfg(not(test))]
pub(in crate::domains) type HostManifestIdentity = ManifestIdentity;
#[cfg(test)]
pub(in crate::domains) type HostManifestIdentity = ();

pub(crate) type DomainStop = StopLifecycle<HostManifestIdentity, ContentId>;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod relation_tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StopError {
    NotArmed,
    HandleMismatch,
    ManifestMismatch,
    ComponentMismatch,
    ScenarioMismatch,
    StateMismatch,
}

impl StopError {
    pub(crate) const fn as_reason(self) -> &'static str {
        match self {
            Self::NotArmed => "stop_not_armed",
            Self::HandleMismatch => "stop_handle_mismatch",
            Self::ManifestMismatch => "stop_manifest_mismatch",
            Self::ComponentMismatch => "stop_component_mismatch",
            Self::ScenarioMismatch => "stop_scenario_mismatch",
            Self::StateMismatch => "stop_state_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StopTicket<G, C> {
    handle: DomainHandle,
    manifest_identity: G,
    component_id: C,
    scenario: Scenario,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StopObservation<G, C> {
    handle: DomainHandle,
    manifest_identity: G,
    component_id: C,
    scenario: Scenario,
    outcome: Outcome,
}

impl<G, C> StopObservation<G, C> {
    pub(in crate::domains) const fn handle(&self) -> DomainHandle {
        self.handle
    }

    #[cfg(test)]
    pub(in crate::domains) const fn manifest_identity(&self) -> &G {
        &self.manifest_identity
    }

    pub(in crate::domains) const fn component_id(&self) -> &C {
        &self.component_id
    }

    pub(in crate::domains) const fn scenario(&self) -> Scenario {
        self.scenario
    }

    pub(in crate::domains) const fn outcome(&self) -> Outcome {
        self.outcome
    }
}

impl<G, C> StopTicket<G, C>
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
    ) -> Result<(), StopError> {
        if self.handle != handle {
            return Err(StopError::HandleMismatch);
        }
        if self.manifest_identity != manifest_identity {
            return Err(StopError::ManifestMismatch);
        }
        if self.component_id != component_id {
            return Err(StopError::ComponentMismatch);
        }
        if self.scenario != scenario {
            return Err(StopError::ScenarioMismatch);
        }
        Ok(())
    }
}

impl<G, C> StopLifecycle<G, C>
where
    G: Copy + PartialEq,
    C: Copy + PartialEq,
{
    #[cfg(test)]
    pub(in crate::domains) fn completed_observation(
        &self,
        handle: DomainHandle,
        manifest_identity: G,
        component_id: C,
        scenario: Scenario,
    ) -> Option<StopObservation<G, C>> {
        let Self::Completed(ticket) = self else {
            return None;
        };
        ticket
            .verify(handle, manifest_identity, component_id, scenario)
            .ok()?;
        (ticket.scenario == Scenario::RunningStop).then_some(StopObservation {
            handle: ticket.handle,
            manifest_identity: ticket.manifest_identity,
            component_id: ticket.component_id,
            scenario: ticket.scenario,
            outcome: Outcome::Cancelled,
        })
    }

    pub(in crate::domains) fn completed_observation_for(
        &self,
        handle: DomainHandle,
        component_id: C,
        scenario: Scenario,
    ) -> Option<StopObservation<G, C>> {
        let Self::Completed(ticket) = self else {
            return None;
        };
        ticket
            .verify(handle, ticket.manifest_identity, component_id, scenario)
            .ok()?;
        (ticket.scenario == Scenario::RunningStop).then_some(StopObservation {
            handle: ticket.handle,
            manifest_identity: ticket.manifest_identity,
            component_id: ticket.component_id,
            scenario: ticket.scenario,
            outcome: Outcome::Cancelled,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StopLifecycle<G, C> {
    Inactive,
    Staged(StopTicket<G, C>),
    Armed(StopTicket<G, C>),
    Taken(StopTicket<G, C>),
    Completed(StopTicket<G, C>),
    Aborted(StopTicket<G, C>),
}

impl<G, C> StopLifecycle<G, C>
where
    G: Copy + PartialEq,
    C: Copy + PartialEq,
{
    pub(crate) const fn inactive() -> Self {
        Self::Inactive
    }

    pub(crate) fn stage(
        handle: DomainHandle,
        manifest_identity: G,
        component_id: C,
        scenario: Scenario,
    ) -> Result<Self, StopError> {
        if scenario != Scenario::RunningStop {
            return Ok(Self::Inactive);
        }
        if handle.generation().value() == 0 {
            return Err(StopError::HandleMismatch);
        }
        let ticket = StopTicket {
            handle,
            manifest_identity,
            component_id,
            scenario,
        };
        #[cfg(not(test))]
        serial::ev_stop_staged(handle.id().0 + 1, handle.generation().0, scenario.value());
        #[cfg(test)]
        let _ = (handle, scenario);
        Ok(Self::Staged(ticket))
    }

    pub(crate) fn into_armed(
        self,
        handle: DomainHandle,
        manifest_identity: G,
        component_id: C,
        scenario: Scenario,
    ) -> Result<Self, StopError> {
        match self {
            Self::Inactive if scenario != Scenario::RunningStop => Ok(Self::Inactive),
            Self::Inactive => Err(StopError::NotArmed),
            Self::Staged(ticket) => {
                ticket.verify(handle, manifest_identity, component_id, scenario)?;
                Ok(Self::Armed(ticket))
            },
            _ => Err(StopError::StateMismatch),
        }
    }

    pub(in crate::domains) fn take_timer(
        &mut self,
        handle: DomainHandle,
        scenario: Scenario,
    ) -> Result<(), StopError> {
        let Self::Armed(ticket) = *self else {
            return Err(StopError::NotArmed);
        };
        ticket.verify(
            handle,
            ticket.manifest_identity,
            ticket.component_id,
            scenario,
        )?;
        *self = Self::Taken(ticket);
        Ok(())
    }

    fn abort(&mut self, handle: DomainHandle) -> Result<(), StopError> {
        let Self::Armed(ticket) = *self else {
            return Err(StopError::NotArmed);
        };
        if ticket.handle != handle {
            return Err(StopError::HandleMismatch);
        }
        *self = Self::Aborted(ticket);
        Ok(())
    }

    pub(super) const fn is_taken(&self) -> bool {
        matches!(self, Self::Taken(_))
    }

    fn is_armed(&self) -> bool {
        matches!(self, Self::Armed(_))
    }

    pub(super) fn finish(&mut self, handle: DomainHandle, complete: bool) -> Result<(), StopError> {
        let ticket = match self {
            Self::Taken(ticket) | Self::Aborted(ticket) => *ticket,
            _ => return Err(StopError::NotArmed),
        };
        if let Self::Aborted(_) = self {
            return Ok(());
        }
        ticket.verify(
            handle,
            ticket.manifest_identity,
            ticket.component_id,
            ticket.scenario,
        )?;
        *self = if complete {
            Self::Completed(ticket)
        } else {
            Self::Aborted(ticket)
        };
        Ok(())
    }
}

#[cfg(not(test))]
pub(crate) fn take_timer_trap(handle: DomainHandle) {
    let scenario = Scenario::try_from(CURRENT.scenario.load(core::sync::atomic::Ordering::SeqCst))
        .unwrap_or_else(|_| fail_terminal("stop_scenario_invalid"));
    let root = CURRENT.root.load(core::sync::atomic::Ordering::SeqCst);
    let flags = CURRENT
        .root_flags
        .load(core::sync::atomic::Ordering::SeqCst);
    let (current_root, current_flags) = x86_64::registers::control::Cr3::read();
    if handle != super::wait::current_handle()
        || scenario != Scenario::RunningStop
        || current_root.start_address().as_u64() != root
        || current_flags.bits() != flags
    {
        fail_terminal("stop_trap_context_mismatch");
    }
    {
        let mut manager = MANAGER.lock();
        if manager.take_running_stop(handle, scenario).is_err() {
            fail_terminal("stop_take_rejected");
        }
    }
}

#[cfg(not(test))]
pub(crate) fn abort_for_terminal(handle: DomainHandle) -> bool {
    let mut manager = MANAGER.lock();
    let Some(domain) = manager.valid_domain_mut(handle) else {
        return false;
    };
    if domain.stop.is_armed() {
        domain.stop.abort(handle).is_ok()
    } else {
        !domain.stop.is_taken()
    }
}

#[cfg(not(test))]
pub(in crate::domains) fn observe_completed_stop(
    handle: DomainHandle,
    component_id: ContentId,
    scenario: Scenario,
) -> Option<StopObservation<HostManifestIdentity, ContentId>> {
    if CURRENT.active.load(core::sync::atomic::Ordering::SeqCst)
        || CURRENT.root.load(core::sync::atomic::Ordering::SeqCst) != 0
        || CURRENT
            .root_flags
            .load(core::sync::atomic::Ordering::SeqCst)
            != 0
    {
        return None;
    }
    let manager = MANAGER.lock();
    manager.completed_running_stop(handle, component_id, scenario)
}
