//! Host-test fixtures for the production domain authority state.

use super::manager::{Domain, DomainState, MANAGER};
use super::types::{DomainHandle, Scenario};

pub(crate) fn reset() {
    *MANAGER.lock() = super::manager::Manager::default();
}

pub(crate) fn install_blocked(handle: DomainHandle) -> bool {
    let index = handle.id().value() as usize;
    let mut manager = MANAGER.lock();
    if manager.slots[index].is_some() {
        return false;
    }
    manager.slots[index] = Some(Domain {
        generation: handle.generation().value(),
        state: DomainState::Blocked,
        scenario: Scenario::IpcClient,
        quota_ticks: 1,
        space: None,
        ipc_enabled: true,
        stop: super::stop::DomainStop::inactive(),
    });
    true
}

pub(crate) fn is_blocked(handle: DomainHandle) -> bool {
    MANAGER
        .lock()
        .valid_domain(handle)
        .is_some_and(|domain| domain.state == DomainState::Blocked)
}
