//! Same-lock audit staging for the single wired IPC mutation.

#[cfg(test)]
use core::sync::atomic::{AtomicBool, Ordering};

use super::capability::{CapSlot, Rights};
use super::{CapabilityFacts, DomainToken, ObjectGeneration};
use crate::audit::{
    AuditClass, AuditEvent, AuditObject, AuditObjectKind, AuditRights, AuditSubject,
};
use crate::relations::endpoint_created;

use spin::Mutex;

static TRANSACTION_SCRATCH: Mutex<Option<super::IpcState>> = Mutex::new(None);

/// Fixed-capacity transaction image. `IpcState` is intentionally kept out of
/// the small domain stack; IPC -> scratch -> audit is the only nesting order.
pub(super) fn transaction_scratch() -> spin::MutexGuard<'static, Option<super::IpcState>> {
    TRANSACTION_SCRATCH.lock()
}

#[cfg(test)]
static FORCE_AUDIT_FAILURE: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
pub(crate) fn force_failure_for_test(force: bool) {
    FORCE_AUDIT_FAILURE.store(force, Ordering::SeqCst);
}

#[cfg(test)]
fn forced_failure() -> bool {
    FORCE_AUDIT_FAILURE.load(Ordering::SeqCst)
}

#[cfg(not(test))]
fn forced_failure() -> bool {
    false
}

pub(super) fn forced_failure_now() -> bool {
    forced_failure()
}

#[inline(never)]
pub(super) fn project_grant(
    staged: &mut super::IpcState,
    domain: DomainToken,
    facts: CapabilityFacts,
) -> Result<(), super::IpcError> {
    endpoint_created(&mut staged.relations, domain, facts)
        .map_err(|_| super::IpcError::AuditRelation)
}

#[inline(never)]
pub(super) fn prepare_grant_event(
    staged: &super::IpcState,
    domain: DomainToken,
    capability_slot: CapSlot,
    generation: ObjectGeneration,
    rights: Rights,
) -> Result<AuditEvent, super::IpcError> {
    let lease = staged
        .relations
        .reader_lease(domain)
        .ok_or(super::IpcError::AuditRejected)?;
    let object = AuditObject::capability_instance(
        lease.token().get(),
        capability_slot.index(),
        generation.get(),
        AuditObjectKind::Endpoint,
        generation.get(),
    )
    .ok_or(super::IpcError::AuditRejected)?;
    let event = AuditEvent::new(
        AuditClass::CapabilityGrant,
        AuditSubject::from_domain(domain),
    )
    .with_object(object)
    .ok_or(super::IpcError::AuditRejected)?
    .with_rights(AuditRights::from_bits(rights.bits()).ok_or(super::IpcError::AuditRejected)?);
    Ok(event)
}

pub(super) fn record_grant(
    event: AuditEvent,
) -> Result<crate::audit::AuditObservation, super::IpcError> {
    match crate::audit::record(event) {
        Ok(observation) => Ok(observation),
        Err(error) => Err(match error {
            crate::audit::AuditError::RootMismatch => super::IpcError::AuditFold,
            _ => super::IpcError::AuditRejected,
        }),
    }
}
