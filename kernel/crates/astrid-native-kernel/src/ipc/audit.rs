//! Same-lock audit staging for the single wired IPC mutation.

#[cfg(test)]
use core::sync::atomic::{AtomicBool, Ordering};

use super::capability::{CapSlot, Rights};
use super::endpoint::Endpoint;
use super::{CapabilityFacts, DomainToken, EndpointId, ObjectGeneration};
use crate::audit::{
    AuditClass, AuditEvent, AuditObject, AuditObjectKind, AuditRights, AuditSubject,
};
use crate::relations::endpoint_created;

use spin::Mutex;

use super::{Capability, IPC};

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

/// Complete same-lock EndpointCreate transaction. The public wrapper stays in
/// `ipc::mod`; every fallible and commit step lives here with the audit hook.
pub(super) fn endpoint_create(domain: DomainToken) -> Result<(u64, u64), super::IpcError> {
    if crate::audit::identity().is_none() {
        return Err(super::IpcError::AuditUnavailable);
    }
    let mut state = IPC.lock();
    // A Copy of the bounded state is the transaction buffer. Every fallible
    // projection and audit transition lands here first; `*state = staged` is
    // the one infallible commit.
    let generation =
        ObjectGeneration::new(state.next_object_generation).ok_or(super::IpcError::NoSpace)?;
    let mut endpoint = Endpoint::new(generation);
    if !endpoint.bind(domain) {
        return Err(super::IpcError::Busy);
    }
    let index = state
        .objects
        .iter()
        .position(|object| object.is_none())
        .ok_or(super::IpcError::NoSpace)?;
    let slot = state.capabilities[domain.slot().index()]
        .free_slot(domain)
        .ok_or(super::IpcError::NoSpace)?;
    let id = EndpointId::try_new(index)?;
    let capability = Capability {
        endpoint: id,
        rights: Rights::ALL,
        generation,
        parent: None,
    };
    let mut scratch = transaction_scratch();
    *scratch = Some(*state);
    let staged = scratch
        .as_mut()
        .expect("transaction scratch was just populated");
    if staged.capabilities[domain.slot().index()]
        .install(domain, slot, capability)
        .is_err()
    {
        *scratch = None;
        return Err(super::IpcError::NoSpace);
    }
    staged.objects[index] = Some(endpoint);
    staged.next_object_generation += 1;
    let facts = CapabilityFacts::new(
        u64::from(slot.get()),
        generation.get(),
        generation.get(),
        Rights::ALL.bits(),
    );
    if forced_failure_now() {
        *scratch = None;
        return Err(super::IpcError::AuditRejected);
    }
    if let Err(error) = project_grant(staged, domain, facts) {
        *scratch = None;
        return Err(error);
    }
    let event = match prepare_grant_event(staged, domain, slot, generation, Rights::ALL) {
        Ok(event) => event,
        Err(error) => {
            *scratch = None;
            return Err(error);
        },
    };
    let observation = match record_grant(event) {
        Ok(observation) => observation,
        Err(error) => {
            *scratch = None;
            return Err(error);
        },
    };

    // Commit IPC objects, capability, relation projection, generation, and
    // the already-retired audit observation as one lock-protected assignment.
    *state = *scratch.as_ref().expect("stage remains until commit");
    *scratch = None;
    drop(scratch);
    super::project_relation_evidence(&mut state, domain);
    drop(state);
    #[cfg(not(test))]
    if let Some(identity) = crate::audit::identity() {
        crate::serial::ev_audit_observed(
            &identity.boot().bytes(),
            identity.authority_id(),
            observation.seq(),
            observation.class() as u16,
            observation.root(),
            true,
        );
    }
    #[cfg(test)]
    let _ = observation;
    Ok((0, u64::from(slot.get())))
}
