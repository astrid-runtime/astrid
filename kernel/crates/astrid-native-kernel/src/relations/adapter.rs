//! Same-lock translation of authoritative IPC/domain state into relations.

#[cfg(test)]
use super::delta::DeltaCursor;
#[cfg(test)]
use super::projection::Snapshot;
use super::projection::{ProjectionStore, ReaderLease};
use super::types::{
    CapabilityGeneration, CapabilityInstance, CapabilitySlot, ObjectKind, ObjectRef, ObjectToken,
    ProjectionError, Relation, RelationChange, RelationRights,
};
use crate::ipc::DomainToken;

/// The projection-visible portion of a landed capability, with no private IPC
/// type in the signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CapabilityFacts {
    slot: u64,
    object: u64,
    generation: u64,
    rights: u16,
}

impl CapabilityFacts {
    pub(crate) const fn new(slot: u64, object: u64, generation: u64, rights: u16) -> Self {
        Self {
            slot,
            object,
            generation,
            rights,
        }
    }
}

/// Runtime evidence from one same-lock fold check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProjectionEvidence {
    pub(crate) epoch: u64,
    pub(crate) rows: usize,
    pub(crate) fold_epoch: u64,
    pub(crate) fold_rows: usize,
    pub(crate) fold_matches: bool,
}

pub(crate) fn domain_registered(
    store: &mut ProjectionStore,
    domain: DomainToken,
) -> Result<(), ProjectionError> {
    let lease = store.register_reader(domain)?;
    let object = ObjectRef::new(
        ObjectKind::Domain,
        domain_object(domain).ok_or(ProjectionError::Denied)?,
    );
    store
        .apply_mutation(
            lease,
            RelationChange::Upsert(Relation::object(lease.token(), object)),
        )
        .map(|_| ())
}

pub(crate) fn endpoint_created(
    store: &mut ProjectionStore,
    domain: DomainToken,
    facts: CapabilityFacts,
) -> Result<(), ProjectionError> {
    let lease = reader(store, domain)?;
    let object = ObjectRef::new(
        ObjectKind::Endpoint,
        ObjectToken::new(facts.object).ok_or(ProjectionError::Denied)?,
    );
    let capability = instance(lease, facts)?;
    let rights = rights(facts)?;
    store.apply_mutation(
        lease,
        RelationChange::Upsert(Relation::object(lease.token(), object)),
    )?;
    store
        .apply_mutation(
            lease,
            RelationChange::Upsert(
                Relation::holds(lease.token(), capability, object, rights)
                    .ok_or(ProjectionError::Denied)?,
            ),
        )
        .map(|_| ())
}

pub(crate) fn capability_installed(
    store: &mut ProjectionStore,
    owner: DomainToken,
    owner_facts: CapabilityFacts,
    child: DomainToken,
    child_facts: CapabilityFacts,
) -> Result<(), ProjectionError> {
    let child_lease = reader(store, child)?;
    let parent_lease = reader(store, owner)?;
    let object = ObjectRef::new(
        ObjectKind::Endpoint,
        ObjectToken::new(child_facts.object).ok_or(ProjectionError::Denied)?,
    );
    let parent = instance(parent_lease, owner_facts)?;
    let capability = instance(child_lease, child_facts)?;
    let rights = rights(child_facts)?;
    store.apply_mutation(
        child_lease,
        RelationChange::Upsert(Relation::object(child_lease.token(), object)),
    )?;
    store.apply_mutation(
        child_lease,
        RelationChange::Upsert(
            Relation::holds(child_lease.token(), capability, object, rights)
                .ok_or(ProjectionError::Denied)?,
        ),
    )?;
    store
        .apply_mutation(
            child_lease,
            RelationChange::Upsert(
                Relation::derives(child_lease.token(), parent, capability)
                    .ok_or(ProjectionError::Denied)?,
            ),
        )
        .map(|_| ())
}

pub(crate) fn capability_removed(
    store: &mut ProjectionStore,
    owner: DomainToken,
    facts: CapabilityFacts,
) -> Result<usize, ProjectionError> {
    let capability = capability_without_lease(store, owner, facts)?;
    store.remove_capability(capability)
}

pub(crate) fn endpoint_reclaimed(
    store: &mut ProjectionStore,
    generation: u64,
) -> Result<usize, ProjectionError> {
    let object = ObjectRef::new(
        ObjectKind::Endpoint,
        ObjectToken::new(generation).ok_or(ProjectionError::Denied)?,
    );
    store.record_object_reclaim(object)
}

pub(crate) fn domain_released(
    store: &mut ProjectionStore,
    domain: DomainToken,
) -> Result<(), ProjectionError> {
    store.retire_reader(domain)
}

#[cfg(test)]
pub(crate) fn projection_observation(
    store: &ProjectionStore,
    domain: DomainToken,
) -> Result<(Snapshot, DeltaCursor), ProjectionError> {
    let lease = reader(store, domain)?;
    Ok((store.snapshot(lease)?, store.delta_cursor(lease)?))
}

#[cfg(test)]
pub(crate) fn projection_fold_evidence(
    store: &ProjectionStore,
    domain: DomainToken,
    base: Snapshot,
    cursor: DeltaCursor,
) -> Result<ProjectionEvidence, ProjectionError> {
    let lease = reader(store, domain)?;
    let replayed = store.fold(lease, base, cursor)?;
    let direct = store.snapshot(lease)?;
    Ok(ProjectionEvidence {
        epoch: direct.epoch(),
        rows: direct.len(),
        fold_epoch: replayed.epoch(),
        fold_rows: replayed.len(),
        fold_matches: replayed == direct,
    })
}

fn reader(store: &ProjectionStore, domain: DomainToken) -> Result<ReaderLease, ProjectionError> {
    store.reader_lease(domain).ok_or(ProjectionError::Denied)
}

fn domain_object(domain: DomainToken) -> Option<ObjectToken> {
    ObjectToken::new(domain.generation().get())
}

fn instance(
    lease: ReaderLease,
    facts: CapabilityFacts,
) -> Result<CapabilityInstance, ProjectionError> {
    let slot = CapabilitySlot::try_new(facts.slot as usize).ok_or(ProjectionError::Denied)?;
    let generation = CapabilityGeneration::new(facts.generation).ok_or(ProjectionError::Denied)?;
    let object = ObjectRef::new(
        ObjectKind::Endpoint,
        ObjectToken::new(facts.object).ok_or(ProjectionError::Denied)?,
    );
    CapabilityInstance::try_new(lease.token(), slot, object, generation)
        .ok_or(ProjectionError::Denied)
}

fn capability_without_lease(
    store: &ProjectionStore,
    owner: DomainToken,
    facts: CapabilityFacts,
) -> Result<CapabilityInstance, ProjectionError> {
    let lease = reader(store, owner)?;
    instance(lease, facts)
}

fn rights(facts: CapabilityFacts) -> Result<RelationRights, ProjectionError> {
    RelationRights::from_landed(facts.rights).ok_or(ProjectionError::Denied)
}
