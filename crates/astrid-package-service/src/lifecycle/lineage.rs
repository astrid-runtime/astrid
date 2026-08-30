use super::generation::next_generation_value;
use crate::error::{PackageServiceError, PackageServiceResult};
use crate::identity::Nonce;
use crate::journal::{OperationJournalRecord, PackageSlotRecord};
use crate::state::{CanonicalInstalledState, DrainLineage, LifecycleState};
use std::num::NonZeroU64;

pub(super) fn active_drain_lineage(
    slot_record: &PackageSlotRecord,
    nonce: &Nonce,
) -> PackageServiceResult<DrainLineage> {
    let lineage = slot_record
        .journal_record(nonce)
        .and_then(OperationJournalRecord::drain_lineage)
        .cloned()
        .ok_or(PackageServiceError::OccupancyCorruption)?;
    let state = slot_record
        .state()
        .ok_or(PackageServiceError::LifecycleTransition)?;
    validate(&lineage, state, nonce)?;
    Ok(lineage)
}

fn restore_prior_content_to_successor(
    state: CanonicalInstalledState,
    completing_nonce: Nonce,
    generation: NonZeroU64,
) -> CanonicalInstalledState {
    let plan = *state.lifecycle_plan();
    let mut restored = state;
    restored.set_lifecycle_result(LifecycleState::Inactive, plan, generation, completing_nonce);
    restored
}

pub(super) fn validate(
    lineage: &DrainLineage,
    state: &CanonicalInstalledState,
    nonce: &Nonce,
) -> PackageServiceResult<()> {
    let base = lineage.base_state();
    if !base.has_valid_digest()
        || base.lifecycle_plan().as_bytes() == &[0; 32]
        || matches!(base.lifecycle_state(), LifecycleState::Draining { .. })
    {
        return Err(PackageServiceError::OccupancyCorruption);
    }

    let LifecycleState::Draining {
        deadline: _,
        nonce: drain_nonce,
        live_leases: _,
        destination: _,
    } = state.lifecycle_state()
    else {
        return Err(PackageServiceError::LifecycleTransition);
    };
    if !state.has_valid_digest()
        || drain_nonce.as_bytes() != nonce.as_bytes()
        || state.generation_value() != lineage.boundary_generation()
        || state.generation_value().get() <= base.generation_value().get()
        || base.slot() != state.slot()
        || base.artifact() != state.artifact()
        || base.content_root() != state.content_root()
        || base.manifest() != state.manifest()
        || base.authority_digest() != state.authority_digest()
        || base.provenance() != state.provenance()
    {
        return Err(PackageServiceError::OccupancyCorruption);
    }
    Ok(())
}

pub(super) fn restore_to_boundary_successor(
    lineage: &DrainLineage,
    nonce: &Nonce,
) -> PackageServiceResult<CanonicalInstalledState> {
    let generation: NonZeroU64 = next_generation_value(lineage.boundary_generation())?;
    Ok(restore_prior_content_to_successor(
        lineage.base_state().clone(),
        *nonce,
        generation,
    ))
}
