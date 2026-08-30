use super::generation::{next_generation, next_transition_generation};
use super::lineage::active_drain_lineage;
use crate::context::{Operation, OperationContext, Timestamp};
use crate::digest::{
    AuthorityDecisionDigest, Blake3Digest, DigestWriter, PlanDigest, ProvenanceDigest, StateDigest,
};
use crate::error::{PackageServiceError, PackageServiceResult};
use crate::identity::{Nonce, ProvenanceEvidence, ValidatedArtifact};
use crate::journal::{JournalStatus, PackageSlotRecord, ReceiptOutcome};
use crate::state::{CanonicalInstalledState, DrainDestination, InstalledStateSpec, LifecycleState};
use std::num::NonZeroU64;

pub(super) struct DrainProof<'a> {
    pub(super) nonce: &'a Nonce,
    pub(super) now: Timestamp,
    pub(super) zero_leases: bool,
}

pub(super) fn validate_context_artifact(
    context: &OperationContext,
    artifact: &ValidatedArtifact,
) -> PackageServiceResult<()> {
    if context.artifact() != artifact.artifact() || context.manifest() != artifact.manifest() {
        return Err(PackageServiceError::BindingMismatch);
    }
    if context.content_root() != artifact.content_root()
        || context.provenance() != &provenance_digest(artifact.provenance())
    {
        return Err(PackageServiceError::BindingMismatch);
    }
    Ok(())
}

pub(super) fn require_staged_commit(
    context: &OperationContext,
    artifact: &ValidatedArtifact,
    staged_commit_plan: Option<PlanDigest>,
) -> PackageServiceResult<()> {
    validate_context_artifact(context, artifact)?;
    let plan = commit_plan_digest(
        context,
        artifact.content_root(),
        &provenance_digest(artifact.provenance()),
    );
    if Some(plan) != staged_commit_plan || context.commit_plan_digest() != &plan {
        return Err(PackageServiceError::BindingMismatch);
    }
    Ok(())
}

pub(super) fn commit_install(
    record_slot: &mut PackageSlotRecord,
    context: &OperationContext,
    authority_digest: AuthorityDecisionDigest,
    artifact: &ValidatedArtifact,
    staged_commit_plan: Option<PlanDigest>,
) -> PackageServiceResult<(StateDigest, ReceiptOutcome, NonZeroU64)> {
    require_staged_commit(context, artifact, staged_commit_plan)?;
    let state = new_installed_state(
        context,
        authority_digest,
        artifact,
        LifecycleState::Inactive,
        next_transition_generation(Some(record_slot), Operation::Install)?,
    )?;
    let generation = state.generation_value();
    record_slot.replace_state_with_generation(Some(state), generation)?;
    Ok((
        record_slot.expected_state_digest(),
        ReceiptOutcome::Installed,
        generation,
    ))
}

pub(super) fn commit_retained_state(
    record_slot: &mut PackageSlotRecord,
    context: &OperationContext,
    state: CanonicalInstalledState,
    nonce: &Nonce,
) -> PackageServiceResult<(StateDigest, ReceiptOutcome, NonZeroU64)> {
    let next_lifecycle = if context.operation() == Operation::Activate {
        LifecycleState::Active
    } else {
        LifecycleState::Inactive
    };
    let generation = next_generation(&state)?;
    let mut replacement = state;
    replacement.set_lifecycle_result(next_lifecycle, *context.plan_digest(), generation, *nonce);
    record_slot.replace_state_with_generation(Some(replacement), generation)?;
    let outcome = if context.operation() == Operation::Activate {
        ReceiptOutcome::Activated
    } else {
        ReceiptOutcome::Deactivated
    };
    Ok((record_slot.expected_state_digest(), outcome, generation))
}

pub(super) fn commit_removal(
    record_slot: &mut PackageSlotRecord,
    state: &CanonicalInstalledState,
    nonce: &Nonce,
    proof: &DrainProof<'_>,
) -> PackageServiceResult<(StateDigest, ReceiptOutcome, NonZeroU64)> {
    require_open_drain(state, proof.nonce, proof.now)?;
    require_zero_drain(state, *nonce, DrainDestination::Removal)?;
    active_drain_lineage(record_slot, proof.nonce)?;
    if !proof.zero_leases {
        return Err(PackageServiceError::DrainBlocked);
    }
    let generation = next_generation(state)?;
    record_slot.replace_state_with_generation(None, generation)?;
    Ok((
        record_slot.expected_state_digest(),
        ReceiptOutcome::Retired,
        generation,
    ))
}

pub(super) fn commit_update(
    record_slot: &mut PackageSlotRecord,
    context: &OperationContext,
    authority_digest: AuthorityDecisionDigest,
    artifact: &ValidatedArtifact,
    staged_commit_plan: Option<PlanDigest>,
    proof: &DrainProof<'_>,
) -> PackageServiceResult<(StateDigest, ReceiptOutcome, NonZeroU64)> {
    let Some(state) = record_slot.state().cloned() else {
        return Err(PackageServiceError::LifecycleTransition);
    };
    require_open_drain(&state, proof.nonce, proof.now)?;
    require_zero_drain(&state, *proof.nonce, DrainDestination::Replacement)?;
    active_drain_lineage(record_slot, proof.nonce)?;
    if !proof.zero_leases {
        return Err(PackageServiceError::DrainBlocked);
    }
    require_staged_commit(context, artifact, staged_commit_plan)?;
    let replacement = new_installed_state(
        context,
        authority_digest,
        artifact,
        LifecycleState::Inactive,
        next_generation(&state)?,
    )?;
    let generation = replacement.generation_value();
    record_slot.replace_state_with_generation(Some(replacement), generation)?;
    Ok((
        record_slot.expected_state_digest(),
        ReceiptOutcome::Updated,
        generation,
    ))
}

pub(super) fn commit_record_metadata(
    record_slot: &PackageSlotRecord,
    nonce: &Nonce,
) -> PackageServiceResult<(StateDigest, AuthorityDecisionDigest, Option<PlanDigest>)> {
    let record = record_slot
        .journal_record(nonce)
        .ok_or(PackageServiceError::RecordMissing)?;
    if record.status() != JournalStatus::Executing {
        return Err(PackageServiceError::RecordNotReconcilable);
    }
    Ok((
        record.before_state(),
        *record.authority_digest(),
        record.staged_commit_plan().copied(),
    ))
}

pub(super) fn commit_plan_digest(
    context: &OperationContext,
    content_root: &Blake3Digest,
    provenance: &ProvenanceDigest,
) -> PlanDigest {
    crate::context::operation_commit_plan_digest(
        context.operation(),
        context.artifact(),
        context.manifest(),
        content_root,
        provenance,
        (context.operation() == Operation::Update).then_some(*context.plan_digest()),
    )
}

pub(super) fn new_installed_state(
    context: &OperationContext,
    authority_digest: AuthorityDecisionDigest,
    artifact: &ValidatedArtifact,
    lifecycle: LifecycleState,
    generation: NonZeroU64,
) -> PackageServiceResult<CanonicalInstalledState> {
    CanonicalInstalledState::new(InstalledStateSpec {
        owner: context.target_owner(),
        package_object: context.package_object(),
        artifact: *context.artifact(),
        content_root: *artifact.content_root(),
        manifest: context.manifest().clone(),
        authority_digest,
        provenance: provenance_digest(artifact.provenance()),
        lifecycle_state: lifecycle,
        lifecycle_plan: *context.plan_digest(),
        generation,
        completing_nonce: context.nonce(),
    })
}

pub(super) fn recorded_drain_deadline(
    state: &CanonicalInstalledState,
    nonce: &Nonce,
) -> PackageServiceResult<Option<Timestamp>> {
    let LifecycleState::Draining {
        deadline,
        nonce: drain_nonce,
        live_leases: _,
        destination: _,
    } = state.lifecycle_state()
    else {
        return Ok(None);
    };
    if drain_nonce.as_bytes() != nonce.as_bytes() {
        return Err(PackageServiceError::LifecycleTransition);
    }
    Ok(Some(*deadline))
}

fn require_open_drain(
    state: &CanonicalInstalledState,
    nonce: &Nonce,
    now: Timestamp,
) -> PackageServiceResult<()> {
    let Some(deadline) = recorded_drain_deadline(state, nonce)? else {
        return Err(PackageServiceError::LifecycleTransition);
    };
    if now >= deadline {
        return Err(PackageServiceError::AuthorityExpired);
    }
    Ok(())
}

fn require_zero_drain(
    state: &CanonicalInstalledState,
    nonce: Nonce,
    destination: DrainDestination,
) -> PackageServiceResult<()> {
    let LifecycleState::Draining {
        destination: observed_destination,
        nonce: observed_nonce,
        live_leases,
        deadline: _,
    } = state.lifecycle_state()
    else {
        return Err(PackageServiceError::LifecycleTransition);
    };
    if observed_destination != &destination
        || observed_nonce.as_bytes() != nonce.as_bytes()
        || live_leases != &0
    {
        return Err(PackageServiceError::DrainBlocked);
    }
    Ok(())
}

pub(super) fn provenance_digest(value: &ProvenanceEvidence) -> ProvenanceDigest {
    let mut writer = DigestWriter::new();
    writer.tag(value.class().tag());
    writer.digest(value.evidence());
    writer.bytes(value.bounded_evidence().as_bytes());
    writer.finish("astrid.package.provenance.v1")
}
