use super::{
    PackageServiceModel, active_drain_lineage, commit_plan_digest, first_state_generation,
    next_generation_value, recorded_drain_deadline, restore_to_boundary_successor,
};
use crate::bytes::RecoveryToken;
use crate::context::{Operation, OperationContext, Timestamp};
use crate::digest::{AuthorityDecisionDigest, PlanDigest, StateDigest};
use crate::error::{PackageServiceError, PackageServiceResult};
use crate::identity::{Nonce, STATE_SCHEMA_VERSION};
use crate::journal::{JournalStatus, OperationReceipt, ReceiptOutcome, RecoveryEvidence};
use crate::state::{
    CanonicalInstalledState, DrainDestination, DrainLineage, LifecycleState, PackageSlot,
};
use std::num::NonZeroU64;

#[derive(Clone)]
struct RecoverySnapshot {
    context: OperationContext,
    authority: AuthorityDecisionDigest,
    token: RecoveryToken,
    before: StateDigest,
    boundary_generation: Option<NonZeroU64>,
    drain_deadline: Option<Timestamp>,
    drain_lineage: Option<DrainLineage>,
    drain_destination: Option<DrainDestination>,
    retained_state: Option<CanonicalInstalledState>,
    staged_commit_plan: Option<PlanDigest>,
}

enum RecoveryEffect {
    RestoreInactive,
    Commit(Option<Box<CanonicalInstalledState>>),
}

impl PackageServiceModel {
    /// Reconciles an unknown record from retained canonical observations.
    pub fn recover(
        &mut self,
        nonce: &Nonce,
        evidence: &RecoveryEvidence,
        now: crate::context::Timestamp,
    ) -> PackageServiceResult<Option<OperationReceipt>> {
        let snapshot = self.recovery_snapshot(nonce)?;
        if snapshot.token.into_bytes() != evidence.token_bytes() {
            return Err(PackageServiceError::RecoveryUnresolved);
        }
        let observed = self.retained_observation(&snapshot, evidence)?;
        self.resolve_recovery(snapshot, evidence, observed.as_ref(), now)
    }

    /// Adjudicates a backend-observed canonical value without retaining trust.
    ///
    /// A successful commit re-derives or restores the only canonical value
    /// admitted by the retained operation contract; the caller's value is
    /// never copied into state merely because its digest was echoed.
    pub fn recover_observed(
        &mut self,
        nonce: &Nonce,
        evidence: &RecoveryEvidence,
        observed: Option<&CanonicalInstalledState>,
        now: crate::context::Timestamp,
    ) -> PackageServiceResult<Option<OperationReceipt>> {
        let snapshot = self.recovery_snapshot(nonce)?;
        if snapshot.token.into_bytes() != evidence.token_bytes() {
            return Err(PackageServiceError::RecoveryUnresolved);
        }
        self.resolve_recovery(snapshot, evidence, observed, now)
    }

    fn recovery_snapshot(&self, nonce: &Nonce) -> PackageServiceResult<RecoverySnapshot> {
        let slot = self
            .nonce_locations
            .get(nonce)
            .copied()
            .ok_or(PackageServiceError::RecordMissing)?;
        let record = self
            .slots
            .get(&slot)
            .and_then(|slot_record| slot_record.journal_record(nonce))
            .ok_or(PackageServiceError::RecordMissing)?;
        if record.status() != JournalStatus::Unknown {
            return Err(PackageServiceError::RecordNotReconcilable);
        }
        let nonce = record.context().nonce();
        let slot_record = self
            .slots
            .get(&slot)
            .ok_or(PackageServiceError::RecordMissing)?;
        let drain_deadline = match slot_record.state() {
            Some(state) => recorded_drain_deadline(state, &nonce)?,
            None => None,
        };
        let (drain_lineage, drain_destination) = match slot_record.state() {
            Some(state) if matches!(state.lifecycle_state(), LifecycleState::Draining { .. }) => {
                let lineage = active_drain_lineage(slot_record, &nonce)?;
                let LifecycleState::Draining { destination, .. } = state.lifecycle_state() else {
                    return Err(PackageServiceError::OccupancyCorruption);
                };
                (Some(lineage), Some(*destination))
            },
            _ => (None, None),
        };
        Ok(RecoverySnapshot {
            context: record.context().clone(),
            authority: *record.authority_digest(),
            token: record.recovery_token(),
            before: record.before_state(),
            boundary_generation: record.state_generation(),
            drain_deadline,
            drain_lineage,
            drain_destination,
            retained_state: slot_record.state().cloned(),
            staged_commit_plan: record.staged_commit_plan().copied(),
        })
    }

    fn retained_observation(
        &self,
        snapshot: &RecoverySnapshot,
        evidence: &RecoveryEvidence,
    ) -> PackageServiceResult<Option<CanonicalInstalledState>> {
        let slot = PackageSlot::new(
            snapshot.context.target_owner(),
            snapshot.context.package_object(),
        );
        let slot_record = self
            .slots
            .get(&slot)
            .ok_or(PackageServiceError::RecordMissing)?;
        slot_record
            .journal_record(&snapshot.context.nonce())
            .ok_or(PackageServiceError::RecordMissing)?;
        if evidence.observed_state().as_bytes() == snapshot.before.as_bytes() {
            let lineage = snapshot
                .drain_lineage
                .as_ref()
                .ok_or(PackageServiceError::RecoveryUnresolved)?;
            if lineage.base_state().digest() != snapshot.before {
                return Err(PackageServiceError::RecoveryUnresolved);
            }
            return Ok(Some(lineage.base_state().clone()));
        }
        Ok(slot_record.state().cloned())
    }

    fn resolve_recovery(
        &mut self,
        snapshot: RecoverySnapshot,
        evidence: &RecoveryEvidence,
        observed: Option<&CanonicalInstalledState>,
        now: crate::context::Timestamp,
    ) -> PackageServiceResult<Option<OperationReceipt>> {
        let effect = recovery_effect(&snapshot, evidence, observed, now)?;
        let slot = PackageSlot::new(
            snapshot.context.target_owner(),
            snapshot.context.package_object(),
        );
        let nonce = snapshot.context.nonce();
        let record_slot = self
            .slots
            .get_mut(&slot)
            .ok_or(PackageServiceError::RecordMissing)?;
        match effect {
            RecoveryEffect::RestoreInactive => {
                let lineage = record_slot
                    .journal_record(&nonce)
                    .and_then(crate::journal::OperationJournalRecord::drain_lineage)
                    .cloned()
                    .ok_or(PackageServiceError::OccupancyCorruption)?;
                let restored = restore_to_boundary_successor(&lineage, &nonce)?;
                let generation = restored.generation_value();
                record_slot.replace_state(Some(restored));
                let journal = record_slot
                    .journal_mut(&nonce)
                    .ok_or(PackageServiceError::RecordMissing)?;
                journal.take_drain_lineage();
                journal.take_staged_commit_plan();
                journal.set_state_generation(generation);
                journal.resolve_recovery(None, JournalStatus::Failed, now);
            },
            RecoveryEffect::Commit(after_state) => {
                let after = after_state.as_deref().map_or_else(
                    || StateDigest::from_bytes([0; 32]),
                    CanonicalInstalledState::digest,
                );
                let receipt = OperationReceipt::new(
                    &snapshot.context,
                    receipt_outcome(snapshot.context.operation())?,
                    snapshot.before,
                    after,
                    exact_successor_generation(&snapshot)?,
                    evidence.activation_receipt(),
                );
                record_slot.replace_state(after_state.map(|state| *state));
                let journal = record_slot
                    .journal_mut(&nonce)
                    .ok_or(PackageServiceError::RecordMissing)?;
                journal.take_drain_lineage();
                journal.take_staged_commit_plan();
                journal.set_state_generation(exact_successor_generation(&snapshot)?);
                journal.resolve_recovery(Some(receipt.clone()), JournalStatus::Committed, now);
                return Ok(Some(receipt));
            },
        }
        Ok(None)
    }
}

fn recovery_effect(
    snapshot: &RecoverySnapshot,
    evidence: &RecoveryEvidence,
    observed: Option<&CanonicalInstalledState>,
    now: Timestamp,
) -> PackageServiceResult<RecoveryEffect> {
    if evidence.observed_state().as_bytes() == snapshot.before.as_bytes() {
        return restore_effect(snapshot, evidence, observed);
    }
    if *evidence.observed_state().as_bytes() == [0; 32] {
        return absence_effect(snapshot, evidence, observed);
    }
    if snapshot.context.operation() == crate::context::Operation::Update {
        let deadline = snapshot
            .drain_deadline
            .ok_or(PackageServiceError::LifecycleTransition)?;
        if now >= deadline {
            return Err(PackageServiceError::AuthorityExpired);
        }
    }
    let state = observed.ok_or(PackageServiceError::RecoveryUnresolved)?;
    if snapshot.context.operation() == crate::context::Operation::Update
        && (snapshot.drain_lineage.is_none()
            || snapshot.drain_destination != Some(DrainDestination::Replacement))
    {
        return Err(PackageServiceError::RecoveryUnresolved);
    }
    validate_observed_state(snapshot, evidence, state)?;
    match snapshot.context.operation() {
        crate::context::Operation::Install => {
            Ok(RecoveryEffect::Commit(Some(Box::new(state.clone()))))
        },
        crate::context::Operation::Update => {
            Ok(RecoveryEffect::Commit(Some(Box::new(state.clone()))))
        },
        crate::context::Operation::Activate => {
            Ok(RecoveryEffect::Commit(Some(Box::new(state.clone()))))
        },
        crate::context::Operation::Deactivate => {
            Ok(RecoveryEffect::Commit(Some(Box::new(state.clone()))))
        },
        crate::context::Operation::Remove | crate::context::Operation::Recover => {
            Err(PackageServiceError::RecoveryUnresolved)
        },
    }
}

fn restore_effect(
    snapshot: &RecoverySnapshot,
    evidence: &RecoveryEvidence,
    observed: Option<&CanonicalInstalledState>,
) -> PackageServiceResult<RecoveryEffect> {
    if !matches!(
        snapshot.context.operation(),
        crate::context::Operation::Update | crate::context::Operation::Remove
    ) {
        return Err(PackageServiceError::RecoveryUnresolved);
    }
    let state = observed.ok_or(PackageServiceError::RecoveryUnresolved)?;
    let lineage = snapshot
        .drain_lineage
        .as_ref()
        .ok_or(PackageServiceError::RecoveryUnresolved)?;
    let base = lineage.base_state();
    let expected_generation = base.generation_value();
    if evidence.activation_receipt().is_some() {
        return Err(PackageServiceError::BindingMismatch);
    }
    if state.digest() != snapshot.before
        || lineage.base_state().digest() != snapshot.before
        || state != base
        || !state.has_valid_digest()
        || state.schema_version() != STATE_SCHEMA_VERSION
        || state.generation_value() != expected_generation
        || evidence.runtime_generation() != expected_generation
        || state.authority_digest().as_bytes() == &[0; 32]
        || state.lifecycle_plan().as_bytes() == &[0; 32]
        || matches!(state.lifecycle_state(), LifecycleState::Draining { .. })
    {
        return Err(PackageServiceError::RecoveryUnresolved);
    }
    Ok(RecoveryEffect::RestoreInactive)
}

fn absence_effect(
    snapshot: &RecoverySnapshot,
    evidence: &RecoveryEvidence,
    observed: Option<&CanonicalInstalledState>,
) -> PackageServiceResult<RecoveryEffect> {
    if snapshot.context.operation() != crate::context::Operation::Remove
        || snapshot.drain_lineage.is_none()
        || snapshot.drain_destination != Some(DrainDestination::Removal)
        || observed.is_some()
        || !evidence.zero_leases_proved()
    {
        return Err(PackageServiceError::RecoveryUnresolved);
    }
    let generation = exact_successor_generation(snapshot)?;
    if evidence.activation_receipt().is_some() {
        return Err(PackageServiceError::BindingMismatch);
    }
    if evidence.runtime_generation() != generation {
        return Err(PackageServiceError::RecoveryUnresolved);
    }
    Ok(RecoveryEffect::Commit(None))
}

fn validate_observed_state(
    snapshot: &RecoverySnapshot,
    evidence: &RecoveryEvidence,
    state: &CanonicalInstalledState,
) -> PackageServiceResult<()> {
    let expected_commit_plan =
        commit_plan_digest(&snapshot.context, state.content_root(), state.provenance());
    if matches!(
        snapshot.context.operation(),
        crate::context::Operation::Install | crate::context::Operation::Update
    ) && snapshot.staged_commit_plan != Some(expected_commit_plan)
    {
        return Err(PackageServiceError::RecoveryUnresolved);
    }
    if state.digest() != evidence.observed_state()
        || !state.has_valid_digest()
        || state.schema_version() != STATE_SCHEMA_VERSION
        || state.generation_value() != exact_successor_generation(snapshot)?
        || evidence.runtime_generation() != exact_successor_generation(snapshot)?
        || state.slot()
            != PackageSlot::new(
                snapshot.context.target_owner(),
                snapshot.context.package_object(),
            )
        || state.completing_nonce() != snapshot.context.nonce()
        || state.authority_digest() != &snapshot.authority
        || state.artifact() != snapshot.context.artifact()
        || state.manifest() != snapshot.context.manifest()
        || state.lifecycle_plan() != snapshot.context.plan_digest()
        || state.content_root().as_bytes() == &[0; 32]
        || state.provenance().as_bytes() == &[0; 32]
        || *state.lifecycle_state() != expected_lifecycle(snapshot.context.operation())
    {
        return Err(PackageServiceError::RecoveryUnresolved);
    }
    if matches!(
        snapshot.context.operation(),
        crate::context::Operation::Activate | crate::context::Operation::Deactivate
    ) {
        let baseline = snapshot
            .retained_state
            .as_ref()
            .ok_or(PackageServiceError::RecoveryUnresolved)?;
        if state.content_root() != baseline.content_root()
            || state.provenance() != baseline.provenance()
        {
            return Err(PackageServiceError::RecoveryUnresolved);
        }
    }
    if snapshot.context.operation() == crate::context::Operation::Activate {
        if evidence.activation_receipt().is_none() {
            return Err(PackageServiceError::BindingMismatch);
        }
    } else if evidence.activation_receipt().is_some() {
        return Err(PackageServiceError::BindingMismatch);
    }
    if matches!(
        snapshot.context.operation(),
        crate::context::Operation::Update | crate::context::Operation::Remove
    ) && !evidence.zero_leases_proved()
    {
        return Err(PackageServiceError::DrainBlocked);
    }
    Ok(())
}

fn exact_successor_generation(snapshot: &RecoverySnapshot) -> PackageServiceResult<NonZeroU64> {
    if snapshot.context.operation() == crate::context::Operation::Install {
        return first_state_generation();
    }
    if let Some(lineage) = snapshot.drain_lineage.as_ref() {
        return next_generation_value(lineage.boundary_generation());
    }
    next_generation_value(
        snapshot
            .boundary_generation
            .ok_or(PackageServiceError::RecoveryUnresolved)?,
    )
}

fn expected_lifecycle(operation: crate::context::Operation) -> LifecycleState {
    match operation {
        crate::context::Operation::Activate => LifecycleState::Active,
        crate::context::Operation::Install
        | crate::context::Operation::Update
        | crate::context::Operation::Deactivate
        | crate::context::Operation::Remove
        | crate::context::Operation::Recover => LifecycleState::Inactive,
    }
}

fn receipt_outcome(operation: Operation) -> PackageServiceResult<ReceiptOutcome> {
    match operation {
        Operation::Install => Ok(ReceiptOutcome::Installed),
        Operation::Update => Ok(ReceiptOutcome::Updated),
        Operation::Activate => Ok(ReceiptOutcome::Activated),
        Operation::Deactivate => Ok(ReceiptOutcome::Deactivated),
        Operation::Remove => Ok(ReceiptOutcome::Retired),
        Operation::Recover => Err(PackageServiceError::RecordNotReconcilable),
    }
}
