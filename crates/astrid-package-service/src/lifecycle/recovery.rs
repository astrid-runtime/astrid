use super::{
    PackageServiceModel, first_state_generation, next_generation_value, recorded_drain_deadline,
    restore_prior_content_to_successor,
};
use crate::bytes::RecoveryToken;
use crate::context::{Operation, OperationContext, Timestamp};
use crate::digest::{AuthorityDecisionDigest, StateDigest};
use crate::error::{PackageServiceError, PackageServiceResult};
use crate::identity::{Nonce, STATE_SCHEMA_VERSION};
use crate::journal::{JournalStatus, OperationReceipt, ReceiptOutcome, RecoveryEvidence};
use crate::state::{CanonicalInstalledState, LifecycleState, PackageSlot};
use std::num::NonZeroU64;

#[derive(Clone)]
struct RecoverySnapshot {
    context: OperationContext,
    authority: AuthorityDecisionDigest,
    token: RecoveryToken,
    before: StateDigest,
    boundary_generation: Option<NonZeroU64>,
    drain_deadline: Option<Timestamp>,
    base_state: Option<CanonicalInstalledState>,
}

enum RecoveryEffect {
    RestoreInactive { generation: NonZeroU64 },
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
        let drain_deadline = match self
            .slots
            .get(&slot)
            .and_then(|slot_record| slot_record.state())
        {
            Some(state) => recorded_drain_deadline(state, &nonce)?,
            None => None,
        };
        Ok(RecoverySnapshot {
            context: record.context().clone(),
            authority: *record.authority_digest(),
            token: record.recovery_token(),
            before: record.before_state(),
            boundary_generation: record.state_generation(),
            drain_deadline,
            base_state: record.drain_base_state().cloned(),
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
            let record = slot_record
                .journal_record(&snapshot.context.nonce())
                .ok_or(PackageServiceError::RecordMissing)?;
            return Ok(record.drain_base_state().cloned());
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
            RecoveryEffect::RestoreInactive { generation } => {
                let base = record_slot
                    .journal_mut(&nonce)
                    .and_then(crate::journal::OperationJournalRecord::take_drain_base_state)
                    .ok_or(PackageServiceError::OccupancyCorruption)?;
                let restored = restore_prior_content_to_successor(base, nonce, generation)?;
                let generation = restored.generation_value();
                record_slot.replace_state(Some(restored));
                let journal = record_slot
                    .journal_mut(&nonce)
                    .ok_or(PackageServiceError::RecordMissing)?;
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
    let expected_base = snapshot
        .base_state
        .as_ref()
        .ok_or(PackageServiceError::RecoveryUnresolved)?;
    if state != expected_base {
        return Err(PackageServiceError::RecoveryUnresolved);
    }
    let expected_generation = snapshot
        .boundary_generation
        .and_then(|generation| generation.get().checked_sub(1))
        .and_then(NonZeroU64::new)
        .ok_or(PackageServiceError::RecoveryUnresolved)?;
    if state.digest() != snapshot.before
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
    let generation = next_generation_value(
        snapshot
            .boundary_generation
            .ok_or(PackageServiceError::RecoveryUnresolved)?,
    )?;
    Ok(RecoveryEffect::RestoreInactive { generation })
}

fn absence_effect(
    snapshot: &RecoverySnapshot,
    evidence: &RecoveryEvidence,
    observed: Option<&CanonicalInstalledState>,
) -> PackageServiceResult<RecoveryEffect> {
    if snapshot.context.operation() != crate::context::Operation::Remove
        || observed.is_some()
        || !evidence.zero_leases_proved()
    {
        return Err(PackageServiceError::RecoveryUnresolved);
    }
    let generation = exact_successor_generation(snapshot)?;
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
