use crate::authority::AuthenticatedAuthority;
use crate::context::{
    AdmittedService, AuthenticatedIngress, Operation, OperationContext, Timestamp,
};
use crate::digest::{Blake3Digest, DigestWriter, ProvenanceDigest, StateDigest};
use crate::error::{PackageServiceError, PackageServiceResult};
use crate::identity::{Nonce, ProvenanceEvidence, ValidatedArtifact};
use crate::journal::{
    DrainPlan, DrainResult, JournalStatus, OperationJournalRecord, OperationReceipt,
    PackageSlotRecord, ReceiptOutcome, ReplayOutcome, Tombstone,
};
use crate::policy::{JournalPolicy, Occupancy};
use crate::state::{
    CanonicalInstalledState, DrainDestination, ExpectedPackageState, InstalledStateSpec,
    LifecycleState, PackageSlot,
};
use std::collections::BTreeMap;
use std::num::NonZeroU64;

mod recovery;

/// Pure executable owner/package state model.
#[derive(Debug)]
pub struct PackageServiceModel {
    policy: JournalPolicy,
    slots: BTreeMap<PackageSlot, PackageSlotRecord>,
    nonce_locations: BTreeMap<Nonce, PackageSlot>,
    tombstones: BTreeMap<Nonce, Tombstone>,
    occupancy: Occupancy,
}

impl PackageServiceModel {
    /// Creates a model governed by the supplied bounded policy.
    #[must_use]
    pub fn new(policy: JournalPolicy) -> Self {
        Self {
            policy,
            slots: BTreeMap::new(),
            nonce_locations: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            occupancy: Occupancy::default(),
        }
    }

    /// Returns the canonical slot value.
    #[must_use]
    pub fn slot_record(&self, slot: &PackageSlot) -> Option<&PackageSlotRecord> {
        self.slots.get(slot)
    }

    /// Returns current occupancy.
    #[must_use]
    pub const fn occupancy(&self) -> Occupancy {
        self.occupancy
    }

    /// Durably represents an intent before any budgeted model effect.
    pub fn begin(
        &mut self,
        context: OperationContext,
        authority: &AuthenticatedAuthority,
        ingress: AuthenticatedIngress,
        service: &AdmittedService,
        now: Timestamp,
    ) -> PackageServiceResult<Nonce> {
        if context.protocol_version().get() != crate::identity::PROTOCOL_VERSION.get() {
            return Err(PackageServiceError::ProtocolVersion);
        }
        if now >= context.expiry() {
            return Err(PackageServiceError::AuthorityExpired);
        }
        authority.verify(&context, &ingress, service, now)?;
        let slot = PackageSlot::new(context.target_owner(), context.package_object());
        self.validate_current_state(&slot, context.expected_state(), context.operation())?;
        if self.nonce_locations.contains_key(&context.nonce())
            || self.tombstones.contains_key(&context.nonce())
        {
            return Err(PackageServiceError::ReplayRejected);
        }
        if self.slot_record(&slot).is_some_and(|record| {
            record
                .journal_values()
                .any(|entry| entry.status().is_unresolved())
        }) {
            return Err(PackageServiceError::RecordNotReconcilable);
        }
        if let Some(state) = self.slot_record(&slot).and_then(PackageSlotRecord::state) {
            self.validate_context_bindings(&context, state)?;
        }

        let current_generation = self
            .slot_record(&slot)
            .and_then(|record| record.state())
            .map(CanonicalInstalledState::generation_value);
        let record = OperationJournalRecord::new_intent(
            context,
            authority.decision_digest(),
            &ingress,
            service,
            now,
            current_generation,
        );
        let record_bytes = record.encoded_len();
        self.collect(now, self.policy.collection_batch_limit())?;
        if !self
            .policy
            .has_admission_room(&self.occupancy, record_bytes)
        {
            return Err(self.policy.admission_error());
        }
        let nonce = record.context().nonce();
        self.slots.entry(slot).or_default().insert_intent(record)?;
        self.occupancy.add_record(record_bytes);
        self.nonce_locations.insert(nonce, slot);
        Ok(nonce)
    }

    fn validate_current_state(
        &self,
        slot: &PackageSlot,
        expected: &ExpectedPackageState,
        operation: Operation,
    ) -> PackageServiceResult<()> {
        let actual = self.slots.get(slot).map_or_else(
            || StateDigest::from_bytes([0; 32]),
            PackageSlotRecord::expected_state_digest,
        );
        if !expected.matches_digest(actual) {
            return Err(PackageServiceError::ExpectedStateMismatch);
        }
        let lifecycle = self
            .slots
            .get(slot)
            .and_then(|record| record.state())
            .map(|state| state.lifecycle_state());
        let valid = matches!(
            (operation, lifecycle),
            (Operation::Install, None)
                | (
                    Operation::Update,
                    Some(LifecycleState::Inactive) | Some(LifecycleState::Active)
                )
                | (Operation::Activate, Some(LifecycleState::Inactive))
                | (Operation::Deactivate, Some(LifecycleState::Active))
                | (
                    Operation::Remove,
                    Some(LifecycleState::Inactive) | Some(LifecycleState::Active)
                )
        );
        if valid {
            Ok(())
        } else {
            Err(PackageServiceError::LifecycleTransition)
        }
    }

    fn validate_context_bindings(
        &self,
        context: &OperationContext,
        state: &CanonicalInstalledState,
    ) -> PackageServiceResult<()> {
        if !matches!(
            context.operation(),
            Operation::Activate | Operation::Deactivate | Operation::Remove
        ) {
            return Ok(());
        }
        if context.artifact() != state.artifact() || context.manifest() != state.manifest() {
            return Err(PackageServiceError::BindingMismatch);
        }
        if context.operation() != Operation::Remove {
            let expected_plan = context
                .expected_state()
                .lifecycle_plan_digest(context.operation())?;
            if context.plan_digest() != &expected_plan {
                return Err(PackageServiceError::BindingMismatch);
            }
        }
        Ok(())
    }

    fn record_mut(&mut self, nonce: &Nonce) -> PackageServiceResult<&mut OperationJournalRecord> {
        let slot = self
            .nonce_locations
            .get(nonce)
            .copied()
            .ok_or(PackageServiceError::RecordMissing)?;
        self.slots
            .get_mut(&slot)
            .and_then(|record| record.journal_mut(nonce))
            .ok_or(PackageServiceError::RecordMissing)
    }

    fn context_for(&self, nonce: &Nonce) -> PackageServiceResult<OperationContext> {
        let slot = self
            .nonce_locations
            .get(nonce)
            .copied()
            .ok_or(PackageServiceError::RecordMissing)?;
        self.slots
            .get(&slot)
            .and_then(|record| record.journal_record(nonce))
            .map(|record| record.context().clone())
            .ok_or(PackageServiceError::RecordMissing)
    }

    /// Moves an intent to executing after checking authority expiry.
    pub fn begin_work(&mut self, nonce: &Nonce, now: Timestamp) -> PackageServiceResult<()> {
        let expiry = self.context_for(nonce)?.expiry();
        if now >= expiry {
            return Err(PackageServiceError::AuthorityExpired);
        }
        let record = self.record_mut(nonce)?;
        if record.status() != JournalStatus::Intent {
            return Err(PackageServiceError::RecordNotReconcilable);
        }
        record.set_executing(now);
        Ok(())
    }

    /// Durably places the exact state into a bounded drain.
    pub fn begin_drain(
        &mut self,
        nonce: &Nonce,
        destination: DrainDestination,
        deadline: Timestamp,
        live_leases: u32,
        now: Timestamp,
    ) -> PackageServiceResult<()> {
        let context = self.context_for(nonce)?;
        let required = match destination {
            DrainDestination::Replacement => Operation::Update,
            DrainDestination::Removal => Operation::Remove,
        };
        if context.operation() != required || deadline > context.expiry() || deadline <= now {
            return Err(PackageServiceError::BindingMismatch);
        }
        let slot_for_plan = self
            .nonce_locations
            .get(nonce)
            .copied()
            .ok_or(PackageServiceError::RecordMissing)?;
        let current_digest = self
            .slots
            .get(&slot_for_plan)
            .and_then(PackageSlotRecord::state)
            .map(CanonicalInstalledState::digest)
            .ok_or(PackageServiceError::LifecycleTransition)?;
        let plan = DrainPlan::new(
            destination,
            ExpectedPackageState::Exact(current_digest),
            deadline,
            *nonce,
        )
        .map_err(|_| PackageServiceError::BindingMismatch)?;
        if *context.plan_digest() != plan.digest() {
            return Err(PackageServiceError::BindingMismatch);
        }
        self.begin_work(nonce, now)?;
        let slot = self
            .nonce_locations
            .get(nonce)
            .copied()
            .ok_or(PackageServiceError::RecordMissing)?;
        let Some(record) = self.slots.get_mut(&slot) else {
            return Err(PackageServiceError::RecordMissing);
        };
        let Some(state) = record.state().cloned() else {
            return Err(PackageServiceError::LifecycleTransition);
        };
        let base_state = state.clone();
        let generation = next_generation(&state)?;
        let mut replacement = state;
        replacement.set_lifecycle_result(
            LifecycleState::Draining {
                destination,
                deadline,
                nonce: *nonce,
                live_leases,
            },
            *context.plan_digest(),
            generation,
            *nonce,
        );
        if let Some(journal) = record.journal_mut(nonce) {
            journal.set_drain_base_state(base_state);
        }
        record.replace_state(Some(replacement.clone()));
        let journal = record
            .journal_mut(nonce)
            .ok_or(PackageServiceError::RecordMissing)?;
        journal.set_state_generation(generation);
        Ok(())
    }

    /// Records independently proved runtime lease count without completing the drain.
    pub fn prove_drain_leases(
        &mut self,
        nonce: &Nonce,
        live_leases: u32,
        now: Timestamp,
    ) -> PackageServiceResult<()> {
        let context = self.context_for(nonce)?;
        if now >= context.expiry() {
            return Err(PackageServiceError::AuthorityExpired);
        }
        let slot = self
            .nonce_locations
            .get(nonce)
            .copied()
            .ok_or(PackageServiceError::RecordMissing)?;
        let record = self
            .slots
            .get_mut(&slot)
            .ok_or(PackageServiceError::RecordMissing)?;
        let Some(state) = record.state().cloned() else {
            return Err(PackageServiceError::LifecycleTransition);
        };
        let LifecycleState::Draining {
            deadline,
            nonce: drain_nonce,
            live_leases: _,
            destination,
        } = state.lifecycle_state()
        else {
            return Err(PackageServiceError::LifecycleTransition);
        };
        if drain_nonce.as_bytes() != nonce.as_bytes() {
            return Err(PackageServiceError::LifecycleTransition);
        }
        if now >= *deadline {
            return Err(PackageServiceError::AuthorityExpired);
        }
        let deadline = *deadline;
        let destination = *destination;
        let generation = next_generation(&state)?;
        let mut replacement = state;
        replacement.set_lifecycle_result(
            LifecycleState::Draining {
                destination,
                deadline,
                nonce: *nonce,
                live_leases,
            },
            *context.plan_digest(),
            generation,
            *nonce,
        );
        record.replace_state(Some(replacement));
        let journal = record
            .journal_mut(nonce)
            .ok_or(PackageServiceError::RecordMissing)?;
        journal.set_state_generation(generation);
        Ok(())
    }

    /// Commits install, update, activation, deactivation, or final retirement.
    pub fn complete(
        &mut self,
        nonce: &Nonce,
        artifact: Option<&ValidatedArtifact>,
        activation_receipt: Option<Blake3Digest>,
        zero_leases_proved: bool,
        now: Timestamp,
    ) -> PackageServiceResult<OperationReceipt> {
        let context = self.context_for(nonce)?;
        if now >= context.expiry() {
            return Err(PackageServiceError::AuthorityExpired);
        }
        let receipt_allowed = if context.operation() == Operation::Activate {
            activation_receipt.is_some_and(|receipt| receipt.as_bytes() != &[0; 32])
        } else {
            activation_receipt.is_none()
        };
        if !receipt_allowed {
            return Err(PackageServiceError::BindingMismatch);
        }
        let slot = self
            .nonce_locations
            .get(nonce)
            .copied()
            .ok_or(PackageServiceError::RecordMissing)?;
        let record_slot = self
            .slots
            .get_mut(&slot)
            .ok_or(PackageServiceError::RecordMissing)?;
        let journal_status = record_slot
            .journal_record(nonce)
            .map(|record| record.status())
            .ok_or(PackageServiceError::RecordMissing)?;
        let before = record_slot
            .journal_record(nonce)
            .map(|record| record.before_state())
            .ok_or(PackageServiceError::RecordMissing)?;
        let authority_digest = record_slot
            .journal_record(nonce)
            .map(|record| *record.authority_digest())
            .ok_or(PackageServiceError::RecordMissing)?;
        if journal_status != JournalStatus::Executing {
            return Err(PackageServiceError::RecordNotReconcilable);
        }

        let (after_state, outcome, generation) = match context.operation() {
            Operation::Install => {
                let artifact = artifact.ok_or(PackageServiceError::BindingMismatch)?;
                validate_context_artifact(&context, artifact)?;
                let state = new_installed_state(
                    &context,
                    authority_digest,
                    artifact,
                    LifecycleState::Inactive,
                    first_state_generation()?,
                )?;
                let generation = state.generation_value();
                record_slot.replace_state(Some(state));
                (
                    record_slot.expected_state_digest(),
                    ReceiptOutcome::Installed,
                    generation,
                )
            },
            Operation::Update => {
                let artifact = artifact.ok_or(PackageServiceError::BindingMismatch)?;
                validate_context_artifact(&context, artifact)?;
                let Some(state) = record_slot.state().cloned() else {
                    return Err(PackageServiceError::LifecycleTransition);
                };
                require_open_drain(&state, nonce, now)?;
                require_zero_drain(&state, *nonce, DrainDestination::Replacement)?;
                if !zero_leases_proved {
                    return Err(PackageServiceError::DrainBlocked);
                }
                let replacement = new_installed_state(
                    &context,
                    authority_digest,
                    artifact,
                    LifecycleState::Inactive,
                    next_generation(&state)?,
                )?;
                let generation = replacement.generation_value();
                record_slot.replace_state(Some(replacement));
                (
                    record_slot.expected_state_digest(),
                    ReceiptOutcome::Updated,
                    generation,
                )
            },
            Operation::Activate | Operation::Deactivate => {
                let Some(state) = record_slot.state().cloned() else {
                    return Err(PackageServiceError::LifecycleTransition);
                };
                let next_lifecycle = if context.operation() == Operation::Activate {
                    LifecycleState::Active
                } else {
                    LifecycleState::Inactive
                };
                let generation = next_generation(&state)?;
                let mut replacement = state;
                replacement.set_lifecycle_result(
                    next_lifecycle,
                    *context.plan_digest(),
                    generation,
                    *nonce,
                );
                record_slot.replace_state(Some(replacement));
                (
                    record_slot.expected_state_digest(),
                    if context.operation() == Operation::Activate {
                        ReceiptOutcome::Activated
                    } else {
                        ReceiptOutcome::Deactivated
                    },
                    generation,
                )
            },
            Operation::Remove => {
                let Some(state) = record_slot.state().cloned() else {
                    return Err(PackageServiceError::LifecycleTransition);
                };
                require_open_drain(&state, nonce, now)?;
                require_zero_drain(&state, *nonce, DrainDestination::Removal)?;
                if !zero_leases_proved {
                    return Err(PackageServiceError::DrainBlocked);
                }
                let generation = next_generation(&state)?;
                record_slot.replace_state(None);
                (
                    record_slot.expected_state_digest(),
                    ReceiptOutcome::Retired,
                    generation,
                )
            },
            Operation::Recover => return Err(PackageServiceError::RecordNotReconcilable),
        };
        let receipt = OperationReceipt::new(
            &context,
            outcome,
            before,
            after_state,
            generation,
            activation_receipt,
        );
        let journal = record_slot
            .journal_mut(nonce)
            .ok_or(PackageServiceError::RecordMissing)?;
        journal.set_state_generation(generation);
        journal.commit(receipt.clone(), now);
        Ok(receipt)
    }

    /// Moves an executing result to unknown after an uncertain boundary.
    pub fn mark_unknown(&mut self, nonce: &Nonce, now: Timestamp) -> PackageServiceResult<()> {
        let record = self.record_mut(nonce)?;
        if record.status() != JournalStatus::Executing {
            return Err(PackageServiceError::RecordNotReconcilable);
        }
        record.mark_unknown(now);
        Ok(())
    }

    /// Cancels advisory work only before an unknown commit boundary.
    pub fn cancel(&mut self, nonce: &Nonce, now: Timestamp) -> PackageServiceResult<()> {
        let context = self.context_for(nonce)?;
        if now >= context.expiry() {
            return Err(PackageServiceError::AuthorityExpired);
        }
        let slot = self
            .nonce_locations
            .get(nonce)
            .copied()
            .ok_or(PackageServiceError::RecordMissing)?;
        let record_slot = self
            .slots
            .get_mut(&slot)
            .ok_or(PackageServiceError::RecordMissing)?;
        let cancellable = record_slot.journal_record(nonce).is_some_and(|record| {
            matches!(
                record.status(),
                JournalStatus::Intent | JournalStatus::Executing
            )
        });
        if !cancellable {
            return Err(PackageServiceError::RecordNotReconcilable);
        }
        if let Some(state) = record_slot.state().cloned()
            && let Some(deadline) = recorded_drain_deadline(&state, nonce)?
        {
            if now >= deadline {
                return Err(PackageServiceError::LifecycleTransition);
            }
            let restored = record_slot
                .journal_mut(nonce)
                .and_then(OperationJournalRecord::take_drain_base_state)
                .ok_or(PackageServiceError::OccupancyCorruption)?;
            let safe_restored = restore_prior_content(restored, *nonce)?;
            record_slot.replace_state(Some(safe_restored));
        }
        let journal = record_slot
            .journal_mut(nonce)
            .ok_or(PackageServiceError::RecordMissing)?;
        journal.terminal_failure(JournalStatus::Aborted, now);
        Ok(())
    }

    /// Advances a drain at or after its deadline without inventing retirement.
    pub fn expire_drain(
        &mut self,
        nonce: &Nonce,
        now: Timestamp,
        zero_leases_proved: bool,
    ) -> PackageServiceResult<DrainResult> {
        let _context = self.context_for(nonce)?;
        let slot = self
            .nonce_locations
            .get(nonce)
            .copied()
            .ok_or(PackageServiceError::RecordMissing)?;
        let record_slot = self
            .slots
            .get_mut(&slot)
            .ok_or(PackageServiceError::RecordMissing)?;
        let Some(state) = record_slot.state().cloned() else {
            return Err(PackageServiceError::LifecycleTransition);
        };
        let LifecycleState::Draining {
            deadline,
            nonce: drain_nonce,
            live_leases,
            destination,
        } = state.lifecycle_state()
        else {
            return Err(PackageServiceError::LifecycleTransition);
        };
        if drain_nonce.as_bytes() != nonce.as_bytes() || now < *deadline {
            return Err(PackageServiceError::LifecycleTransition);
        }
        if *live_leases > 0 || !zero_leases_proved {
            let journal = record_slot
                .journal_mut(nonce)
                .ok_or(PackageServiceError::RecordMissing)?;
            journal.mark_unknown(now);
            return Ok(DrainResult::Blocked);
        }
        if *destination == DrainDestination::Removal {
            let generation = record_slot
                .journal_record(nonce)
                .and_then(OperationJournalRecord::state_generation)
                .map(next_generation_value)
                .transpose()?;
            record_slot.replace_state(None);
            let journal = record_slot
                .journal_mut(nonce)
                .ok_or(PackageServiceError::RecordMissing)?;
            if let Some(generation) = generation {
                journal.set_state_generation(generation);
            }
            journal.terminal_failure(JournalStatus::Expired, now);
            return Ok(DrainResult::Completed);
        }
        let restored = record_slot
            .journal_mut(nonce)
            .and_then(OperationJournalRecord::take_drain_base_state)
            .ok_or(PackageServiceError::OccupancyCorruption)?;
        let safe_restored = restore_prior_content(restored, *nonce)?;
        record_slot.replace_state(Some(safe_restored));
        let journal = record_slot
            .journal_mut(nonce)
            .ok_or(PackageServiceError::RecordMissing)?;
        journal.terminal_failure(JournalStatus::Expired, now);
        Ok(DrainResult::Completed)
    }

    /// Makes an authority-expired admission explicitly terminal or recoverable.
    pub fn expire_unresolved(&mut self, nonce: &Nonce, now: Timestamp) -> PackageServiceResult<()> {
        let context = self.context_for(nonce)?;
        if now < context.expiry() {
            return Err(PackageServiceError::AuthorityExpired);
        }
        let record = self.record_mut(nonce)?;
        match record.status() {
            JournalStatus::Intent => {
                record.terminal_failure(JournalStatus::Expired, now);
                Ok(())
            },
            JournalStatus::Executing => {
                record.mark_unknown(now);
                Ok(())
            },
            _ => Err(PackageServiceError::RecordNotReconcilable),
        }
    }

    /// Replays a retained receipt or distinguishes collection from loss.
    pub fn replay(
        &self,
        nonce: &Nonce,
        context_digest: Option<crate::digest::ContextDigest>,
    ) -> PackageServiceResult<ReplayOutcome> {
        if let Some(tombstone) = self.tombstones.get(nonce) {
            if let Some(requested) = context_digest
                && tombstone.context_digest() != requested
            {
                return Err(PackageServiceError::ReplayRejected);
            }
            return Ok(ReplayOutcome::Tombstoned(tombstone.clone()));
        }
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
        if let Some(requested) = context_digest
            && *record.context().digest() != requested
        {
            return Err(PackageServiceError::ReplayRejected);
        }
        if let Some(receipt) = record.receipt() {
            return Ok(ReplayOutcome::Receipt(receipt.clone()));
        }
        Ok(ReplayOutcome::Unresolved)
    }

    /// Performs one bounded collection pass; unresolved records are never eligible.
    pub fn collect(&mut self, now: Timestamp, batch_limit: u64) -> PackageServiceResult<u64> {
        let (occupied_records, occupied_bytes, tombstones) = self.occupancy.values();
        let mut actual_records = 0u64;
        let mut actual_bytes = 0u64;
        for slot_record in self.slots.values() {
            for record in slot_record.journal_values() {
                actual_records = actual_records
                    .checked_add(1)
                    .ok_or(PackageServiceError::OccupancyCorruption)?;
                actual_bytes = actual_bytes
                    .checked_add(record.encoded_len())
                    .ok_or(PackageServiceError::OccupancyCorruption)?;
            }
        }
        if actual_records != occupied_records || actual_bytes != occupied_bytes {
            return Err(PackageServiceError::OccupancyCorruption);
        }

        let mut selected = Vec::new();
        for (slot, slot_record) in &self.slots {
            for record in slot_record.journal_values() {
                if selected.len() as u64 == batch_limit {
                    break;
                }
                if self.policy.retention_eligible(record, now) {
                    selected.push((*slot, record.context().nonce()));
                }
            }
        }
        let selected_count =
            u64::try_from(selected.len()).map_err(PackageServiceError::IntegerBounds)?;
        let tombstone_room = self
            .policy
            .tombstone_capacity()
            .checked_sub(tombstones)
            .ok_or(PackageServiceError::OccupancyCorruption)?;
        if selected_count > tombstone_room {
            return Err(PackageServiceError::QuotaExhausted);
        }

        let mut collected = 0u64;
        for (slot, nonce) in selected {
            let slot_record = self
                .slots
                .get_mut(&slot)
                .ok_or(PackageServiceError::OccupancyCorruption)?;
            let tombstone = slot_record
                .remove_journal(&nonce)
                .ok_or(PackageServiceError::OccupancyCorruption)?;
            self.occupancy.remove_record(1024);
            self.occupancy.add_tombstone();
            self.tombstones.insert(nonce, tombstone);
            self.nonce_locations.remove(&nonce);
            collected = collected
                .checked_add(1)
                .ok_or(PackageServiceError::GenerationOverflow)?;
        }
        Ok(collected)
    }
}

fn validate_context_artifact(
    context: &OperationContext,
    artifact: &ValidatedArtifact,
) -> PackageServiceResult<()> {
    if context.artifact() != artifact.artifact() || context.manifest() != artifact.manifest() {
        return Err(PackageServiceError::BindingMismatch);
    }
    Ok(())
}

fn new_installed_state(
    context: &OperationContext,
    authority_digest: crate::digest::AuthorityDecisionDigest,
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

fn first_state_generation() -> PackageServiceResult<NonZeroU64> {
    NonZeroU64::new(1).ok_or(PackageServiceError::InvalidValue("package generation"))
}

fn recorded_drain_deadline(
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

fn restore_prior_content(
    state: CanonicalInstalledState,
    completing_nonce: Nonce,
) -> PackageServiceResult<CanonicalInstalledState> {
    let generation = next_generation(&state)?;
    restore_prior_content_to_successor(state, completing_nonce, generation)
}

fn restore_prior_content_to_successor(
    state: CanonicalInstalledState,
    completing_nonce: Nonce,
    generation: NonZeroU64,
) -> PackageServiceResult<CanonicalInstalledState> {
    let plan = *state.lifecycle_plan();
    let mut restored = state;
    restored.set_lifecycle_result(LifecycleState::Inactive, plan, generation, completing_nonce);
    Ok(restored)
}

fn next_generation(state: &CanonicalInstalledState) -> PackageServiceResult<NonZeroU64> {
    next_generation_value(state.generation_value())
}

fn next_generation_value(generation: NonZeroU64) -> PackageServiceResult<NonZeroU64> {
    let value = generation
        .get()
        .checked_add(1)
        .ok_or(PackageServiceError::GenerationOverflow)?;
    NonZeroU64::try_from(value).map_err(PackageServiceError::from)
}

fn provenance_digest(value: &ProvenanceEvidence) -> ProvenanceDigest {
    let mut writer = DigestWriter::new();
    writer.tag(value.class().tag());
    writer.digest(value.evidence());
    writer.bytes(value.bounded_evidence().as_bytes());
    writer.finish("astrid.package.provenance.v1")
}

#[cfg(test)]
mod tests;
