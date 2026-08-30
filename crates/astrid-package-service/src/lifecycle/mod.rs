use crate::authority::AuthenticatedAuthority;
use crate::context::{
    AdmittedService, AuthenticatedIngress, Operation, OperationContext, Timestamp,
};
use crate::digest::{Blake3Digest, StateDigest};
use crate::error::{PackageServiceError, PackageServiceResult};
use crate::identity::{Nonce, ValidatedArtifact};
use crate::journal::{
    DrainPlan, DrainResult, JournalStatus, OperationJournalRecord, OperationReceipt,
    PackageSlotRecord, ReplayOutcome, Tombstone,
};
use crate::policy::{JournalPolicy, Occupancy};
use crate::state::{
    CanonicalInstalledState, DrainDestination, DrainLineage, ExpectedPackageState, LifecycleState,
    PackageSlot,
};
use std::collections::BTreeMap;

mod commit;
mod generation;
mod lineage;
mod recovery;

use self::commit::{
    DrainProof, commit_install, commit_plan_digest, commit_record_metadata, commit_removal,
    commit_retained_state, commit_update, provenance_digest, recorded_drain_deadline,
    validate_context_artifact,
};
use self::generation::{next_generation, next_generation_value, next_transition_generation};
use self::lineage::{active_drain_lineage, restore_to_boundary_successor};

#[cfg(test)]
use self::commit::new_installed_state;
#[cfg(test)]
use self::generation::next_generation_from_high_watermark;

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
    ///
    /// # Errors
    /// Returns typed admission failures before any durable intent is inserted.
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
            Self::validate_context_bindings(&context, state)?;
        }
        next_transition_generation(self.slots.get(&slot), context.operation())?;

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
            return Err(JournalPolicy::admission_error());
        }
        let nonce = record.context().nonce();
        self.slots.entry(slot).or_default().insert_intent(record)?;
        self.occupancy.add_record(record_bytes)?;
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
            .map(super::state::CanonicalInstalledState::lifecycle_state);
        let valid = matches!(
            (operation, lifecycle),
            (Operation::Install, None)
                | (
                    Operation::Update | Operation::Remove,
                    Some(LifecycleState::Inactive | LifecycleState::Active)
                )
                | (Operation::Activate, Some(LifecycleState::Inactive))
                | (Operation::Deactivate, Some(LifecycleState::Active))
        );
        if valid {
            Ok(())
        } else {
            Err(PackageServiceError::LifecycleTransition)
        }
    }

    fn validate_context_bindings(
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
        if context.content_root() != state.content_root()
            || context.provenance() != state.provenance()
        {
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
    ///
    /// # Errors
    /// Returns expiry or record-state failures without changing status.
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
    ///
    /// # Errors
    /// Returns typed binding or transition failures before recording a drain.
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
        let required_matches = context.operation() == required;
        let expiry_allows = deadline <= context.expiry();
        let now_allows = deadline > now;
        if !(required_matches && expiry_allows && now_allows) {
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
        if context.operation() == Operation::Update {
            let unified_plan =
                commit_plan_digest(&context, context.content_root(), context.provenance());
            if context.commit_plan_digest() != &unified_plan {
                return Err(PackageServiceError::BindingMismatch);
            }
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
            journal.set_drain_lineage(DrainLineage::new(base_state, generation)?);
        }
        record.replace_state_with_generation(Some(replacement.clone()), generation)?;
        let journal = record
            .journal_mut(nonce)
            .ok_or(PackageServiceError::RecordMissing)?;
        journal.set_state_generation(generation);
        Ok(())
    }

    /// Binds the exact staged commit content before the uncertain boundary.
    ///
    /// # Errors
    /// Returns binding or record-state failures without replacing an existing stage.
    pub fn stage_commit_artifact(
        &mut self,
        nonce: &Nonce,
        artifact: &ValidatedArtifact,
    ) -> PackageServiceResult<()> {
        let context = self.context_for(nonce)?;
        if !matches!(context.operation(), Operation::Install | Operation::Update) {
            return Err(PackageServiceError::LifecycleTransition);
        }
        validate_context_artifact(&context, artifact)?;
        let plan = commit_plan_digest(
            &context,
            artifact.content_root(),
            &provenance_digest(artifact.provenance()),
        );
        if context.commit_plan_digest() != &plan {
            return Err(PackageServiceError::BindingMismatch);
        }
        let record = self.record_mut(nonce)?;
        if !matches!(
            record.status(),
            JournalStatus::Intent | JournalStatus::Executing
        ) {
            return Err(PackageServiceError::RecordNotReconcilable);
        }
        if record
            .staged_commit_plan()
            .is_some_and(|existing| *existing != plan)
        {
            return Err(PackageServiceError::BindingMismatch);
        }
        record.set_staged_commit_plan(plan);
        Ok(())
    }

    /// Records independently proved runtime lease count without completing the drain.
    ///
    /// # Errors
    /// Returns expiry, lineage, or generation failures without a canonical commit.
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
        active_drain_lineage(record, nonce)?;
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
        record.replace_state_with_generation(Some(replacement), generation)?;
        let journal = record
            .journal_mut(nonce)
            .ok_or(PackageServiceError::RecordMissing)?;
        journal.advance_drain_boundary()?;
        Ok(())
    }

    /// Commits install, update, activation, deactivation, or final retirement.
    ///
    /// # Errors
    /// Returns typed binding, expiry, drain, or transition failures before commit.
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
        let (before, authority_digest, staged_commit_plan) =
            commit_record_metadata(record_slot, nonce)?;

        let (after_state, outcome, generation) = match context.operation() {
            Operation::Install => {
                let artifact = artifact.ok_or(PackageServiceError::BindingMismatch)?;
                commit_install(
                    record_slot,
                    &context,
                    authority_digest,
                    artifact,
                    staged_commit_plan,
                )?
            },
            Operation::Update => {
                let artifact = artifact.ok_or(PackageServiceError::BindingMismatch)?;
                commit_update(
                    record_slot,
                    &context,
                    authority_digest,
                    artifact,
                    staged_commit_plan,
                    &DrainProof {
                        nonce,
                        now,
                        zero_leases: zero_leases_proved,
                    },
                )?
            },
            Operation::Activate | Operation::Deactivate => {
                let Some(state) = record_slot.state().cloned() else {
                    return Err(PackageServiceError::LifecycleTransition);
                };
                commit_retained_state(record_slot, &context, state, nonce)?
            },
            Operation::Remove => {
                let Some(state) = record_slot.state().cloned() else {
                    return Err(PackageServiceError::LifecycleTransition);
                };
                commit_removal(
                    record_slot,
                    &state,
                    nonce,
                    &DrainProof {
                        nonce,
                        now,
                        zero_leases: zero_leases_proved,
                    },
                )?
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
        journal.take_drain_lineage();
        journal.take_staged_commit_plan();
        journal.set_state_generation(generation);
        journal.commit(receipt.clone(), now);
        Ok(receipt)
    }

    /// Moves an executing result to unknown after an uncertain boundary.
    ///
    /// # Errors
    /// Returns record-state failures unless the record is currently executing.
    pub fn mark_unknown(&mut self, nonce: &Nonce, now: Timestamp) -> PackageServiceResult<()> {
        let record = self.record_mut(nonce)?;
        if record.status() != JournalStatus::Executing {
            return Err(PackageServiceError::RecordNotReconcilable);
        }
        record.mark_unknown(now);
        Ok(())
    }

    /// Cancels advisory work only before an unknown commit boundary.
    ///
    /// # Errors
    /// Returns expiry, transition, or restoration failures before terminal status.
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
            let lineage = active_drain_lineage(record_slot, nonce)?;
            let safe_restored = restore_to_boundary_successor(&lineage, nonce)?;
            let restored_generation = safe_restored.generation_value();
            record_slot.replace_state_with_generation(Some(safe_restored), restored_generation)?;
            let journal = record_slot
                .journal_mut(nonce)
                .ok_or(PackageServiceError::RecordMissing)?;
            journal.take_drain_lineage();
            journal.set_state_generation(restored_generation);
        }
        let journal = record_slot
            .journal_mut(nonce)
            .ok_or(PackageServiceError::RecordMissing)?;
        journal.take_staged_commit_plan();
        journal.terminal_failure(JournalStatus::Aborted, now);
        Ok(())
    }

    /// Advances a drain at or after its deadline without inventing retirement.
    ///
    /// # Errors
    /// Returns transition or generation failures without a partial drain resolution.
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
            live_leases: _,
            destination,
        } = state.lifecycle_state()
        else {
            return Err(PackageServiceError::LifecycleTransition);
        };
        if drain_nonce.as_bytes() != nonce.as_bytes() || now < *deadline {
            return Err(PackageServiceError::LifecycleTransition);
        }
        if !zero_leases_proved {
            let journal = record_slot
                .journal_mut(nonce)
                .ok_or(PackageServiceError::RecordMissing)?;
            journal.mark_unknown(now);
            return Ok(DrainResult::Blocked);
        }
        let lineage = active_drain_lineage(record_slot, nonce)?;
        if *destination == DrainDestination::Removal {
            let generation = record_slot
                .journal_record(nonce)
                .and_then(OperationJournalRecord::state_generation)
                .map(next_generation_value)
                .transpose()?
                .ok_or(PackageServiceError::OccupancyCorruption)?;
            record_slot.replace_state_with_generation(None, generation)?;
            let journal = record_slot
                .journal_mut(nonce)
                .ok_or(PackageServiceError::RecordMissing)?;
            journal.set_state_generation(generation);
            journal.take_drain_lineage();
            journal.take_staged_commit_plan();
            journal.terminal_failure(JournalStatus::Expired, now);
            return Ok(DrainResult::Completed);
        }
        let safe_restored = restore_to_boundary_successor(&lineage, nonce)?;
        let restored_generation = safe_restored.generation_value();
        record_slot.replace_state_with_generation(Some(safe_restored), restored_generation)?;
        let journal = record_slot
            .journal_mut(nonce)
            .ok_or(PackageServiceError::RecordMissing)?;
        journal.take_drain_lineage();
        journal.take_staged_commit_plan();
        journal.set_state_generation(restored_generation);
        journal.terminal_failure(JournalStatus::Expired, now);
        Ok(DrainResult::Completed)
    }

    /// Makes an authority-expired admission explicitly terminal or recoverable.
    ///
    /// # Errors
    /// Returns record-state failures when the record cannot expire yet.
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
    ///
    /// # Errors
    /// Returns replay failures for missing records or mismatched context digests.
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
    ///
    /// # Errors
    /// Returns quota and occupancy failures atomically before collecting records.
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

        let mut collected_records = OccupiedRecords::ZERO;
        for (slot, nonce) in selected {
            let slot_record = self
                .slots
                .get_mut(&slot)
                .ok_or(PackageServiceError::OccupancyCorruption)?;
            let tombstone = slot_record
                .remove_journal(&nonce)
                .ok_or(PackageServiceError::OccupancyCorruption)?;
            self.occupancy.remove_record(1024)?;
            self.occupancy.add_tombstone()?;
            self.tombstones.insert(nonce, tombstone);
            self.nonce_locations.remove(&nonce);
            collected_records = collected_records
                .checked_add(1)
                .ok_or(PackageServiceError::GenerationOverflow)?;
        }
        Ok(collected_records.value())
    }
}

#[cfg(test)]
mod tests;

#[derive(Clone, Copy)]
struct OccupiedRecords(u64);

impl OccupiedRecords {
    const ZERO: Self = Self(0);

    const fn checked_add(self, records: u64) -> Option<Self> {
        match self.0.checked_add(records) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    const fn value(self) -> u64 {
        self.0
    }
}
