//! Pure executable owner/package lifecycle model.

use crate::authority::AuthenticatedAuthority;
use crate::context::{Operation, OperationContext};
use crate::digest::RuntimeReceiptDigest;
use crate::error::{PackageServiceError, PackageServiceResult};
use crate::identity::Nonce;
use crate::journal::{
    DrainProof, OperationReceipt, OperationRecord, RecoveryEvidence, ReplayOutcome,
};
use crate::state::{LifecycleState, PackageSlot, SlotRecord, valid_transition};
use std::collections::{BTreeMap, VecDeque};
use std::num::{NonZeroU64, NonZeroUsize};

/// Fixed conservative durable-record accounting unit.
const RECORD_BYTES: u64 = 256;

/// Bounded durable history policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalPolicy {
    maximum_records: NonZeroUsize,
    maximum_bytes: NonZeroU64,
}

impl JournalPolicy {
    /// Creates a positive record and byte ceiling.
    #[must_use]
    pub const fn new(maximum_records: NonZeroUsize, maximum_bytes: NonZeroU64) -> Self {
        Self {
            maximum_records,
            maximum_bytes,
        }
    }
}

/// Pure model owning all canonical slot and journal state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageServiceModel {
    policy: JournalPolicy,
    slots: BTreeMap<PackageSlot, SlotRecord>,
    records: BTreeMap<Nonce, OperationRecord>,
    record_slots: BTreeMap<Nonce, PackageSlot>,
    history: VecDeque<Nonce>,
    history_bytes: u64,
}

impl PackageServiceModel {
    /// Creates an empty model governed by bounded history policy.
    #[must_use]
    pub fn new(policy: JournalPolicy) -> Self {
        Self {
            policy,
            slots: BTreeMap::new(),
            records: BTreeMap::new(),
            record_slots: BTreeMap::new(),
            history: VecDeque::new(),
            history_bytes: 0,
        }
    }

    /// Returns the canonical slot value.
    #[must_use]
    pub fn slot(&self, slot: &PackageSlot) -> Option<&SlotRecord> {
        self.slots.get(slot)
    }

    /// Returns a durable record for exact replay or reconciliation.
    #[must_use]
    pub fn record(&self, nonce: &Nonce) -> Option<&OperationRecord> {
        self.records.get(nonce)
    }

    /// Returns the monotonic generation high-watermark.
    #[must_use]
    pub fn high_watermark(&self, slot: &PackageSlot) -> Option<u64> {
        self.slots.get(slot).map(SlotRecord::high_watermark)
    }

    /// Admits one exact nonce before any budgeted state effect.
    ///
    /// # Errors
    /// Returns all authority, stale-state, binding, replay, and quota failures
    /// before inserting durable state.
    pub fn begin(
        &mut self,
        context: OperationContext,
        authority: &AuthenticatedAuthority,
        now: u64,
    ) -> PackageServiceResult<Nonce> {
        authority.verify_context(context)?;
        let slot = PackageSlot::new(context.target_owner(), *context.package());
        if self.record_slots.contains_key(context.nonce()) {
            return Err(PackageServiceError::NonceReplay);
        }
        let record = self.slots.get(&slot);
        if !record.is_none_or(|value| value.matches_expected(context.expected())) {
            return Err(PackageServiceError::ExpectedStateMismatch);
        }
        if !valid_transition(
            context.operation(),
            record.and_then(SlotRecord::current).is_some(),
        ) {
            return Err(PackageServiceError::InvalidTransition);
        }
        if record.is_some_and(SlotRecord::draining) {
            return Err(PackageServiceError::InvalidDrain);
        }
        if let Some(record) = record {
            Self::validate_bindings(&context, record)?;
        }
        if self.record_slots.iter().any(|(nonce, owned)| {
            *owned == slot
                && self
                    .records
                    .get(nonce)
                    .is_some_and(OperationRecord::is_unresolved)
        }) {
            return Err(PackageServiceError::RecordUnavailable);
        }
        self.reserve_history()?;
        self.slots.entry(slot).or_insert_with(SlotRecord::absent);
        let nonce = *context.nonce();
        self.records.insert(
            nonce,
            OperationRecord::new(&context, authority.digest(), now),
        );
        self.record_slots.insert(nonce, slot);
        self.history.push_back(nonce);
        self.history_bytes = self
            .history_bytes
            .checked_add(RECORD_BYTES)
            .ok_or(PackageServiceError::JournalFull)?;
        Ok(nonce)
    }

    fn validate_bindings(
        context: &OperationContext,
        record: &SlotRecord,
    ) -> PackageServiceResult<()> {
        let current = record.current();
        match context.operation() {
            Operation::Install | Operation::Update => {
                if context.artifact().artifact_size() > context.budget().maximum_artifact_bytes() {
                    return Err(PackageServiceError::BudgetExceeded);
                }
            },
            Operation::Activate => {
                let current = current.ok_or(PackageServiceError::InvalidTransition)?;
                if current.artifact() != context.artifact()
                    || current.lifecycle() != LifecycleState::Inactive
                {
                    return Err(PackageServiceError::BindingMismatch);
                }
            },
            Operation::Deactivate => {
                let current = current.ok_or(PackageServiceError::InvalidTransition)?;
                if current.artifact() != context.artifact()
                    || current.lifecycle() != LifecycleState::Active
                {
                    return Err(PackageServiceError::BindingMismatch);
                }
            },
            Operation::Remove => {
                let current = current.ok_or(PackageServiceError::InvalidTransition)?;
                if current.artifact() != context.artifact() {
                    return Err(PackageServiceError::BindingMismatch);
                }
            },
        }
        Ok(())
    }

    fn reserve_history(&mut self) -> PackageServiceResult<()> {
        while self.history.len() >= self.policy.maximum_records.get() {
            let oldest = self
                .history
                .front()
                .copied()
                .ok_or(PackageServiceError::JournalFull)?;
            let Some(record) = self.records.get(&oldest) else {
                self.history.pop_front();
                continue;
            };
            if record.is_unresolved() {
                return Err(PackageServiceError::JournalFull);
            }
            self.history.pop_front();
            self.records.remove(&oldest);
            self.record_slots.remove(&oldest);
            self.history_bytes = self
                .history_bytes
                .checked_sub(RECORD_BYTES)
                .ok_or(PackageServiceError::JournalFull)?;
        }
        if self
            .history_bytes
            .checked_add(RECORD_BYTES)
            .ok_or(PackageServiceError::JournalFull)?
            > self.policy.maximum_bytes.get()
        {
            return Err(PackageServiceError::JournalFull);
        }
        Ok(())
    }

    fn context(&self, nonce: &Nonce) -> PackageServiceResult<OperationContext> {
        self.records
            .get(nonce)
            .map(|record| *record.context())
            .ok_or(PackageServiceError::RecordUnavailable)
    }

    fn slot_mut(&mut self, nonce: &Nonce) -> PackageServiceResult<&mut SlotRecord> {
        let slot = self
            .record_slots
            .get(nonce)
            .copied()
            .ok_or(PackageServiceError::RecordUnavailable)?;
        self.slots
            .get_mut(&slot)
            .ok_or(PackageServiceError::RecordUnavailable)
    }

    /// Moves an admitted intent to executing before its authority expires.
    ///
    /// # Errors
    /// Returns expiry or record-state failures without changing status.
    pub fn begin_work(&mut self, nonce: &Nonce, now: u64) -> PackageServiceResult<()> {
        if now >= self.context(nonce)?.expiry() {
            return Err(PackageServiceError::AuthorityExpired);
        }
        self.records
            .get_mut(nonce)
            .ok_or(PackageServiceError::RecordUnavailable)?
            .begin_work(now)
    }

    /// Places the exact prior state into the context's bounded drain.
    ///
    /// # Errors
    /// Returns expiry, status, plan, or drain failures before mutating state.
    pub fn begin_drain(&mut self, nonce: &Nonce, now: u64) -> PackageServiceResult<u64> {
        let context = self.context(nonce)?;
        if now >= context.expiry() {
            return Err(PackageServiceError::AuthorityExpired);
        }
        let mut record = self
            .records
            .remove(nonce)
            .ok_or(PackageServiceError::RecordUnavailable)?;
        let result = record.begin_drain(self.slot_mut(nonce)?, now);
        self.records.insert(*nonce, record);
        result
    }

    /// Records authoritative proof that live leases reached zero.
    ///
    /// # Errors
    /// Returns expiry, deadline, receipt, or record failures without advancing.
    pub fn prove_drain(
        &mut self,
        nonce: &Nonce,
        proof: DrainProof,
        now: u64,
    ) -> PackageServiceResult<()> {
        let context = self.context(nonce)?;
        if now > context.expiry() {
            return Err(PackageServiceError::AuthorityExpired);
        }
        let mut record = self
            .records
            .remove(nonce)
            .ok_or(PackageServiceError::RecordUnavailable)?;
        let result = record.prove_drain(self.slot_mut(nonce)?, proof, now);
        self.records.insert(*nonce, record);
        result
    }

    /// Marks a lost outcome explicitly unknown; mid-drain observation proves nothing.
    ///
    /// # Errors
    /// Returns record-state or authority-expiry failures without changing status.
    pub fn report_unknown(&mut self, nonce: &Nonce, now: u64) -> PackageServiceResult<()> {
        self.records
            .get_mut(nonce)
            .ok_or(PackageServiceError::RecordUnavailable)?
            .report_unknown(now)
    }

    /// Cancels an intent only before the drain boundary.
    ///
    /// # Errors
    /// Returns authority, expiry, or drain-boundary failures without mutation.
    pub fn cancel(
        &mut self,
        nonce: &Nonce,
        authority: &AuthenticatedAuthority,
        now: u64,
    ) -> PackageServiceResult<()> {
        let context = self.context(nonce)?;
        authority.verify_context(context)?;
        if now >= context.expiry() {
            return Err(PackageServiceError::AuthorityExpired);
        }
        self.records
            .get_mut(nonce)
            .ok_or(PackageServiceError::RecordUnavailable)?
            .cancel()
    }

    /// Expires a drain after its authoritative deadline and restores the boundary.
    ///
    /// # Errors
    /// Returns record-state or deadline failures without restoring the boundary.
    pub fn expire(&mut self, nonce: &Nonce, now: u64) -> PackageServiceResult<u64> {
        let mut record = self
            .records
            .remove(nonce)
            .ok_or(PackageServiceError::RecordUnavailable)?;
        let result = record.expire(self.slot_mut(nonce)?, now);
        self.records.insert(*nonce, record);
        result
    }

    /// Commits the exact context-bound content after preconditions are met.
    ///
    /// # Errors
    /// Returns expiry, proof, binding, generation, or transition failures.
    pub fn commit(
        &mut self,
        nonce: &Nonce,
        runtime_receipt: RuntimeReceiptDigest,
        now: u64,
    ) -> PackageServiceResult<OperationReceipt> {
        let context = self.context(nonce)?;
        if now >= context.expiry() {
            return Err(PackageServiceError::AuthorityExpired);
        }
        let mut record = self
            .records
            .remove(nonce)
            .ok_or(PackageServiceError::RecordUnavailable)?;
        let result = record.commit(
            self.slot_mut(nonce)?,
            *context.artifact(),
            runtime_receipt,
            now,
        );
        self.records.insert(*nonce, record);
        result
    }

    /// Reconciles an explicit unknown outcome without inferring success from observation.
    ///
    /// # Errors
    /// Returns authority, binding, deadline, or recovery failures; `Ok(None)`
    /// means the record remains explicitly unresolved.
    pub fn recover(
        &mut self,
        nonce: &Nonce,
        authority: &AuthenticatedAuthority,
        evidence: RecoveryEvidence,
        now: u64,
    ) -> PackageServiceResult<Option<OperationReceipt>> {
        let context = self.context(nonce)?;
        authority.verify_context(context)?;
        let mut record = self
            .records
            .remove(nonce)
            .ok_or(PackageServiceError::RecordUnavailable)?;
        let result = record.recover(self.slot_mut(nonce)?, evidence, now);
        self.records.insert(*nonce, record);
        result
    }

    /// Replays only durable terminal semantics.
    ///
    /// # Errors
    /// Returns [`PackageServiceError::RecordUnavailable`] for an unknown nonce.
    pub fn replay(&self, nonce: &Nonce) -> PackageServiceResult<ReplayOutcome> {
        self.records
            .get(nonce)
            .ok_or(PackageServiceError::RecordUnavailable)?
            .replay()
    }
}
