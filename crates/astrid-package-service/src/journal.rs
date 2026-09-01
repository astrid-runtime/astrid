//! Bounded intent, drain, receipt, and replay records.

use crate::context::{ExpectedPackageState, LifecyclePlan, Operation, OperationContext};
use crate::digest::{
    AuthorityDigest, DigestWriter, ReceiptDigest, RuntimeReceiptDigest, StateDigest,
};
use crate::error::{PackageServiceError, PackageServiceResult};
use crate::identity::{Nonce, PROTOCOL_VERSION, ValidatedArtifact};
use crate::state::{DrainDestination, SlotRecord};
use core::num::NonZeroU64;

/// Status of one durable operation intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalStatus {
    /// Admitted before any state effect.
    Intent,
    /// A bounded budgeted effect is executing.
    Executing,
    /// Outcome is unresolved and must be retained.
    Unknown,
    /// A successful terminal receipt is present.
    Committed,
    /// A typed cancellation before the commit boundary.
    Aborted,
    /// Authority or drain expiry retired the intent.
    Expired,
}

impl JournalStatus {
    /// Whether a record still controls a slot and cannot be garbage collected.
    #[must_use]
    pub const fn is_unresolved(self) -> bool {
        matches!(self, Self::Intent | Self::Executing | Self::Unknown)
    }
}

/// Successful receipt outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptOutcome {
    /// Exact context-bound content became installed.
    Installed,
    /// Exact context-bound content replaced the prior state.
    Updated,
    /// Runtime publication succeeded.
    Activated,
    /// Runtime publication stopped.
    Deactivated,
    /// Exact prior content retired after zero-lease drain proof.
    Retired,
}

/// At-most-once terminal success receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationReceipt {
    operation: Operation,
    before: StateDigest,
    after: StateDigest,
    generation: NonZeroU64,
    runtime_receipt: RuntimeReceiptDigest,
    authority: AuthorityDigest,
    nonce: Nonce,
    digest: ReceiptDigest,
}

impl OperationReceipt {
    pub(crate) fn new(
        context: &OperationContext,
        before: StateDigest,
        after: StateDigest,
        generation: NonZeroU64,
        runtime_receipt: RuntimeReceiptDigest,
        authority: AuthorityDigest,
    ) -> Self {
        let outcome = receipt_outcome(context.operation());
        let mut writer = DigestWriter::new();
        writer.u64(u64::from(PROTOCOL_VERSION));
        writer.tag(context.operation().tag());
        writer.digest(&before);
        writer.digest(&after);
        writer.u64(generation.get());
        writer.digest(&runtime_receipt);
        writer.digest(&authority);
        writer.bytes(context.nonce().as_bytes());
        writer.tag(outcome_tag(outcome));
        let digest = writer.finish("astrid.package.receipt.v1");
        Self {
            operation: context.operation(),
            before,
            after,
            generation,
            runtime_receipt,
            authority,
            nonce: *context.nonce(),
            digest,
        }
    }

    /// Returns the canonical receipt digest.
    #[must_use]
    pub const fn digest(&self) -> ReceiptDigest {
        self.digest
    }

    /// Returns the nonce that owns this receipt.
    #[must_use]
    pub const fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Returns the successful operation.
    #[must_use]
    pub const fn operation(&self) -> Operation {
        self.operation
    }

    /// Returns the exact prior state.
    #[must_use]
    pub const fn before(&self) -> StateDigest {
        self.before
    }

    /// Returns the exact successor state.
    #[must_use]
    pub const fn after(&self) -> StateDigest {
        self.after
    }

    /// Returns the generation established by the receipt.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation.get()
    }

    /// Returns the exact runtime receipt that completed the operation.
    #[must_use]
    pub const fn runtime_receipt(&self) -> &RuntimeReceiptDigest {
        &self.runtime_receipt
    }

    /// Returns the admitting authority digest bound to this receipt.
    #[must_use]
    pub const fn authority(&self) -> AuthorityDigest {
        self.authority
    }
}

/// Authoritative zero-lease drain proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrainProof {
    runtime_receipt: RuntimeReceiptDigest,
    proof_time: u64,
}

impl DrainProof {
    /// Returns exact proof bytes and instant.
    #[must_use]
    pub const fn new(runtime_receipt: RuntimeReceiptDigest, proof_time: u64) -> Self {
        Self {
            runtime_receipt,
            proof_time,
        }
    }

    /// Returns the exact runtime receipt presented by the proof.
    #[must_use]
    pub const fn runtime_receipt(&self) -> &RuntimeReceiptDigest {
        &self.runtime_receipt
    }

    /// Returns the instant claimed by the runtime proof.
    #[must_use]
    pub const fn proof_time(&self) -> u64 {
        self.proof_time
    }
}

/// Evidence required to reconcile an explicit unknown outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryEvidence {
    observed_state: StateDigest,
    zero_leases_proved: bool,
    runtime_receipt: RuntimeReceiptDigest,
}

impl RecoveryEvidence {
    /// Binds observed-state evidence to explicit zero-lease knowledge.
    #[must_use]
    pub const fn new(
        observed_state: StateDigest,
        zero_leases_proved: bool,
        runtime_receipt: RuntimeReceiptDigest,
    ) -> Self {
        Self {
            observed_state,
            zero_leases_proved,
            runtime_receipt,
        }
    }
}

/// One durable journal entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationRecord {
    context: OperationContext,
    authority: AuthorityDigest,
    status: JournalStatus,
    admitted_at: u64,
    drain: Option<DrainDestination>,
    proofs: u32,
    receipt: Option<OperationReceipt>,
}

impl OperationRecord {
    fn context_state(
        &self,
        artifact: ValidatedArtifact,
        generation: NonZeroU64,
    ) -> PackageServiceResult<crate::state::CanonicalInstalledState> {
        crate::state::CanonicalInstalledState::new(crate::state::InstalledStateSpec {
            owner: self.context.target_owner(),
            package: *self.context.package(),
            artifact,
            authority: self.authority,
            lifecycle: crate::state::LifecycleState::Inactive,
            plan: *self.context.plan_digest(),
            generation,
            completing_nonce: *self.context.nonce(),
        })
    }

    pub(crate) fn new(
        context: &OperationContext,
        authority: AuthorityDigest,
        admitted_at: u64,
    ) -> Self {
        Self {
            context: *context,
            authority,
            status: JournalStatus::Intent,
            admitted_at,
            drain: None,
            proofs: 0,
            receipt: None,
        }
    }

    /// Returns the exact original context.
    #[must_use]
    pub const fn context(&self) -> &OperationContext {
        &self.context
    }

    /// Returns the authority digest that admitted the context.
    #[must_use]
    pub const fn authority(&self) -> AuthorityDigest {
        self.authority
    }

    /// Returns the current record status.
    #[must_use]
    pub const fn status(&self) -> JournalStatus {
        self.status
    }

    /// Returns the successful receipt, if any.
    #[must_use]
    pub const fn receipt(&self) -> Option<&OperationReceipt> {
        self.receipt.as_ref()
    }

    /// Returns the number of accepted zero-lease proofs.
    #[must_use]
    pub const fn drain_proofs(self) -> u32 {
        self.proofs
    }

    pub(crate) fn begin_work(&mut self, now: u64) -> PackageServiceResult<()> {
        if self.status != JournalStatus::Intent || now >= self.context.expiry() {
            return Err(PackageServiceError::RecordUnavailable);
        }
        self.status = JournalStatus::Executing;
        Ok(())
    }

    pub(crate) fn begin_drain(
        &mut self,
        slot: &mut SlotRecord,
        now: u64,
    ) -> PackageServiceResult<u64> {
        if self.status != JournalStatus::Executing || self.drain.is_some() {
            return Err(PackageServiceError::RecordUnavailable);
        }
        let (LifecyclePlan::ReplacementDrain { deadline }
        | LifecyclePlan::RemovalDrain { deadline }) = self.context.plan()
        else {
            return Err(PackageServiceError::InvalidDrain);
        };
        let destination = match self.context.operation() {
            Operation::Update => DrainDestination::Replacement,
            Operation::Remove => DrainDestination::Removal,
            _ => return Err(PackageServiceError::InvalidDrain),
        };
        if now >= deadline {
            return Err(PackageServiceError::InvalidDrain);
        }
        let _lineage = slot.begin_drain(destination)?;
        self.drain = Some(destination);
        Ok(deadline)
    }

    pub(crate) fn prove_drain(
        &mut self,
        slot: &mut SlotRecord,
        proof: DrainProof,
        now: u64,
    ) -> PackageServiceResult<()> {
        if self.status != JournalStatus::Executing || self.drain.is_none() {
            return Err(PackageServiceError::RecordUnavailable);
        }
        let deadline = self
            .context
            .plan()
            .drain_deadline()
            .ok_or(PackageServiceError::InvalidDrain)?;
        if now > deadline
            || proof.proof_time > deadline
            || proof.proof_time > now
            || proof.runtime_receipt != *self.context.drain_receipt()
        {
            return Err(PackageServiceError::InvalidDrain);
        }
        slot.drain_mut()
            .ok_or(PackageServiceError::InvalidDrain)?
            .advance()?;
        self.proofs = self.proofs.saturating_add(1);
        Ok(())
    }

    pub(crate) fn report_unknown(&mut self, now: u64) -> PackageServiceResult<()> {
        if self.status != JournalStatus::Executing || now >= self.context.expiry() {
            return Err(PackageServiceError::RecordUnavailable);
        }
        if matches!(
            self.context.operation(),
            Operation::Update | Operation::Remove
        ) {
            let deadline = self
                .context
                .plan()
                .drain_deadline()
                .ok_or(PackageServiceError::InvalidDrain)?;
            if now > deadline {
                return Err(PackageServiceError::InvalidDrain);
            }
        }
        self.status = JournalStatus::Unknown;
        Ok(())
    }

    pub(crate) fn cancel(&mut self) -> PackageServiceResult<()> {
        if self.status != JournalStatus::Intent || self.drain.is_some() {
            return Err(PackageServiceError::RecordUnavailable);
        }
        self.status = JournalStatus::Aborted;
        Ok(())
    }

    pub(crate) fn expire(&mut self, slot: &mut SlotRecord, now: u64) -> PackageServiceResult<u64> {
        if !matches!(
            self.status,
            JournalStatus::Executing | JournalStatus::Unknown
        ) {
            return Err(PackageServiceError::RecordUnavailable);
        }
        let deadline = self
            .context
            .plan()
            .drain_deadline()
            .ok_or(PackageServiceError::InvalidDrain)?;
        if now <= deadline {
            return Err(PackageServiceError::InvalidDrain);
        }
        let boundary = slot.restore_boundary()?;
        self.status = JournalStatus::Expired;
        Ok(boundary.get())
    }

    pub(crate) fn commit(
        &mut self,
        slot: &mut SlotRecord,
        artifact: ValidatedArtifact,
        runtime_receipt: RuntimeReceiptDigest,
        now: u64,
    ) -> PackageServiceResult<OperationReceipt> {
        if self.status != JournalStatus::Executing || now >= self.context.expiry() {
            return Err(PackageServiceError::RecordUnavailable);
        }
        if runtime_receipt != *self.context.runtime_receipt()
            || artifact != *self.context.artifact()
        {
            return Err(PackageServiceError::BindingMismatch);
        }
        let before = slot.current().map_or_else(
            || ExpectedPackageState::Absent.digest(),
            crate::state::CanonicalInstalledState::digest,
        );
        let operation = self.context.operation();
        let generation;
        let after;
        match operation {
            Operation::Install => {
                generation = slot.next_generation()?;
                let state = self.context_state(artifact, generation)?;
                after = state.digest();
                slot.set_state(&state);
            },
            Operation::Update => {
                if self.proofs == 0 {
                    return Err(PackageServiceError::InvalidDrain);
                }
                let lineage = slot.drain().ok_or(PackageServiceError::InvalidDrain)?;
                generation = NonZeroU64::try_from(
                    lineage
                        .boundary()
                        .get()
                        .checked_add(1)
                        .ok_or(PackageServiceError::GenerationExhausted)?,
                )
                .map_err(|_| PackageServiceError::GenerationExhausted)?;
                let state = self.context_state(artifact, generation)?;
                after = state.digest();
                slot.set_state(&state);
            },
            Operation::Activate | Operation::Deactivate => {
                let current = slot
                    .current()
                    .ok_or(PackageServiceError::InvalidTransition)?;
                generation = current.generation_value();
                let lifecycle = if operation == Operation::Activate {
                    crate::state::LifecycleState::Active
                } else {
                    crate::state::LifecycleState::Inactive
                };
                let state =
                    crate::state::CanonicalInstalledState::new(crate::state::InstalledStateSpec {
                        owner: current.owner(),
                        package: *current.package(),
                        artifact: *current.artifact(),
                        authority: self.authority,
                        lifecycle,
                        plan: *self.context.plan_digest(),
                        generation,
                        completing_nonce: *self.context.nonce(),
                    })?;
                after = state.digest();
                slot.set_state(&state);
            },
            Operation::Remove => {
                if self.proofs == 0 {
                    return Err(PackageServiceError::InvalidDrain);
                }
                generation = slot
                    .drain()
                    .ok_or(PackageServiceError::InvalidDrain)?
                    .boundary();
                after = ExpectedPackageState::Absent.digest();
                slot.set_absent(generation);
            },
        }
        let receipt = OperationReceipt::new(
            &self.context,
            before,
            after,
            generation,
            runtime_receipt,
            self.authority,
        );
        self.receipt = Some(receipt);
        self.status = JournalStatus::Committed;
        Ok(receipt)
    }

    pub(crate) fn recover(
        &mut self,
        slot: &mut SlotRecord,
        evidence: RecoveryEvidence,
        now: u64,
    ) -> PackageServiceResult<Option<OperationReceipt>> {
        if self.status != JournalStatus::Unknown {
            return Err(PackageServiceError::RecordUnavailable);
        }
        let is_drain = self.context.plan().drain_deadline().is_some();
        if is_drain {
            if evidence.zero_leases_proved != (self.proofs > 0)
                || evidence.runtime_receipt != *self.context.drain_receipt()
            {
                return Err(PackageServiceError::BindingMismatch);
            }
            if now
                > self
                    .context
                    .plan()
                    .drain_deadline()
                    .ok_or(PackageServiceError::InvalidDrain)?
            {
                return Err(PackageServiceError::InvalidDrain);
            }
        } else if evidence.zero_leases_proved
            || evidence.runtime_receipt != *self.context.runtime_receipt()
        {
            return Err(PackageServiceError::BindingMismatch);
        }
        let base_digest = slot
            .drain()
            .map_or_else(
                || {
                    slot.current()
                        .map(crate::state::CanonicalInstalledState::digest)
                },
                |lineage| Some(lineage.base().digest()),
            )
            .ok_or(PackageServiceError::RecordUnavailable)?;
        if evidence.observed_state != base_digest {
            return Err(PackageServiceError::BindingMismatch);
        }

        if is_drain {
            slot.restore_boundary()?;
            self.status = JournalStatus::Expired;
            return Ok(None);
        }

        self.status = JournalStatus::Expired;
        Ok(None)
    }

    pub(crate) fn replay(&self) -> PackageServiceResult<ReplayOutcome> {
        match self.status {
            JournalStatus::Committed => Ok(ReplayOutcome::Committed(Box::new(
                self.receipt.ok_or(PackageServiceError::RecordUnavailable)?,
            ))),
            JournalStatus::Aborted => Ok(ReplayOutcome::Aborted),
            JournalStatus::Expired => Ok(ReplayOutcome::Expired),
            JournalStatus::Intent | JournalStatus::Executing | JournalStatus::Unknown => {
                Ok(ReplayOutcome::Unresolved)
            },
        }
    }

    pub(crate) const fn is_unresolved(&self) -> bool {
        self.status.is_unresolved()
    }
}

/// Result of replaying a durable nonce.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayOutcome {
    /// The nonce completed successfully; only the same receipt may replay.
    Committed(Box<OperationReceipt>),
    /// The nonce was cancelled before any effect.
    Aborted,
    /// The nonce expired and recovery retained the authoritative boundary.
    Expired,
    /// The outcome remains unknown and must be reconciled.
    Unresolved,
}

const fn receipt_outcome(operation: Operation) -> ReceiptOutcome {
    match operation {
        Operation::Install => ReceiptOutcome::Installed,
        Operation::Update => ReceiptOutcome::Updated,
        Operation::Activate => ReceiptOutcome::Activated,
        Operation::Deactivate => ReceiptOutcome::Deactivated,
        Operation::Remove => ReceiptOutcome::Retired,
    }
}

const fn outcome_tag(outcome: ReceiptOutcome) -> u8 {
    match outcome {
        ReceiptOutcome::Installed => 1,
        ReceiptOutcome::Updated => 2,
        ReceiptOutcome::Activated => 3,
        ReceiptOutcome::Deactivated => 4,
        ReceiptOutcome::Retired => 5,
    }
}
