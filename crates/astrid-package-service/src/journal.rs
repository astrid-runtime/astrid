use crate::bytes::RecoveryToken;
use crate::context::{Operation, OperationContext, Timestamp};
use crate::digest::{
    AuthorityDecisionDigest, Blake3Digest, DigestWriter, PlanDigest, ReceiptDigest, RequestDigest,
    StateDigest, TypedDigest,
};
use crate::error::{PackageServiceError, PackageServiceResult};
use crate::identity::{JOURNAL_SCHEMA_VERSION, JournalSchemaVersion, Nonce, ProtocolVersion};
use crate::state::{CanonicalInstalledState, DrainDestination, PackageSlot};
use std::collections::BTreeMap;
use std::num::NonZeroU64;

pub(crate) type ReservationDigest = RequestDigest;

/// Status of the authoritative operation journal record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalStatus {
    /// Durable before any budgeted effect.
    Intent,
    /// A bounded budgeted effect is in progress.
    Executing,
    /// The outcome cannot yet be proved.
    Unknown,
    /// A successful receipt is retained.
    Committed,
    /// A typed failure is terminal.
    Failed,
    /// Authority or lease expiry is terminal.
    Expired,
    /// Cancellation before the commit boundary is terminal.
    Aborted,
}

impl JournalStatus {
    const fn tag(&self) -> u8 {
        match self {
            Self::Intent => 1,
            Self::Executing => 2,
            Self::Unknown => 3,
            Self::Committed => 4,
            Self::Failed => 5,
            Self::Expired => 6,
            Self::Aborted => 7,
        }
    }

    pub(crate) const fn is_unresolved(&self) -> bool {
        matches!(self, Self::Intent | Self::Executing | Self::Unknown)
    }
}

/// Success or typed retirement outcome carried by a receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptOutcome {
    /// Exact new state became installed and inactive.
    Installed,
    /// Exact new state replaced the prior state.
    Updated,
    /// Runtime publication succeeded.
    Activated,
    /// Runtime publication stopped.
    Deactivated,
    /// Canonical state became absent; retirement exists only here.
    Retired,
}

impl ReceiptOutcome {
    const fn tag(&self) -> u8 {
        match self {
            Self::Installed => 1,
            Self::Updated => 2,
            Self::Activated => 3,
            Self::Deactivated => 4,
            Self::Retired => 5,
        }
    }
}

/// At-most-once success evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationReceipt {
    protocol_version: ProtocolVersion,
    operation: Operation,
    slot: PackageSlot,
    nonce: Nonce,
    outcome: ReceiptOutcome,
    before_state: StateDigest,
    after_state: StateDigest,
    state_generation: NonZeroU64,
    service_generation: NonZeroU64,
    activation_receipt: Option<Blake3Digest>,
    expiry: Timestamp,
    digest: ReceiptDigest,
}

impl OperationReceipt {
    pub(crate) fn new(
        context: &OperationContext,
        outcome: ReceiptOutcome,
        before_state: StateDigest,
        after_state: StateDigest,
        state_generation: NonZeroU64,
        activation_receipt: Option<Blake3Digest>,
    ) -> Self {
        let value = Self {
            protocol_version: context.protocol_version(),
            operation: context.operation(),
            slot: PackageSlot::new(context.target_owner(), context.package_object()),
            nonce: context.nonce(),
            outcome,
            before_state,
            after_state,
            state_generation,
            service_generation: context.service_generation().as_non_zero(),
            activation_receipt,
            expiry: context.expiry(),
            digest: TypedDigest::from_bytes([0; 32]),
        };
        let mut writer = DigestWriter::new();
        value.write(&mut writer);
        let digest = writer.finish("astrid.package.receipt.v1");
        Self { digest, ..value }
    }

    fn write(&self, writer: &mut DigestWriter) {
        writer.u64(u64::from(self.protocol_version.get()));
        writer.tag(self.operation.tag());
        writer.bytes(self.slot.owner().as_bytes());
        writer.bytes(self.slot.package_object().as_bytes());
        writer.bytes(self.nonce.as_bytes());
        writer.tag(self.outcome.tag());
        writer.digest(&self.before_state);
        writer.digest(&self.after_state);
        writer.u64(self.state_generation.get());
        writer.u64(self.service_generation.get());
        match &self.activation_receipt {
            Some(receipt) => {
                writer.tag(1);
                writer.digest(receipt);
            },
            None => writer.tag(0),
        }
        writer.u64(self.expiry.get());
    }

    /// Returns the exact receipt digest.
    #[must_use]
    pub const fn digest(&self) -> ReceiptDigest {
        self.digest
    }

    /// Returns the receipt protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the operation class.
    #[must_use]
    pub const fn operation(&self) -> Operation {
        self.operation
    }

    /// Returns the immutable owner/package slot.
    #[must_use]
    pub const fn slot(&self) -> PackageSlot {
        self.slot
    }

    /// Returns the operation nonce.
    #[must_use]
    pub const fn nonce(&self) -> Nonce {
        self.nonce
    }

    /// Returns the outcome.
    #[must_use]
    pub const fn outcome(&self) -> ReceiptOutcome {
        self.outcome
    }

    /// Returns the canonical state before the operation.
    #[must_use]
    pub const fn before_state(&self) -> StateDigest {
        self.before_state
    }

    /// Returns the canonical state after the operation.
    #[must_use]
    pub const fn after_state(&self) -> StateDigest {
        self.after_state
    }

    /// Returns the canonical package-state generation produced by the receipt.
    #[must_use]
    pub const fn state_generation(&self) -> NonZeroU64 {
        self.state_generation
    }

    /// Returns the admitted-service generation covered by the receipt.
    #[must_use]
    pub const fn service_generation(&self) -> NonZeroU64 {
        self.service_generation
    }
}

/// Durable intent for a bounded drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrainPlan {
    destination: DrainDestination,
    state_digest: StateDigest,
    deadline: Timestamp,
    nonce: Nonce,
}

impl DrainPlan {
    /// Validates a drain against the exact canonical state it may alter.
    pub fn new(
        destination: DrainDestination,
        expected_state: crate::state::ExpectedPackageState,
        deadline: Timestamp,
        nonce: Nonce,
    ) -> PackageServiceResult<Self> {
        let crate::state::ExpectedPackageState::Exact(state_digest) = expected_state else {
            return Err(PackageServiceError::InvalidValue("drain expected state"));
        };
        if nonce.as_bytes() == &[0; 32] || deadline.get() == 0 {
            return Err(PackageServiceError::InvalidValue("drain plan"));
        }
        Ok(Self {
            destination,
            state_digest,
            deadline,
            nonce,
        })
    }

    /// Returns the destination.
    #[must_use]
    pub const fn destination(&self) -> DrainDestination {
        self.destination
    }

    /// Returns the bounded deadline.
    #[must_use]
    pub const fn deadline(&self) -> Timestamp {
        self.deadline
    }

    /// Returns the owning nonce.
    #[must_use]
    pub const fn nonce(&self) -> Nonce {
        self.nonce
    }

    /// Returns the canonical plan digest bound into the operation context.
    #[must_use]
    pub fn digest(&self) -> PlanDigest {
        let mut writer = DigestWriter::new();
        writer.tag(match self.destination {
            DrainDestination::Replacement => 1,
            DrainDestination::Removal => 2,
        });
        writer.digest(&self.state_digest);
        writer.u64(self.deadline.get());
        writer.bytes(self.nonce.as_bytes());
        writer.finish("astrid.package.plan.v1")
    }
}

/// Result of advancing a drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainResult {
    /// The drain remains durable and activation is refused.
    Draining,
    /// The deadline passed with live leases; recovery remains blocked.
    Blocked,
    /// The destination proved zero leases and completed.
    Completed,
}

/// Exact evidence used to reconcile an unknown result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryEvidence {
    token: RecoveryToken,
    observed_state: StateDigest,
    runtime_generation: NonZeroU64,
    activation_receipt: Option<Blake3Digest>,
    zero_leases_proved: bool,
}

impl RecoveryEvidence {
    pub(crate) const fn token_bytes(&self) -> [u8; 32] {
        self.token.into_bytes()
    }

    pub(crate) const fn observed_state(&self) -> StateDigest {
        self.observed_state
    }

    pub(crate) const fn runtime_generation(&self) -> NonZeroU64 {
        self.runtime_generation
    }

    pub(crate) const fn activation_receipt(&self) -> Option<Blake3Digest> {
        self.activation_receipt
    }

    pub(crate) const fn zero_leases_proved(&self) -> bool {
        self.zero_leases_proved
    }

    /// Constructs recovery evidence from independently read state/runtime values.
    #[must_use]
    pub const fn new(
        token: RecoveryToken,
        observed_state: StateDigest,
        runtime_generation: NonZeroU64,
        activation_receipt: Option<Blake3Digest>,
        zero_leases_proved: bool,
    ) -> Self {
        Self {
            token,
            observed_state,
            runtime_generation,
            activation_receipt,
            zero_leases_proved,
        }
    }
}

/// The authoritative co-located operation record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationJournalRecord {
    schema_version: JournalSchemaVersion,
    context: OperationContext,
    authority_digest: AuthorityDecisionDigest,
    request_digest: RequestDigest,
    intent_digest: TypedDigest<10>,
    reservation_digest: ReservationDigest,
    status: JournalStatus,
    started_at: Timestamp,
    terminal_at: Timestamp,
    receipt: Option<OperationReceipt>,
    recovery_token: RecoveryToken,
    state_generation: Option<NonZeroU64>,
    drain_base_state: Option<CanonicalInstalledState>,
}

impl OperationJournalRecord {
    pub(crate) fn new_intent(
        context: OperationContext,
        authority_digest: AuthorityDecisionDigest,
        ingress: &crate::context::AuthenticatedIngress,
        service: &crate::context::AdmittedService,
        now: Timestamp,
        state_generation: Option<NonZeroU64>,
    ) -> Self {
        let request_digest = {
            let mut writer = DigestWriter::new();
            writer.digest(context.digest());
            writer.digest(&authority_digest);
            writer.tag(ingress.channel_tag());
            writer.digest(ingress.evidence());
            writer.digest(service.evidence());
            writer.finish("astrid.package.request.v1")
        };
        let intent_digest = {
            let mut writer = DigestWriter::new();
            writer.digest(&request_digest);
            writer.tag(JournalStatus::Intent.tag());
            writer.finish("astrid.package.journal-intent.v1")
        };
        let reservation_digest = {
            let mut writer = DigestWriter::new();
            writer.digest(context.budget_digest());
            writer.u64(context.reservation_bytes());
            writer.finish("astrid.package.reservation.v1")
        };
        let recovery_token = {
            let mut writer = DigestWriter::new();
            writer.bytes(context.nonce().as_bytes());
            writer.digest(&intent_digest);
            let bytes: crate::digest::RequestDigest = writer.finish("astrid.package.recovery.v1");
            RecoveryToken::from_bytes(bytes.into_bytes())
        };
        Self {
            schema_version: JOURNAL_SCHEMA_VERSION,
            context,
            authority_digest,
            request_digest,
            intent_digest,
            reservation_digest,
            status: JournalStatus::Intent,
            started_at: now,
            terminal_at: now,
            receipt: None,
            recovery_token,
            state_generation,
            drain_base_state: None,
        }
    }

    /// Stable approximate encoded size charged against bounded capacity.
    #[must_use]
    pub const fn encoded_len(&self) -> u64 {
        1024
    }

    /// Returns the nonce-scoped recovery token.
    #[must_use]
    pub const fn recovery_token(&self) -> RecoveryToken {
        self.recovery_token
    }

    /// Returns the current journal status.
    #[must_use]
    pub const fn status(&self) -> JournalStatus {
        self.status
    }

    /// Returns the terminal timestamp when status is terminal.
    #[must_use]
    pub const fn terminal_at(&self) -> Timestamp {
        self.terminal_at
    }

    /// Returns the retained receipt when committed.
    #[must_use]
    pub const fn receipt(&self) -> Option<&OperationReceipt> {
        self.receipt.as_ref()
    }

    pub(crate) const fn context(&self) -> &OperationContext {
        &self.context
    }

    pub(crate) const fn authority_digest(&self) -> &AuthorityDecisionDigest {
        &self.authority_digest
    }

    pub(crate) fn record_digest(&self) -> TypedDigest<11> {
        let mut writer = DigestWriter::new();
        writer.u64(u64::from(self.schema_version.get()));
        writer.digest(&self.intent_digest);
        writer.tag(self.status.tag());
        writer.u64(self.started_at.get());
        writer.u64(self.terminal_at.get());
        match &self.receipt {
            Some(receipt) => {
                writer.tag(1);
                writer.digest(&receipt.digest);
            },
            None => writer.tag(0),
        }
        writer.finish("astrid.package.journal-record.v1")
    }

    pub(crate) const fn state_generation(&self) -> Option<NonZeroU64> {
        self.state_generation
    }

    pub(crate) const fn set_state_generation(&mut self, generation: NonZeroU64) {
        self.state_generation = Some(generation);
    }

    pub(crate) fn set_drain_base_state(&mut self, state: CanonicalInstalledState) {
        self.drain_base_state = Some(state);
    }

    pub(crate) fn take_drain_base_state(&mut self) -> Option<CanonicalInstalledState> {
        self.drain_base_state.take()
    }

    pub(crate) const fn before_state(&self) -> StateDigest {
        self.context.expected_state().digest()
    }

    pub(crate) fn set_executing(&mut self, now: Timestamp) {
        self.status = JournalStatus::Executing;
        self.started_at = now;
    }

    pub(crate) fn mark_unknown(&mut self, now: Timestamp) {
        self.status = JournalStatus::Unknown;
        self.terminal_at = now;
    }

    pub(crate) fn terminal_failure(&mut self, status: JournalStatus, now: Timestamp) {
        self.status = status;
        self.terminal_at = now;
    }

    pub(crate) fn commit(&mut self, receipt: OperationReceipt, now: Timestamp) {
        self.status = JournalStatus::Committed;
        self.terminal_at = now;
        self.receipt = Some(receipt);
    }

    pub(crate) fn resolve_recovery(
        &mut self,
        receipt: Option<OperationReceipt>,
        status: JournalStatus,
        now: Timestamp,
    ) {
        self.status = status;
        self.terminal_at = now;
        self.receipt = receipt;
    }
}

/// Bounded replay evidence retained even after record collection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tombstone {
    nonce: Nonce,
    terminal_status: JournalStatus,
    context_digest: crate::digest::ContextDigest,
    outcome: Option<ReceiptOutcome>,
    record_digest: TypedDigest<11>,
}

impl Tombstone {
    /// Returns the collected nonce.
    #[must_use]
    pub const fn nonce(&self) -> Nonce {
        self.nonce
    }

    /// Returns the terminal record class retained by the tombstone.
    #[must_use]
    pub const fn terminal_status(&self) -> JournalStatus {
        self.terminal_status
    }

    /// Returns the operation context originally covered by the record.
    #[must_use]
    pub const fn context_digest(&self) -> crate::digest::ContextDigest {
        self.context_digest
    }

    /// Returns the outcome class when a receipt had committed.
    #[must_use]
    pub const fn outcome(&self) -> Option<ReceiptOutcome> {
        self.outcome
    }
}

/// Outcome of replaying a nonce.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayOutcome {
    /// The exact terminal receipt was retained.
    Receipt(OperationReceipt),
    /// The operation is still unresolved and may only resume or recover.
    Unresolved,
    /// The record was collected, but a bounded tombstone proves later replay.
    Tombstoned(Tombstone),
}

/// One owner/package slot holding canonical state and its authoritative journal.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PackageSlotRecord {
    state: Option<CanonicalInstalledState>,
    journal: BTreeMap<Nonce, OperationJournalRecord>,
}

impl PackageSlotRecord {
    /// Returns the canonical state digest, with a fixed digest for absence.
    #[must_use]
    pub const fn expected_state_digest(&self) -> StateDigest {
        match &self.state {
            Some(state) => state.digest(),
            None => StateDigest::from_bytes([0; 32]),
        }
    }

    /// Returns canonical installed state.
    #[must_use]
    pub const fn state(&self) -> Option<&CanonicalInstalledState> {
        self.state.as_ref()
    }

    /// Returns a journal record by nonce.
    #[must_use]
    pub fn journal_record(&self, nonce: &Nonce) -> Option<&OperationJournalRecord> {
        self.journal.get(nonce)
    }

    pub(crate) fn journal_mut(&mut self, nonce: &Nonce) -> Option<&mut OperationJournalRecord> {
        self.journal.get_mut(nonce)
    }

    pub(crate) fn insert_intent(
        &mut self,
        record: OperationJournalRecord,
    ) -> PackageServiceResult<()> {
        if self.journal.contains_key(&record.context().nonce()) {
            return Err(PackageServiceError::ReplayRejected);
        }
        self.journal.insert(record.context().nonce(), record);
        Ok(())
    }

    pub(crate) fn journal_values(&self) -> impl Iterator<Item = &OperationJournalRecord> {
        self.journal.values()
    }

    pub(crate) fn remove_journal(&mut self, nonce: &Nonce) -> Option<Tombstone> {
        let record = self.journal.remove(nonce)?;
        Some(Tombstone {
            nonce: *nonce,
            terminal_status: record.status(),
            context_digest: *record.context().digest(),
            outcome: record.receipt().map(|receipt| receipt.outcome()),
            record_digest: record.record_digest(),
        })
    }

    /// Replaces canonical state and journal as one logical value.
    pub(crate) fn replace_state(&mut self, state: Option<CanonicalInstalledState>) {
        self.state = state;
    }
}
