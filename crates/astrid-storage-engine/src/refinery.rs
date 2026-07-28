//! Privilege-separated seams for bounded cold-path storage passes.

use astrid_storage_model::{ObjectId, ObjectIdentity, ObjectKind, ObjectRecord, PlacementEpoch};

/// Identity of one pinned Refinery pass descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefineryPassDescriptorId(ObjectId);

impl RefineryPassDescriptorId {
    /// Construct a descriptor identity.
    #[must_use]
    pub const fn new(object: ObjectId) -> Self {
        Self(object)
    }

    /// Return the underlying logical object identity.
    #[must_use]
    pub const fn object_id(self) -> ObjectId {
        self.0
    }
}

/// Identity of the immutable liveness/input snapshot for one batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefinerySnapshotId(ObjectId);

impl RefinerySnapshotId {
    /// Construct a snapshot identity.
    #[must_use]
    pub const fn new(object: ObjectId) -> Self {
        Self(object)
    }

    /// Return the underlying logical object identity.
    #[must_use]
    pub const fn object_id(self) -> ObjectId {
        self.0
    }
}

/// Identity of an opaque, pass-specific resumable checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefineryCheckpointId(ObjectId);

impl RefineryCheckpointId {
    /// Construct a checkpoint identity.
    #[must_use]
    pub const fn new(object: ObjectId) -> Self {
        Self(object)
    }

    /// Return the underlying logical object identity.
    #[must_use]
    pub const fn object_id(self) -> ObjectId {
        self.0
    }
}

/// Operator-authorized resource ceiling for one cold-path work lease.
///
/// The common Astrid resource authority creates these values. Refinery does
/// not infer defaults or silently borrow from a principal's foreground budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefineryResourceBudget {
    cpu_time_ns: u64,
    resident_byte_ns: u128,
    bytes_read: u64,
    bytes_written: u64,
    device_work_units: u64,
    retained_output_bytes: u64,
}

impl RefineryResourceBudget {
    /// Construct an explicit resource ceiling.
    #[must_use]
    pub const fn new(
        cpu_time_ns: u64,
        resident_byte_ns: u128,
        bytes_read: u64,
        bytes_written: u64,
        device_work_units: u64,
        retained_output_bytes: u64,
    ) -> Self {
        Self {
            cpu_time_ns,
            resident_byte_ns,
            bytes_read,
            bytes_written,
            device_work_units,
            retained_output_bytes,
        }
    }

    /// Return the CPU-time ceiling in nanoseconds.
    #[must_use]
    pub const fn cpu_time_ns(self) -> u64 {
        self.cpu_time_ns
    }

    /// Return the resident byte-time ceiling.
    #[must_use]
    pub const fn resident_byte_ns(self) -> u128 {
        self.resident_byte_ns
    }

    /// Return the read-byte ceiling.
    #[must_use]
    pub const fn bytes_read(self) -> u64 {
        self.bytes_read
    }

    /// Return the physical write-byte ceiling.
    #[must_use]
    pub const fn bytes_written(self) -> u64 {
        self.bytes_written
    }

    /// Return the device or accelerator work-unit ceiling.
    #[must_use]
    pub const fn device_work_units(self) -> u64 {
        self.device_work_units
    }

    /// Return the retained Evidence/Derived byte ceiling.
    #[must_use]
    pub const fn retained_output_bytes(self) -> u64 {
        self.retained_output_bytes
    }
}

/// Immutable context shared by every observer in one Refinery batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefineryBatchContext {
    snapshot: RefinerySnapshotId,
    placement_epoch: PlacementEpoch,
    budget: RefineryResourceBudget,
    checkpoint: Option<RefineryCheckpointId>,
}

impl RefineryBatchContext {
    /// Construct one engine-selected batch context.
    #[must_use]
    pub const fn new(
        snapshot: RefinerySnapshotId,
        placement_epoch: PlacementEpoch,
        budget: RefineryResourceBudget,
        checkpoint: Option<RefineryCheckpointId>,
    ) -> Self {
        Self {
            snapshot,
            placement_epoch,
            budget,
            checkpoint,
        }
    }

    /// Return the frozen input/liveness snapshot identity.
    #[must_use]
    pub const fn snapshot(self) -> RefinerySnapshotId {
        self.snapshot
    }

    /// Return the physical placement epoch observed by this batch.
    #[must_use]
    pub const fn placement_epoch(self) -> PlacementEpoch {
        self.placement_epoch
    }

    /// Return the operator-authorized resource ceiling.
    #[must_use]
    pub const fn budget(self) -> RefineryResourceBudget {
        self.budget
    }

    /// Return the optional resumable checkpoint.
    #[must_use]
    pub const fn checkpoint(self) -> Option<RefineryCheckpointId> {
        self.checkpoint
    }
}

/// Immutable object admitted and identity-verified by the engine.
///
/// The constructor is engine-private. Observer implementations receive this
/// read-only view and cannot create a token around unverified caller bytes.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedRefineryObject<'a> {
    id: ObjectId,
    record: &'a ObjectRecord,
}

impl VerifiedRefineryObject<'_> {
    /// Return the recomputed logical object identity.
    #[must_use]
    pub const fn id(self) -> ObjectId {
        self.id
    }
}

impl<'a> VerifiedRefineryObject<'a> {
    pub(crate) const fn from_engine(id: ObjectId, record: &'a ObjectRecord) -> Self {
        Self { id, record }
    }

    /// Borrow the immutable canonical object with the source lifetime.
    #[must_use]
    pub const fn as_record(self) -> &'a ObjectRecord {
        self.record
    }
}

/// Output class accepted from an observer pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefineryOutputClass {
    /// Auditable statement about verified input or work.
    Evidence,
    /// Rebuildable materialization or index.
    Derived,
}

/// One proposed observer output awaiting normal admission and publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposedRefineryOutput {
    class: RefineryOutputClass,
    record: ObjectRecord,
}

impl ProposedRefineryOutput {
    /// Return the proposed output class.
    #[must_use]
    pub const fn class(&self) -> RefineryOutputClass {
        self.class
    }

    /// Borrow the untrusted proposed record.
    #[must_use]
    pub const fn record(&self) -> &ObjectRecord {
        &self.record
    }
}

/// Engine-owned sink for observer proposals.
///
/// Proposals are not persisted, trusted, or published by this sink. The
/// engine later recomputes identity and applies contract, closure, quota, and
/// root-CAS validation through the ordinary path.
#[derive(Debug, Default)]
pub struct RefineryProposalSink {
    outputs: Vec<ProposedRefineryOutput>,
}

impl RefineryProposalSink {
    pub(crate) const fn new() -> Self {
        Self {
            outputs: Vec::new(),
        }
    }

    /// Propose one generic Evidence object.
    ///
    /// # Errors
    ///
    /// Returns [`RefineryProposalError::WrongObjectKind`] unless the record is
    /// generic `Evidence`.
    pub fn propose_evidence(&mut self, record: ObjectRecord) -> Result<(), RefineryProposalError> {
        self.propose(RefineryOutputClass::Evidence, ObjectKind::Evidence, record)
    }

    /// Propose one rebuildable Derived object.
    ///
    /// # Errors
    ///
    /// Returns [`RefineryProposalError::WrongObjectKind`] unless the record is
    /// `Derived`.
    pub fn propose_derived(&mut self, record: ObjectRecord) -> Result<(), RefineryProposalError> {
        self.propose(RefineryOutputClass::Derived, ObjectKind::Derived, record)
    }

    fn propose(
        &mut self,
        class: RefineryOutputClass,
        expected: ObjectKind,
        record: ObjectRecord,
    ) -> Result<(), RefineryProposalError> {
        if record.kind() != expected {
            return Err(RefineryProposalError::WrongObjectKind {
                expected,
                actual: record.kind(),
            });
        }
        self.outputs.push(ProposedRefineryOutput { class, record });
        Ok(())
    }

    pub(crate) fn into_outputs(self) -> Vec<ProposedRefineryOutput> {
        self.outputs
    }
}

/// Observer pass over engine-selected, verified immutable objects.
///
/// Implementations have no root, arena, placement, deletion, or publication
/// handle. They may only inspect the batch context and verified stream, retain
/// their own resumable state, and propose Evidence/Derived outputs.
pub trait RefineryPass: Send {
    /// Pass-specific execution failure.
    type Error;

    /// Return the pinned descriptor participating in invocation identity.
    fn descriptor(&self) -> RefineryPassDescriptorId;

    /// Start or resume one immutable batch.
    ///
    /// # Errors
    ///
    /// Returns a pass-specific bounded-work failure.
    fn begin(&mut self, context: RefineryBatchContext) -> Result<(), Self::Error>;

    /// Observe one engine-verified immutable object.
    ///
    /// # Errors
    ///
    /// Returns a pass-specific bounded-work failure. The pass may use
    /// [`RefineryProposalSink`] only to propose untrusted outputs.
    fn observe(
        &mut self,
        object: VerifiedRefineryObject<'_>,
        proposals: &mut RefineryProposalSink,
    ) -> Result<(), Self::Error>;

    /// Finish the current batch after the verified stream ends.
    ///
    /// # Errors
    ///
    /// Returns a pass-specific failure. Proposed outputs still require normal
    /// engine admission.
    fn finish(&mut self, proposals: &mut RefineryProposalSink) -> Result<(), Self::Error>;

    /// Return an optional bounded resume checkpoint after interruption.
    fn checkpoint(&self) -> Option<RefineryCheckpointId>;
}

/// Run one observer through the common identity-verifying pass boundary.
///
/// The caller selects records from the frozen batch snapshot. This function
/// rechecks each logical identity before minting the read-only observer token,
/// collects only untrusted proposals, and never publishes them.
///
/// # Errors
///
/// Returns an identity mismatch before exposing substituted bytes or a
/// pass-specific execution failure.
pub fn run_refinery_observer<I, P>(
    identity: &I,
    pass: &mut P,
    context: RefineryBatchContext,
    objects: &[(ObjectId, ObjectRecord)],
) -> Result<Vec<ProposedRefineryOutput>, RefineryRunError<P::Error>>
where
    I: ObjectIdentity,
    P: RefineryPass,
{
    for (declared, record) in objects {
        if identity.identify(record) != *declared {
            return Err(RefineryRunError::ObjectIdentityMismatch(*declared));
        }
    }
    pass.begin(context).map_err(RefineryRunError::Pass)?;
    let mut proposals = RefineryProposalSink::new();
    for (declared, record) in objects {
        pass.observe(
            VerifiedRefineryObject::from_engine(*declared, record),
            &mut proposals,
        )
        .map_err(RefineryRunError::Pass)?;
    }
    pass.finish(&mut proposals)
        .map_err(RefineryRunError::Pass)?;
    Ok(proposals.into_outputs())
}

/// Failure from the common observer runner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefineryRunError<E> {
    /// A selected record did not hash to its declared identity.
    ObjectIdentityMismatch(ObjectId),
    /// The observer pass failed within its bounded work contract.
    Pass(E),
}

impl<E: std::fmt::Display> std::fmt::Display for RefineryRunError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ObjectIdentityMismatch(id) => {
                write!(formatter, "Refinery object identity mismatch at {id:?}")
            },
            Self::Pass(error) => write!(formatter, "Refinery pass failed: {error}"),
        }
    }
}

/// Proposal validation failure at the observer boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefineryProposalError {
    /// An observer attempted to submit a record outside its declared output
    /// class.
    WrongObjectKind {
        /// Required object kind.
        expected: ObjectKind,
        /// Supplied object kind.
        actual: ObjectKind,
    },
}

impl std::fmt::Display for RefineryProposalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongObjectKind { expected, actual } => write!(
                formatter,
                "wrong Refinery proposal kind: expected {expected:?}, actual {actual:?}"
            ),
        }
    }
}

/// Engine-only compaction implementation.
///
/// The private supertrait makes this impossible to implement outside the
/// storage engine. Sharing a scheduler with observer passes never grants them
/// physical-placement or deletion authority.
pub trait EngineCompactionPass: sealed::EngineCompactionSealed {
    /// Return the pinned native operation contract.
    fn operation_contract(&self) -> ObjectId;
}

pub(crate) struct NativeArenaCompactionPass {
    operation_contract: ObjectId,
}

impl NativeArenaCompactionPass {
    pub(crate) const fn new(operation_contract: ObjectId) -> Self {
        Self { operation_contract }
    }
}

impl sealed::EngineCompactionSealed for NativeArenaCompactionPass {}

impl EngineCompactionPass for NativeArenaCompactionPass {
    fn operation_contract(&self) -> ObjectId {
        self.operation_contract
    }
}

pub(crate) mod sealed {
    pub trait EngineCompactionSealed {}
}

#[cfg(test)]
mod tests {
    use astrid_storage_model::{ObjectClass, ObjectFormatVersion};

    use super::*;

    #[derive(Clone, Copy)]
    struct TestIdentity;

    impl ObjectIdentity for TestIdentity {
        fn identify(&self, record: &ObjectRecord) -> ObjectId {
            let mut bytes = [0_u8; 32];
            bytes[..2].copy_from_slice(&record.kind().code().to_le_bytes());
            bytes[2] = record
                .canonical_bytes()
                .first()
                .copied()
                .unwrap_or_default();
            ObjectId::new(bytes)
        }
    }

    #[derive(Default)]
    struct RecordingPass {
        observed: Vec<ObjectId>,
    }

    impl RefineryPass for RecordingPass {
        type Error = &'static str;

        fn descriptor(&self) -> RefineryPassDescriptorId {
            RefineryPassDescriptorId::new(ObjectId::new([1; 32]))
        }

        fn begin(&mut self, _context: RefineryBatchContext) -> Result<(), Self::Error> {
            Ok(())
        }

        fn observe(
            &mut self,
            object: VerifiedRefineryObject<'_>,
            proposals: &mut RefineryProposalSink,
        ) -> Result<(), Self::Error> {
            self.observed.push(object.id());
            proposals
                .propose_evidence(record(ObjectKind::Evidence))
                .map_err(|_| "proposal rejected")
        }

        fn finish(&mut self, _proposals: &mut RefineryProposalSink) -> Result<(), Self::Error> {
            Ok(())
        }

        fn checkpoint(&self) -> Option<RefineryCheckpointId> {
            None
        }
    }

    fn record(kind: ObjectKind) -> ObjectRecord {
        ObjectRecord::new(
            kind,
            ObjectFormatVersion::V1,
            b"result".to_vec(),
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )
        .unwrap()
    }

    #[test]
    fn observer_sink_accepts_only_evidence_and_derived_records() {
        let mut sink = RefineryProposalSink::new();
        sink.propose_evidence(record(ObjectKind::Evidence)).unwrap();
        sink.propose_derived(record(ObjectKind::Derived)).unwrap();
        assert_eq!(
            sink.propose_evidence(record(ObjectKind::Chunk)),
            Err(RefineryProposalError::WrongObjectKind {
                expected: ObjectKind::Evidence,
                actual: ObjectKind::Chunk,
            })
        );
        let outputs = sink.into_outputs();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].class(), RefineryOutputClass::Evidence);
        assert_eq!(outputs[1].class(), RefineryOutputClass::Derived);
    }

    #[test]
    fn verified_object_is_a_read_only_engine_token() {
        let record = record(ObjectKind::Chunk);
        let id = ObjectId::new([7; 32]);
        let object = VerifiedRefineryObject::from_engine(id, &record);
        assert_eq!(object.id(), id);
        assert_eq!(object.as_record(), &record);
    }

    #[test]
    fn common_runner_recomputes_identity_before_observation() {
        let identity = TestIdentity;
        let selected = record(ObjectKind::Chunk);
        let id = identity.identify(&selected);
        let context = RefineryBatchContext::new(
            RefinerySnapshotId::new(ObjectId::new([2; 32])),
            PlacementEpoch::new(3),
            RefineryResourceBudget::new(1, 2, 3, 4, 5, 6),
            None,
        );
        let mut pass = RecordingPass::default();
        let outputs =
            run_refinery_observer(&identity, &mut pass, context, &[(id, selected.clone())])
                .unwrap();
        assert_eq!(pass.observed, vec![id]);
        assert_eq!(outputs.len(), 1);

        let mut rejected_pass = RecordingPass::default();
        let result = run_refinery_observer(
            &identity,
            &mut rejected_pass,
            context,
            &[(id, selected.clone()), (ObjectId::new([9; 32]), selected)],
        );
        assert!(matches!(
            result,
            Err(RefineryRunError::ObjectIdentityMismatch(_))
        ));
        assert!(rejected_pass.observed.is_empty());
    }
}
