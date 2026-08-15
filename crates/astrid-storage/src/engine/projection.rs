//! Generic principal-state projection boundary.
//!
//! KV, content, filesystem, and future principal-owned projections share one
//! atomic principal root. This trait prevents each projection from inventing
//! a side root while keeping the engine unaware of projection semantics.

use std::any::Any;
use std::fmt;
use std::mem::{size_of, size_of_val};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use crate::storage_model::{
    InsertOutcome, ModelError, ObjectId, ObjectIdentity, ObjectRecord, RootState,
};

use crate::engine::{CommitOutcome, InMemoryEngine, RootTransaction};
#[cfg(not(target_family = "wasm"))]
use crate::engine::{DurableEngine, DurableError, PersistentObjectIdentity, PrincipalCodec};

/// Opaque name for one projection-owned process-local cache value.
///
/// The key is meaningful only to the projection that defines it. The engine
/// uses it to keep independently typed accelerators apart while governing all
/// retained host memory through one cache authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProjectionCacheKey(u64);

impl ProjectionCacheKey {
    /// Construct a stable projection-local cache key.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// Process-local payload accepted by the governed projection cache.
///
/// Implementations must include owned heap allocations in `retained_bytes`.
/// The value is an accelerator only: refusing or evicting it must never change
/// projection correctness.
pub trait ProjectionCachePayload: Any + Send + Sync {
    /// Return the complete resident-memory charge for this value.
    fn retained_bytes(&self) -> u64;
}

/// Type-erased projection-cache entry crossing the engine boundary.
#[derive(Clone)]
pub struct ProjectionCacheEntry {
    value: Arc<dyn Any + Send + Sync>,
    retained_bytes: u64,
}

/// Privileged phase name emitted by measured projection operations.
///
/// These phases expose shared-engine work and must remain below every
/// principal-visible API boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProjectionPhase {
    /// Canonical object validation, identity, and frame preparation.
    ObjectPreparation,
    /// Authoritative existing-object collision probe.
    AdmissionProbe,
    /// Direct physical-identity construction.
    DirectIdentity,
    /// Append of prepared immutable-object frames.
    ArenaAppend,
    /// Physical representation-map staging or publication.
    PhysicalMapUpdate,
    /// Owning-closure validation before a root transition.
    ClosureValidation,
    /// Append of the authoritative root transition.
    RootPublication,
    /// Durable media flushes guarding publication acknowledgement.
    Flush,
}

/// Operator-owned sink for projection phase measurements.
pub trait ProjectionObserver: Send + Sync {
    /// Record elapsed time for one privileged phase occurrence.
    fn record(&self, phase: ProjectionPhase, elapsed: Duration);
}

/// Process-local phase buffer used to keep observer code outside engine locks.
#[derive(Default)]
pub(crate) struct ProjectionPhaseBuffer {
    events: Mutex<Vec<(ProjectionPhase, Duration)>>,
}

impl ProjectionObserver for ProjectionPhaseBuffer {
    fn record(&self, phase: ProjectionPhase, elapsed: Duration) {
        self.events.lock().push((phase, elapsed));
    }
}

impl ProjectionPhaseBuffer {
    pub(crate) fn flush_into(&self, observer: &dyn ProjectionObserver) {
        let events = std::mem::take(&mut *self.events.lock());
        for (phase, elapsed) in events {
            observer.record(phase, elapsed);
        }
    }
}

#[cfg(not(target_family = "wasm"))]
pub(crate) fn with_buffered_observer<T>(
    observer: Option<&dyn ProjectionObserver>,
    operation: impl FnOnce(Option<&dyn ProjectionObserver>) -> T,
) -> T {
    let Some(observer) = observer else {
        return operation(None);
    };
    let buffer = ProjectionPhaseBuffer::default();
    let result = operation(Some(&buffer));
    buffer.flush_into(observer);
    result
}

pub(crate) fn object_record_retained_bytes(record: &ObjectRecord) -> usize {
    size_of::<ObjectRecord>()
        .saturating_add(record.canonical_bytes().len())
        .saturating_add(size_of_val(record.references()))
        .saturating_add(
            record
                .references()
                .iter()
                .map(|reference| reference.label().as_bytes().len())
                .sum::<usize>(),
        )
}

/// Opaque, engine-bound preparation for one immutable-object batch.
///
/// Preparation may carry checksums and physical identities across a worker
/// boundary, but admission remains authoritative: the receiving engine
/// validates ownership of this value and rechecks every identity and collision
/// before appending bytes.
pub struct PreparedProjectionBatch {
    payload: Box<dyn Any + Send>,
    retained_bytes: usize,
}

struct InMemoryPreparedBatch {
    authority: Arc<()>,
    records: Vec<ObjectRecord>,
}

impl PreparedProjectionBatch {
    fn in_memory(authority: Arc<()>, records: Vec<ObjectRecord>) -> Self {
        let retained_bytes = records
            .iter()
            .fold(size_of::<InMemoryPreparedBatch>(), |total, record| {
                total.saturating_add(object_record_retained_bytes(record))
            });
        Self {
            payload: Box::new(InMemoryPreparedBatch { authority, records }),
            retained_bytes,
        }
    }

    #[cfg(not(target_family = "wasm"))]
    pub(crate) fn engine<T: Any + Send>(payload: T, retained_bytes: usize) -> Self {
        Self {
            payload: Box::new(payload),
            retained_bytes,
        }
    }

    pub(crate) fn into_payload<T: Any + Send>(self) -> Result<T, PrincipalProjectionError> {
        self.payload
            .downcast::<T>()
            .map(|payload| *payload)
            .map_err(|_| {
                PrincipalProjectionError::Engine(
                    "prepared object batch does not belong to this engine".to_owned(),
                )
            })
    }

    fn into_in_memory(
        self,
        authority: &Arc<()>,
    ) -> Result<Vec<ObjectRecord>, PrincipalProjectionError> {
        let prepared = self.into_payload::<InMemoryPreparedBatch>()?;
        if !Arc::ptr_eq(authority, &prepared.authority) {
            return Err(foreign_preparation());
        }
        Ok(prepared.records)
    }

    #[cfg(not(target_family = "wasm"))]
    pub(crate) fn into_engine_payload<T: Any + Send>(self) -> Option<T> {
        self.payload.downcast::<T>().ok().map(|payload| *payload)
    }

    /// Return the bytes retained by the prepared batch while awaiting admission.
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }
}

impl ProjectionCacheEntry {
    /// Wrap one typed accelerator and capture its resident-memory charge.
    #[must_use]
    pub fn new<T: ProjectionCachePayload>(value: T) -> Self {
        Self {
            retained_bytes: value.retained_bytes(),
            value: Arc::new(value),
        }
    }

    /// Recover a shared typed value when the cache key belongs to `T`.
    #[must_use]
    pub fn downcast<T: ProjectionCachePayload>(&self) -> Option<Arc<T>> {
        Arc::downcast(Arc::clone(&self.value)).ok()
    }

    /// Return the payload's declared resident-memory charge.
    #[must_use]
    pub const fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }

    #[cfg(not(target_family = "wasm"))]
    pub(crate) fn into_parts(self) -> (Arc<dyn Any + Send + Sync>, u64) {
        (self.value, self.retained_bytes)
    }

    #[cfg(not(target_family = "wasm"))]
    pub(crate) const fn from_parts(value: Arc<dyn Any + Send + Sync>, retained_bytes: u64) -> Self {
        Self {
            value,
            retained_bytes,
        }
    }
}

/// Failure at the generic principal projection boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrincipalProjectionError {
    /// The portable object/root model rejected the operation.
    Model(ModelError),
    /// The durable engine failed outside the portable model.
    Engine(String),
}

impl fmt::Display for PrincipalProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model(error) => error.fmt(formatter),
            Self::Engine(error) => write!(formatter, "principal projection engine: {error}"),
        }
    }
}

impl std::error::Error for PrincipalProjectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Model(error) => Some(error),
            Self::Engine(_) => None,
        }
    }
}

impl From<ModelError> for PrincipalProjectionError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

/// Engine operations shared by typed principal-state projections.
pub trait PrincipalProjectionEngine<P>: Send + Sync {
    /// Compute one canonical object identity.
    fn identify_object(&self, record: &ObjectRecord) -> ObjectId;

    /// Stage one immutable object without publishing a principal root.
    ///
    /// The engine recomputes identity and rejects collisions. A successful new
    /// admission need not be durable until a later [`Self::commit_root`]
    /// flushes the object arena before publishing its root. Staged objects are
    /// unreachable and may be reclaimed when no committed root refers to them.
    /// Callers must keep the returned admission outcome below the guest API
    /// boundary because it reveals whether deduplication found existing bytes.
    ///
    /// The default keeps this method additive for projection engines that do
    /// not support incremental staging.
    ///
    /// # Errors
    ///
    /// Returns a projection error when incremental staging is unsupported or
    /// object admission fails.
    fn stage_object(
        &self,
        _record: ObjectRecord,
    ) -> Result<(ObjectId, InsertOutcome), PrincipalProjectionError> {
        Err(PrincipalProjectionError::Engine(
            "incremental object staging is unsupported".to_owned(),
        ))
    }

    /// Stage immutable objects as one implementation-defined append batch.
    ///
    /// Results must correspond to input order. The default preserves support
    /// for existing engines by calling [`Self::stage_object`] for each record;
    /// durable engines may coalesce the physical write. Admission outcomes are
    /// privileged diagnostics and must not become guest-visible.
    ///
    /// # Errors
    ///
    /// Returns a projection error when any object cannot be admitted.
    fn stage_objects(
        &self,
        records: Vec<ObjectRecord>,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, PrincipalProjectionError> {
        records
            .into_iter()
            .map(|record| self.stage_object(record))
            .collect()
    }

    /// Stage objects while reporting privileged operator phase measurements.
    ///
    /// Engines without finer instrumentation report the complete call as
    /// [`ProjectionPhase::ObjectPreparation`].
    ///
    /// # Errors
    ///
    /// Returns the same model or engine failure as [`Self::stage_objects`].
    fn stage_objects_observed(
        &self,
        records: Vec<ObjectRecord>,
        observer: &dyn ProjectionObserver,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, PrincipalProjectionError> {
        let started = std::time::Instant::now();
        let outcome = self.stage_objects(records);
        observer.record(ProjectionPhase::ObjectPreparation, started.elapsed());
        outcome
    }

    /// Prepare immutable objects for later authoritative admission.
    ///
    /// # Errors
    ///
    /// Returns a projection error when this engine does not implement an
    /// engine-bound preparation path or cannot validate an object.
    fn prepare_objects(
        &self,
        _records: Vec<ObjectRecord>,
    ) -> Result<PreparedProjectionBatch, PrincipalProjectionError> {
        Err(unsupported_preparation())
    }

    /// Prepare immutable objects while reporting privileged phase measurements.
    ///
    /// # Errors
    ///
    /// Returns the same failure as [`Self::prepare_objects`].
    fn prepare_objects_observed(
        &self,
        records: Vec<ObjectRecord>,
        observer: &dyn ProjectionObserver,
    ) -> Result<PreparedProjectionBatch, PrincipalProjectionError> {
        let started = std::time::Instant::now();
        let prepared = self.prepare_objects(records);
        observer.record(ProjectionPhase::ObjectPreparation, started.elapsed());
        prepared
    }

    /// Authoritatively admit a batch prepared by this engine.
    ///
    /// # Errors
    ///
    /// Returns a projection error for a foreign preparation, invalid identity,
    /// collision, encoding failure, or append failure.
    fn stage_prepared_objects(
        &self,
        _prepared: PreparedProjectionBatch,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, PrincipalProjectionError> {
        Err(unsupported_preparation())
    }

    /// Admit a prepared batch while reporting privileged phase measurements.
    ///
    /// # Errors
    ///
    /// Returns the same failure as [`Self::stage_prepared_objects`].
    fn stage_prepared_objects_observed(
        &self,
        prepared: PreparedProjectionBatch,
        observer: &dyn ProjectionObserver,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, PrincipalProjectionError> {
        let started = std::time::Instant::now();
        let outcome = self.stage_prepared_objects(prepared);
        observer.record(ProjectionPhase::ArenaAppend, started.elapsed());
        outcome
    }

    /// Return a principal's current root.
    ///
    /// # Errors
    ///
    /// Returns a projection error when authoritative root state cannot be
    /// read.
    fn current_root(&self, principal: &P) -> Result<Option<RootState>, PrincipalProjectionError>;

    /// Load one immutable object.
    ///
    /// # Errors
    ///
    /// Returns a projection error when the object arena cannot complete the
    /// read.
    fn load_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, PrincipalProjectionError>;

    /// Load one immutable object with principal cache attribution.
    ///
    /// The default preserves engines without a governed decoded-object cache.
    /// Cache policy is a performance and resource-accounting concern; it must
    /// never change the bytes or errors returned by [`Self::load_object`].
    ///
    /// # Errors
    ///
    /// Returns a projection error when the object arena cannot complete the
    /// read.
    fn load_object_for(
        &self,
        _principal: &P,
        id: ObjectId,
    ) -> Result<Option<ObjectRecord>, PrincipalProjectionError> {
        self.load_object(id)
    }

    /// Load one immutable object through a shared allocation with principal
    /// cache attribution.
    ///
    /// The default preserves engines that return owned records. Governed
    /// caching engines should override this method so a hit only increments a
    /// reference count.
    ///
    /// # Errors
    ///
    /// Returns a projection error when the object arena cannot complete the
    /// read.
    fn load_shared_object_for(
        &self,
        principal: &P,
        id: ObjectId,
    ) -> Result<Option<Arc<ObjectRecord>>, PrincipalProjectionError> {
        self.load_object_for(principal, id)
            .map(|record| record.map(Arc::new))
    }

    /// Load immutable objects in request order with principal cache
    /// attribution.
    ///
    /// The default preserves engines without a coalesced batch path.
    ///
    /// # Errors
    ///
    /// Returns a projection error when the object arena cannot complete the
    /// reads.
    fn load_objects_for(
        &self,
        principal: &P,
        ids: &[ObjectId],
    ) -> Result<Vec<Option<ObjectRecord>>, PrincipalProjectionError> {
        ids.iter()
            .map(|id| self.load_object_for(principal, *id))
            .collect()
    }

    /// Load immutable objects through shared allocations in request order.
    ///
    /// The default preserves engines without a shared batch path.
    ///
    /// # Errors
    ///
    /// Returns a projection error when the object arena cannot complete the
    /// reads.
    fn load_shared_objects_for(
        &self,
        principal: &P,
        ids: &[ObjectId],
    ) -> Result<Vec<Option<Arc<ObjectRecord>>>, PrincipalProjectionError> {
        self.load_objects_for(principal, ids).map(|records| {
            records
                .into_iter()
                .map(|record| record.map(Arc::new))
                .collect()
        })
    }

    /// Load one projection-owned accelerator under principal attribution.
    ///
    /// The default disables retention. A cache miss, disabled budget, or
    /// eviction returns `None`; callers must also treat a typed downcast
    /// mismatch as a miss and take the ordinary correctness path.
    fn load_projection_cache(
        &self,
        _principal: &P,
        _object: ObjectId,
        _key: ProjectionCacheKey,
    ) -> Option<ProjectionCacheEntry> {
        None
    }

    /// Retain one projection-owned accelerator under the same global and
    /// per-principal budgets as decoded immutable objects.
    ///
    /// Returns `false` when policy declines retention. Callers must still
    /// return the valid result that produced the accelerator.
    fn retain_projection_cache(
        &self,
        _principal: &P,
        _object: ObjectId,
        _key: ProjectionCacheKey,
        _value: ProjectionCacheEntry,
    ) -> bool {
        false
    }

    /// Discard one projection-owned accelerator when a stronger or newer
    /// process-local value makes it redundant.
    fn discard_projection_cache(
        &self,
        _principal: &P,
        _object: ObjectId,
        _key: ProjectionCacheKey,
    ) -> bool {
        false
    }

    /// Atomically publish one principal-state transition.
    ///
    /// # Errors
    ///
    /// Returns a projection error when identity, graph, compare-and-swap, or
    /// durable publication fails.
    fn commit_root(
        &self,
        transaction: RootTransaction<P>,
    ) -> Result<CommitOutcome, PrincipalProjectionError>;

    /// Publish a root while reporting privileged operator phase measurements.
    ///
    /// Engines without finer instrumentation report the complete call as
    /// [`ProjectionPhase::RootPublication`].
    ///
    /// # Errors
    ///
    /// Returns the same model or engine failure as [`Self::commit_root`].
    fn commit_root_observed(
        &self,
        transaction: RootTransaction<P>,
        observer: Arc<dyn ProjectionObserver>,
    ) -> Result<CommitOutcome, PrincipalProjectionError> {
        let started = std::time::Instant::now();
        let outcome = self.commit_root(transaction);
        observer.record(ProjectionPhase::RootPublication, started.elapsed());
        outcome
    }

    /// Flush authoritative engine state.
    ///
    /// # Errors
    ///
    /// Returns a projection error when durable state cannot be flushed.
    fn flush_projection(&self) -> Result<(), PrincipalProjectionError>;
}

impl<P, I> PrincipalProjectionEngine<P> for InMemoryEngine<P, I>
where
    P: Clone + Ord + Send + Sync,
    I: ObjectIdentity + Send + Sync,
{
    fn identify_object(&self, record: &ObjectRecord) -> ObjectId {
        self.identify(record)
    }

    fn stage_object(
        &self,
        record: ObjectRecord,
    ) -> Result<(ObjectId, InsertOutcome), PrincipalProjectionError> {
        self.put_object(record).map_err(Into::into)
    }

    fn stage_objects(
        &self,
        records: Vec<ObjectRecord>,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, PrincipalProjectionError> {
        records
            .into_iter()
            .map(|record| self.put_object(record).map_err(Into::into))
            .collect()
    }

    fn prepare_objects(
        &self,
        records: Vec<ObjectRecord>,
    ) -> Result<PreparedProjectionBatch, PrincipalProjectionError> {
        Ok(PreparedProjectionBatch::in_memory(
            Arc::clone(&self.preparation_authority),
            records,
        ))
    }

    fn stage_prepared_objects(
        &self,
        prepared: PreparedProjectionBatch,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, PrincipalProjectionError> {
        self.stage_objects(prepared.into_in_memory(&self.preparation_authority)?)
    }

    fn current_root(&self, principal: &P) -> Result<Option<RootState>, PrincipalProjectionError> {
        Ok(self.root(principal))
    }

    fn load_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, PrincipalProjectionError> {
        Ok(self.object(id))
    }

    fn commit_root(
        &self,
        transaction: RootTransaction<P>,
    ) -> Result<CommitOutcome, PrincipalProjectionError> {
        self.commit(transaction).map_err(Into::into)
    }

    fn flush_projection(&self) -> Result<(), PrincipalProjectionError> {
        Ok(())
    }
}

#[cfg(not(target_family = "wasm"))]
impl<P, I, C> PrincipalProjectionEngine<P> for DurableEngine<P, I, C>
where
    P: Clone + Ord + Send + Sync,
    I: PersistentObjectIdentity + Send + Sync,
    C: PrincipalCodec<P> + Send + Sync,
{
    fn identify_object(&self, record: &ObjectRecord) -> ObjectId {
        self.identify(record)
    }

    fn stage_object(
        &self,
        record: ObjectRecord,
    ) -> Result<(ObjectId, InsertOutcome), PrincipalProjectionError> {
        DurableEngine::stage_object(self, &record).map_err(map_durable)
    }

    fn stage_objects(
        &self,
        records: Vec<ObjectRecord>,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, PrincipalProjectionError> {
        DurableEngine::stage_objects(self, records).map_err(map_durable)
    }

    fn stage_objects_observed(
        &self,
        records: Vec<ObjectRecord>,
        observer: &dyn ProjectionObserver,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, PrincipalProjectionError> {
        DurableEngine::stage_objects_observed(self, records, observer).map_err(map_durable)
    }

    fn prepare_objects(
        &self,
        records: Vec<ObjectRecord>,
    ) -> Result<PreparedProjectionBatch, PrincipalProjectionError> {
        self.prepare_objects_for_projection(records, None)
            .map_err(map_durable)
    }

    fn prepare_objects_observed(
        &self,
        records: Vec<ObjectRecord>,
        observer: &dyn ProjectionObserver,
    ) -> Result<PreparedProjectionBatch, PrincipalProjectionError> {
        self.prepare_objects_for_projection(records, Some(observer))
            .map_err(map_durable)
    }

    fn stage_prepared_objects(
        &self,
        prepared: PreparedProjectionBatch,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, PrincipalProjectionError> {
        self.stage_prepared_for_projection(prepared, None)
    }

    fn stage_prepared_objects_observed(
        &self,
        prepared: PreparedProjectionBatch,
        observer: &dyn ProjectionObserver,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, PrincipalProjectionError> {
        self.stage_prepared_for_projection(prepared, Some(observer))
    }

    fn current_root(&self, principal: &P) -> Result<Option<RootState>, PrincipalProjectionError> {
        self.root(principal).map_err(map_durable)
    }

    fn load_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, PrincipalProjectionError> {
        self.object(id).map_err(map_durable)
    }

    fn load_object_for(
        &self,
        principal: &P,
        id: ObjectId,
    ) -> Result<Option<ObjectRecord>, PrincipalProjectionError> {
        self.object_for(principal, id).map_err(map_durable)
    }

    fn load_shared_object_for(
        &self,
        principal: &P,
        id: ObjectId,
    ) -> Result<Option<Arc<ObjectRecord>>, PrincipalProjectionError> {
        self.shared_object_for(principal, id).map_err(map_durable)
    }

    fn load_objects_for(
        &self,
        principal: &P,
        ids: &[ObjectId],
    ) -> Result<Vec<Option<ObjectRecord>>, PrincipalProjectionError> {
        self.objects_for(principal, ids).map_err(map_durable)
    }

    fn load_shared_objects_for(
        &self,
        principal: &P,
        ids: &[ObjectId],
    ) -> Result<Vec<Option<Arc<ObjectRecord>>>, PrincipalProjectionError> {
        self.shared_objects_for(principal, ids).map_err(map_durable)
    }

    fn load_projection_cache(
        &self,
        principal: &P,
        object: ObjectId,
        key: ProjectionCacheKey,
    ) -> Option<ProjectionCacheEntry> {
        self.projection_cache(principal, object, key)
    }

    fn retain_projection_cache(
        &self,
        principal: &P,
        object: ObjectId,
        key: ProjectionCacheKey,
        value: ProjectionCacheEntry,
    ) -> bool {
        DurableEngine::retain_projection_cache(self, principal, object, key, value)
    }

    fn discard_projection_cache(
        &self,
        principal: &P,
        object: ObjectId,
        key: ProjectionCacheKey,
    ) -> bool {
        DurableEngine::discard_projection_cache(self, principal, object, key)
    }

    fn commit_root(
        &self,
        transaction: RootTransaction<P>,
    ) -> Result<CommitOutcome, PrincipalProjectionError> {
        self.commit(transaction).map_err(map_durable)
    }

    fn commit_root_observed(
        &self,
        transaction: RootTransaction<P>,
        observer: Arc<dyn ProjectionObserver>,
    ) -> Result<CommitOutcome, PrincipalProjectionError> {
        self.commit_observed(transaction, observer.as_ref())
            .map_err(map_durable)
    }

    fn flush_projection(&self) -> Result<(), PrincipalProjectionError> {
        self.flush().map_err(map_durable)
    }
}

#[cfg(not(target_family = "wasm"))]
pub(crate) fn map_durable(error: DurableError) -> PrincipalProjectionError {
    match error {
        DurableError::Model(model) => PrincipalProjectionError::Model(model),
        other => PrincipalProjectionError::Engine(other.to_string()),
    }
}

fn foreign_preparation() -> PrincipalProjectionError {
    PrincipalProjectionError::Engine(
        "prepared object batch does not belong to this engine".to_owned(),
    )
}

fn unsupported_preparation() -> PrincipalProjectionError {
    PrincipalProjectionError::Engine(
        "projection engine does not support prepared object admission".to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_model::{ObjectClass, ObjectFormatVersion, ObjectIdentity, ObjectKind};

    #[derive(Clone, Copy)]
    struct TestIdentity;

    impl ObjectIdentity for TestIdentity {
        fn identify(&self, _record: &ObjectRecord) -> ObjectId {
            ObjectId::new([42; 32])
        }
    }

    #[test]
    fn prepared_projection_batches_are_bound_to_the_in_memory_engine() {
        let first = InMemoryEngine::<String, _>::new(TestIdentity);
        let second = InMemoryEngine::<String, _>::new(TestIdentity);
        let record = ObjectRecord::new(
            ObjectKind::Chunk,
            ObjectFormatVersion::V1,
            b"engine-bound".to_vec(),
            Vec::new(),
            12,
            ObjectClass::Data,
        )
        .unwrap();
        let prepared =
            PrincipalProjectionEngine::<String>::prepare_objects(&first, vec![record]).unwrap();

        let error = PrincipalProjectionEngine::<String>::stage_prepared_objects(&second, prepared)
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("prepared object batch does not belong to this engine")
        );
        assert_eq!(second.object_count(), 0);
    }

    #[test]
    fn prepared_projection_batch_accounts_for_record_allocation() {
        let engine = InMemoryEngine::<String, _>::new(TestIdentity);
        let record = ObjectRecord::new(
            ObjectKind::Chunk,
            ObjectFormatVersion::V1,
            b"resident charge".to_vec(),
            Vec::new(),
            15,
            ObjectClass::Data,
        )
        .unwrap();
        let canonical_bytes = record.canonical_bytes().len();

        let prepared =
            PrincipalProjectionEngine::<String>::prepare_objects(&engine, vec![record]).unwrap();

        assert!(prepared.retained_bytes() > canonical_bytes);
    }

    #[test]
    fn projection_model_error_preserves_typed_source() {
        let error = PrincipalProjectionError::from(ModelError::ArithmeticOverflow);
        let source = std::error::Error::source(&error).unwrap();

        assert_eq!(
            source.downcast_ref::<ModelError>(),
            Some(&ModelError::ArithmeticOverflow)
        );
    }
}
