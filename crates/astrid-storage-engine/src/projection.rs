//! Generic principal-state projection boundary.
//!
//! KV, content, filesystem, and future principal-owned projections share one
//! atomic principal root. This trait prevents each projection from inventing
//! a side root while keeping the engine unaware of projection semantics.

use std::any::Any;
use std::fmt;
use std::sync::Arc;

use astrid_storage_model::{
    InsertOutcome, ModelError, ObjectId, ObjectIdentity, ObjectRecord, RootState,
};

use crate::{CommitOutcome, InMemoryEngine, RootTransaction};
#[cfg(not(target_family = "wasm"))]
use crate::{DurableEngine, DurableError, PersistentObjectIdentity, PrincipalCodec};

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

    fn flush_projection(&self) -> Result<(), PrincipalProjectionError> {
        self.flush().map_err(map_durable)
    }
}

#[cfg(not(target_family = "wasm"))]
fn map_durable(error: DurableError) -> PrincipalProjectionError {
    match error {
        DurableError::Model(model) => PrincipalProjectionError::Model(model),
        other => PrincipalProjectionError::Engine(other.to_string()),
    }
}
