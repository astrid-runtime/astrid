//! Engine boundary for the typed KV projection and its optional accelerators.
use super::KvProjectionError;
use super::ReadyKvRoot;
#[cfg(not(target_family = "wasm"))]
use super::map_durable_error;
use crate::engine::{
    CommitOutcome, InMemoryEngine, ProjectionCacheEntry, ProjectionCacheKey, RootSnapshot,
    RootTransaction,
};
#[cfg(not(target_family = "wasm"))]
use crate::engine::{
    DurableEngine, PersistentObjectIdentity, PrincipalCodec, PrincipalProjectionEngine,
};
use crate::storage_model::{ObjectId, ObjectIdentity, ObjectRecord, RootState};

/// Minimal engine contract required by the typed key/value projection.
///
/// This keeps the compatibility adapter independent of whether the principal
/// world is held in memory or reconstructed lazily from a durable arena.
pub trait KvProjectionEngine<P>: Send + Sync {
    /// Compute the logical identity of one canonical object.
    fn identify_kv_object(&self, record: &ObjectRecord) -> ObjectId;

    /// Return the current root of one principal without materializing it.
    ///
    /// # Errors
    ///
    /// Returns an engine error when the root index is unavailable.
    fn current_kv_root(&self, principal: &P) -> Result<Option<RootState>, KvProjectionError>;

    /// Return the current root only when it is already available without I/O
    /// or waiting for an engine writer.
    fn current_kv_root_if_ready(&self, _principal: &P) -> Option<ReadyKvRoot> {
        None
    }

    /// Load one immutable object by identity.
    ///
    /// # Errors
    ///
    /// Returns an engine or frame error when the object cannot be read.
    fn load_kv_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, KvProjectionError>;

    /// Load one immutable object with principal cache attribution.
    ///
    /// The default preserves projection engines without a governed object
    /// cache. Cache policy cannot change the bytes or errors returned by
    /// [`Self::load_kv_object`].
    ///
    /// # Errors
    ///
    /// Returns an engine or frame error when the object cannot be read.
    fn load_kv_object_for(
        &self,
        _principal: &P,
        id: ObjectId,
    ) -> Result<Option<ObjectRecord>, KvProjectionError> {
        self.load_kv_object(id)
    }

    /// Load an optional decoded KV accelerator under the engine's cache budgets.
    /// A miss must take the ordinary authenticated reconstruction path.
    fn load_kv_projection_cache(
        &self,
        _principal: &P,
        _head: ObjectId,
        _key: ProjectionCacheKey,
    ) -> Option<ProjectionCacheEntry> {
        None
    }

    /// Attempt budgeted retention. Refusal never changes a committed result.
    fn retain_kv_projection_cache(
        &self,
        _principal: &P,
        _head: ObjectId,
        _key: ProjectionCacheKey,
        _value: ProjectionCacheEntry,
    ) -> bool {
        false
    }

    /// Discard an accelerator made redundant by a new immutable KV head.
    fn discard_kv_projection_cache(
        &self,
        _principal: &P,
        _head: ObjectId,
        _key: ProjectionCacheKey,
    ) -> bool {
        false
    }

    /// Capture one principal's root and owning closure.
    ///
    /// # Errors
    ///
    /// Returns an engine or graph error when the closure cannot be captured.
    fn snapshot_kv_root(&self, principal: &P) -> Result<Option<RootSnapshot>, KvProjectionError>;

    /// Atomically publish one encoded key/value transition.
    ///
    /// # Errors
    ///
    /// Returns an engine, graph, identity, or root-conflict error.
    fn commit_kv_root(
        &self,
        transaction: RootTransaction<P>,
    ) -> Result<CommitOutcome, KvProjectionError>;

    /// Flush authoritative engine state before the embedding store closes.
    ///
    /// # Errors
    ///
    /// Returns an engine I/O or recovery-required error.
    fn flush_kv(&self) -> Result<(), KvProjectionError>;

    /// Release any engine resources owned by the embedding store.
    ///
    /// The default flushes engines that do not distinguish flush from close.
    /// Durable engines override this to release their singleton lock and file
    /// handles while rejecting subsequent operations.
    ///
    /// # Errors
    ///
    /// Returns an engine flush, close, or recovery-required error.
    fn close_kv(&self) -> Result<(), KvProjectionError> {
        self.flush_kv()
    }
}

impl<P, I> KvProjectionEngine<P> for InMemoryEngine<P, I>
where
    P: Clone + Ord + Send + Sync,
    I: ObjectIdentity + Send + Sync,
{
    fn identify_kv_object(&self, record: &ObjectRecord) -> ObjectId {
        self.identify(record)
    }

    fn current_kv_root(&self, principal: &P) -> Result<Option<RootState>, KvProjectionError> {
        Ok(self.root(principal))
    }

    fn current_kv_root_if_ready(&self, principal: &P) -> Option<ReadyKvRoot> {
        self.world
            .try_read()
            .map(|world| ReadyKvRoot::new(world.root(principal)))
    }

    fn load_kv_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, KvProjectionError> {
        Ok(self.object(id))
    }

    fn snapshot_kv_root(&self, principal: &P) -> Result<Option<RootSnapshot>, KvProjectionError> {
        self.snapshot(principal).map_err(Into::into)
    }

    fn commit_kv_root(
        &self,
        transaction: RootTransaction<P>,
    ) -> Result<CommitOutcome, KvProjectionError> {
        self.commit(transaction).map_err(Into::into)
    }

    fn flush_kv(&self) -> Result<(), KvProjectionError> {
        Ok(())
    }
}

#[cfg(not(target_family = "wasm"))]
impl<P, I, C> KvProjectionEngine<P> for DurableEngine<P, I, C>
where
    P: Clone + Ord + Send + Sync,
    I: PersistentObjectIdentity + Send + Sync,
    C: PrincipalCodec<P> + Send + Sync,
{
    fn identify_kv_object(&self, record: &ObjectRecord) -> ObjectId {
        self.identify(record)
    }

    fn current_kv_root(&self, principal: &P) -> Result<Option<RootState>, KvProjectionError> {
        self.root(principal).map_err(map_durable_error)
    }

    fn current_kv_root_if_ready(&self, principal: &P) -> Option<ReadyKvRoot> {
        self.root_if_ready(principal)
    }

    fn load_kv_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, KvProjectionError> {
        self.object(id).map_err(map_durable_error)
    }

    fn load_kv_object_for(
        &self,
        principal: &P,
        id: ObjectId,
    ) -> Result<Option<ObjectRecord>, KvProjectionError> {
        self.object_for(principal, id).map_err(map_durable_error)
    }

    fn load_kv_projection_cache(
        &self,
        principal: &P,
        head: ObjectId,
        key: ProjectionCacheKey,
    ) -> Option<ProjectionCacheEntry> {
        self.load_projection_cache(principal, head, key)
    }
    fn retain_kv_projection_cache(
        &self,
        principal: &P,
        head: ObjectId,
        key: ProjectionCacheKey,
        value: ProjectionCacheEntry,
    ) -> bool {
        self.retain_projection_cache(principal, head, key, value)
    }
    fn discard_kv_projection_cache(
        &self,
        principal: &P,
        head: ObjectId,
        key: ProjectionCacheKey,
    ) -> bool {
        self.discard_projection_cache(principal, head, key)
    }

    fn snapshot_kv_root(&self, principal: &P) -> Result<Option<RootSnapshot>, KvProjectionError> {
        self.snapshot(principal).map_err(map_durable_error)
    }

    fn commit_kv_root(
        &self,
        transaction: RootTransaction<P>,
    ) -> Result<CommitOutcome, KvProjectionError> {
        self.commit(transaction).map_err(map_durable_error)
    }

    fn flush_kv(&self) -> Result<(), KvProjectionError> {
        self.flush().map_err(map_durable_error)
    }

    fn close_kv(&self) -> Result<(), KvProjectionError> {
        self.close().map_err(map_durable_error)
    }
}
