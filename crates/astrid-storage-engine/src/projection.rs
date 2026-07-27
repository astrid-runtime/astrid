//! Generic principal-state projection boundary.
//!
//! KV, content, filesystem, and future principal-owned projections share one
//! atomic principal root. This trait prevents each projection from inventing
//! a side root while keeping the engine unaware of projection semantics.

use std::fmt;

use astrid_storage_model::{
    InsertOutcome, ModelError, ObjectId, ObjectIdentity, ObjectRecord, RootState,
};

use crate::{CommitOutcome, InMemoryEngine, RootTransaction};
#[cfg(not(target_family = "wasm"))]
use crate::{DurableEngine, DurableError, PersistentObjectIdentity, PrincipalCodec};

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
