//! Read-only KV projection adapter used by content-side quota validation.

use astrid_storage_engine::{
    CommitOutcome, KvProjectionEngine, KvProjectionError, PrincipalProjectionEngine,
    PrincipalProjectionError, RootSnapshot, RootTransaction,
};
use astrid_storage_model::{ObjectId, ObjectRecord, RootState};

pub(super) struct PrincipalKvAdapter<'a, E>(&'a E);

impl<'a, E> PrincipalKvAdapter<'a, E> {
    pub(super) const fn new(engine: &'a E) -> Self {
        Self(engine)
    }
}

impl<P, E> KvProjectionEngine<P> for PrincipalKvAdapter<'_, E>
where
    E: PrincipalProjectionEngine<P>,
{
    fn identify_kv_object(&self, record: &ObjectRecord) -> ObjectId {
        self.0.identify_object(record)
    }

    fn current_kv_root(&self, principal: &P) -> Result<Option<RootState>, KvProjectionError> {
        self.0.current_root(principal).map_err(map_error)
    }

    fn load_kv_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, KvProjectionError> {
        self.0.load_object(id).map_err(map_error)
    }

    fn snapshot_kv_root(&self, _principal: &P) -> Result<Option<RootSnapshot>, KvProjectionError> {
        Err(KvProjectionError::Engine(
            "content validation adapter does not capture root snapshots".to_owned(),
        ))
    }

    fn commit_kv_root(
        &self,
        transaction: RootTransaction<P>,
    ) -> Result<CommitOutcome, KvProjectionError> {
        self.0.commit_root(transaction).map_err(map_error)
    }

    fn flush_kv(&self) -> Result<(), KvProjectionError> {
        self.0.flush_projection().map_err(map_error)
    }
}

fn map_error(error: PrincipalProjectionError) -> KvProjectionError {
    match error {
        PrincipalProjectionError::Model(error) => KvProjectionError::Model(error),
        PrincipalProjectionError::Engine(error) => KvProjectionError::Engine(error),
        other => KvProjectionError::Engine(other.to_string()),
    }
}
