//! Durable KV projection reads retain principal-accounted shared objects.

use super::{
    Arc, CommitOutcome, DurableEngine, KvProjectionEngine, KvProjectionError, ObjectId,
    ObjectRecord, PersistentObjectIdentity, PrincipalCodec, ReadyKvRoot, RootSnapshot, RootState,
    RootTransaction, map_durable_error,
};

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

    fn load_shared_kv_object_for(
        &self,
        principal: &P,
        id: ObjectId,
    ) -> Result<Option<Arc<ObjectRecord>>, KvProjectionError> {
        self.shared_object_for(principal, id)
            .map_err(map_durable_error)
    }

    fn load_shared_kv_objects_for(
        &self,
        principal: &P,
        ids: &[ObjectId],
    ) -> Result<Vec<Option<Arc<ObjectRecord>>>, KvProjectionError> {
        self.shared_objects_for(principal, ids)
            .map_err(map_durable_error)
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
