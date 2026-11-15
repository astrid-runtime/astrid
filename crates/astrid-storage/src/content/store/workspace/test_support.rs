use super::{PrincipalContentStore, WorkspaceBranchStore, WorkspaceUid};
use crate::StateOwner;
use crate::engine::{
    CommitOutcome, InMemoryEngine, PrincipalProjectionEngine, PrincipalProjectionError,
    RootTransaction,
};
use crate::principal_state::Blake3ObjectIdentityV1;
use crate::storage_model::{InsertOutcome, ObjectId, ObjectRecord, RootState};
use astrid_core::PrincipalUid;
use parking_lot::Mutex;
use std::sync::Arc;

type Inner = InMemoryEngine<StateOwner, Blake3ObjectIdentityV1>;

pub(super) struct InterleavingEngine {
    inner: Inner,
    pub(super) before_commit: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl PrincipalProjectionEngine<StateOwner> for InterleavingEngine {
    fn identify_object(&self, record: &ObjectRecord) -> ObjectId {
        self.inner.identify_object(record)
    }

    fn stage_object(
        &self,
        record: ObjectRecord,
    ) -> Result<(ObjectId, InsertOutcome), PrincipalProjectionError> {
        self.inner.stage_object(record)
    }

    fn current_root(
        &self,
        owner: &StateOwner,
    ) -> Result<Option<RootState>, PrincipalProjectionError> {
        self.inner.current_root(owner)
    }

    fn load_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, PrincipalProjectionError> {
        self.inner.load_object(id)
    }

    fn commit_root(
        &self,
        transaction: RootTransaction<StateOwner>,
    ) -> Result<CommitOutcome, PrincipalProjectionError> {
        let interleave = self.before_commit.lock().take();
        if let Some(interleave) = interleave {
            interleave();
        }
        self.inner.commit_root(transaction)
    }

    fn flush_projection(&self) -> Result<(), PrincipalProjectionError> {
        Ok(())
    }
}

pub(super) fn fixture() -> (
    Arc<InterleavingEngine>,
    WorkspaceBranchStore<StateOwner, InterleavingEngine>,
    StateOwner,
    WorkspaceUid,
) {
    let engine = Arc::new(InterleavingEngine {
        inner: Inner::new(Blake3ObjectIdentityV1),
        before_commit: Mutex::new(None),
    });
    let content = Arc::new(PrincipalContentStore::from_engine(Arc::clone(&engine)));
    let branches = WorkspaceBranchStore::new(content);
    let owner = StateOwner::Principal(PrincipalUid::from_bytes([91; 32]));
    let id = WorkspaceUid::from_bytes([91; 16]);
    branches.begin_with_uid(&owner, id).unwrap();
    (engine, branches, owner, id)
}
