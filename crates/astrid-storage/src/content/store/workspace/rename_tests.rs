use std::sync::Arc;

use astrid_core::PrincipalUid;
use parking_lot::Mutex;

use crate::StateOwner;
use crate::engine::{
    CommitOutcome, InMemoryEngine, PrincipalProjectionEngine, PrincipalProjectionError,
    RootTransaction,
};
use crate::principal_state::Blake3ObjectIdentityV1;
use crate::storage_model::{InsertOutcome, ObjectId, ObjectRecord, RootState};

use super::{
    FilesystemError, FilesystemPath, PrincipalContentStore, WorkspaceBranchStore, WorkspaceUid,
};

type Inner = InMemoryEngine<StateOwner, Blake3ObjectIdentityV1>;

struct InterleavingEngine {
    inner: Inner,
    before_commit: Mutex<Option<Box<dyn FnOnce() + Send>>>,
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

fn fixture() -> (
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

#[test]
fn directory_rename_replans_source_after_root_conflict() {
    let (engine, branches, owner, id) = fixture();
    let fs = branches.filesystem(owner.clone(), id);
    let old = FilesystemPath::new("old").unwrap();
    let new = FilesystemPath::new("new").unwrap();
    let late = FilesystemPath::new("old/late").unwrap();
    fs.create_dir(&old).unwrap();
    fs.write(&FilesystemPath::new("old/file").unwrap(), b"file")
        .unwrap();
    let interleaving_fs = branches.filesystem(owner, id);
    *engine.before_commit.lock() = Some(Box::new(move || {
        interleaving_fs.write(&late, b"late").unwrap();
    }));
    fs.rename(&old, &new).unwrap();
    assert!(matches!(
        fs.stat(&old),
        Err(super::WorkspaceBranchError::Filesystem(
            FilesystemError::NotFound(_)
        ))
    ));
    assert_eq!(
        fs.read(&FilesystemPath::new("new/late").unwrap(), 0, 4)
            .unwrap(),
        b"late"
    );
    assert_eq!(
        fs.read(&FilesystemPath::new("new/file").unwrap(), 0, 4)
            .unwrap(),
        b"file"
    );
}

#[test]
fn replacing_directory_rechecks_empty_destination_after_root_conflict() {
    let (engine, branches, owner, id) = fixture();
    let fs = branches.filesystem(owner.clone(), id);
    let old = FilesystemPath::new("old").unwrap();
    let new = FilesystemPath::new("new").unwrap();
    fs.create_dir(&old).unwrap();
    fs.create_dir(&new).unwrap();
    let interleaving_fs = branches.filesystem(owner, id);
    *engine.before_commit.lock() = Some(Box::new(move || {
        interleaving_fs
            .write(&FilesystemPath::new("new/late").unwrap(), b"late")
            .unwrap();
    }));
    assert!(matches!(
        fs.rename_replacing(&old, &new),
        Err(super::WorkspaceBranchError::Filesystem(
            FilesystemError::DirectoryNotEmpty(_)
        ))
    ));
    assert!(fs.stat(&old).is_ok());
    assert_eq!(
        fs.read(&FilesystemPath::new("new/late").unwrap(), 0, 4)
            .unwrap(),
        b"late"
    );
}

#[test]
fn rename_rechecks_destination_parent_after_root_conflict() {
    let (engine, branches, owner, id) = fixture();
    let fs = branches.filesystem(owner.clone(), id);
    let parent = FilesystemPath::new("parent").unwrap();
    let source = FilesystemPath::new("source").unwrap();
    let destination = FilesystemPath::new("parent/file").unwrap();
    fs.create_dir(&parent).unwrap();
    fs.write(&source, b"file").unwrap();
    let interleaving_fs = branches.filesystem(owner, id);
    *engine.before_commit.lock() = Some(Box::new(move || {
        interleaving_fs.remove(&parent).unwrap();
    }));
    assert!(matches!(
        fs.rename(&source, &destination),
        Err(super::WorkspaceBranchError::Filesystem(
            FilesystemError::NotFound(_)
        ))
    ));
    assert_eq!(fs.read(&source, 0, 4).unwrap(), b"file");
    assert!(matches!(
        fs.stat(&destination),
        Err(super::WorkspaceBranchError::Filesystem(
            FilesystemError::NotFound(_)
        ))
    ));
}
