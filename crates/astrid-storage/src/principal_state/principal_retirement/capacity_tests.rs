//! Reclamation frees slots; it does not weaken live workspace admission.
use crate::principal_state::{StateOwner, open_runtime_principal_store};
use crate::{ContentName, WorkspaceBranchError, WorkspaceBranchStore, WorkspaceUid};
use astrid_core::dirs::AstridHome;
use astrid_core::{FleetUid, PrincipalUid};
use std::sync::Arc;

fn uid(index: u16) -> PrincipalUid {
    let mut bytes = [0; 32];
    bytes[..2].copy_from_slice(&index.to_be_bytes());
    PrincipalUid::from_bytes(bytes)
}

#[tokio::test]
async fn retired_bindings_release_capacity_while_live_limit_stays_enforced() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, Arc::new(|_: &StateOwner| Ok(None)))
        .await
        .unwrap();
    let owner = StateOwner::Fleet(FleetUid::from_bytes([0x65; 32]));
    let branches = WorkspaceBranchStore::new(store.content());
    let prefix = ContentName::new("workspace/default").unwrap();
    for index in 0..128 {
        branches
            .begin_for_uid_at(&owner, uid(index), WorkspaceUid::random(), prefix.clone())
            .unwrap();
    }
    assert!(matches!(
        branches.begin_for_uid_at(&owner, uid(128), WorkspaceUid::random(), prefix.clone()),
        Err(WorkspaceBranchError::BranchLimitExceeded),
    ));
    for index in 1..128 {
        assert!(store.purge_principal_state(uid(index)).unwrap());
        assert!(
            branches
                .list_bindings_by_uid(&owner, uid(index))
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(
        branches.list_bindings_by_uid(&owner, uid(0)).unwrap().len(),
        1
    );
    for index in 128..255 {
        branches
            .begin_for_uid_at(&owner, uid(index), WorkspaceUid::random(), prefix.clone())
            .unwrap();
    }
    assert_eq!(branches.list_branches(&owner).unwrap().len(), 128);
    assert!(matches!(
        branches.begin_for_uid_at(&owner, uid(255), WorkspaceUid::random(), prefix),
        Err(WorkspaceBranchError::BranchLimitExceeded),
    ));
    store.engine.close().unwrap();
}
