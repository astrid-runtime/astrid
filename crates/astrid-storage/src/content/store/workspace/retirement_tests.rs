use super::test_support::fixture;
use super::{
    ContentName, FilesystemPath, MAX_WORKSPACE_BRANCHES, WorkspaceBindingLifecycle,
    WorkspaceBranchError, WorkspaceUid,
};
use astrid_core::PrincipalUid;

#[test]
fn retirement_releases_only_selected_owner_uid_live_branches() {
    let (_engine, branches, owner, legacy) = fixture();
    let uid = PrincipalUid::from_bytes([1; 32]);
    let peer_uid = PrincipalUid::from_bytes([2; 32]);
    let foreign = crate::StateOwner::Principal(PrincipalUid::from_bytes([3; 32]));
    let prefix = ContentName::new("workspace/default").unwrap();
    let promoted = branches
        .begin_for_uid_at(&owner, uid, WorkspaceUid::random(), prefix.clone())
        .unwrap();
    let name = FilesystemPath::new("published.txt").unwrap();
    branches
        .filesystem(owner, promoted.id())
        .write(&name, b"keep")
        .unwrap();
    branches.promote(&owner, promoted.id()).unwrap();
    for selected in [
        prefix.clone(),
        ContentName::new("workspace/second").unwrap(),
    ] {
        branches
            .begin_for_uid_at(&owner, uid, WorkspaceUid::random(), selected)
            .unwrap();
    }
    let peer = branches
        .begin_for_uid_at(&owner, peer_uid, WorkspaceUid::random(), prefix.clone())
        .unwrap();
    let other = branches
        .begin_for_uid_at(&foreign, uid, WorkspaceUid::random(), prefix)
        .unwrap();
    assert_eq!(branches.retire_for_uid(&owner, uid).unwrap(), 2);
    assert_eq!(branches.retire_for_uid(&owner, uid).unwrap(), 0);
    let remaining = branches.list_branches(&owner).unwrap();
    assert_eq!(remaining.len(), 2);
    assert!(remaining.iter().any(|branch| branch.id() == legacy));
    assert!(remaining.iter().any(|branch| branch.id() == peer.id()));
    assert_eq!(
        branches.binding(&owner, promoted.id()).unwrap().lifecycle(),
        WorkspaceBindingLifecycle::Promoted
    );
    assert_eq!(
        branches.binding(&foreign, other.id()).unwrap().lifecycle(),
        WorkspaceBindingLifecycle::Live
    );
    assert_eq!(
        branches
            .filesystem(owner, peer.id())
            .read(&name, 0, 4)
            .unwrap(),
        b"keep"
    );
}

#[test]
fn retirement_preserves_a_promotion_that_wins_the_root_cas() {
    let (engine, branches, owner, _legacy) = fixture();
    let uid = PrincipalUid::from_bytes([4; 32]);
    let prefix = ContentName::new("workspace/default").unwrap();
    let branch = branches
        .begin_for_uid_at(&owner, uid, WorkspaceUid::random(), prefix.clone())
        .unwrap();
    let path = FilesystemPath::new("winner.txt").unwrap();
    branches
        .filesystem(owner, branch.id())
        .write(&path, b"winner")
        .unwrap();
    let concurrent = branches.clone();
    let branch_id = branch.id();
    *engine.before_commit.lock() = Some(Box::new(move || {
        concurrent.promote(&owner, branch_id).unwrap();
    }));
    assert_eq!(branches.retire_for_uid(&owner, uid).unwrap(), 0);
    assert_eq!(
        branches.binding(&owner, branch.id()).unwrap().lifecycle(),
        WorkspaceBindingLifecycle::Promoted
    );
    let reader = branches
        .begin_for_uid_at(
            &owner,
            PrincipalUid::from_bytes([5; 32]),
            WorkspaceUid::random(),
            prefix,
        )
        .unwrap();
    assert_eq!(
        branches
            .filesystem(owner, reader.id())
            .read(&path, 0, 6)
            .unwrap(),
        b"winner"
    );
}

#[test]
fn retirement_restores_branch_capacity_without_raising_the_limit() {
    let (_engine, branches, owner, legacy) = fixture();
    let prefix = ContentName::new("workspace/default").unwrap();
    for round in 0_u8..2 {
        let mut uids = Vec::new();
        for index in 0..MAX_WORKSPACE_BRANCHES - 1 {
            let mut bytes = [42; 32];
            bytes[0] = round;
            bytes[1] = u8::try_from(index).unwrap();
            let uid = PrincipalUid::from_bytes(bytes);
            branches
                .begin_for_uid_at(&owner, uid, WorkspaceUid::random(), prefix.clone())
                .unwrap();
            uids.push(uid);
        }
        assert_eq!(
            branches.list_branches(&owner).unwrap().len(),
            MAX_WORKSPACE_BRANCHES
        );
        assert!(matches!(
            branches.begin_for_uid_at(
                &owner,
                PrincipalUid::from_bytes([99; 32]),
                WorkspaceUid::random(),
                prefix.clone()
            ),
            Err(WorkspaceBranchError::BranchLimitExceeded)
        ));
        for uid in uids {
            assert_eq!(branches.retire_for_uid(&owner, uid).unwrap(), 1);
        }
        let remaining = branches.list_branches(&owner).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id(), legacy);
    }
}
