//! Conflicting workspace mutations against the durable writer and its reopened state.
use super::test_support::fixture_with_engine;
use super::{ContentName, PrincipalContentStore, WorkspaceUid};
use crate::engine::{DurableEngine, RecoveryLimits};
use crate::{Blake3ObjectIdentityV1, StateOwner, StateOwnerCodecV2};
use std::{path::Path, sync::Arc};

fn open(path: &Path) -> DurableEngine<StateOwner, Blake3ObjectIdentityV1, StateOwnerCodecV2> {
    DurableEngine::open(
        path,
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::new(1024 * 1024).unwrap(),
    )
    .unwrap()
}

#[test]
fn promotion_rebuilds_from_branch_write_that_wins_the_root_cas() {
    let directory = tempfile::tempdir().unwrap();
    let (engine, branches, owner, id) = fixture_with_engine(open(directory.path()));
    let name = ContentName::new("note").unwrap();
    branches.write(&owner, id, &name, b"first").unwrap();

    let concurrent = branches.clone();
    let key = name.clone();
    *engine.before_commit.lock() = Some(Box::new(move || {
        concurrent.write(&owner, id, &key, b"second").unwrap();
    }));

    let promoted = branches.promote(&owner, id).unwrap();
    assert_eq!(
        branches.content.read(&owner, &name).unwrap().as_deref(),
        Some(b"second".as_slice())
    );
    drop(branches);
    drop(engine);
    let reopened = Arc::new(PrincipalContentStore::from_engine(Arc::new(open(
        directory.path(),
    ))));
    assert_eq!(
        reopened.workspace_branches().promote(&owner, id).unwrap(),
        promoted
    );
    assert_eq!(
        reopened.read(&owner, &name).unwrap().as_deref(),
        Some(b"second".as_slice())
    );
}

#[test]
fn rollback_rebuilds_from_owner_root_with_new_peer_branch() {
    let directory = tempfile::tempdir().unwrap();
    let (engine, branches, owner, id) = fixture_with_engine(open(directory.path()));
    let peer = WorkspaceUid::from_bytes([92; 16]);
    let concurrent = branches.clone();
    *engine.before_commit.lock() = Some(Box::new(move || {
        concurrent.begin_with_uid(&owner, peer).unwrap();
    }));

    branches.rollback(&owner, id).unwrap();
    let live = branches.list_branches(&owner).unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].id(), peer);
    branches.rollback(&owner, id).unwrap();
    drop(branches);
    drop(engine);
    let reopened = Arc::new(PrincipalContentStore::from_engine(Arc::new(open(
        directory.path(),
    ))));
    assert_eq!(
        reopened.workspace_branches().list_branches(&owner).unwrap(),
        live
    );
}

#[test]
fn branch_replacement_preserves_same_key_in_peer_after_retry_and_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let (engine, branches, owner, selected) = fixture_with_engine(open(directory.path()));
    let peer = WorkspaceUid::from_bytes([92; 16]);
    branches.begin_with_uid(&owner, peer).unwrap();

    let key = ContentName::new("note").unwrap();
    let concurrent = branches.clone();
    let peer_key = key.clone();
    *engine.before_commit.lock() = Some(Box::new(move || {
        concurrent.write(&owner, peer, &peer_key, b"peer").unwrap();
    }));
    branches.write(&owner, selected, &key, b"selected").unwrap();

    drop(branches);
    drop(engine);
    let content = Arc::new(PrincipalContentStore::from_engine(Arc::new(open(
        directory.path(),
    ))));
    let reopened = content.workspace_branches();
    assert_eq!(
        reopened.read(&owner, selected, &key).unwrap().as_deref(),
        Some(b"selected".as_slice())
    );
    assert_eq!(
        reopened.read(&owner, peer, &key).unwrap().as_deref(),
        Some(b"peer".as_slice())
    );
    assert_eq!(content.read(&owner, &key).unwrap(), None);
}

#[test]
fn quota_is_rechecked_after_a_sibling_branch_wins_the_root_conflict() {
    let directory = tempfile::tempdir().unwrap();
    let (engine, _, owner, selected) = fixture_with_engine(open(directory.path()));
    let content = Arc::new(PrincipalContentStore::from_engine_with_quota(
        Arc::clone(&engine),
        Arc::new(move |principal: &StateOwner| {
            assert_eq!(*principal, owner);
            Ok(Some(11))
        }),
    ));
    let branches = content.workspace_branches();
    let sibling = WorkspaceUid::from_bytes([92; 16]);
    branches.begin_with_uid(&owner, sibling).unwrap();
    let key = ContentName::new("é").unwrap();
    let concurrent = branches.clone();
    let sibling_key = key.clone();
    *engine.before_commit.lock() = Some(Box::new(move || {
        concurrent
            .write(&owner, sibling, &sibling_key, b"peer")
            .unwrap();
    }));

    assert!(matches!(
        branches.write(&owner, selected, &key, b"data"),
        Err(super::WorkspaceBranchError::QuotaExceeded {
            used: 12,
            limit: 11
        })
    ));
    drop(branches);
    drop(content);
    drop(engine);
    let reopened = Arc::new(PrincipalContentStore::from_engine(Arc::new(open(
        directory.path(),
    ))));
    let branches = reopened.workspace_branches();
    assert_eq!(branches.read(&owner, selected, &key).unwrap(), None);
    assert_eq!(
        branches.read(&owner, sibling, &key).unwrap().as_deref(),
        Some(b"peer".as_slice())
    );
}
