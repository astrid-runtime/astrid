use super::*;
use crate::{KvStore, MemoryKvStore, PrincipalDirectory};
use astrid_core::UserUid;
use astrid_core::{
    FleetGenesis, FleetIdentity, PrincipalId, PrincipalOwnership, UserGenesis, UserIdentity,
};
use std::sync::Arc;

async fn fixture() -> (
    Arc<MemoryKvStore>,
    OwnershipStore,
    UserUid,
    PrincipalUid,
    [PrincipalUid; 2],
) {
    let backend = Arc::new(MemoryKvStore::new());
    let directory = PrincipalDirectory::default();
    let parent = PrincipalUid::from_bytes([1; 32]);
    let children = [
        PrincipalUid::from_bytes([2; 32]),
        PrincipalUid::from_bytes([3; 32]),
    ];
    for (name, uid) in [
        ("default", parent),
        ("first", children[0]),
        ("second", children[1]),
    ] {
        directory
            .register(PrincipalId::new(name).unwrap(), uid)
            .unwrap();
    }
    let store = OwnershipStore::new(backend.clone(), directory).unwrap();
    let user = UserIdentity::from_genesis(UserGenesis::from_parts(
        uuid::Uuid::from_u128(1),
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        [4; 32],
    ))
    .unwrap();
    let fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
        uuid::Uuid::from_u128(2),
        chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
        user.uid,
    ))
    .unwrap();
    store.create_user(user.clone()).await.unwrap();
    store.create_fleet(fleet.clone()).await.unwrap();
    store
        .assign_principal(PrincipalOwnership {
            principal_uid: parent,
            fleet_uid: fleet.uid,
            assigned_by: user.uid,
        })
        .await
        .unwrap();
    store
        .bind_user_device(parent, [5; 32], user.uid, user.uid)
        .await
        .unwrap();
    backend
        .set("test:enrollment", "token", vec![1])
        .await
        .unwrap();
    (backend, store, user.uid, parent, children)
}

async fn commit(
    store: &OwnershipStore,
    child: PrincipalUid,
    delegation: &CreationDelegation,
) -> bool {
    let key = KvEntryKey::new("test:enrollment", "token").unwrap();
    store
        .commit_enrolled_principal(
            child,
            delegation,
            vec![KvBatchCondition::ValueEquals {
                key: key.clone(),
                expected: Some(vec![1]),
            }],
            vec![KvBatchMutation::Delete { key }],
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn revoked_then_regranted_binding_does_not_revive_old_enrollment() {
    let (backend, store, user, parent, children) = fixture().await;
    let original = store
        .capture_creation_delegation(parent, &[5; 32])
        .await
        .unwrap();
    store
        .revoke_user_device(parent, [5; 32], user)
        .await
        .unwrap();
    assert!(!commit(&store, children[0], &original).await);
    store
        .bind_user_device(parent, [5; 32], user, user)
        .await
        .unwrap();
    assert!(!commit(&store, children[0], &original).await);
    assert_eq!(
        backend.get("test:enrollment", "token").await.unwrap(),
        Some(vec![1])
    );
    assert!(
        store
            .load()
            .await
            .unwrap()
            .principal_owner(children[0])
            .is_none()
    );
    let fresh = store
        .capture_creation_delegation(parent, &[5; 32])
        .await
        .unwrap();
    assert_ne!(original, fresh);
    assert!(commit(&store, children[0], &fresh).await);
    assert!(
        backend
            .get("test:enrollment", "token")
            .await
            .unwrap()
            .is_none()
    );
    let graph = store.load().await.unwrap();
    assert_eq!(
        graph.principal_owner(children[0]).unwrap().assigned_by,
        user
    );
    assert!(graph.user_for_device(children[0], &[5; 32]).is_none());
    assert!(!commit(&store, children[1], &fresh).await);
    assert!(
        store
            .load()
            .await
            .unwrap()
            .principal_owner(children[1])
            .is_none()
    );
}

#[tokio::test]
async fn concurrent_enrollment_has_one_token_winner_and_one_owned_child() {
    let (backend, store, _, parent, children) = fixture().await;
    // Independent handles deliberately do not share the in-process mutation lock.
    let independent = OwnershipStore::new(backend.clone(), store.principals.clone()).unwrap();
    let delegation = store
        .capture_creation_delegation(parent, &[5; 32])
        .await
        .unwrap();
    let (first, second) = tokio::join!(
        commit(&store, children[0], &delegation),
        commit(&independent, children[1], &delegation),
    );
    assert_ne!(first, second);
    let graph = store.load().await.unwrap();
    assert_eq!(graph.principal_owner(children[0]).is_some(), first);
    assert_eq!(graph.principal_owner(children[1]).is_some(), second);
    assert!(
        backend
            .get("test:enrollment", "token")
            .await
            .unwrap()
            .is_none()
    );
}
