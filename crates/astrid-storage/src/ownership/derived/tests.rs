use crate::ownership::OwnershipStore;
use crate::{MemoryKvStore, PrincipalDirectory};
use astrid_core::{
    FleetGenesis, FleetIdentity, PrincipalId, PrincipalOwnership, PrincipalUid, UserGenesis,
    UserIdentity,
};
use std::sync::Arc;

#[tokio::test]
async fn spawn_inherits_fleet_without_human_delegation_and_rejects_stale_or_owned_children() {
    let directory = PrincipalDirectory::default();
    let creator = PrincipalUid::from_bytes([1; 32]);
    let child = PrincipalUid::from_bytes([2; 32]);
    let stale_child = PrincipalUid::from_bytes([3; 32]);
    for (alias, uid) in [
        ("creator", creator),
        ("child", child),
        ("stale", stale_child),
    ] {
        directory
            .register(PrincipalId::new(alias).unwrap(), uid)
            .unwrap();
    }
    let store = OwnershipStore::new(Arc::new(MemoryKvStore::new()), directory).unwrap();
    let user = UserIdentity::from_genesis(UserGenesis::from_parts(
        uuid::Uuid::from_u128(1),
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        [4; 32],
    ))
    .unwrap();
    store.create_user(user.clone()).await.unwrap();
    let fleets: Vec<_> = [2, 3]
        .into_iter()
        .map(|id| {
            FleetIdentity::from_genesis(FleetGenesis::from_parts(
                uuid::Uuid::from_u128(id),
                chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
                user.uid,
            ))
            .unwrap()
        })
        .collect();
    for fleet in &fleets {
        store.create_fleet(fleet.clone()).await.unwrap();
    }
    assert!(store.capture_derived_ownership(creator).await.is_err());
    store
        .assign_principal(PrincipalOwnership {
            principal_uid: creator,
            fleet_uid: fleets[0].uid,
            assigned_by: user.uid,
        })
        .await
        .unwrap();
    let captured = store.capture_derived_ownership(creator).await.unwrap();
    store
        .assign_derived_principal(child, &captured)
        .await
        .unwrap();
    let graph = store.load().await.unwrap();
    assert_eq!(
        graph.principal_owner(child).unwrap().fleet_uid,
        fleets[0].uid
    );
    assert!(graph.user_for_device(child, &[4; 32]).is_none());
    assert!(
        store
            .assign_derived_principal(child, &captured)
            .await
            .is_err()
    );
    store
        .transfer_principal(creator, fleets[0].uid, fleets[1].uid, user.uid)
        .await
        .unwrap();
    let before = store.load().await.unwrap();
    assert!(
        store
            .assign_derived_principal(stale_child, &captured)
            .await
            .is_err()
    );
    assert_eq!(before, store.load().await.unwrap());
    let fresh = store.capture_derived_ownership(creator).await.unwrap();
    store
        .assign_derived_principal(stale_child, &fresh)
        .await
        .unwrap();
    assert_eq!(
        store
            .load()
            .await
            .unwrap()
            .principal_owner(stale_child)
            .unwrap()
            .fleet_uid,
        fleets[1].uid
    );
}
