use super::*;
use crate::MemoryKvStore;
use astrid_core::{
    FleetGenesis, FleetIdentity, PrincipalId, PrincipalOwnership, UserGenesis, UserIdentity,
};
use std::sync::Arc;

#[tokio::test]
async fn local_bootstrap_does_not_restore_revoked_delegation_after_reopen() {
    let backend = Arc::new(MemoryKvStore::new());
    let directory = PrincipalDirectory::default();
    let principal = PrincipalUid::from_bytes([1; 32]);
    let child = PrincipalUid::from_bytes([2; 32]);
    directory
        .register(PrincipalId::default(), principal)
        .unwrap();
    directory
        .register(PrincipalId::new("child").unwrap(), child)
        .unwrap();
    let store = OwnershipStore::new(backend.clone(), directory.clone()).unwrap();
    let user = UserIdentity::from_genesis(UserGenesis::from_parts(
        uuid::Uuid::from_u128(1),
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        [3; 32],
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
            principal_uid: principal,
            fleet_uid: fleet.uid,
            assigned_by: user.uid,
        })
        .await
        .unwrap();
    let key = [4; 32];
    store
        .initialize_local_user_device(principal, key, user.uid, fleet.uid)
        .await
        .unwrap();
    assert_eq!(
        store.load().await.unwrap().user_for_device(principal, &key),
        Some(user.uid)
    );
    store
        .revoke_user_device(principal, key, user.uid)
        .await
        .unwrap();

    let reopened = OwnershipStore::new(backend, directory).unwrap();
    reopened
        .initialize_local_user_device(principal, key, user.uid, fleet.uid)
        .await
        .unwrap();
    assert_eq!(
        reopened
            .load()
            .await
            .unwrap()
            .user_for_device(principal, &key),
        None
    );
    assert!(matches!(
        reopened.assign_created_principal_for_device(child, principal, &key).await,
        Err(OwnershipError::UserDeviceNotBound(uid)) if uid == principal
    ));
    assert!(
        reopened
            .load()
            .await
            .unwrap()
            .principal_owner(child)
            .is_none()
    );

    reopened
        .bind_user_device(principal, key, user.uid, user.uid)
        .await
        .unwrap();
    reopened
        .assign_created_principal_for_device(child, principal, &key)
        .await
        .unwrap();
    let graph = reopened.load().await.unwrap();
    let owner = graph.principal_owner(child).unwrap();
    assert_eq!(owner.fleet_uid, fleet.uid);
    assert_eq!(owner.assigned_by, user.uid);
}
