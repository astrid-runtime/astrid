use super::*;
use crate::{MemoryKvStore, PrincipalDirectory};
use astrid_core::{
    FleetGenesis, FleetIdentity, FleetRole, PrincipalId, PrincipalOwnership, UserGenesis,
    UserIdentity,
};
use std::sync::Arc;

fn user(id: u128) -> UserIdentity {
    UserIdentity::from_genesis(UserGenesis::from_parts(
        uuid::Uuid::from_u128(id),
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        [1; 32],
    ))
    .unwrap()
}

async fn fixture() -> (OwnershipStore, PrincipalUid, UserIdentity, FleetIdentity) {
    let directory = PrincipalDirectory::default();
    let principal = PrincipalUid::from_bytes([2; 32]);
    directory
        .register(PrincipalId::default(), principal)
        .unwrap();
    let store = OwnershipStore::new(Arc::new(MemoryKvStore::new()), directory).unwrap();
    let owner = user(1);
    let fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
        uuid::Uuid::from_u128(2),
        chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
        owner.uid,
    ))
    .unwrap();
    store.create_user(owner.clone()).await.unwrap();
    store.create_fleet(fleet.clone()).await.unwrap();
    store
        .assign_principal(PrincipalOwnership {
            principal_uid: principal,
            fleet_uid: fleet.uid,
            assigned_by: owner.uid,
        })
        .await
        .unwrap();
    store
        .bind_user_device(principal, [3; 32], owner.uid, owner.uid)
        .await
        .unwrap();
    (store, principal, owner, fleet)
}

async fn legacy_bytes(store: &OwnershipStore) {
    let bytes = store
        .storage
        .get(super::super::GRAPH_KEY)
        .await
        .unwrap()
        .unwrap();
    let mut graph: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    graph.as_object_mut().unwrap().remove("accountable_users");
    store
        .storage
        .set(super::super::GRAPH_KEY, serde_json::to_vec(&graph).unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn personal_legacy_graph_migrates_idempotently_and_survives_reload() {
    let (store, principal, owner, _) = fixture().await;
    legacy_bytes(&store).await;
    assert_eq!(
        store.load().await.unwrap().accountable_user(principal),
        None
    );
    assert!(
        store
            .reconcile_local_accountable_users(principal, &[3; 32])
            .await
            .unwrap()
            .is_empty()
    );
    let first = store.load().await.unwrap();
    assert_eq!(first.accountable_user(principal), Some(owner.uid));
    assert!(
        store
            .reconcile_local_accountable_users(principal, &[3; 32])
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.load().await.unwrap(), first);
}

#[tokio::test]
async fn legacy_accountability_survives_volume_reopen_without_changing_capsule_state() {
    use crate::{
        IdentityStore, KvIdentityStore, ScopedKvStore, StateOwner,
        open_runtime_principal_store_with_directory,
    };

    let (_, _, owner, fleet) = fixture().await;
    let temp = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temp.path());
    let directory = PrincipalDirectory::default();
    let quota =
        || -> Arc<dyn crate::KvQuotaResolver<StateOwner>> { Arc::new(|_: &StateOwner| Ok(None)) };
    let runtime = open_runtime_principal_store_with_directory(&home, quota(), directory.clone())
        .await
        .unwrap();
    let kv = runtime.kv();
    let identities = KvIdentityStore::with_principal_directory(
        ScopedKvStore::new(Arc::clone(&kv), "system:identity").unwrap(),
        directory.clone(),
    );
    let identity = identities
        .create_principal(PrincipalId::default(), [3; 32])
        .await
        .unwrap();
    let principal = identities
        .get_principal_identity(identity.id)
        .await
        .unwrap()
        .unwrap()
        .uid;
    let store = OwnershipStore::new(Arc::clone(&kv), directory.clone()).unwrap();
    store.create_user(owner.clone()).await.unwrap();
    store.create_fleet(fleet.clone()).await.unwrap();
    store
        .assign_principal(PrincipalOwnership {
            principal_uid: principal,
            fleet_uid: fleet.uid,
            assigned_by: owner.uid,
        })
        .await
        .unwrap();
    store
        .bind_user_device(principal, [3; 32], owner.uid, owner.uid)
        .await
        .unwrap();
    legacy_bytes(&store).await;
    kv.set(
        "default:capsule:upgrade-probe",
        "state",
        b"retained capsule state".to_vec(),
    )
    .await
    .unwrap();
    assert_eq!(
        store.load().await.unwrap().accountable_user(principal),
        None
    );
    assert!(
        store
            .reconcile_local_accountable_users(principal, &[3; 32])
            .await
            .unwrap()
            .is_empty()
    );
    let migrated = store.load().await.unwrap();
    assert_eq!(migrated.accountable_user(principal), Some(owner.uid));
    drop(store);
    drop(identities);
    kv.close().await.unwrap();
    drop(kv);
    drop(runtime);

    assert!(home.storage_volume_path().is_file());
    let directory = PrincipalDirectory::default();
    let reopened = open_runtime_principal_store_with_directory(&home, quota(), directory.clone())
        .await
        .unwrap();
    let kv = reopened.kv();
    let store = OwnershipStore::new(Arc::clone(&kv), directory).unwrap();
    assert_eq!(store.load().await.unwrap(), migrated);
    assert!(
        store
            .reconcile_local_accountable_users(principal, &[3; 32])
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.load().await.unwrap(), migrated);
    assert_eq!(
        kv.get("default:capsule:upgrade-probe", "state")
            .await
            .unwrap(),
        Some(b"retained capsule state".to_vec())
    );
    drop(store);
    kv.close().await.unwrap();
}

#[tokio::test]
async fn ambiguous_or_revoked_local_identity_is_not_guessed() {
    let (store, principal, owner, _) = fixture().await;
    legacy_bytes(&store).await;
    store
        .revoke_user_device(principal, [3; 32], owner.uid)
        .await
        .unwrap();
    assert_eq!(
        store
            .reconcile_local_accountable_users(principal, &[3; 32])
            .await
            .unwrap(),
        vec![principal]
    );
    store
        .bind_user_device(principal, [3; 32], owner.uid, owner.uid)
        .await
        .unwrap();
    store.create_user(user(4)).await.unwrap();
    assert_eq!(
        store
            .reconcile_local_accountable_users(principal, &[3; 32])
            .await
            .unwrap(),
        vec![principal]
    );
    assert_eq!(
        store.load().await.unwrap().accountable_user(principal),
        None
    );
}

#[tokio::test]
async fn fleet_transfer_and_membership_changes_do_not_move_the_bill() {
    let (store, principal, owner, fleet) = fixture().await;
    let other = user(4);
    store.create_user(other.clone()).await.unwrap();
    store
        .set_membership(fleet.uid, other.uid, FleetRole::Owner, owner.uid)
        .await
        .unwrap();
    let destination = FleetIdentity::from_genesis(FleetGenesis::from_parts(
        uuid::Uuid::from_u128(5),
        chrono::DateTime::from_timestamp(1_700_000_003, 0).unwrap(),
        other.uid,
    ))
    .unwrap();
    store.create_fleet(destination.clone()).await.unwrap();
    store
        .transfer_principal(principal, fleet.uid, destination.uid, other.uid)
        .await
        .unwrap();
    let graph = store.load().await.unwrap();
    assert_eq!(
        graph.principal_owner(principal).unwrap().assigned_by,
        other.uid
    );
    assert_eq!(graph.accountable_user(principal), Some(owner.uid));
    store
        .assign_accountable_user(principal, Some(owner.uid), other.uid)
        .await
        .unwrap();
    assert!(
        store
            .assign_accountable_user(principal, Some(owner.uid), owner.uid)
            .await
            .is_err()
    );
    assert_eq!(
        store.load().await.unwrap().accountable_user(principal),
        Some(other.uid)
    );
}

#[tokio::test]
async fn derived_service_inherits_accountability_without_user_login() {
    let (store, principal, owner, _) = fixture().await;
    let child = PrincipalUid::from_bytes([6; 32]);
    store
        .principals
        .register(PrincipalId::new("service").unwrap(), child)
        .unwrap();
    store
        .revoke_user_device(principal, [3; 32], owner.uid)
        .await
        .unwrap();
    let captured = store.capture_derived_ownership(principal).await.unwrap();
    store
        .assign_derived_principal(child, &captured)
        .await
        .unwrap();
    assert_eq!(
        store.load().await.unwrap().accountable_user(child),
        Some(owner.uid)
    );
}

#[tokio::test]
async fn unresolved_parent_cannot_spawn_unaccountable_children() {
    let (store, principal, _, _) = fixture().await;
    legacy_bytes(&store).await;
    assert!(matches!(store.capture_derived_ownership(principal).await,
        Err(OwnershipError::AccountableUserRequired(uid)) if uid == principal));
}

#[tokio::test]
async fn unknown_accountable_user_is_input_error_not_graph_corruption() {
    let (store, principal, owner, _) = fixture().await;
    let before = store.load().await.unwrap();
    let missing = UserUid::from_bytes([99; 32]);
    assert!(
        matches!(store.assign_accountable_user(principal, Some(owner.uid), missing).await,
        Err(OwnershipError::UserNotFound(uid)) if uid == missing)
    );
    assert_eq!(store.load().await.unwrap(), before);
}

#[tokio::test]
async fn reassignment_invalidates_captured_spawn_accountability() {
    let (store, principal, owner, _) = fixture().await;
    let child = PrincipalUid::from_bytes([7; 32]);
    store
        .principals
        .register(PrincipalId::new("pending-child").unwrap(), child)
        .unwrap();
    let captured = store.capture_derived_ownership(principal).await.unwrap();
    let other = user(8);
    store.create_user(other.clone()).await.unwrap();
    store
        .assign_accountable_user(principal, Some(owner.uid), other.uid)
        .await
        .unwrap();
    assert!(
        store
            .assign_derived_principal(child, &captured)
            .await
            .is_err()
    );
    let graph = store.load().await.unwrap();
    assert!(graph.principal_owner(child).is_none());
    assert!(graph.accountable_user(child).is_none());
}
