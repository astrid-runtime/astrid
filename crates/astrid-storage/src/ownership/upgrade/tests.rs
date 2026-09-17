use super::*;
use crate::{MemoryKvStore, PrincipalDirectory};
use astrid_core::{
    FleetGenesis, FleetIdentity, FleetRole, PrincipalGenesis, PrincipalId, PrincipalIdentity,
    PrincipalOwnership, UserGenesis, UserIdentity,
};
use chrono::{TimeZone, Utc};
use std::sync::Arc;
use uuid::Uuid;

fn at(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0).single().unwrap()
}

fn user(id: u128, key: u8) -> UserIdentity {
    UserIdentity::from_genesis(UserGenesis::from_parts(
        Uuid::from_u128(id),
        at(1_700_000_000),
        [key; 32],
    ))
    .unwrap()
}

fn fleet(id: u128, creator: UserUid) -> FleetIdentity {
    FleetIdentity::from_genesis(FleetGenesis::from_parts(
        Uuid::from_u128(id),
        at(1_700_000_001),
        creator,
    ))
    .unwrap()
}

fn principal(id: u128, key: u8) -> PrincipalUid {
    PrincipalIdentity::from_genesis(PrincipalGenesis::from_parts(
        Uuid::from_u128(id),
        at(1_700_000_002),
        [key; 32],
    ))
    .unwrap()
    .uid
}

fn admit(directory: &PrincipalDirectory, alias: &str, uid: PrincipalUid) {
    directory
        .register(PrincipalId::new(alias).unwrap(), uid)
        .unwrap();
}

async fn single_operator_store() -> (
    OwnershipStore,
    UserIdentity,
    FleetIdentity,
    PrincipalUid,
    PrincipalUid,
) {
    let directory = PrincipalDirectory::default();
    let default_uid = principal(20, 2);
    let extra_uid = principal(21, 3);
    admit(&directory, "default", default_uid);
    admit(&directory, "packed-agent", extra_uid);
    let store = OwnershipStore::new(Arc::new(MemoryKvStore::new()), directory).unwrap();
    let owner = user(1, 1);
    let owned_fleet = fleet(10, owner.uid);
    store.create_user(owner.clone()).await.unwrap();
    store.create_fleet(owned_fleet.clone()).await.unwrap();
    store
        .assign_principal(PrincipalOwnership {
            principal_uid: default_uid,
            fleet_uid: owned_fleet.uid,
            assigned_by: owner.uid,
        })
        .await
        .unwrap();
    (store, owner, owned_fleet, default_uid, extra_uid)
}

#[tokio::test]
async fn single_operator_graph_adopts_unowned_admitted_principals() {
    let (store, owner, owned_fleet, default_uid, extra_uid) = single_operator_store().await;
    let result = store
        .reconcile_local_operator_unowned_principals(owner.uid, owned_fleet.uid)
        .await
        .unwrap();
    assert_eq!(result.adopted(), &[extra_uid]);
    assert!(result.deferred().is_empty());
    assert_eq!(result.deferral(), None);
    let graph = store.load().await.unwrap();
    assert_eq!(
        graph.principal_owner(default_uid).unwrap().fleet_uid,
        owned_fleet.uid
    );
    assert_eq!(
        graph.principal_owner(extra_uid).unwrap().assigned_by,
        owner.uid
    );
}

#[tokio::test]
async fn packed_upgrade_adoption_is_idempotent() {
    let (store, owner, owned_fleet, _, extra_uid) = single_operator_store().await;
    store
        .reconcile_local_operator_unowned_principals(owner.uid, owned_fleet.uid)
        .await
        .unwrap();
    let second = store
        .reconcile_local_operator_unowned_principals(owner.uid, owned_fleet.uid)
        .await
        .unwrap();
    assert!(second.adopted().is_empty());
    assert!(second.deferred().is_empty());
    assert_eq!(
        store
            .load()
            .await
            .unwrap()
            .principal_owner(extra_uid)
            .unwrap()
            .fleet_uid,
        owned_fleet.uid
    );
}

#[tokio::test]
async fn extra_user_leaves_unowned_principals_for_explicit_disposition() {
    let (store, owner, owned_fleet, default_uid, extra_uid) = single_operator_store().await;
    let other = user(2, 9);
    store.create_user(other.clone()).await.unwrap();
    store
        .set_membership(owned_fleet.uid, other.uid, FleetRole::Member, owner.uid)
        .await
        .unwrap();
    let result = store
        .reconcile_local_operator_unowned_principals(owner.uid, owned_fleet.uid)
        .await
        .unwrap();
    assert!(result.adopted().is_empty());
    assert_eq!(result.deferred(), &[extra_uid]);
    assert_eq!(
        result.deferral(),
        Some(UnownedPrincipalDeferral::AmbiguousAuthority)
    );
    let graph = store.load().await.unwrap();
    assert_eq!(
        graph.principal_owner(default_uid).unwrap().fleet_uid,
        owned_fleet.uid
    );
    assert!(graph.principal_owner(extra_uid).is_none());
}

#[tokio::test]
async fn extra_fleet_does_not_claim_unowned_principals() {
    let (store, owner, owned_fleet, _, extra_uid) = single_operator_store().await;
    let other_fleet = fleet(11, owner.uid);
    store.create_fleet(other_fleet.clone()).await.unwrap();
    let result = store
        .reconcile_local_operator_unowned_principals(owner.uid, owned_fleet.uid)
        .await
        .unwrap();
    assert!(result.adopted().is_empty());
    assert_eq!(result.deferred(), &[extra_uid]);
    assert_eq!(
        result.deferral(),
        Some(UnownedPrincipalDeferral::AmbiguousAuthority)
    );
    assert!(
        store
            .load()
            .await
            .unwrap()
            .principal_owner(extra_uid)
            .is_none()
    );
}

#[tokio::test]
async fn transferred_assignment_is_not_moved_and_unowned_is_not_claimed() {
    let (store, owner, owned_fleet, default_uid, extra_uid) = single_operator_store().await;
    let destination = fleet(11, owner.uid);
    store.create_fleet(destination.clone()).await.unwrap();
    store
        .transfer_principal(default_uid, owned_fleet.uid, destination.uid, owner.uid)
        .await
        .unwrap();
    let result = store
        .reconcile_local_operator_unowned_principals(owner.uid, owned_fleet.uid)
        .await
        .unwrap();
    assert!(result.adopted().is_empty());
    assert_eq!(result.deferred(), &[extra_uid]);
    let graph = store.load().await.unwrap();
    assert_eq!(
        graph.principal_owner(default_uid).unwrap().fleet_uid,
        destination.uid
    );
    assert!(graph.principal_owner(extra_uid).is_none());
}

#[tokio::test]
async fn deletion_reservation_is_not_adopted() {
    let directory = PrincipalDirectory::default();
    let default_uid = principal(20, 2);
    let extra_uid = principal(21, 3);
    admit(&directory, "default", default_uid);
    admit(&directory, "retiring", extra_uid);
    let store = OwnershipStore::new(Arc::new(MemoryKvStore::new()), directory.clone()).unwrap();
    let owner = user(1, 1);
    let owned_fleet = fleet(10, owner.uid);
    store.create_user(owner.clone()).await.unwrap();
    store.create_fleet(owned_fleet.clone()).await.unwrap();
    store
        .assign_principal(PrincipalOwnership {
            principal_uid: default_uid,
            fleet_uid: owned_fleet.uid,
            assigned_by: owner.uid,
        })
        .await
        .unwrap();
    let guard = store.guard_principal_deletion(extra_uid).await.unwrap();
    // The reservation is durable; the guard only serializes graph writers.
    drop(guard);
    let result = store
        .reconcile_local_operator_unowned_principals(owner.uid, owned_fleet.uid)
        .await
        .unwrap();
    assert!(result.adopted().is_empty());
    assert!(result.deferred().is_empty());
    assert!(
        store
            .load()
            .await
            .unwrap()
            .principal_owner(extra_uid)
            .is_none()
    );
}

#[tokio::test]
async fn non_manager_actor_is_rejected_before_assignment() {
    let (store, owner, owned_fleet, _, extra_uid) = single_operator_store().await;
    let member = user(2, 9);
    store.create_user(member.clone()).await.unwrap();
    store
        .set_membership(owned_fleet.uid, member.uid, FleetRole::Member, owner.uid)
        .await
        .unwrap();
    assert!(matches!(
        store
            .reconcile_local_operator_unowned_principals(member.uid, owned_fleet.uid)
            .await,
        Err(OwnershipError::NotFleetManager { user, fleet })
            if user == member.uid && fleet == owned_fleet.uid
    ));
    assert!(
        store
            .load()
            .await
            .unwrap()
            .principal_owner(extra_uid)
            .is_none()
    );
}

const LOCAL_DEVICE_KEY: [u8; 32] = [4; 32];

async fn bind_local_operator(
    store: &OwnershipStore,
    principal: PrincipalUid,
    user: UserUid,
    fleet: FleetUid,
) {
    store
        .initialize_local_user_device(principal, LOCAL_DEVICE_KEY, user, fleet)
        .await
        .unwrap();
}

#[tokio::test]
async fn bound_local_operator_adopts_unowned_admitted_principals() {
    let (store, owner, owned_fleet, default_uid, extra_uid) = single_operator_store().await;
    bind_local_operator(&store, default_uid, owner.uid, owned_fleet.uid).await;
    let result = store
        .reconcile_bound_local_operator_unowned_principals(default_uid, &LOCAL_DEVICE_KEY)
        .await
        .unwrap();
    assert_eq!(result.adopted(), &[extra_uid]);
    assert_eq!(result.deferral(), None);
    assert_eq!(
        store
            .load()
            .await
            .unwrap()
            .principal_owner(extra_uid)
            .unwrap()
            .assigned_by,
        owner.uid
    );
}

#[tokio::test]
async fn singleton_graph_without_local_device_does_not_adopt() {
    let (store, _, _, default_uid, extra_uid) = single_operator_store().await;
    let result = store
        .reconcile_bound_local_operator_unowned_principals(default_uid, &LOCAL_DEVICE_KEY)
        .await
        .unwrap();
    assert!(result.adopted().is_empty());
    assert_eq!(result.deferred(), &[extra_uid]);
    assert_eq!(
        result.deferral(),
        Some(UnownedPrincipalDeferral::LocalOperatorNotBound)
    );
    assert!(
        store
            .load()
            .await
            .unwrap()
            .principal_owner(extra_uid)
            .is_none()
    );
}

#[tokio::test]
async fn bound_local_operator_still_defers_extra_user_and_keeps_assignments() {
    let (store, owner, owned_fleet, default_uid, extra_uid) = single_operator_store().await;
    bind_local_operator(&store, default_uid, owner.uid, owned_fleet.uid).await;
    let other = user(2, 9);
    store.create_user(other.clone()).await.unwrap();
    store
        .set_membership(owned_fleet.uid, other.uid, FleetRole::Member, owner.uid)
        .await
        .unwrap();
    let result = store
        .reconcile_bound_local_operator_unowned_principals(default_uid, &LOCAL_DEVICE_KEY)
        .await
        .unwrap();
    assert!(result.adopted().is_empty());
    assert_eq!(result.deferred(), &[extra_uid]);
    assert_eq!(
        result.deferral(),
        Some(UnownedPrincipalDeferral::AmbiguousAuthority)
    );
    let graph = store.load().await.unwrap();
    assert_eq!(
        graph.principal_owner(default_uid).unwrap().fleet_uid,
        owned_fleet.uid
    );
    assert!(graph.principal_owner(extra_uid).is_none());
}

#[tokio::test]
async fn bound_local_operator_does_not_move_a_transferred_assignment() {
    let (store, owner, owned_fleet, default_uid, extra_uid) = single_operator_store().await;
    bind_local_operator(&store, default_uid, owner.uid, owned_fleet.uid).await;
    let destination = fleet(11, owner.uid);
    store.create_fleet(destination.clone()).await.unwrap();
    store
        .transfer_principal(default_uid, owned_fleet.uid, destination.uid, owner.uid)
        .await
        .unwrap();
    let result = store
        .reconcile_bound_local_operator_unowned_principals(default_uid, &LOCAL_DEVICE_KEY)
        .await
        .unwrap();
    assert!(result.adopted().is_empty());
    assert_eq!(
        result.deferral(),
        Some(UnownedPrincipalDeferral::LocalOperatorNotBound)
    );
    let graph = store.load().await.unwrap();
    assert_eq!(
        graph.principal_owner(default_uid).unwrap().fleet_uid,
        destination.uid
    );
    assert!(graph.principal_owner(extra_uid).is_none());
}

#[tokio::test]
async fn bound_local_upgrade_adoption_is_idempotent() {
    let (store, owner, owned_fleet, default_uid, extra_uid) = single_operator_store().await;
    bind_local_operator(&store, default_uid, owner.uid, owned_fleet.uid).await;
    store
        .reconcile_bound_local_operator_unowned_principals(default_uid, &LOCAL_DEVICE_KEY)
        .await
        .unwrap();
    let second = store
        .reconcile_bound_local_operator_unowned_principals(default_uid, &LOCAL_DEVICE_KEY)
        .await
        .unwrap();
    assert!(second.adopted().is_empty());
    assert_eq!(second.deferral(), None);
    assert_eq!(
        store
            .load()
            .await
            .unwrap()
            .principal_owner(extra_uid)
            .unwrap()
            .fleet_uid,
        owned_fleet.uid
    );
}
