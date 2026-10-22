use super::*;
use crate::{MemoryKvStore, PrincipalDirectory};

async fn fixture() -> (
    OwnershipStore,
    PrincipalDirectory,
    PrincipalUid,
    DerivedPrincipalProvision,
) {
    let directory = PrincipalDirectory::default();
    let store = OwnershipStore::new(Arc::new(MemoryKvStore::new()), directory.clone()).unwrap();
    crate::ownership::tests::enroll_store(&store, &directory).await;
    let graph = store.load().await.unwrap();
    let creator = graph.principal_ownership.keys().next().copied().unwrap();
    let child = PrincipalUid::from_bytes([29; 32]);
    directory
        .register(PrincipalId::new("provisional-child").unwrap(), child)
        .unwrap();
    let captured = store.capture_derived_ownership(creator).await.unwrap();
    let provision = store
        .assign_derived_principal_for_provisioning(child, &captured)
        .await
        .unwrap();
    (store, directory, child, provision)
}

#[tokio::test]
async fn exact_provisional_rollback_retains_durable_retirement_until_identity_removal() {
    let (store, directory, child, provision) = fixture().await;
    let alias = provision.alias.clone();
    let fleet = provision.owner.fleet_uid;
    let guard = store
        .guard_derived_principal_rollback(provision)
        .await
        .unwrap();
    let graph = store.load().await.unwrap();
    assert!(graph.principal_owner(child).is_none());
    assert!(graph.accountable_user(child).is_none());
    assert_eq!(
        graph.principal_deletions[&child].alias.as_ref(),
        Some(&alias)
    );
    assert_eq!(graph.principal_deletions[&child].fleet, Some(fleet));
    drop(guard);
    assert!(store.ensure_alias_available(&alias).await.is_err());
    directory.unregister(&alias, child);
    assert!(
        store
            .finish_principal_deletion_by_alias(&alias)
            .await
            .unwrap()
    );
    assert!(
        !store
            .load()
            .await
            .unwrap()
            .principal_deletions
            .contains_key(&child)
    );
}

#[tokio::test]
async fn changed_provisional_identity_or_authority_never_deletes_current_assignment() {
    for change in ["fleet", "payer", "device", "alias", "store", "retiring"] {
        let (store, directory, child, provision) = fixture().await;
        let owner = provision.owner.clone();
        match change {
            "fleet" => {
                let fleet = astrid_core::FleetIdentity::from_genesis(
                    astrid_core::FleetGenesis::from_parts(
                        uuid::Uuid::from_u128(991),
                        chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
                        owner.assigned_by,
                    ),
                )
                .unwrap();
                store.create_fleet(fleet.clone()).await.unwrap();
                store
                    .transfer_principal(child, owner.fleet_uid, fleet.uid, owner.assigned_by)
                    .await
                    .unwrap();
            },
            "payer" => {
                let user =
                    astrid_core::UserIdentity::from_genesis(astrid_core::UserGenesis::from_parts(
                        uuid::Uuid::from_u128(992),
                        chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
                        [98; 32],
                    ))
                    .unwrap();
                store.create_user(user.clone()).await.unwrap();
                store
                    .assign_accountable_user(child, Some(provision.payer), user.uid)
                    .await
                    .unwrap();
            },
            "device" => store
                .bind_user_device(child, [99; 32], provision.payer, owner.assigned_by)
                .await
                .unwrap(),
            "alias" => directory
                .rename(
                    child,
                    &provision.alias,
                    PrincipalId::new("changed-child").unwrap(),
                )
                .unwrap(),
            "store" => {
                let other =
                    OwnershipStore::new(Arc::new(MemoryKvStore::new()), directory.clone()).unwrap();
                crate::ownership::tests::enroll_store(&other, &directory).await;
                let before = other.load().await.unwrap();
                assert!(
                    other
                        .guard_derived_principal_rollback(provision)
                        .await
                        .is_err()
                );
                assert_eq!(before, other.load().await.unwrap());
                continue;
            },
            "retiring" => {
                let creator = store
                    .load()
                    .await
                    .unwrap()
                    .principal_ownership
                    .keys()
                    .find(|uid| **uid != child)
                    .copied()
                    .unwrap();
                store
                    .bind_user_device(creator, [99; 32], provision.payer, owner.assigned_by)
                    .await
                    .unwrap();
                drop(
                    store
                        .guard_principal_deletion_for_device(
                            child,
                            provision.alias.clone(),
                            creator,
                            &[99; 32],
                        )
                        .await
                        .unwrap(),
                );
            },
            _ => unreachable!(),
        }
        let before = store.load().await.unwrap();
        assert!(
            store
                .guard_derived_principal_rollback(provision)
                .await
                .is_err(),
            "{change}"
        );
        assert_eq!(before, store.load().await.unwrap(), "{change}");
    }
}

#[tokio::test]
async fn abandoning_provisioning_preserves_the_exact_owned_child_for_diagnosis() {
    let (store, directory, child, provision) = fixture().await;
    let alias = provision.alias.clone();
    let before = store.load().await.unwrap();
    drop(provision);
    assert_eq!(before, store.load().await.unwrap());
    assert_eq!(directory.uid_for(&alias).unwrap(), child);
    assert!(store.load().await.unwrap().principal_owner(child).is_some());
}
