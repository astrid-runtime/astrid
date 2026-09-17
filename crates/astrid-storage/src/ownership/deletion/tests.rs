use std::sync::Arc;

use astrid_core::{
    FleetGenesis, FleetIdentity, PrincipalId, PrincipalOwnership, PrincipalUid, UserGenesis,
    UserIdentity, UserUid,
};

use crate::ownership::{OwnershipError, OwnershipStore};

#[tokio::test]
async fn demoted_manager_cannot_start_or_resume_deletion() {
    for reserve_first in [false, true] {
        let f = fixture().await;
        let graph = f.store.load().await.unwrap();
        let fleet = graph.principal_owner(f.target).unwrap().fleet_uid;
        let backup = graph.user_for_device(f.foreign, &[9; 32]).unwrap();
        f.store
            .set_membership(fleet, backup, astrid_core::FleetRole::Owner, f.user)
            .await
            .unwrap();
        if reserve_first {
            drop(
                f.store
                    .guard_principal_deletion_for_device(
                        f.target,
                        f.alias.clone(),
                        f.operator,
                        &[9; 32],
                    )
                    .await
                    .unwrap(),
            );
        }
        f.store
            .set_membership(fleet, f.user, astrid_core::FleetRole::Member, backup)
            .await
            .unwrap();
        let before = f.store.load().await.unwrap();
        assert!(
            f.store
                .guard_principal_deletion_for_device(
                    f.target,
                    f.alias.clone(),
                    f.operator,
                    &[9; 32]
                )
                .await
                .is_err()
        );
        assert_eq!(before, f.store.load().await.unwrap());
    }
}
use crate::{MemoryKvStore, PrincipalDirectory};

struct Fixture {
    store: OwnershipStore,
    backend: Arc<MemoryKvStore>,
    directory: PrincipalDirectory,
    operator: PrincipalUid,
    foreign: PrincipalUid,
    target: PrincipalUid,
    user: UserUid,
    alias: PrincipalId,
}

async fn fixture() -> Fixture {
    let backend = Arc::new(MemoryKvStore::new());
    let directory = PrincipalDirectory::default();
    let operator = PrincipalUid::from_bytes([1; 32]);
    let target = PrincipalUid::from_bytes([2; 32]);
    let foreign = PrincipalUid::from_bytes([3; 32]);
    let alias = PrincipalId::new("child").unwrap();
    for (name, uid) in [
        (PrincipalId::default(), operator),
        (alias.clone(), target),
        (PrincipalId::new("foreign").unwrap(), foreign),
    ] {
        directory.register(name, uid).unwrap();
    }
    let store = OwnershipStore::new(backend.clone(), directory.clone()).unwrap();
    let mut operator_user = None;
    for (n, principal) in [(1_u8, operator), (2_u8, foreign)] {
        let user = UserIdentity::from_genesis(UserGenesis::from_parts(
            uuid::Uuid::from_u128(u128::from(n)),
            chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            [n; 32],
        ))
        .unwrap();
        let fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
            uuid::Uuid::from_u128(u128::from(n)),
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
        store
            .bind_user_device(principal, [9; 32], user.uid, user.uid)
            .await
            .unwrap();
        if principal == operator {
            operator_user = Some(user.uid);
            store
                .assign_principal(PrincipalOwnership {
                    principal_uid: target,
                    fleet_uid: fleet.uid,
                    assigned_by: user.uid,
                })
                .await
                .unwrap();
            store
                .bind_user_device(target, [8; 32], user.uid, user.uid)
                .await
                .unwrap();
        }
    }
    Fixture {
        store,
        backend,
        directory,
        operator,
        foreign,
        target,
        user: operator_user.unwrap(),
        alias,
    }
}

#[tokio::test]
async fn foreign_missing_and_revoked_delegation_leave_ownership_unchanged() {
    let f = fixture().await;
    let before = f.store.load().await.unwrap();
    assert!(
        f.store
            .guard_principal_deletion_for_device(f.target, f.alias.clone(), f.foreign, &[9; 32])
            .await
            .is_err()
    );
    assert!(
        f.store
            .guard_principal_deletion_for_device(f.target, f.alias.clone(), f.operator, &[7; 32])
            .await
            .is_err()
    );
    assert!(
        f.store
            .guard_principal_deletion_for_alias(f.target, f.alias.clone())
            .await
            .is_err()
    );
    assert_eq!(before, f.store.load().await.unwrap());
    f.store
        .revoke_user_device(f.operator, [9; 32], f.user)
        .await
        .unwrap();
    let revoked = f.store.load().await.unwrap();
    assert!(
        f.store
            .guard_principal_deletion_for_device(f.target, f.alias.clone(), f.operator, &[9; 32])
            .await
            .is_err()
    );
    assert_eq!(revoked, f.store.load().await.unwrap());
}

#[tokio::test]
async fn failed_alias_validation_keeps_owner_and_device_bindings() {
    let f = fixture().await;
    let before = f.store.load().await.unwrap();
    assert!(
        f.store
            .guard_principal_deletion_for_device(
                f.target,
                PrincipalId::new("wrong").unwrap(),
                f.operator,
                &[9; 32]
            )
            .await
            .is_err()
    );
    assert_eq!(before, f.store.load().await.unwrap());
}

#[tokio::test]
async fn interrupted_deletion_retains_fleet_authority_after_identity_removal() {
    let f = fixture().await;
    let guard = f
        .store
        .guard_principal_deletion_for_device(f.target, f.alias.clone(), f.operator, &[9; 32])
        .await
        .unwrap();
    let graph = f.store.load().await.unwrap();
    assert!(graph.principal_owner(f.target).is_none());
    assert!(graph.user_for_device(f.target, &[8; 32]).is_none());
    assert!(f.store.ensure_alias_available(&f.alias).await.is_err());
    drop(guard);
    f.directory.unregister(&f.alias, f.target);
    // Reopen the store so this exercises persisted reservation authority, not
    // a retained in-memory authorization object.
    let reopened = OwnershipStore::new(f.backend, f.directory).unwrap();
    assert!(matches!(
        reopened.resume_principal_deletion_by_alias(&f.alias).await,
        Err(OwnershipError::PrincipalAlreadyOwned { .. })
    ));
    assert!(
        reopened
            .resume_principal_deletion_for_device(&f.alias, f.foreign, &[9; 32])
            .await
            .is_err()
    );
    reopened
        .revoke_user_device(f.operator, [9; 32], f.user)
        .await
        .unwrap();
    assert!(
        reopened
            .resume_principal_deletion_for_device(&f.alias, f.operator, &[9; 32])
            .await
            .is_err()
    );
    reopened
        .bind_user_device(f.operator, [9; 32], f.user, f.user)
        .await
        .unwrap();
    let resumed = reopened
        .resume_principal_deletion_for_device(&f.alias, f.operator, &[9; 32])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resumed.principal_uid(), f.target);
    resumed.finish().await.unwrap();
    reopened.ensure_alias_available(&f.alias).await.unwrap();
}
