use super::*;
use crate::first_owner_test_support;
use std::sync::Arc;

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one ownership-bootstrap scenario must retain the same store across initial \
                  adoption, idempotent replay, transfer, and non-legacy restart"
)]
async fn legacy_root_ownership_bootstrap_is_deterministic_and_idempotent() {
    let backend: Arc<dyn astrid_storage::KvStore> = Arc::new(astrid_storage::MemoryKvStore::new());
    let directory = astrid_storage::PrincipalDirectory::default();
    let ownership_store = astrid_storage::OwnershipStore::new(backend, directory.clone()).unwrap();
    let root_signing_key =
        astrid_crypto::KeyPair::from_secret_key(&[2; 32]).expect("manual root key");
    let principal_identity =
        astrid_core::PrincipalIdentity::from_genesis(astrid_core::PrincipalGenesis::from_parts(
            uuid::Uuid::from_u128(2),
            chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            *root_signing_key.public_key_bytes(),
        ))
        .unwrap();
    directory
        .register(astrid_core::PrincipalId::default(), principal_identity.uid)
        .unwrap();
    let legacy_principal_identity =
        astrid_core::PrincipalIdentity::from_genesis(astrid_core::PrincipalGenesis::from_parts(
            uuid::Uuid::from_u128(4),
            chrono::DateTime::from_timestamp(1_700_000_002, 0).unwrap(),
            [4; 32],
        ))
        .unwrap();
    directory
        .register(
            astrid_core::PrincipalId::new("legacy-agent").unwrap(),
            legacy_principal_identity.uid,
        )
        .unwrap();
    let root_user = astrid_core::AstridUserId {
        id: uuid::Uuid::from_u128(1),
        principal: astrid_core::PrincipalId::default(),
        public_key: None,
        display_name: None,
        created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
    };

    first_owner_test_support::enroll_test_first_owner(
        &ownership_store,
        &directory,
        &root_user,
        &principal_identity,
        &root_signing_key,
    )
    .await;

    bootstrap_cli_root_ownership(
        &ownership_store,
        &directory,
        root_user.clone(),
        principal_identity.clone(),
    )
    .await
    .unwrap();
    let first = ownership_store.load().await.unwrap();
    bootstrap_cli_root_ownership(
        &ownership_store,
        &directory,
        root_user.clone(),
        principal_identity.clone(),
    )
    .await
    .unwrap();
    let second = ownership_store.load().await.unwrap();

    assert_eq!(first, second);
    let principal_owner = second.principal_owner(principal_identity.uid).unwrap();
    let root_user_uid = principal_owner.assigned_by;
    let initial_fleet_uid = principal_owner.fleet_uid;
    let expected_user =
        astrid_core::UserIdentity::from_genesis(astrid_core::UserGenesis::from_parts(
            root_user.id,
            root_user.created_at,
            principal_identity.genesis.initial_public_key,
        ))
        .unwrap();
    assert_eq!(root_user_uid, expected_user.uid);
    assert_eq!(second.fleets().count(), 1);
    assert!(second.fleet(principal_owner.fleet_uid).is_some());
    assert_eq!(
        second
            .principal_owner(legacy_principal_identity.uid)
            .unwrap()
            .fleet_uid,
        initial_fleet_uid
    );

    let destination =
        astrid_core::FleetIdentity::from_genesis(astrid_core::FleetGenesis::from_parts(
            uuid::Uuid::from_u128(3),
            chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
            root_user_uid,
        ))
        .unwrap();
    ownership_store
        .create_fleet(destination.clone())
        .await
        .unwrap();
    ownership_store
        .transfer_principal(
            principal_identity.uid,
            initial_fleet_uid,
            destination.uid,
            root_user_uid,
        )
        .await
        .unwrap();

    bootstrap_cli_root_ownership(
        &ownership_store,
        &directory,
        root_user,
        principal_identity.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        ownership_store
            .load()
            .await
            .unwrap()
            .principal_owner(principal_identity.uid)
            .unwrap()
            .fleet_uid,
        destination.uid
    );
}
