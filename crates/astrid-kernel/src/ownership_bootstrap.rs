//! CLI root user and fleet ownership bootstrap.

use astrid_core::{
    FleetGenesis, FleetIdentity, PrincipalId, PrincipalIdentity, PrincipalOwnership, UserGenesis,
    UserIdentity,
};
use astrid_storage::{OwnershipError, OwnershipStore, PrincipalDirectory};

/// Create the deterministic local-operator user/fleet and assign the CLI root.
///
/// After the durable `cli/local` device is bound, unowned admitted principals
/// are adopted only for that bound local operator. A singleton graph is a
/// refusal rail, not proof those identities are personal: extra users, fleets,
/// or foreign assignments stay unowned for named confirmation.
pub(crate) async fn bootstrap_cli_root_ownership(
    store: &OwnershipStore,
    principal_directory: &PrincipalDirectory,
    root_user: astrid_core::AstridUserId,
    root_principal_identity: PrincipalIdentity,
) -> Result<(), OwnershipError> {
    let user = UserIdentity::from_genesis(UserGenesis::from_parts(
        root_user.id,
        root_user.created_at,
        root_principal_identity.genesis.initial_public_key,
    ))?;
    store.create_user(user.clone()).await?;

    // Reuse the legacy root UUID and timestamp as deterministic fleet genesis
    // inputs. User/fleet UID derivation is domain-separated, so their durable
    // identifiers remain distinct while every boot derives the same records.
    let fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
        root_user.id,
        root_user.created_at,
        user.uid,
    ))?;
    store.create_fleet(fleet.clone()).await?;

    let principal_uid = principal_directory
        .uid_for(&PrincipalId::default())
        .map_err(OwnershipError::Storage)?;
    if store.load().await?.principal_owner(principal_uid).is_none() {
        store
            .assign_principal(PrincipalOwnership {
                principal_uid,
                fleet_uid: fleet.uid,
                assigned_by: user.uid,
            })
            .await?;
    }
    store
        .initialize_local_user_device(
            principal_uid,
            root_principal_identity.genesis.initial_public_key,
            user.uid,
            fleet.uid,
        )
        .await?;
    let reconciliation = store
        .reconcile_bound_local_operator_unowned_principals(
            principal_uid,
            &root_principal_identity.genesis.initial_public_key,
        )
        .await?;
    if !reconciliation.adopted().is_empty() || reconciliation.deferral().is_some() {
        tracing::info!(
            adopted = reconciliation.adopted().len(),
            deferred = reconciliation.deferred().len(),
            deferral = ?reconciliation.deferral(),
            "reconciled unowned principals for the bound local operator"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use astrid_core::PrincipalGenesis;
    use astrid_storage::MemoryKvStore;

    fn root_identity() -> PrincipalIdentity {
        PrincipalIdentity::from_genesis(PrincipalGenesis::from_parts(
            uuid::Uuid::from_u128(2),
            chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            [2; 32],
        ))
        .unwrap()
    }

    fn extra_identity() -> PrincipalIdentity {
        PrincipalIdentity::from_genesis(PrincipalGenesis::from_parts(
            uuid::Uuid::from_u128(4),
            chrono::DateTime::from_timestamp(1_700_000_002, 0).unwrap(),
            [4; 32],
        ))
        .unwrap()
    }

    fn root_user() -> astrid_core::AstridUserId {
        astrid_core::AstridUserId {
            id: uuid::Uuid::from_u128(1),
            principal: PrincipalId::default(),
            public_key: None,
            display_name: None,
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        }
    }

    fn operator_user() -> UserIdentity {
        UserIdentity::from_genesis(UserGenesis::from_parts(
            uuid::Uuid::from_u128(1),
            chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            [2; 32],
        ))
        .unwrap()
    }

    fn seeded_directory() -> (PrincipalDirectory, PrincipalIdentity, PrincipalIdentity) {
        let directory = PrincipalDirectory::default();
        let root = root_identity();
        let extra = extra_identity();
        directory
            .register(PrincipalId::default(), root.uid)
            .unwrap();
        directory
            .register(PrincipalId::new("packed-agent").unwrap(), extra.uid)
            .unwrap();
        (directory, root, extra)
    }

    #[tokio::test]
    async fn packed_home_bound_local_operator_adopts_unowned_directory_principals() {
        let backend: Arc<dyn astrid_storage::KvStore> = Arc::new(MemoryKvStore::new());
        let (directory, root, extra) = seeded_directory();
        let store = OwnershipStore::new(backend, directory.clone()).unwrap();

        bootstrap_cli_root_ownership(&store, &directory, root_user(), root.clone())
            .await
            .unwrap();
        let graph = store.load().await.unwrap();
        let owner = graph.principal_owner(root.uid).unwrap();
        assert_eq!(
            graph.principal_owner(extra.uid).unwrap().fleet_uid,
            owner.fleet_uid
        );
        assert_eq!(graph.fleets().count(), 1);
        assert_eq!(graph.users().count(), 1);
    }

    #[tokio::test]
    async fn packed_home_local_upgrade_is_idempotent_across_restart() {
        let backend: Arc<dyn astrid_storage::KvStore> = Arc::new(MemoryKvStore::new());
        let (directory, root, extra) = seeded_directory();
        let store = OwnershipStore::new(backend, directory.clone()).unwrap();
        bootstrap_cli_root_ownership(&store, &directory, root_user(), root.clone())
            .await
            .unwrap();
        let first = store.load().await.unwrap();
        bootstrap_cli_root_ownership(&store, &directory, root_user(), root.clone())
            .await
            .unwrap();
        let second = store.load().await.unwrap();
        assert_eq!(first, second);
        assert_eq!(
            second.principal_owner(extra.uid).unwrap().fleet_uid,
            first.principal_owner(root.uid).unwrap().fleet_uid
        );
        let third = store
            .reconcile_bound_local_operator_unowned_principals(
                root.uid,
                &root.genesis.initial_public_key,
            )
            .await
            .unwrap();
        assert!(third.adopted().is_empty());
        assert_eq!(third.deferral(), None);
    }

    #[tokio::test]
    async fn transferred_root_assignment_is_preserved_and_does_not_steal_extras() {
        let backend: Arc<dyn astrid_storage::KvStore> = Arc::new(MemoryKvStore::new());
        let (directory, root, extra) = seeded_directory();
        let store = OwnershipStore::new(backend, directory.clone()).unwrap();
        bootstrap_cli_root_ownership(&store, &directory, root_user(), root.clone())
            .await
            .unwrap();
        let graph = store.load().await.unwrap();
        let owner = graph.principal_owner(root.uid).unwrap().clone();
        let extra_owner = graph.principal_owner(extra.uid).unwrap().clone();
        assert_eq!(extra_owner.fleet_uid, owner.fleet_uid);
        let destination = FleetIdentity::from_genesis(FleetGenesis::from_parts(
            uuid::Uuid::from_u128(3),
            chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
            owner.assigned_by,
        ))
        .unwrap();
        store.create_fleet(destination.clone()).await.unwrap();
        store
            .transfer_principal(
                root.uid,
                owner.fleet_uid,
                destination.uid,
                owner.assigned_by,
            )
            .await
            .unwrap();

        bootstrap_cli_root_ownership(&store, &directory, root_user(), root.clone())
            .await
            .unwrap();
        let after = store.load().await.unwrap();
        assert_eq!(
            after.principal_owner(root.uid).unwrap().fleet_uid,
            destination.uid
        );
        assert_eq!(
            after.principal_owner(extra.uid).unwrap().fleet_uid,
            extra_owner.fleet_uid
        );
    }

    #[tokio::test]
    async fn extra_fleet_does_not_claim_unowned_packed_principals() {
        let backend: Arc<dyn astrid_storage::KvStore> = Arc::new(MemoryKvStore::new());
        let (directory, root, extra) = seeded_directory();
        let store = OwnershipStore::new(backend, directory.clone()).unwrap();
        store.create_user(operator_user()).await.unwrap();
        let operator = FleetIdentity::from_genesis(FleetGenesis::from_parts(
            uuid::Uuid::from_u128(1),
            chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            operator_user().uid,
        ))
        .unwrap();
        store.create_fleet(operator.clone()).await.unwrap();
        let other = FleetIdentity::from_genesis(FleetGenesis::from_parts(
            uuid::Uuid::from_u128(9),
            chrono::DateTime::from_timestamp(1_700_000_009, 0).unwrap(),
            operator.genesis.created_by,
        ))
        .unwrap();
        store.create_fleet(other).await.unwrap();

        bootstrap_cli_root_ownership(&store, &directory, root_user(), root.clone())
            .await
            .unwrap();
        let graph = store.load().await.unwrap();
        assert!(graph.principal_owner(root.uid).is_some());
        assert!(graph.principal_owner(extra.uid).is_none());
        let result = store
            .reconcile_bound_local_operator_unowned_principals(
                root.uid,
                &root.genesis.initial_public_key,
            )
            .await
            .unwrap();
        assert!(result.adopted().is_empty());
        assert_eq!(
            result.deferral(),
            Some(astrid_storage::UnownedPrincipalDeferral::AmbiguousAuthority)
        );
        assert!(
            store
                .load()
                .await
                .unwrap()
                .principal_owner(extra.uid)
                .is_none()
        );
    }

    #[tokio::test]
    async fn extra_user_after_upgrade_preserves_assignments() {
        let backend: Arc<dyn astrid_storage::KvStore> = Arc::new(MemoryKvStore::new());
        let (directory, root, extra) = seeded_directory();
        let store = OwnershipStore::new(backend, directory.clone()).unwrap();
        bootstrap_cli_root_ownership(&store, &directory, root_user(), root.clone())
            .await
            .unwrap();
        let owner = store
            .load()
            .await
            .unwrap()
            .principal_owner(root.uid)
            .unwrap()
            .clone();
        let other = UserIdentity::from_genesis(UserGenesis::from_parts(
            uuid::Uuid::from_u128(8),
            chrono::DateTime::from_timestamp(1_700_000_008, 0).unwrap(),
            [8; 32],
        ))
        .unwrap();
        store.create_user(other.clone()).await.unwrap();
        store
            .set_membership(
                owner.fleet_uid,
                other.uid,
                astrid_core::FleetRole::Member,
                owner.assigned_by,
            )
            .await
            .unwrap();
        // Packed extras were adopted before the second user existed. A later
        // extra user must not move or drop that assignment on reboot.
        assert_eq!(
            store
                .load()
                .await
                .unwrap()
                .principal_owner(extra.uid)
                .unwrap()
                .fleet_uid,
            owner.fleet_uid
        );
        bootstrap_cli_root_ownership(&store, &directory, root_user(), root.clone())
            .await
            .unwrap();
        let after = store.load().await.unwrap();
        assert_eq!(
            after.principal_owner(root.uid).unwrap().fleet_uid,
            owner.fleet_uid
        );
        assert_eq!(
            after.principal_owner(extra.uid).unwrap().fleet_uid,
            owner.fleet_uid
        );
        assert_eq!(after.users().count(), 2);
    }

    #[tokio::test]
    async fn second_user_present_before_upgrade_defers_unowned_principals() {
        let backend: Arc<dyn astrid_storage::KvStore> = Arc::new(MemoryKvStore::new());
        let (directory, root, extra) = seeded_directory();
        let store = OwnershipStore::new(backend, directory.clone()).unwrap();
        store.create_user(operator_user()).await.unwrap();
        let operator = FleetIdentity::from_genesis(FleetGenesis::from_parts(
            uuid::Uuid::from_u128(1),
            chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            operator_user().uid,
        ))
        .unwrap();
        store.create_fleet(operator.clone()).await.unwrap();
        let other = UserIdentity::from_genesis(UserGenesis::from_parts(
            uuid::Uuid::from_u128(8),
            chrono::DateTime::from_timestamp(1_700_000_008, 0).unwrap(),
            [8; 32],
        ))
        .unwrap();
        store.create_user(other.clone()).await.unwrap();
        store
            .set_membership(
                operator.uid,
                other.uid,
                astrid_core::FleetRole::Member,
                operator.genesis.created_by,
            )
            .await
            .unwrap();
        bootstrap_cli_root_ownership(&store, &directory, root_user(), root.clone())
            .await
            .unwrap();
        let graph = store.load().await.unwrap();
        assert!(graph.principal_owner(root.uid).is_some());
        assert!(graph.principal_owner(extra.uid).is_none());
        assert_eq!(graph.users().count(), 2);
    }
}
