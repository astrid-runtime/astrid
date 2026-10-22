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
    let unresolved = store
        .reconcile_local_accountable_users(
            principal_uid,
            &root_principal_identity.genesis.initial_public_key,
        )
        .await?;
    if !unresolved.is_empty() {
        tracing::warn!(principals = ?unresolved,
            "legacy resource accountability needs explicit operator assignment; existing ownership preserved");
    }
    Ok(())
}

#[cfg(test)]
mod replay_tests;
#[cfg(test)]
mod tests;
