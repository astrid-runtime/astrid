//! Mutation-fenced mount publication, revoke, and principal deletion drain.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use astrid_core::PrincipalId;
use astrid_core::storage_provider::{StorageMountId, StorageProviderViewV1};
use astrid_core::{FleetUid, PrincipalUid, WorkspaceUid};
use astrid_storage::{StateOwner, WorkspaceBranchStore};

use super::StorageMountLeaseState;
#[cfg(test)]
use super::cleanup::MountCleanupStage;
use super::cleanup::{MountCleanupError, cleanup_error, cleanup_resource_paths};
use crate::Kernel;

const PUBLICATION_CLOSED: &str = "cannot issue a storage mount lease for a retiring principal";

/// Alias plus the immutable UID captured before any admission await.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PrincipalBinding {
    alias: PrincipalId,
    uid: PrincipalUid,
}

impl PrincipalBinding {
    pub(super) fn capture(kernel: &Kernel, alias: &PrincipalId) -> Result<Self, String> {
        let uid = kernel.principal_directory.uid_for(alias).map_err(|error| {
            format!("principal `{alias}` has no immutable storage identity: {error}")
        })?;
        Ok(Self {
            alias: alias.clone(),
            uid,
        })
    }

    pub(super) const fn uid(&self) -> PrincipalUid {
        self.uid
    }

    pub(super) fn alias(&self) -> &PrincipalId {
        &self.alias
    }
}

/// Authorization facts resolved against the captured caller UID.
#[derive(Clone, Debug, Default)]
pub(super) struct PublicationProof {
    viewed: Option<PrincipalBinding>,
    fleet_membership: Option<FleetUid>,
    workspace: Option<WorkspaceUid>,
}

impl PublicationProof {
    pub(super) fn principal(viewed: PrincipalBinding) -> Self {
        Self {
            viewed: Some(viewed),
            fleet_membership: None,
            workspace: None,
        }
    }

    pub(super) fn fleet(membership: Option<FleetUid>) -> Self {
        Self {
            viewed: None,
            fleet_membership: membership,
            workspace: None,
        }
    }

    pub(super) fn admin() -> Self {
        Self::default()
    }

    pub(super) fn with_workspace(mut self, workspace: WorkspaceUid) -> Self {
        self.workspace = Some(workspace);
        self
    }
}

pub(super) async fn refuse_if_retiring(
    kernel: &Kernel,
    caller: &PrincipalId,
    view: &StorageProviderViewV1,
) -> Result<(), String> {
    if kernel.capabilities.is_principal_retiring(caller).await {
        return Err(PUBLICATION_CLOSED.to_owned());
    }
    if let StorageProviderViewV1::Principal(viewed) = view
        && kernel.capabilities.is_principal_retiring(viewed).await
    {
        return Err(PUBLICATION_CLOSED.to_owned());
    }
    Ok(())
}

/// Recheck captured caller/viewed/owner facts in the publication critical section.
pub(super) async fn revalidate_publication(
    kernel: &Kernel,
    caller: &PrincipalBinding,
    owner: StateOwner,
    proof: &PublicationProof,
) -> Result<(), String> {
    refuse_live_binding(kernel, caller).await?;
    if let Some(viewed) = &proof.viewed {
        refuse_live_binding(kernel, viewed).await?;
        if owner != StateOwner::Principal(viewed.uid) {
            return Err(PUBLICATION_CLOSED.to_owned());
        }
    }
    if let Some(fleet) = proof.fleet_membership {
        confirm_fleet_membership(kernel, caller.uid, fleet, owner).await?;
    }
    if let Some(workspace) = proof.workspace {
        confirm_workspace_binding(kernel, caller.uid, owner, workspace)?;
    }
    Ok(())
}

async fn refuse_live_binding(kernel: &Kernel, binding: &PrincipalBinding) -> Result<(), String> {
    if kernel
        .capabilities
        .is_principal_retiring(&binding.alias)
        .await
        || !binding_still_matches(kernel, &binding.alias, binding.uid)
    {
        return Err(PUBLICATION_CLOSED.to_owned());
    }
    Ok(())
}

async fn confirm_fleet_membership(
    kernel: &Kernel,
    caller_uid: PrincipalUid,
    fleet: FleetUid,
    owner: StateOwner,
) -> Result<(), String> {
    let ownership = kernel
        .ownership_store()
        .load()
        .await
        .map_err(|error| format!("read fleet ownership graph: {error}"))?;
    let admitted = ownership
        .principal_owner(caller_uid)
        .is_some_and(|owned| owned.fleet_uid == fleet);
    if !admitted || owner != StateOwner::Fleet(fleet) {
        return Err(PUBLICATION_CLOSED.to_owned());
    }
    Ok(())
}

fn confirm_workspace_binding(
    kernel: &Kernel,
    caller_uid: PrincipalUid,
    owner: StateOwner,
    workspace: WorkspaceUid,
) -> Result<(), String> {
    let store = kernel
        .principal_store
        .clone()
        .ok_or_else(|| "native principal store is unavailable".to_owned())?;
    let descriptor = WorkspaceBranchStore::new(store.content())
        .describe(&owner, workspace)
        .map_err(|error| format!("resolve workspace branch: {error}"))?;
    if descriptor.binding_uid() != Some(caller_uid) {
        return Err(PUBLICATION_CLOSED.to_owned());
    }
    Ok(())
}

fn binding_still_matches(kernel: &Kernel, principal: &PrincipalId, expected: PrincipalUid) -> bool {
    kernel
        .principal_directory
        .uid_for(principal)
        .is_ok_and(|uid| uid == expected)
}

pub(super) fn cleanup_unpublished(
    resource_path: &Path,
    callback_path: &Path,
) -> Result<(), String> {
    cleanup_resource_paths(resource_path, callback_path, None)
        .map_err(|(stage, source)| cleanup_error(None, stage, source).to_string())
}

pub(super) fn cleanup_mapped_lease(
    kernel: &Kernel,
    state: &StorageMountLeaseState,
) -> Result<(), MountCleanupError> {
    let fault = {
        #[cfg(test)]
        {
            injected_cleanup_fault(state)
        }
        #[cfg(not(test))]
        {
            None
        }
    };
    cleanup_resource_paths(&state.resource_path, &state.callback_path, fault)
        .map_err(|(stage, source)| cleanup_error(Some(state.mount_id), stage, source))?;
    kernel.storage_mounts.remove(&state.mount_id);
    Ok(())
}

/// Revoke one mapped lease, including a revoked entry left after failed cleanup.
pub(crate) async fn revoke_lease(
    kernel: &Kernel,
    caller: &PrincipalId,
    allow_cross_owner: bool,
    mount_id: StorageMountId,
) -> Result<(), String> {
    let state = mapped_owned_lease(kernel, caller, allow_cross_owner, mount_id)?;
    force_revoke_lease(kernel, &state).await
}

/// Revoke every live or stale mount that can still name `principal`.
///
/// Matches leases requested by the principal, leases whose admitted view is
/// that principal, and leases whose typed owner is the principal's immutable
/// UID. Expired map entries are included so a stale callback cannot outlive
/// identity deletion. Cleanup failures keep a revoked map entry so retry can
/// find it. Fail closed if any matching unrevoked lease remains afterwards.
pub(crate) async fn revoke_all_leases_for_principal(
    kernel: &Kernel,
    principal: &PrincipalId,
) -> Result<(), String> {
    let uid = kernel.principal_directory.uid_for(principal).ok();
    revoke_visible(&mapped_leases_for_principal(kernel, principal, uid));
    let _mutation_guard = kernel.storage_mount_mutations.lock().await;
    let matched = mapped_leases_for_principal(kernel, principal, uid);
    revoke_visible(&matched);
    let mut errors = Vec::new();
    for state in &matched {
        if let Err(error) = cleanup_mapped_lease(kernel, state) {
            errors.push(error.to_string());
        }
    }
    if mapped_leases_for_principal(kernel, principal, uid)
        .iter()
        .any(|state| !state.revoked.load(Ordering::Acquire))
    {
        return Err("storage mount lease survived principal deletion drain".to_owned());
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

async fn force_revoke_lease(kernel: &Kernel, state: &StorageMountLeaseState) -> Result<(), String> {
    state.revoked.store(true, Ordering::Release);
    let _ = state.shutdown_tx.send(true);
    let _mutation_guard = kernel.storage_mount_mutations.lock().await;
    cleanup_mapped_lease(kernel, state).map_err(|error| error.to_string())
}

pub(super) async fn expire_idle_mapped_lease(kernel: &Kernel, state: &StorageMountLeaseState) {
    state.revoked.store(true, Ordering::Release);
    let _mutation_guard = kernel.storage_mount_mutations.lock().await;
    if let Err(error) = cleanup_mapped_lease(kernel, state) {
        tracing::warn!(
            mount_id = %state.mount_id,
            %error,
            "idle storage mount cleanup failed; revoked lease remains mapped"
        );
    }
}

fn lease_covers_principal(
    state: &StorageMountLeaseState,
    principal: &PrincipalId,
    uid: Option<astrid_storage::PrincipalUid>,
) -> bool {
    if &state.requested_by == principal {
        return true;
    }
    if let StorageProviderViewV1::Principal(viewed) = &state.view
        && viewed == principal
    {
        return true;
    }
    uid.is_some_and(|uid| matches!(state.owner, StateOwner::Principal(owner) if owner == uid))
}

fn mapped_leases_for_principal(
    kernel: &Kernel,
    principal: &PrincipalId,
    uid: Option<astrid_storage::PrincipalUid>,
) -> Vec<Arc<StorageMountLeaseState>> {
    kernel
        .storage_mounts
        .iter()
        .filter(|entry| lease_covers_principal(entry.value(), principal, uid))
        .map(|entry| Arc::clone(entry.value()))
        .collect()
}

fn revoke_visible(states: &[Arc<StorageMountLeaseState>]) {
    for state in states {
        state.revoked.store(true, Ordering::Release);
        let _ = state.shutdown_tx.send(true);
    }
}

pub(super) fn owned_lease(
    kernel: &Kernel,
    caller: &PrincipalId,
    allow_cross_owner: bool,
    mount_id: StorageMountId,
) -> Result<Arc<StorageMountLeaseState>, String> {
    let state = mapped_owned_lease(kernel, caller, allow_cross_owner, mount_id)?;
    if !state.is_live() {
        return Err("storage mount lease is expired or revoked".to_owned());
    }
    Ok(state)
}

fn mapped_owned_lease(
    kernel: &Kernel,
    caller: &PrincipalId,
    allow_cross_owner: bool,
    mount_id: StorageMountId,
) -> Result<Arc<StorageMountLeaseState>, String> {
    let state = kernel
        .storage_mounts
        .get(&mount_id)
        .map(|entry| Arc::clone(entry.value()))
        .ok_or_else(|| format!("storage mount lease {mount_id} was not found"))?;
    if !state.is_owned_by(caller) && !allow_cross_owner {
        return Err("storage mount lease belongs to another principal".to_owned());
    }
    Ok(state)
}

#[cfg(test)]
pub(crate) fn expire_lease_for_test(state: &StorageMountLeaseState) {
    state.expires_at_epoch_secs.store(0, Ordering::Release);
}

#[cfg(test)]
fn injected_cleanup_fault(state: &StorageMountLeaseState) -> Option<MountCleanupStage> {
    *state
        .cleanup_fault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
pub(crate) fn inject_cleanup_fault_for_test(
    lease: &StorageMountLeaseState,
    fault: MountCleanupStage,
) {
    *lease
        .cleanup_fault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(fault);
}

#[cfg(test)]
pub(crate) fn clear_cleanup_fault_for_test(state: &StorageMountLeaseState) {
    *state
        .cleanup_fault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
}
