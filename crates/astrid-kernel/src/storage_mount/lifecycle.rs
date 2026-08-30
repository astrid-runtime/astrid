//! Mutation-fenced mount publication, revoke, and principal deletion drain.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use astrid_capabilities::CapabilityCheck;
use astrid_core::PrincipalId;
use astrid_core::profile::DeviceScope;
use astrid_core::storage_filesystem::StorageFilesystemTargetV1;
use astrid_core::storage_provider::{
    StorageMountId, StorageProviderAccessV1, StorageProviderViewV1,
};
use astrid_core::{FleetUid, PrincipalUid, WorkspaceUid};
use astrid_storage::{AstridFilesystem, StateOwner, WorkspaceBranchStore};
use serde_json::json;

use super::StorageMountLeaseState;
use super::cleanup::MountCleanupStage;
use super::cleanup::{MountCleanupError, cleanup_error, cleanup_resource_paths};
use super::filesystem::{CallbackFilesystem, PrefixedFilesystem};
#[cfg(any(unix, windows))]
use super::{BlockingJobDrain, ListenerDrainOutcome};
use crate::Kernel;

const PUBLICATION_CLOSED: &str = "cannot issue a storage mount lease for a retiring principal";

/// Alias plus the immutable UID captured at the policy decision point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PrincipalBinding {
    alias: PrincipalId,
    uid: PrincipalUid,
}

impl PrincipalBinding {
    pub(crate) fn bound(alias: PrincipalId, uid: PrincipalUid) -> Self {
        Self { alias, uid }
    }

    pub(crate) fn capture(kernel: &Kernel, alias: &PrincipalId) -> Result<Self, String> {
        let uid = kernel.principal_directory.uid_for(alias).map_err(|error| {
            format!("principal `{alias}` has no immutable storage identity: {error}")
        })?;
        Ok(Self::bound(alias.clone(), uid))
    }

    pub(crate) const fn uid(&self) -> PrincipalUid {
        self.uid
    }

    pub(crate) fn alias(&self) -> &PrincipalId {
        &self.alias
    }
}

/// Cross-owner mount scope granted to one authenticated identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MountOwnerScope {
    CallerOnly,
    CrossOwnerRead,
    CrossOwnerWrite,
}

impl MountOwnerScope {
    pub(crate) const fn allows_foreign_read(self) -> bool {
        matches!(self, Self::CrossOwnerRead | Self::CrossOwnerWrite)
    }

    pub(crate) const fn allows_foreign_write(self) -> bool {
        matches!(self, Self::CrossOwnerWrite)
    }

    pub(crate) const fn allows_foreign_issue(self, access: StorageProviderAccessV1) -> bool {
        match access {
            StorageProviderAccessV1::ReadOnly => self.allows_foreign_read(),
            StorageProviderAccessV1::ReadWrite => self.allows_foreign_write(),
        }
    }

    const fn covers(self, required: Self) -> bool {
        match required {
            Self::CallerOnly => true,
            Self::CrossOwnerRead => self.allows_foreign_read(),
            Self::CrossOwnerWrite => self.allows_foreign_write(),
        }
    }
}

/// UID-bound mount grant decided at authorization, not inside `issue_lease`.
#[derive(Clone, Debug)]
pub(crate) struct MountAdmission {
    caller: PrincipalBinding,
    owner_scope: MountOwnerScope,
    required_cap: Option<&'static str>,
    device_scope: Option<DeviceScope>,
}

impl MountAdmission {
    pub(crate) fn bound(
        caller: PrincipalBinding,
        owner_scope: MountOwnerScope,
        required_cap: Option<&'static str>,
        device_scope: Option<DeviceScope>,
    ) -> Self {
        Self {
            caller,
            owner_scope,
            required_cap,
            device_scope,
        }
    }

    pub(crate) fn capture(
        kernel: &Kernel,
        caller: &PrincipalId,
        owner_scope: MountOwnerScope,
    ) -> Result<Self, String> {
        Ok(Self::bound(
            PrincipalBinding::capture(kernel, caller)?,
            owner_scope,
            None,
            None,
        ))
    }

    pub(crate) fn caller(&self) -> &PrincipalBinding {
        &self.caller
    }

    pub(crate) fn alias(&self) -> &PrincipalId {
        self.caller.alias()
    }

    pub(crate) const fn owner_scope(&self) -> MountOwnerScope {
        self.owner_scope
    }
}

/// UID-bound mount grant consumed by Issue/Status/Sync/Revoke handlers.
pub(crate) type MountGrant = MountAdmission;

/// Reconstruct the cross-owner grant implied by a capability check.
pub(crate) fn mount_owner_scope_from_check(check: &CapabilityCheck<'_>) -> MountOwnerScope {
    if check.has("storage:mount")
        || check.has("storage:mount:write")
        || check.has("storage:mount:system:write")
    {
        MountOwnerScope::CrossOwnerWrite
    } else if check.has("storage:mount:read") || check.has("storage:mount:system:read") {
        MountOwnerScope::CrossOwnerRead
    } else {
        MountOwnerScope::CallerOnly
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
    admission: &MountAdmission,
    owner: StateOwner,
    proof: &PublicationProof,
) -> Result<(), String> {
    refuse_live_binding(kernel, admission.caller()).await?;
    confirm_mount_grant(kernel, admission)?;
    if let Some(viewed) = &proof.viewed {
        refuse_live_binding(kernel, viewed).await?;
        if owner != StateOwner::Principal(viewed.uid) {
            return Err(PUBLICATION_CLOSED.to_owned());
        }
    }
    if let Some(fleet) = proof.fleet_membership {
        confirm_fleet_membership(kernel, admission.caller().uid(), fleet, owner).await?;
    }
    if let Some(workspace) = proof.workspace {
        confirm_workspace_binding(kernel, admission.caller().uid(), owner, workspace)?;
    }
    Ok(())
}

fn confirm_mount_grant(kernel: &Kernel, admission: &MountAdmission) -> Result<(), String> {
    let Some(required_cap) = admission.required_cap else {
        return Ok(());
    };
    let profile = kernel
        .profile_cache
        .resolve(admission.alias())
        .map_err(|error| format!("revalidate mount authorization: {error}"))?;
    if !profile.enabled {
        return Err(PUBLICATION_CLOSED.to_owned());
    }
    let groups = kernel.groups.load_full();
    let mut check =
        CapabilityCheck::new_borrowed(profile.as_ref(), groups.as_ref(), admission.alias());
    if let Some(scope) = &admission.device_scope {
        check = check.with_device_scope(scope);
    }
    if check.require(required_cap).is_err()
        || !mount_owner_scope_from_check(&check).covers(admission.owner_scope)
    {
        return Err(PUBLICATION_CLOSED.to_owned());
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

pub(crate) fn cleanup_mapped_lease(
    kernel: &Kernel,
    state: &StorageMountLeaseState,
) -> Result<(), MountCleanupError> {
    cleanup_mapped_lease_resources(state)?;
    complete_cleanup_ledger(state)
        .map_err(|(stage, source)| cleanup_error(Some(state.mount_id), stage, source))?;
    kernel.storage_mounts.remove(&state.mount_id);
    Ok(())
}

/// Remove one mapped lease's host resources without changing authority.
///
/// Issue-set rollback uses this two-phase form so one failed resource cannot
/// strand the other members as unmapped authority.
pub(crate) fn cleanup_mapped_lease_resources(
    state: &StorageMountLeaseState,
) -> Result<(), MountCleanupError> {
    if cleanup_ledger_is_clean(state) {
        return Ok(());
    }
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
    record_cleanup_ledger(state)
        .map_err(|(stage, source)| cleanup_error(Some(state.mount_id), stage, source))?;
    Ok(())
}

fn cleanup_ledger_is_clean(state: &StorageMountLeaseState) -> bool {
    let expected = state.mount_id.to_string();
    state.cleanup_ledger_path.is_file()
        && std::fs::read(&state.cleanup_ledger_path).is_ok_and(|bytes| bytes == expected.as_bytes())
}

fn record_cleanup_ledger(
    state: &StorageMountLeaseState,
) -> Result<(), (MountCleanupStage, std::io::Error)> {
    let parent = state.cleanup_ledger_path.parent().ok_or_else(|| {
        (
            MountCleanupStage::Manifest,
            std::io::Error::other("cleanup ledger has no parent"),
        )
    })?;
    astrid_core::platform_fs::ensure_private_directory(parent).map_err(|error| {
        (
            MountCleanupStage::Manifest,
            std::io::Error::other(format!("create cleanup ledger directory: {error}")),
        )
    })?;
    astrid_core::platform_fs::atomic_write_private_file(
        &state.cleanup_ledger_path,
        state.mount_id.to_string().as_bytes(),
    )
    .map_err(|error| {
        (
            MountCleanupStage::Manifest,
            std::io::Error::other(format!("write cleanup ledger: {error}")),
        )
    })
}

pub(crate) fn complete_cleanup_ledger(
    state: &StorageMountLeaseState,
) -> Result<(), (MountCleanupStage, std::io::Error)> {
    match std::fs::remove_file(&state.cleanup_ledger_path) {
        Ok(()) => {},
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => {
            return Err((
                MountCleanupStage::Manifest,
                std::io::Error::other(format!("remove cleanup ledger: {error}")),
            ));
        },
    }
    if let Some(parent) = state.cleanup_ledger_path.parent() {
        #[cfg(windows)]
        {
            let _ = std::fs::remove_file(parent.join(".astrid-private-write.lock"));
        }
        let _ = std::fs::remove_dir(parent);
    }
    Ok(())
}

/// Revoke one mapped lease, including a revoked entry left after failed cleanup.
#[cfg(test)]
pub(crate) async fn revoke_lease(
    kernel: &Kernel,
    caller: &PrincipalId,
    owner_scope: MountOwnerScope,
    mount_id: StorageMountId,
) -> Result<(), String> {
    revoke_from_grant(
        kernel,
        &MountGrant::capture(kernel, caller, owner_scope)?,
        mount_id,
    )
    .await
}

/// Force-revoke one projection lease by its immutable requester UID.
///
/// Projection drain may run after capability retirement, where reconstructing
/// a normal alias grant would fail. The caller must still own the exact UID
/// bound when the lease was issued.
#[cfg(test)]
pub(crate) async fn force_revoke_projection_lease(
    kernel: &Kernel,
    requester_uid: PrincipalUid,
    expected_owner: StateOwner,
    expected_target: &StorageFilesystemTargetV1,
    mount_id: StorageMountId,
) -> bool {
    let state = match mapped_owned_lease(kernel, requester_uid, false, mount_id) {
        Ok(state) => state,
        Err(_) if kernel.storage_mounts.get(&mount_id).is_none() => return true,
        Err(_) => return false,
    };
    if state.owner != expected_owner
        || state.target != *expected_target
        || state.access != StorageProviderAccessV1::ReadWrite
    {
        return false;
    }
    state.revoked.store(true, Ordering::Release);
    let _ = state.shutdown_tx.send(true);
    if !state.wait_listener_closed().await {
        return false;
    }
    let _mutation_guard = kernel.storage_mount_mutations.lock().await;
    cleanup_mapped_lease(kernel, &state).is_ok()
}

/// Revoke one projection lease without releasing its provider resources.
///
/// A retained provider teardown must make the lease unusable immediately, but
/// cannot prove that the provider endpoint and mount root are gone. Keeping
/// the revoked map entry lets the bounded retry use the exact provider and
/// lease again; the mutation fence drains already admitted writers.
pub(crate) async fn force_fence_projection_lease(
    kernel: &Kernel,
    requester_uid: PrincipalUid,
    expected_owner: StateOwner,
    expected_target: &StorageFilesystemTargetV1,
    mount_id: StorageMountId,
) -> bool {
    let Ok(state) = mapped_owned_lease(kernel, requester_uid, false, mount_id) else {
        return kernel.storage_mounts.get(&mount_id).is_none();
    };
    if state.owner != expected_owner
        || state.target != *expected_target
        || state.access != StorageProviderAccessV1::ReadWrite
    {
        return false;
    }
    state.revoked.store(true, Ordering::Release);
    // This is fence-only: retained teardown deliberately leaves the callback
    // listener and its platform endpoint in place. Actual cleanup and force
    // revoke own listener shutdown.
    let _mutation_guard = kernel.storage_mount_mutations.lock().await;
    true
}

/// Revoke using a UID-bound grant. Alias equality is never ownership.
pub(crate) async fn revoke_from_grant(
    kernel: &Kernel,
    grant: &MountGrant,
    mount_id: StorageMountId,
) -> Result<(), String> {
    revalidate_live_grant(kernel, grant).await?;
    let state = mapped_owned_lease(
        kernel,
        grant.caller().uid(),
        grant.owner_scope().allows_foreign_write(),
        mount_id,
    )?;
    force_revoke_lease(kernel, &state).await
}

async fn force_revoke_lease(kernel: &Kernel, state: &StorageMountLeaseState) -> Result<(), String> {
    state.revoked.store(true, Ordering::Release);
    let _ = state.shutdown_tx.send(true);
    await_retained_drain(state, true).await?;
    let _mutation_guard = kernel.storage_mount_mutations.lock().await;
    cleanup_mapped_lease(kernel, state).map_err(|error| error.to_string())
}

/// Wait outside the mutation fence for the listener's typed retained-work outcome.
async fn await_retained_drain(
    state: &StorageMountLeaseState,
    _caller_requested_latch: bool,
) -> Result<(), String> {
    let include_latched_failure = state.begin_drain_attempt();
    let outcome = state.wait_drain_outcome(include_latched_failure).await;
    match outcome {
        ListenerDrainOutcome::Failed(BlockingJobDrain::JoinFailed) => Err(cleanup_error(
            Some(state.mount_id),
            MountCleanupStage::Drain,
            std::io::Error::other("retained filesystem worker join failed"),
        )
        .to_string()),
        ListenerDrainOutcome::Failed(BlockingJobDrain::TimedOut)
        | ListenerDrainOutcome::TimedOut => Err(drain_timeout_error(state).to_string()),
        ListenerDrainOutcome::Failed(BlockingJobDrain::Completed)
        | ListenerDrainOutcome::Closed => Ok(()),
    }
}

fn drain_timeout_error(state: &StorageMountLeaseState) -> MountCleanupError {
    cleanup_error(
        Some(state.mount_id),
        MountCleanupStage::Drain,
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "retained filesystem jobs did not finish within {:?}",
                state.drain_timeouts().accepted_task
            ),
        ),
    )
}

pub(super) async fn revalidate_live_grant(
    kernel: &Kernel,
    grant: &MountGrant,
) -> Result<(), String> {
    refuse_live_binding(kernel, grant.caller()).await?;
    confirm_mount_grant(kernel, grant)
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
    let matched = mapped_leases_for_principal(kernel, principal, uid);
    revoke_visible(&matched);
    for state in &matched {
        await_retained_drain(state, true).await?;
    }
    let _mutation_guard = kernel.storage_mount_mutations.lock().await;
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
    if uid.is_some_and(|uid| state.requested_by_uid == uid) {
        return true;
    }
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
    requester_uid: PrincipalUid,
    allow_foreign: bool,
    mount_id: StorageMountId,
) -> Result<Arc<StorageMountLeaseState>, String> {
    let state = mapped_owned_lease(kernel, requester_uid, allow_foreign, mount_id)?;
    if !state.is_live() {
        return Err("storage mount lease is expired or revoked".to_owned());
    }
    Ok(state)
}

fn mapped_owned_lease(
    kernel: &Kernel,
    requester_uid: PrincipalUid,
    allow_foreign: bool,
    mount_id: StorageMountId,
) -> Result<Arc<StorageMountLeaseState>, String> {
    let state = kernel
        .storage_mounts
        .get(&mount_id)
        .map(|entry| Arc::clone(entry.value()))
        .ok_or_else(|| format!("storage mount lease {mount_id} was not found"))?;
    if !state.is_owned_by(requester_uid) && !allow_foreign {
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

#[cfg(test)]
pub(crate) async fn lease_status(
    kernel: &Kernel,
    caller: &PrincipalId,
    owner_scope: MountOwnerScope,
    mount_id: StorageMountId,
) -> Result<serde_json::Value, String> {
    lease_status_from_grant(
        kernel,
        &MountGrant::capture(kernel, caller, owner_scope)?,
        mount_id,
    )
    .await
}

pub(crate) async fn lease_status_from_grant(
    kernel: &Kernel,
    grant: &MountGrant,
    mount_id: StorageMountId,
) -> Result<serde_json::Value, String> {
    revalidate_live_grant(kernel, grant).await?;
    let state = owned_lease(
        kernel,
        grant.caller().uid(),
        grant.owner_scope().allows_foreign_read(),
        mount_id,
    )?;
    if state.try_admit().is_none() {
        return Err("storage mount lease is expired or revoked".to_owned());
    }
    Ok(json!({
        "mount_id": state.mount_id,
        "view": state.view,
        "target": state.target,
        "access": state.access,
        "provider": state.provider,
        "mountpoint": state.mountpoint,
        "resource_path": state.resource_path,
        "callback_path": state.callback_path,
        "dirty": state.dirty.load(Ordering::Acquire),
        "in_flight_mutations": state.in_flight_mutations.load(Ordering::Acquire),
        "expires_at_epoch_secs": state.expires_at_epoch_secs.load(Ordering::Acquire),
    }))
}

#[cfg(test)]
pub(crate) async fn sync_lease(
    kernel: &Kernel,
    caller: &PrincipalId,
    owner_scope: MountOwnerScope,
    mount_id: StorageMountId,
) -> Result<(), String> {
    sync_lease_from_grant(
        kernel,
        &MountGrant::capture(kernel, caller, owner_scope)?,
        mount_id,
    )
    .await
}

pub(crate) async fn sync_lease_from_grant(
    kernel: &Kernel,
    grant: &MountGrant,
    mount_id: StorageMountId,
) -> Result<(), String> {
    revalidate_live_grant(kernel, grant).await?;
    let state = owned_lease(
        kernel,
        grant.caller().uid(),
        grant.owner_scope().allows_foreign_write(),
        mount_id,
    )?;
    let _mutation_guard = kernel.storage_mount_mutations.lock().await;
    if !state.is_live() {
        return Err("storage mount lease is expired or revoked".to_owned());
    }
    let store = kernel
        .principal_store
        .clone()
        .ok_or_else(|| "native principal store is unavailable".to_owned())?;
    let owner = state.owner;
    let target = state.target.clone();
    tokio::task::spawn_blocking(move || match target {
        StorageFilesystemTargetV1::OwnerRoot => AstridFilesystem::new(store.content(), owner)
            .sync()
            .map_err(|error| error.to_string()),
        StorageFilesystemTargetV1::WorkspaceBranch { workspace } => {
            WorkspaceBranchStore::new(store.content())
                .filesystem(owner, workspace)
                .sync()
                .map_err(|error| error.to_string())
        },
        StorageFilesystemTargetV1::OwnerSubtree { prefix } => {
            if prefix == "shared" {
                AstridFilesystem::new_fleet_shared(store.content(), owner)
                    .sync()
                    .map_err(|error| error.to_string())
            } else {
                let filesystem = PrefixedFilesystem {
                    inner: AstridFilesystem::new(store.content(), owner),
                    prefix,
                };
                filesystem.sync().map_err(|error| error.to_string())
            }
        },
    })
    .await
    .map_err(|error| format!("mount sync worker failed: {error}"))??;
    state.dirty.store(false, Ordering::Release);
    state.renew();
    Ok(())
}
