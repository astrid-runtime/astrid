//! Atomic projection retention, rollback, and resource cleanup.

use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use super::{
    CachedProcessProjection, Kernel, ProcessProjectionBinding, ProcessProjectionKey,
    ProcessProjectionTarget, ProcessProjectionTargetSet, ProjectionCleanup, StorageMountId,
    StorageProviderAccessV1, force_revoke_projection_lease, generate_lease_token, local_transport,
    platform_process_provider_name, stop_process_provider,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParentTokenSlot {
    Branch = 1,
    OwnerHome = 2,
    FleetShared = 3,
}

pub(crate) struct RunningProvider {
    // A failed launch can leave an unmanaged provider after its Child handle
    // has been consumed by the launch error path. Retaining the authenticated
    // control identity lets a blocked retry confirm that it is really gone.
    pub(super) child: Option<tokio::process::Child>,
    pub(super) control_path: PathBuf,
    pub(super) token: String,
    pub(super) stopped: bool,
}

pub(crate) struct ProjectionCleanupState {
    pub(super) kernel: std::sync::Weak<Kernel>,
    pub(super) binding: ProcessProjectionBinding,
    pub(super) branch: ProjectionLeaseProvider,
    pub(super) owner: ProjectionLeaseProvider,
    pub(super) shared: Option<ProjectionLeaseProvider>,
    pub(super) mount_root: PathBuf,
    pub(super) cleaned: bool,
}

pub(crate) struct ProjectionLeaseProvider {
    pub(super) running: RunningProvider,
    pub(super) lease: ProjectionLeaseTarget,
}

pub(crate) struct ProjectionLeaseTarget {
    pub(crate) mount_id: StorageMountId,
    pub(crate) target: ProcessProjectionTarget,
}

pub(crate) async fn cleanup_projection_state(
    cleanup_state: Arc<tokio::sync::Mutex<ProjectionCleanupState>>,
) -> bool {
    let mut state = cleanup_state.lock().await;
    cleanup_projection(&mut state).await
}

pub(crate) async fn rollback_or_retain_failed_launch(
    projections: &mut std::collections::BTreeMap<
        ProcessProjectionKey,
        Arc<CachedProcessProjection>,
    >,
    key: &ProcessProjectionKey,
    workspace_mountpoint: PathBuf,
    home_mountpoint: PathBuf,
    fleet_shared_mountpoint: Option<PathBuf>,
    cleanup_state: ProjectionCleanupState,
) {
    let mut cleanup_state = cleanup_state;
    if cleanup_projection(&mut cleanup_state).await {
        return;
    }

    tracing::error!(
        branch_stopped = cleanup_state.branch.running.stopped,
        owner_stopped = cleanup_state.owner.running.stopped,
        shared_stopped = cleanup_state
            .shared
            .as_ref()
            .is_some_and(|shared| shared.running.stopped),
        "native process provider launch rollback failed; retaining unreclaimed resources"
    );
    retain_failed_launch_projection(
        projections,
        key,
        workspace_mountpoint,
        home_mountpoint,
        fleet_shared_mountpoint,
        cleanup_state,
    );
}

async fn cleanup_projection(state: &mut ProjectionCleanupState) -> bool {
    if state.cleaned {
        return true;
    }

    // Provider teardown is an authenticated async protocol: STOP, wait for
    // the service's unmount acknowledgement, then reap the child. A kill is
    // only the emergency fallback when a provider is wedged or gone; keeping
    // the provider handles in the state makes a later mount request retry the
    // same bounded operation instead of creating a second projection.
    if state.binding.validate().is_err() {
        tracing::error!("process storage projection binding became invalid");
        return false;
    }
    let branch_stopped = stop_running_provider(&mut state.branch.running).await;
    let owner_stopped = stop_running_provider(&mut state.owner.running).await;
    let shared_stopped = match state.shared.as_mut() {
        Some(shared) => stop_running_provider(&mut shared.running).await,
        None => true,
    };
    if !branch_stopped || !owner_stopped || !shared_stopped {
        tracing::error!(
            branch_stopped,
            owner_stopped,
            shared_stopped,
            "native process storage provider teardown failed; retaining private mount resources"
        );
        return false;
    }
    let Some(kernel) = state.kernel.upgrade() else {
        tracing::error!("kernel shut down before process storage projection leases were revoked");
        return false;
    };
    if !revoke_projection_leases(
        &kernel,
        &state.binding,
        &state.branch.lease,
        &state.owner.lease,
        state.shared.as_ref().map(|shared| &shared.lease),
    )
    .await
    {
        tracing::error!("failed to revoke process storage projection leases; retaining resources");
        return false;
    }
    if let Err(error) = std::fs::remove_dir_all(&state.mount_root) {
        tracing::error!(%error, "failed to remove process storage projection root");
        return false;
    }
    state.cleaned = true;
    true
}

async fn stop_running_provider(provider: &mut RunningProvider) -> bool {
    if provider.stopped {
        return true;
    }
    let stopped = if let Some(child) = provider.child.as_mut() {
        stop_process_provider(child, provider.control_path.clone(), provider.token.clone()).await
    } else {
        unmanaged_provider_is_stopped(&provider.control_path).await
    };
    if stopped {
        provider.stopped = true;
    }
    stopped
}

async fn unmanaged_provider_is_stopped(control_path: &Path) -> bool {
    match local_transport::connect_outcome(control_path).await {
        Ok(local_transport::ConnectOutcome::Absent | local_transport::ConnectOutcome::Stale) => {
            true
        },
        Ok(local_transport::ConnectOutcome::Connected(_)) | Err(_) => false,
    }
}

pub(crate) fn retain_failed_launch_projection(
    projections: &mut std::collections::BTreeMap<
        ProcessProjectionKey,
        Arc<CachedProcessProjection>,
    >,
    key: &ProcessProjectionKey,
    workspace_mountpoint: PathBuf,
    home_mountpoint: PathBuf,
    fleet_shared_mountpoint: Option<PathBuf>,
    cleanup_state: ProjectionCleanupState,
) {
    let cleanup_state = Arc::new(tokio::sync::Mutex::new(cleanup_state));
    let cleanup_state_for_projection = Arc::clone(&cleanup_state);
    let cleanup: ProjectionCleanup = Arc::new(move || {
        let cleanup_state = Arc::clone(&cleanup_state_for_projection);
        Box::pin(async move { cleanup_projection_state(cleanup_state).await })
    });
    projections.insert(
        key.clone(),
        Arc::new(CachedProcessProjection {
            binding: key.binding.clone(),
            workspace_mountpoint,
            home_mountpoint,
            fleet_shared_mountpoint,
            refs: AtomicU64::new(0),
            closing: AtomicBool::new(false),
            cleanup_failed: AtomicBool::new(true),
            cleanup,
        }),
    );
}

pub(crate) async fn rollback_uncommitted_lease(
    kernel: &Kernel,
    binding: &ProcessProjectionBinding,
    target: &ProcessProjectionTarget,
    mount_id: StorageMountId,
) {
    let expected_owner = target.durable_owner();
    let expected_target = target.durable_target();
    let _ = force_revoke_projection_lease(
        kernel,
        binding.acting_uid,
        expected_owner,
        &expected_target,
        mount_id,
    )
    .await;
}

pub(crate) fn blocked_projection_lease(
    kernel: &Kernel,
    binding: &ProcessProjectionBinding,
) -> Option<String> {
    let targets = [
        Some(&binding.targets.workspace),
        Some(&binding.targets.owner_home),
        binding.targets.fleet_shared.as_ref(),
    ];
    for entry in kernel.storage_mounts.iter() {
        let state = entry.value();
        let target_matches = targets.iter().flatten().any(|target| {
            target.durable_owner() == state.owner && target.durable_target() == state.target
        });
        if state.requested_by_uid == binding.acting_uid
            && state.access == StorageProviderAccessV1::ReadWrite
            && state.provider == platform_process_provider_name()
            && target_matches
        {
            return Some(format!(
                "existing process projection lease {} requires cleanup",
                state.mount_id
            ));
        }
    }
    None
}

pub(crate) async fn revoke_projection_leases(
    kernel: &Kernel,
    binding: &ProcessProjectionBinding,
    branch: &ProjectionLeaseTarget,
    owner: &ProjectionLeaseTarget,
    shared: Option<&ProjectionLeaseTarget>,
) -> bool {
    let branch = revoke_mapped_projection_lease(kernel, binding, branch).await;
    let owner = revoke_mapped_projection_lease(kernel, binding, owner).await;
    let shared = match shared {
        Some(shared) => revoke_mapped_projection_lease(kernel, binding, shared).await,
        None => true,
    };
    branch && owner && shared
}

async fn revoke_mapped_projection_lease(
    kernel: &Kernel,
    binding: &ProcessProjectionBinding,
    lease: &ProjectionLeaseTarget,
) -> bool {
    let expected_owner = lease.target.durable_owner();
    let expected_target = lease.target.durable_target();
    force_revoke_projection_lease(
        kernel,
        binding.acting_uid,
        expected_owner,
        &expected_target,
        lease.mount_id,
    )
    .await
}

pub(crate) async fn retry_failed_projection(
    projection: &Arc<CachedProcessProjection>,
    projections: &mut std::collections::BTreeMap<
        ProcessProjectionKey,
        Arc<CachedProcessProjection>,
    >,
    key: &ProcessProjectionKey,
) -> bool {
    if !(projection.cleanup)().await {
        return false;
    }
    projection.cleanup_failed.store(false, Ordering::Release);
    if projections
        .get(key)
        .is_some_and(|current| Arc::ptr_eq(current, projection))
    {
        projections.remove(key);
    }
    true
}

pub(crate) fn retain_cached_projection(projection: &CachedProcessProjection) -> Result<(), String> {
    if projection.closing.load(Ordering::Acquire) {
        return Err("native process storage projection is closing".to_owned());
    }
    projection.refs.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

pub(crate) fn retain_locked_projection(
    projection: Arc<CachedProcessProjection>,
    projections: tokio::sync::MutexGuard<
        '_,
        std::collections::BTreeMap<ProcessProjectionKey, Arc<CachedProcessProjection>>,
    >,
    cache: Arc<
        tokio::sync::Mutex<
            std::collections::BTreeMap<ProcessProjectionKey, Arc<CachedProcessProjection>>,
        >,
    >,
    key: ProcessProjectionKey,
) -> Result<astrid_capsule::context::ProcessStorageMount, String> {
    retain_cached_projection(&projection)?;
    drop(projections);
    Ok(projection_mount(projection, cache, key))
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn projection_mount(
    projection: Arc<CachedProcessProjection>,
    projections: Arc<
        tokio::sync::Mutex<
            std::collections::BTreeMap<ProcessProjectionKey, Arc<CachedProcessProjection>>,
        >,
    >,
    key: ProcessProjectionKey,
) -> astrid_capsule::context::ProcessStorageMount {
    let workspace_mountpoint = projection.workspace_mountpoint.clone();
    let home_mountpoint = projection.home_mountpoint.clone();
    let fleet_shared_mountpoint = projection.fleet_shared_mountpoint.clone();
    let cleanup_projection = Arc::clone(&projection);
    let cleanup = move || -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            {
                let projections = projections.lock().await;
                if cleanup_projection.refs.fetch_sub(1, Ordering::AcqRel) != 1 {
                    return;
                }
                if !projections
                    .get(&key)
                    .is_some_and(|current| Arc::ptr_eq(current, &cleanup_projection))
                {
                    return;
                }
                cleanup_projection.closing.store(true, Ordering::Release);
            }
            let cleanup_ok = (cleanup_projection.cleanup)().await;
            if !cleanup_ok {
                cleanup_projection
                    .cleanup_failed
                    .store(true, Ordering::Release);
                return;
            }
            let mut projections = projections.lock().await;
            if projections
                .get(&key)
                .is_some_and(|current| Arc::ptr_eq(current, &cleanup_projection))
            {
                projections.remove(&key);
            }
        })
    };
    let mut mount = astrid_capsule::context::ProcessStorageMount::new_async(
        workspace_mountpoint,
        home_mountpoint,
        cleanup,
    );
    mount.fleet_shared_root = fleet_shared_mountpoint;
    mount
}

#[cfg(all(test, any(unix, windows)))]
pub(crate) async fn cached_projection_mount(
    projection: Arc<CachedProcessProjection>,
    projections: Arc<
        tokio::sync::Mutex<
            std::collections::BTreeMap<ProcessProjectionKey, Arc<CachedProcessProjection>>,
        >,
    >,
    key: &ProcessProjectionKey,
) -> Result<astrid_capsule::context::ProcessStorageMount, String> {
    {
        let _guard = projections.lock().await;
        retain_cached_projection(&projection)?;
    }
    Ok(projection_mount(projection, projections, key.clone()))
}

pub(crate) struct ProjectionParentTokens {
    pub(crate) branch: String,
    pub(crate) owner_home: String,
    pub(crate) fleet_shared: Option<String>,
}

pub(crate) fn generate_parent_tokens(
    targets: &ProcessProjectionTargetSet,
) -> Result<ProjectionParentTokens, String> {
    Ok(ProjectionParentTokens {
        branch: random_parent_token(ParentTokenSlot::Branch)?,
        owner_home: random_parent_token(ParentTokenSlot::OwnerHome)?,
        fleet_shared: targets
            .fleet_shared
            .is_some()
            .then(|| random_parent_token(ParentTokenSlot::FleetShared))
            .transpose()?,
    })
}

#[cfg(any(unix, windows))]
fn random_parent_token(slot: ParentTokenSlot) -> Result<String, String> {
    #[cfg(not(test))]
    let _ = slot;
    #[cfg(test)]
    if inject_parent_token_failure(slot) {
        return Err("injected parent token failure".to_owned());
    }
    let (token, _) = generate_lease_token()?;
    Ok(token)
}

#[cfg(all(test, any(unix, windows)))]
static PARENT_TOKEN_FAILURE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[cfg(all(test, any(unix, windows)))]
fn inject_parent_token_failure(slot: ParentTokenSlot) -> bool {
    PARENT_TOKEN_FAILURE
        .compare_exchange(slot as u8, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

#[cfg(all(test, any(unix, windows)))]
pub(crate) fn arm_parent_token_failure(slot: ParentTokenSlot) {
    PARENT_TOKEN_FAILURE.store(slot as u8, Ordering::Release);
}
