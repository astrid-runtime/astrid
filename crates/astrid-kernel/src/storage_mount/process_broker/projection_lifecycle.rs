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
    StorageProviderAccessV1, generate_lease_token, local_transport, platform_process_provider_name,
    stop_process_provider,
};
use crate::storage_mount::lifecycle::cleanup_mapped_lease;
use crate::storage_mount::lifecycle::cleanup_mapped_lease_resources;
use crate::storage_mount::lifecycle::force_fence_projection_lease;

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

#[derive(Clone)]
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
    let binding_valid = state.binding.validate().is_ok();
    if !binding_valid {
        tracing::error!("process storage projection binding became invalid");
    }
    let (branch_stopped, owner_stopped, shared_stopped) = if binding_valid {
        tokio::join!(
            stop_running_provider(&mut state.branch.running),
            stop_running_provider(&mut state.owner.running),
            async {
                match state.shared.as_mut() {
                    Some(shared) => stop_running_provider(&mut shared.running).await,
                    None => true,
                }
            },
        )
    } else {
        (false, false, false)
    };
    if !(binding_valid && branch_stopped && owner_stopped && shared_stopped) {
        tracing::error!(
            binding_valid,
            branch_stopped,
            owner_stopped,
            shared_stopped,
            "native process storage provider teardown failed; retaining private mount resources"
        );
        fence_retained_projection(state).await;
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

async fn fence_retained_projection(state: &mut ProjectionCleanupState) {
    let Some(kernel) = state.kernel.upgrade() else {
        tracing::error!(
            "kernel shut down before retained process storage projection leases were fenced"
        );
        return;
    };
    let fenced = fence_projection_leases(
        &kernel,
        &state.binding,
        &state.branch.lease,
        &state.owner.lease,
        state.shared.as_ref().map(|shared| &shared.lease),
    )
    .await;
    if !fenced {
        tracing::error!(
            "failed to fence every exact process storage projection lease after retained teardown"
        );
    }
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
    let component_mount_ids = projection_component_mount_ids(
        &cleanup_state.branch.lease.mount_id,
        Some(&cleanup_state.owner.lease.mount_id),
        cleanup_state
            .shared
            .as_ref()
            .map(|shared| &shared.lease.mount_id),
    );
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
            component_mount_ids,
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

/// Retain an issue-set failure with a retry that preserves all-or-nothing
/// unmap semantics instead of falling back to provider-launch teardown.
pub(crate) fn retain_failed_issue_projection(
    projections: &mut std::collections::BTreeMap<
        ProcessProjectionKey,
        Arc<CachedProcessProjection>,
    >,
    key: &ProcessProjectionKey,
    kernel: &Arc<Kernel>,
    component_mount_ids: Vec<StorageMountId>,
    paths: RetainedIssuePaths,
    branch: ProjectionLeaseTarget,
    owner: Option<ProjectionLeaseTarget>,
) {
    let kernel = Arc::downgrade(kernel);
    let binding = key.binding.clone();
    let RetainedIssuePaths {
        workspace,
        home,
        fleet_shared,
    } = paths;
    let mount_root = workspace
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let cleanup: ProjectionCleanup = Arc::new(move || {
        let binding = binding.clone();
        let branch = branch.clone();
        let owner = owner.clone();
        let kernel = kernel.clone();
        let mount_root = mount_root.clone();
        Box::pin(async move {
            let Some(kernel) = kernel.upgrade() else {
                return false;
            };
            cleanup_uncommitted_issue_lease_set(&kernel, &binding, &branch, owner.as_ref()).await
                && std::fs::remove_dir_all(mount_root).is_ok()
        })
    });
    projections.insert(
        key.clone(),
        Arc::new(CachedProcessProjection {
            binding: key.binding.clone(),
            component_mount_ids,
            workspace_mountpoint: workspace,
            home_mountpoint: home,
            fleet_shared_mountpoint: fleet_shared,
            refs: AtomicU64::new(0),
            closing: AtomicBool::new(false),
            cleanup_failed: AtomicBool::new(true),
            cleanup,
        }),
    );
}

pub(crate) struct RetainedIssuePaths {
    pub(super) workspace: PathBuf,
    pub(super) home: PathBuf,
    pub(super) fleet_shared: Option<PathBuf>,
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

/// Roll an uncommitted issue set back without unmapping a partial subset.
///
/// Resources are removed first. Only after every mapped member proves
/// resource-free does the second phase unmap the exact revoked set.
pub(crate) async fn cleanup_uncommitted_issue_lease_set(
    kernel: &Kernel,
    binding: &ProcessProjectionBinding,
    branch: &ProjectionLeaseTarget,
    owner: Option<&ProjectionLeaseTarget>,
) -> bool {
    if binding.validate().is_err() {
        return false;
    }
    // A recorded issued member can disappear between issue failure and the
    // bounded retry. Absence is already clean; a present member must still
    // prove the exact actor, owner, target, access, and provider identity.
    let Ok(states) = mapped_projection_leases(kernel, binding, branch, owner, None) else {
        return false;
    };
    fence_projection_states(&states, true);
    let mut listener_checks = tokio::task::JoinSet::new();
    for state in &states {
        let state = Arc::clone(state);
        listener_checks.spawn(async move { state.wait_listener_closed().await });
    }
    let mut listeners_closed = true;
    while let Some(closed) = listener_checks.join_next().await {
        listeners_closed &= closed.unwrap_or_default();
    }
    let _mutation_guard = kernel.storage_mount_mutations.lock().await;
    if !listeners_closed {
        return false;
    }
    for state in &states {
        if cleanup_mapped_lease_resources(state).is_err() {
            return false;
        }
    }
    for state in &states {
        kernel.storage_mounts.remove(&state.mount_id);
    }
    true
}

pub(crate) async fn revoke_projection_leases(
    kernel: &Kernel,
    binding: &ProcessProjectionBinding,
    branch: &ProjectionLeaseTarget,
    owner: &ProjectionLeaseTarget,
    shared: Option<&ProjectionLeaseTarget>,
) -> bool {
    let Ok(states) = mapped_projection_leases(kernel, binding, branch, Some(owner), shared) else {
        return false;
    };
    fence_projection_states(&states, true);
    let mut listener_checks = tokio::task::JoinSet::new();
    for state in &states {
        let state = Arc::clone(state);
        listener_checks.spawn(async move { state.wait_listener_closed().await });
    }
    let mut listeners_closed = true;
    while let Some(closed) = listener_checks.join_next().await {
        listeners_closed &= closed.unwrap_or_default();
    }
    let _mutation_guard = kernel.storage_mount_mutations.lock().await;
    let mut unmapped = true;
    for state in &states {
        unmapped &= cleanup_mapped_lease(kernel, state).is_ok();
    }
    unmapped && listeners_closed
}

async fn fence_available_projection_leases(
    kernel: &Kernel,
    binding: &ProcessProjectionBinding,
    component_mount_ids: &[StorageMountId],
) -> bool {
    let (states, _, _) = exact_projection_lease_states(kernel, binding, component_mount_ids);
    fence_projection_states(&states, true);
    let mut listener_checks = tokio::task::JoinSet::new();
    for state in &states {
        let state = Arc::clone(state);
        listener_checks.spawn(async move { state.wait_listener_closed().await });
    }
    let mut listeners_closed = true;
    while let Some(closed) = listener_checks.join_next().await {
        listeners_closed &= closed.unwrap_or_default();
    }
    if !listeners_closed {
        tracing::error!(
            "failed to drain an authorized process storage projection listener before cleanup"
        );
    }
    listeners_closed
}

pub(crate) fn projection_component_mount_ids(
    branch: &StorageMountId,
    owner: Option<&StorageMountId>,
    shared: Option<&StorageMountId>,
) -> Vec<StorageMountId> {
    [Some(*branch), owner.copied(), shared.copied()]
        .into_iter()
        .flatten()
        .collect()
}

/// Compare a recorded exact set with the kernel and retain authorized states.
///
/// Missing or expired/revoked members make `all_live` false, but still-mapped
/// members with the recorded identity stay in `states` for retained cleanup.
/// Identity mismatches are excluded and make `authorized` false: they are no
/// longer safe to fence or clean as members of this projection. Provider drift
/// is an identity mismatch, not merely degraded liveness.
fn exact_projection_lease_states(
    kernel: &Kernel,
    binding: &ProcessProjectionBinding,
    component_mount_ids: &[StorageMountId],
) -> (Vec<Arc<super::StorageMountLeaseState>>, bool, bool) {
    let targets = [
        Some(&binding.targets.workspace),
        Some(&binding.targets.owner_home),
        binding.targets.fleet_shared.as_ref(),
    ];
    let expected_count = targets.iter().flatten().count();
    if component_mount_ids.len() != expected_count {
        return (Vec::new(), false, false);
    }

    let mut seen_mount_ids = std::collections::HashSet::new();

    let mut states = Vec::with_capacity(expected_count);
    let mut all_live = true;
    let mut authorized = true;
    for (mount_id, target) in component_mount_ids.iter().zip(targets.iter().flatten()) {
        if !seen_mount_ids.insert(*mount_id) {
            return (Vec::new(), false, false);
        }
        let Some(state) = kernel
            .storage_mounts
            .get(mount_id)
            .map(|entry| Arc::clone(entry.value()))
        else {
            all_live = false;
            continue;
        };
        if state.requested_by_uid != binding.acting_uid
            || state.owner != target.durable_owner()
            || state.target != target.durable_target()
            || state.access != StorageProviderAccessV1::ReadWrite
            || state.provider != platform_process_provider_name()
        {
            all_live = false;
            authorized = false;
            continue;
        }
        all_live &= state.provider == platform_process_provider_name() && state.is_live();
        states.push(state);
    }
    (states, all_live, authorized)
}

pub(crate) fn projection_leases_are_live(
    kernel: &Kernel,
    projection: &CachedProcessProjection,
) -> bool {
    let (_, all_live, authorized) =
        exact_projection_lease_states(kernel, &projection.binding, &projection.component_mount_ids);
    all_live && authorized
}

fn mapped_projection_leases(
    kernel: &Kernel,
    binding: &ProcessProjectionBinding,
    branch: &ProjectionLeaseTarget,
    owner: Option<&ProjectionLeaseTarget>,
    shared: Option<&ProjectionLeaseTarget>,
) -> Result<Vec<Arc<super::StorageMountLeaseState>>, ()> {
    let targets = [Some(branch), owner, shared];
    let expected_count = targets.iter().flatten().count();
    let mut states = Vec::with_capacity(expected_count);
    for target in targets.into_iter().flatten() {
        let Some(state) = kernel
            .storage_mounts
            .get(&target.mount_id)
            .map(|entry| Arc::clone(entry.value()))
        else {
            continue;
        };
        if state.requested_by_uid != binding.acting_uid
            || state.owner != target.target.durable_owner()
            || state.target != target.target.durable_target()
            || state.access != StorageProviderAccessV1::ReadWrite
            || state.provider != platform_process_provider_name()
        {
            return Err(());
        }
        states.push(state);
    }
    Ok(states)
}

fn fence_projection_states(
    states: &[Arc<super::StorageMountLeaseState>],
    shutdown_listeners: bool,
) {
    for state in states {
        let admission = state
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.revoked.store(true, Ordering::Release);
        if shutdown_listeners {
            let _ = state.shutdown_tx.send(true);
        }
        drop(admission);
    }
}

async fn fence_projection_leases(
    kernel: &Kernel,
    binding: &ProcessProjectionBinding,
    branch: &ProjectionLeaseTarget,
    owner: &ProjectionLeaseTarget,
    shared: Option<&ProjectionLeaseTarget>,
) -> bool {
    let Ok(states) = mapped_projection_leases(kernel, binding, branch, Some(owner), shared) else {
        return false;
    };
    if states.is_empty() {
        return force_fence_projection_lease(
            kernel,
            binding.acting_uid,
            branch.target.durable_owner(),
            &branch.target.durable_target(),
            branch.mount_id,
        )
        .await;
    }
    fence_projection_states(&states, false);
    let _mutation_guard = kernel.storage_mount_mutations.lock().await;
    true
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
        projection.cleanup_failed.store(true, Ordering::Release);
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

/// Fence and retain-teardown a cache entry whose exact lease set degraded.
///
/// This is called before any reference is taken. It works even when another
/// mount guard still owns a reference: external revocation means the cached
/// provider pair is no longer a complete authority and must not be reused.
pub(crate) async fn invalidate_unhealthy_projection(
    kernel: &Kernel,
    projection: &Arc<CachedProcessProjection>,
    projections: &mut std::collections::BTreeMap<
        ProcessProjectionKey,
        Arc<CachedProcessProjection>,
    >,
    key: &ProcessProjectionKey,
) -> bool {
    let (_, _, authorized) =
        exact_projection_lease_states(kernel, &projection.binding, &projection.component_mount_ids);
    if !authorized {
        projection.cleanup_failed.store(true, Ordering::Release);
        return false;
    }
    if !fence_available_projection_leases(
        kernel,
        &projection.binding,
        &projection.component_mount_ids,
    )
    .await
    {
        projection.cleanup_failed.store(true, Ordering::Release);
        return false;
    }
    if !(projection.cleanup)().await {
        projection.cleanup_failed.store(true, Ordering::Release);
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

#[cfg(all(test, any(unix, windows)))]
pub(crate) async fn fence_projection_leases_for_test(
    kernel: &Kernel,
    binding: &ProcessProjectionBinding,
    branch: &ProjectionLeaseTarget,
    owner: &ProjectionLeaseTarget,
    shared: Option<&ProjectionLeaseTarget>,
) -> bool {
    fence_projection_leases(kernel, binding, branch, owner, shared).await
}

pub(crate) fn retain_cached_projection(projection: &CachedProcessProjection) -> Result<(), String> {
    if projection.closing.load(Ordering::Acquire) {
        return Err("native process storage projection is closing".to_owned());
    }
    projection.refs.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

pub(crate) async fn retain_locked_projection(
    kernel: &Kernel,
    projection: Arc<CachedProcessProjection>,
    cache: Arc<
        tokio::sync::Mutex<
            std::collections::BTreeMap<ProcessProjectionKey, Arc<CachedProcessProjection>>,
        >,
    >,
    key: ProcessProjectionKey,
) -> Result<astrid_capsule::context::ProcessStorageMount, String> {
    // Validation and reference acquisition share the publication/drain lock.
    // A concurrent ordinary revoke or expiry therefore either completes first
    // (the stale set is not retained) or happens after this caller owns a
    // reference (normal authority invalidation for an already admitted mount).
    let _mutation_guard = kernel.storage_mount_mutations.lock().await;
    #[cfg(all(test, any(unix, windows)))]
    pause_retain_validation_for_test().await;
    if !projection_leases_are_live(kernel, &projection) {
        return Err("native process storage projection became unhealthy".to_owned());
    }
    retain_cached_projection(&projection)?;
    Ok(projection_mount(projection, cache, key))
}

#[cfg(all(test, any(unix, windows)))]
#[derive(Default)]
struct RetainValidationGate {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[cfg(all(test, any(unix, windows)))]
static RETAIN_VALIDATION_GATE: std::sync::Mutex<Option<Arc<RetainValidationGate>>> =
    std::sync::Mutex::new(None);

#[cfg(all(test, any(unix, windows)))]
pub(crate) struct RetainValidationGateGuard {
    gate: Arc<RetainValidationGate>,
}

#[cfg(all(test, any(unix, windows)))]
impl RetainValidationGateGuard {
    pub(crate) fn entered(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.gate.entered)
    }

    pub(crate) fn release(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.gate.release)
    }
}

#[cfg(all(test, any(unix, windows)))]
impl Drop for RetainValidationGateGuard {
    fn drop(&mut self) {
        let mut installed = RETAIN_VALIDATION_GATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if installed
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &self.gate))
        {
            *installed = None;
        }
    }
}

#[cfg(all(test, any(unix, windows)))]
pub(crate) fn arm_retain_validation_gate() -> RetainValidationGateGuard {
    let gate = Arc::new(RetainValidationGate::default());
    *RETAIN_VALIDATION_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&gate));
    RetainValidationGateGuard { gate }
}

#[cfg(all(test, any(unix, windows)))]
async fn pause_retain_validation_for_test() {
    let gate = RETAIN_VALIDATION_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .map(Arc::clone);
    if let Some(gate) = gate {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
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
    if inject_parent_token_failure(
        slot,
        super::PROCESS_MOUNT_TEST_ID
            .try_with(|test_id| *test_id)
            .unwrap_or_default(),
    ) {
        return Err("injected parent token failure".to_owned());
    }
    let (token, _) = generate_lease_token()?;
    Ok(token)
}

#[cfg(all(test, any(unix, windows)))]
static PARENT_TOKEN_FAILURE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[cfg(all(test, any(unix, windows)))]
static PARENT_TOKEN_FAILURE_TEST_ID: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[cfg(all(test, any(unix, windows)))]
fn inject_parent_token_failure(slot: ParentTokenSlot, current_test_id: u64) -> bool {
    current_test_id == PARENT_TOKEN_FAILURE_TEST_ID.load(Ordering::Acquire)
        && PARENT_TOKEN_FAILURE
            .compare_exchange(slot as u8, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        && {
            PARENT_TOKEN_FAILURE_TEST_ID.store(0, Ordering::Release);
            true
        }
}

#[cfg(all(test, any(unix, windows)))]
pub(crate) fn arm_parent_token_failure(slot: ParentTokenSlot, test_id: u64) {
    PARENT_TOKEN_FAILURE.store(slot as u8, Ordering::Release);
    PARENT_TOKEN_FAILURE_TEST_ID.store(test_id, Ordering::Release);
}
