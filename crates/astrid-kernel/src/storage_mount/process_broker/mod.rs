use super::*;

#[cfg(any(unix, windows))]
mod process_identity;
#[cfg(any(unix, windows))]
use process_identity::parent_start_identity;
#[cfg(any(unix, windows))]
mod process_stop;
#[cfg(any(unix, windows))]
use process_stop::stop_process_provider;

pub(crate) type ProjectionCleanup =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync + 'static>;

struct RunningProvider {
    child: tokio::process::Child,
    control_path: PathBuf,
    token: String,
    stopped: bool,
}

struct ProjectionCleanupState {
    kernel: std::sync::Weak<Kernel>,
    principal: PrincipalId,
    branch: RunningProvider,
    owner: RunningProvider,
    shared: Option<RunningProvider>,
    branch_id: StorageMountId,
    owner_id: StorageMountId,
    shared_id: Option<StorageMountId>,
    mount_root: PathBuf,
    cleaned: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ProcessProjectionKey {
    pub(crate) principal_uid: astrid_core::PrincipalUid,
    pub(crate) owner: StateOwner,
    pub(crate) branch: astrid_core::WorkspaceUid,
    pub(crate) read_write: bool,
}

pub(crate) struct CachedProcessProjection {
    pub(crate) workspace_mountpoint: PathBuf,
    pub(crate) home_mountpoint: PathBuf,
    pub(crate) fleet_shared_mountpoint: Option<PathBuf>,
    pub(crate) refs: AtomicU64,
    pub(crate) closing: AtomicBool,
    pub(crate) cleanup_failed: AtomicBool,
    pub(super) cleanup: ProjectionCleanup,
}

/// Kernel implementation of the capsule-neutral process storage broker.
///
/// The selected `workspace/default` branch and the acting principal's private
/// owner root are mounted once per immutable projection key and reference
/// counted across child processes. Every caller still receives a separate
/// lease guard, but the provider pair and native mountpoints are shared until
/// the last guard closes. The provider receives only the target-free lease
/// envelope; owner and branch remain in [`StorageMountLeaseState`] and
/// callback dispatch.
#[cfg(any(unix, windows))]
pub(crate) struct KernelProcessStorageMountBroker {
    pub(crate) kernel: std::sync::Weak<Kernel>,
    projections: Arc<
        tokio::sync::Mutex<
            std::collections::BTreeMap<ProcessProjectionKey, Arc<CachedProcessProjection>>,
        >,
    >,
}

#[cfg(any(unix, windows))]
impl KernelProcessStorageMountBroker {
    pub(crate) fn new(kernel: std::sync::Weak<Kernel>) -> Self {
        Self {
            kernel,
            projections: Arc::new(tokio::sync::Mutex::new(std::collections::BTreeMap::new())),
        }
    }
}

#[cfg(any(unix, windows))]
#[async_trait::async_trait]
impl astrid_capsule::context::ProcessStorageMountBroker for KernelProcessStorageMountBroker {
    #[allow(clippy::too_many_lines)]
    async fn mount(
        &self,
        principal: &PrincipalId,
    ) -> Result<astrid_capsule::context::ProcessStorageMount, String> {
        let kernel = self
            .kernel
            .upgrade()
            .ok_or_else(|| "kernel has shut down".to_owned())?;
        let service = kernel
            .workspace_branches
            .as_ref()
            .ok_or_else(|| "workspace branch service is unavailable".to_owned())?;
        // Serialize projection admission and startup. Holding this narrow
        // kernel-local lock through provider readiness prevents concurrent
        // capsules for one immutable UID from racing to create duplicate
        // provider pairs; subsequent callers take the cached fast path.
        let mut projections = self.projections.lock().await;
        let binding = service.bind(principal).await?;
        let principal_uid = kernel
            .principal_directory
            .uid_for(principal)
            .map_err(|error| format!("resolve principal process projection identity: {error}"))?;
        let branch_view = match binding.owner {
            StateOwner::Principal(_) => StorageProviderViewV1::Principal(principal.clone()),
            StateOwner::Fleet(uid) => StorageProviderViewV1::Fleet(uid),
            StateOwner::System | StateOwner::User(_) => {
                return Err("system workspace owner is not process-mountable".to_owned());
            },
        };
        let access = StorageProviderAccessV1::ReadWrite;
        let key = ProcessProjectionKey {
            principal_uid,
            owner: binding.owner,
            branch: binding.branch,
            read_write: matches!(access, StorageProviderAccessV1::ReadWrite),
        };
        if let Some(projection) = projections.get(&key).cloned() {
            let retried = if projection.cleanup_failed.load(Ordering::Acquire) {
                // A failed last-close retains the projection in this cache so
                // a later authenticated mount request can retry STOP/reap,
                // lease revocation, and resource removal. Do not create a
                // second provider pair while any prior resources remain.
                if !retry_failed_projection(&projection, &self.projections, key).await {
                    return Err(
                        "native process storage projection requires administrative cleanup"
                            .to_owned(),
                    );
                }
                true
            } else {
                false
            };
            if !retried {
                return retain_locked_projection(
                    projection,
                    projections,
                    Arc::clone(&self.projections),
                    key,
                );
            }
        }
        // A durable branch is an authority target, not a host mount identity.
        // The random root identifies this one provider-service incarnation;
        // all concurrent children over the same key share it.
        let process_root = kernel.astrid_home.run_dir().join("process-storage");
        astrid_core::platform_fs::ensure_private_directory(&process_root)
            .map_err(|error| format!("create process storage root: {error}"))?;
        let mount_root = process_root.join(uuid::Uuid::new_v4().simple().to_string());
        astrid_core::platform_fs::ensure_private_directory(&mount_root)
            .map_err(|error| format!("validate process storage mount root: {error}"))?;
        let workspace_mountpoint = mount_root.join("workspace");
        let home_mountpoint = mount_root.join("owner");
        astrid_core::platform_fs::ensure_private_directory(&workspace_mountpoint)
            .map_err(|error| format!("create workspace mountpoint: {error}"))?;
        astrid_core::platform_fs::ensure_private_directory(&home_mountpoint)
            .map_err(|error| format!("create owner mountpoint: {error}"))?;
        let fleet_shared_mountpoint = if let StateOwner::Fleet(fleet_uid) = binding.owner {
            ensure_fleet_shared(&kernel, fleet_uid).await?;
            let path = mount_root.join("shared");
            astrid_core::platform_fs::ensure_private_directory(&path)
                .map_err(|error| format!("create Fleet shared mountpoint: {error}"))?;
            Some(path)
        } else {
            None
        };

        let owner_uid = kernel
            .principal_directory
            .uid_for(principal)
            .map_err(|error| format!("resolve principal owner for HOME: {error}"))?;
        ensure_owner_home(&kernel, owner_uid).await?;
        let parent_pid = std::process::id();
        let parent_start = parent_start_identity(parent_pid)
            .ok_or_else(|| "resolve process creation identity for provider lifetime".to_owned())?;

        let provider = platform_process_provider_name();
        let admission = MountAdmission::capture(&kernel, principal, MountOwnerScope::CallerOnly)?;
        let branch_lease = issue_lease(
            &kernel,
            &admission,
            branch_view,
            StorageFilesystemTargetV1::WorkspaceBranch {
                workspace: binding.branch,
            },
            access,
            provider.to_owned(),
            workspace_mountpoint.clone(),
        )
        .await?;
        let owner_lease = match issue_lease(
            &kernel,
            &admission,
            // HOME is always the acting principal's owner-local root.  A
            // principal assigned to a Fleet still receives a private HOME;
            // the Fleet workspace branch above is an explicit separate view.
            StorageProviderViewV1::Principal(principal.clone()),
            StorageFilesystemTargetV1::OwnerSubtree {
                prefix: "home".to_owned(),
            },
            access,
            provider.to_owned(),
            home_mountpoint.clone(),
        )
        .await
        {
            Ok(lease) => lease,
            Err(error) => {
                rollback_uncommitted_lease(&kernel, principal, branch_lease.mount_id).await;
                return Err(error);
            },
        };

        let shared_lease = if let (StateOwner::Fleet(fleet_uid), Some(shared_mountpoint)) =
            (binding.owner, fleet_shared_mountpoint.as_ref())
        {
            match issue_lease(
                &kernel,
                &admission,
                StorageProviderViewV1::Fleet(fleet_uid),
                StorageFilesystemTargetV1::OwnerSubtree {
                    prefix: "shared".to_owned(),
                },
                access,
                provider.to_owned(),
                shared_mountpoint.clone(),
            )
            .await
            {
                Ok(lease) => Some(lease),
                Err(error) => {
                    rollback_uncommitted_lease(&kernel, principal, owner_lease.mount_id).await;
                    rollback_uncommitted_lease(&kernel, principal, branch_lease.mount_id).await;
                    return Err(error);
                },
            }
        } else {
            None
        };

        let branch_parent_token = random_parent_token()?;
        let owner_parent_token = random_parent_token()?;
        let shared_parent_token = match shared_lease.as_ref() {
            Some(_) => Some(random_parent_token()?),
            None => None,
        };
        let branch_control = branch_lease.resource_path.join("process-control.sock");
        let owner_control = owner_lease.resource_path.join("process-control.sock");
        let parent = StorageProviderParentLifetimeV1 {
            pid: parent_pid,
            start_identity: Some(parent_start.clone()),
            token: branch_parent_token,
        };
        let branch_launch = StorageProviderServiceLaunchV1 {
            schema: STORAGE_FILESYSTEM_SERVICE_LAUNCH_SCHEMA_V1,
            lease: branch_lease.clone(),
            mountpoint: workspace_mountpoint.clone(),
            control_path: branch_control.clone(),
            parent: parent.clone(),
        };
        let owner_launch = StorageProviderServiceLaunchV1 {
            schema: STORAGE_FILESYSTEM_SERVICE_LAUNCH_SCHEMA_V1,
            lease: owner_lease.clone(),
            mountpoint: home_mountpoint.clone(),
            control_path: owner_control.clone(),
            parent: StorageProviderParentLifetimeV1 {
                pid: parent.pid,
                start_identity: Some(parent_start),
                token: owner_parent_token,
            },
        };
        let shared_launch =
            shared_lease
                .as_ref()
                .zip(shared_parent_token.as_ref())
                .map(|(lease, token)| StorageProviderServiceLaunchV1 {
                    schema: STORAGE_FILESYSTEM_SERVICE_LAUNCH_SCHEMA_V1,
                    lease: lease.clone(),
                    mountpoint: fleet_shared_mountpoint
                        .as_ref()
                        .expect("shared lease has a mountpoint")
                        .clone(),
                    control_path: lease.resource_path.join("process-control.sock"),
                    parent: StorageProviderParentLifetimeV1 {
                        pid: parent.pid,
                        start_identity: parent.start_identity.clone(),
                        token: token.clone(),
                    },
                });
        let mut branch_child = match launch_process_provider(&branch_launch).await {
            Ok(child) => child,
            Err(error) => {
                if error.cleanup_ok {
                    rollback_uncommitted_lease(&kernel, principal, owner_lease.mount_id).await;
                    rollback_uncommitted_lease(&kernel, principal, branch_lease.mount_id).await;
                } else {
                    tracing::error!(
                        error = %error.message,
                        "native branch provider launch cleanup failed; retaining leases and mount resources"
                    );
                }
                return Err(error.message);
            },
        };
        let mut owner_child = match launch_process_provider(&owner_launch).await {
            Ok(child) => child,
            Err(error) => {
                let branch_stopped = stop_process_provider(
                    &mut branch_child,
                    branch_control.clone(),
                    branch_launch.parent.token.clone(),
                )
                .await;
                if branch_stopped && error.cleanup_ok {
                    rollback_uncommitted_lease(&kernel, principal, owner_lease.mount_id).await;
                    rollback_uncommitted_lease(&kernel, principal, branch_lease.mount_id).await;
                } else {
                    tracing::error!(
                        branch_stopped,
                        owner_stopped = error.cleanup_ok,
                        error = %error.message,
                        "native process provider launch rollback failed; retaining leases and mount resources"
                    );
                }
                return Err(error.message);
            },
        };
        let mut shared_child = if let Some(shared_launch) = shared_launch.clone() {
            match launch_process_provider(&shared_launch).await {
                Ok(child) => Some((child, shared_launch)),
                Err(error) => {
                    let owner_stopped = stop_process_provider(
                        &mut owner_child,
                        owner_control.clone(),
                        owner_launch.parent.token.clone(),
                    )
                    .await;
                    let branch_stopped = stop_process_provider(
                        &mut branch_child,
                        branch_control.clone(),
                        branch_launch.parent.token.clone(),
                    )
                    .await;
                    if owner_stopped && branch_stopped && error.cleanup_ok {
                        rollback_uncommitted_lease(&kernel, principal, owner_lease.mount_id).await;
                        rollback_uncommitted_lease(&kernel, principal, branch_lease.mount_id).await;
                        if let Some(lease) = shared_lease.as_ref() {
                            rollback_uncommitted_lease(&kernel, principal, lease.mount_id).await;
                        }
                    } else {
                        tracing::error!(
                            owner_stopped,
                            branch_stopped,
                            error = %error.message,
                            "Fleet shared provider launch rollback failed; retaining projection resources"
                        );
                    }
                    return Err(error.message);
                },
            }
        } else {
            None
        };
        let cleanup_state = Arc::new(tokio::sync::Mutex::new(ProjectionCleanupState {
            kernel: Arc::downgrade(&kernel),
            principal: principal.clone(),
            branch: RunningProvider {
                child: branch_child,
                control_path: branch_control,
                token: branch_launch.parent.token,
                stopped: false,
            },
            owner: RunningProvider {
                child: owner_child,
                control_path: owner_control,
                token: owner_launch.parent.token,
                stopped: false,
            },
            shared: shared_child.take().map(|(child, launch)| RunningProvider {
                child,
                control_path: launch.control_path,
                token: launch.parent.token,
                stopped: false,
            }),
            branch_id: branch_lease.mount_id,
            owner_id: owner_lease.mount_id,
            shared_id: shared_lease.as_ref().map(|lease| lease.mount_id),
            mount_root: mount_root.clone(),
            cleaned: false,
        }));
        let cleanup_state_for_projection = Arc::clone(&cleanup_state);
        let cleanup: ProjectionCleanup = Arc::new(move || {
            let cleanup_state = Arc::clone(&cleanup_state_for_projection);
            Box::pin(async move { cleanup_projection_state(cleanup_state).await })
        });
        let projection = Arc::new(CachedProcessProjection {
            workspace_mountpoint,
            // The lease target is the fixed `home` owner subtree, so the
            // provider exposes that subtree directly at its mountpoint.
            // Do not append another logical `home` component here: doing so
            // would make `home://file` resolve to `<mount>/home/file` and
            // leave children unable to see the mounted owner subtree.
            home_mountpoint,
            fleet_shared_mountpoint,
            refs: AtomicU64::new(0),
            closing: AtomicBool::new(false),
            cleanup_failed: AtomicBool::new(false),
            cleanup,
        });
        projections.insert(key, Arc::clone(&projection));
        retain_cached_projection(&projection)?;
        drop(projections);
        Ok(projection_mount(
            projection,
            Arc::clone(&self.projections),
            key,
        ))
    }
}

#[cfg(any(unix, windows))]
async fn cleanup_projection_state(
    cleanup_state: Arc<tokio::sync::Mutex<ProjectionCleanupState>>,
) -> bool {
    let mut state = cleanup_state.lock().await;
    if state.cleaned {
        return true;
    }

    // Provider teardown is an authenticated async protocol: STOP, wait for
    // the service's unmount acknowledgement, then reap the child. A kill is
    // only the emergency fallback when a provider is wedged or gone; keeping
    // the provider handles in the state makes a later mount request retry the
    // same bounded operation instead of creating a second projection.
    let branch_stopped = stop_running_provider(&mut state.branch).await;
    let owner_stopped = stop_running_provider(&mut state.owner).await;
    let shared_stopped = match state.shared.as_mut() {
        Some(shared) => stop_running_provider(shared).await,
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
        &state.principal,
        state.branch_id,
        state.owner_id,
        state.shared_id,
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

#[cfg(any(unix, windows))]
async fn stop_running_provider(provider: &mut RunningProvider) -> bool {
    if provider.stopped {
        return true;
    }
    let stopped = stop_process_provider(
        &mut provider.child,
        provider.control_path.clone(),
        provider.token.clone(),
    )
    .await;
    if stopped {
        provider.stopped = true;
    }
    stopped
}

async fn rollback_uncommitted_lease(
    kernel: &Kernel,
    principal: &PrincipalId,
    mount_id: StorageMountId,
) {
    let _ = revoke_lease(kernel, principal, MountOwnerScope::CallerOnly, mount_id).await;
}

#[cfg(any(unix, windows))]
async fn revoke_projection_leases(
    kernel: &Kernel,
    principal: &PrincipalId,
    branch_id: StorageMountId,
    owner_id: StorageMountId,
    shared_id: Option<StorageMountId>,
) -> bool {
    let branch = revoke_mapped_projection_lease(kernel, principal, branch_id).await;
    let owner = revoke_mapped_projection_lease(kernel, principal, owner_id).await;
    let shared = match shared_id {
        Some(shared_id) => revoke_mapped_projection_lease(kernel, principal, shared_id).await,
        None => true,
    };
    branch && owner && shared
}

#[cfg(any(unix, windows))]
async fn revoke_mapped_projection_lease(
    kernel: &Kernel,
    principal: &PrincipalId,
    mount_id: StorageMountId,
) -> bool {
    match revoke_lease(kernel, principal, MountOwnerScope::CallerOnly, mount_id).await {
        Ok(()) => true,
        Err(_) if kernel.storage_mounts.get(&mount_id).is_none() => true,
        Err(_) => false,
    }
}

#[cfg(any(unix, windows))]
pub(crate) async fn retry_failed_projection(
    projection: &Arc<CachedProcessProjection>,
    projections: &Arc<
        tokio::sync::Mutex<
            std::collections::BTreeMap<ProcessProjectionKey, Arc<CachedProcessProjection>>,
        >,
    >,
    key: ProcessProjectionKey,
) -> bool {
    if !(projection.cleanup)().await {
        return false;
    }
    projection.cleanup_failed.store(false, Ordering::Release);
    let mut projections = projections.lock().await;
    if projections
        .get(&key)
        .is_some_and(|current| Arc::ptr_eq(current, projection))
    {
        projections.remove(&key);
    }
    true
}

#[cfg(any(unix, windows))]
fn retain_cached_projection(projection: &CachedProcessProjection) -> Result<(), String> {
    if projection.closing.load(Ordering::Acquire) {
        return Err("native process storage projection is closing".to_owned());
    }
    projection.refs.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

#[cfg(any(unix, windows))]
fn retain_locked_projection(
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

#[cfg(any(unix, windows))]
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
    key: ProcessProjectionKey,
) -> Result<astrid_capsule::context::ProcessStorageMount, String> {
    {
        let _guard = projections.lock().await;
        retain_cached_projection(&projection)?;
    }
    Ok(projection_mount(projection, projections, key))
}

#[cfg(any(unix, windows))]
pub(crate) fn platform_process_provider_name() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "astrid-storage-provider-fuse"
    }
    #[cfg(target_os = "macos")]
    {
        "astrid-storage-provider-fskit"
    }
    #[cfg(windows)]
    {
        "astrid-storage-provider-winfsp"
    }
}

#[cfg(any(unix, windows))]
fn platform_process_provider_argument() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "--astrid-provider-fuse-service-v1"
    }
    #[cfg(target_os = "macos")]
    {
        "--astrid-provider-fskit-service-v1"
    }
    #[cfg(windows)]
    {
        "--astrid-provider-winfsp-service-v1"
    }
}

#[cfg(any(unix, windows))]
fn find_process_provider(name: &str) -> Result<PathBuf, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("resolve kernel executable for storage provider: {error}"))?;
    let directory = executable
        .parent()
        .ok_or_else(|| "kernel executable has no installation directory".to_owned())?;
    let candidate = directory.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    validate_process_provider_binary(&candidate)?;
    Ok(candidate)
}

#[cfg(any(unix, windows))]
fn validate_process_provider_binary(candidate: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(candidate)
        .map_err(|error| format!("inspect coinstalled storage provider: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("coinstalled storage provider is not a regular non-symlink file".to_owned());
    }
    astrid_core::platform_fs::verify_no_redirects(candidate)
        .map_err(|error| format!("validate coinstalled storage provider path: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(
                "coinstalled storage provider is group/world writable and not trusted".to_owned(),
            );
        }
    }
    Ok(())
}

#[cfg(any(unix, windows))]
struct ProcessProviderLaunchError {
    message: String,
    cleanup_ok: bool,
}

#[cfg(any(unix, windows))]
#[allow(clippy::too_many_lines)]
async fn launch_process_provider(
    launch: &StorageProviderServiceLaunchV1,
) -> Result<tokio::process::Child, ProcessProviderLaunchError> {
    let binary = find_process_provider(platform_process_provider_name()).map_err(|message| {
        ProcessProviderLaunchError {
            message,
            cleanup_ok: true,
        }
    })?;
    let mut command = tokio::process::Command::new(binary);
    command
        .arg(platform_process_provider_argument())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| ProcessProviderLaunchError {
            message: format!("launch native storage provider: {error}"),
            cleanup_ok: true,
        })?;
    let stderr_task = child.stderr.take().map(|stderr| {
        tokio::spawn(async move {
            let mut bytes = Vec::new();
            let _ = stderr.take(64 * 1024 + 1).read_to_end(&mut bytes).await;
            bytes.truncate(64 * 1024);
            bytes
        })
    });
    let payload = match serde_json::to_vec(launch) {
        Ok(payload) => payload,
        Err(error) => {
            return Err(abort_process_provider(
                child,
                launch,
                format!("encode native storage provider launch: {error}"),
                stderr_task,
            )
            .await);
        },
    };
    let Some(mut stdin) = child.stdin.take() else {
        return Err(abort_process_provider(
            child,
            launch,
            "native storage provider stdin unavailable".to_owned(),
            stderr_task,
        )
        .await);
    };
    if let Err(error) = stdin.write_all(&payload).await {
        return Err(abort_process_provider(
            child,
            launch,
            format!("send native storage provider launch: {error}"),
            stderr_task,
        )
        .await);
    }
    drop(stdin);
    let Some(stdout) = child.stdout.take() else {
        return Err(abort_process_provider(
            child,
            launch,
            "native storage provider stdout unavailable".to_owned(),
            stderr_task,
        )
        .await);
    };
    let mut line = String::new();
    let reader = tokio::io::BufReader::new(stdout);
    let read = match tokio::time::timeout(
        std::time::Duration::from_secs(15),
        reader.take((64 * 1024 + 1) as u64).read_line(&mut line),
    )
    .await
    {
        Ok(Ok(read)) => read,
        Ok(Err(error)) => {
            return Err(abort_process_provider(
                child,
                launch,
                format!("read native storage provider readiness: {error}"),
                stderr_task,
            )
            .await);
        },
        Err(_) => {
            return Err(abort_process_provider(
                child,
                launch,
                "timed out waiting for native storage provider readiness".to_owned(),
                stderr_task,
            )
            .await);
        },
    };
    if read > 64 * 1024 || !line.ends_with('\n') {
        return Err(abort_process_provider(
            child,
            launch,
            "native storage provider readiness frame is malformed or oversized".to_owned(),
            stderr_task,
        )
        .await);
    }
    let line = line.strip_suffix('\n').unwrap_or(&line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if let Err(error) = validate_process_provider_ready(launch, line) {
        return Err(abort_process_provider(child, launch, error, stderr_task).await);
    }
    drop(stderr_task);
    Ok(child)
}

#[cfg(any(unix, windows))]
async fn abort_process_provider(
    mut child: tokio::process::Child,
    launch: &StorageProviderServiceLaunchV1,
    message: String,
    stderr_task: Option<tokio::task::JoinHandle<Vec<u8>>>,
) -> ProcessProviderLaunchError {
    let cleanup_ok = stop_process_provider(
        &mut child,
        launch.control_path.clone(),
        launch.parent.token.clone(),
    )
    .await;
    let diagnostics = match stderr_task {
        Some(task) => task.await.ok().and_then(|bytes| {
            (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).trim().to_owned())
        }),
        None => None,
    };
    let message = diagnostics.map_or_else(
        || message.clone(),
        |diagnostics| format!("{message}; provider diagnostics: {diagnostics}"),
    );
    ProcessProviderLaunchError {
        message,
        cleanup_ok,
    }
}

#[cfg(any(unix, windows))]
pub(crate) fn validate_process_provider_ready(
    launch: &StorageProviderServiceLaunchV1,
    line: &str,
) -> Result<(), String> {
    if line.len() > 64 * 1024 {
        return Err("native storage provider readiness exceeds the bounded frame".to_owned());
    }
    let ready: StorageProviderServiceReadyV1 = serde_json::from_str(line)
        .map_err(|error| format!("decode native storage provider readiness: {error}"))?;
    let canonical = serde_json::to_string(&ready)
        .map_err(|error| format!("encode native storage provider readiness: {error}"))?;
    if canonical != line {
        return Err("native storage provider readiness is not canonical JSON".to_owned());
    }
    if ready.schema != STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1
        || ready.provider != platform_process_provider_name()
        || ready.mount_id != launch.lease.mount_id.as_uuid()
        || ready.control_path != launch.control_path
    {
        return Err("native storage provider readiness identity mismatch".to_owned());
    }
    let expected = storage_provider_service_ready_challenge(
        &launch.parent.token,
        STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1,
        platform_process_provider_name(),
        launch.lease.mount_id.as_uuid(),
        &launch.control_path,
        &launch.lease.resource_path,
        &launch.lease.callback_path,
    )
    .map_err(|error| format!("derive native storage provider readiness challenge: {error}"))?;
    if !bool::from(expected.as_bytes().ct_eq(ready.challenge.as_bytes())) {
        return Err("native storage provider readiness challenge mismatch".to_owned());
    }
    Ok(())
}

async fn ensure_owner_home(
    kernel: &Arc<Kernel>,
    uid: astrid_core::PrincipalUid,
) -> Result<(), String> {
    let store = kernel
        .principal_store
        .clone()
        .ok_or_else(|| "native principal store is unavailable".to_owned())?;
    tokio::task::spawn_blocking(move || {
        let filesystem = AstridFilesystem::new(store.content(), StateOwner::Principal(uid));
        let path = FilesystemPath::new("home").map_err(|error| error.to_string())?;
        match filesystem.stat(&path) {
            Ok(entry) if entry.kind() == FilesystemEntryKind::Directory => Ok(()),
            Ok(_) => Err("principal HOME entry is not a directory".to_owned()),
            Err(FilesystemError::NotFound(_)) => filesystem
                .create_dir(&path)
                .map_err(|error| format!("create principal HOME entry: {error}")),
            Err(error) => Err(format!("inspect principal HOME entry: {error}")),
        }
    })
    .await
    .map_err(|error| format!("HOME preparation worker failed: {error}"))?
}

async fn ensure_fleet_shared(
    kernel: &Arc<Kernel>,
    fleet_uid: astrid_core::FleetUid,
) -> Result<(), String> {
    let store = kernel
        .principal_store
        .clone()
        .ok_or_else(|| "native principal store is unavailable".to_owned())?;
    tokio::task::spawn_blocking(move || {
        let filesystem =
            AstridFilesystem::new_fleet_shared(store.content(), StateOwner::Fleet(fleet_uid));
        let root = FilesystemPath::root();
        match filesystem.stat(&root) {
            Ok(entry) if entry.kind() == FilesystemEntryKind::Directory => Ok(()),
            Ok(_) => Err("Fleet shared attachment is not a directory".to_owned()),
            Err(FilesystemError::NotFound(_)) => filesystem
                .create_dir(&root)
                .map_err(|error| format!("create Fleet shared attachment: {error}")),
            Err(error) => Err(format!("inspect Fleet shared attachment: {error}")),
        }
    })
    .await
    .map_err(|error| format!("Fleet shared preparation worker failed: {error}"))?
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn provider_binary_validation_rejects_group_or_world_writable_files() {
        let temporary = tempfile::tempdir().expect("provider fixture root");
        let provider = temporary.path().join("astrid-storage-provider");
        std::fs::write(&provider, b"provider").expect("provider fixture");
        std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o755))
            .expect("trusted provider mode");
        validate_process_provider_binary(&provider).expect("trusted provider accepted");

        std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o775))
            .expect("unsafe provider mode");
        let error = validate_process_provider_binary(&provider)
            .expect_err("group-writable provider must fail closed");
        assert!(error.contains("group/world writable"));
    }
}

#[cfg(any(unix, windows))]
fn random_parent_token() -> Result<String, String> {
    let (token, _) = generate_lease_token()?;
    Ok(token)
}

#[cfg(all(test, any(unix, windows)))]
mod lease_cleanup_tests;
