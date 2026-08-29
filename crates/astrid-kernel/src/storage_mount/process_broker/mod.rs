#[cfg(any(unix, windows))]
pub(crate) use super::lifecycle::force_revoke_projection_lease;
use super::*;

#[cfg(any(unix, windows))]
mod process_identity;
#[cfg(any(unix, windows))]
mod process_stop;
#[cfg(any(unix, windows))]
use process_stop::stop_process_provider;
#[cfg(any(unix, windows))]
mod process_launch;
#[cfg(any(unix, windows))]
use process_launch::launch_process_provider;
pub(crate) use process_launch::platform_process_provider_name;
#[cfg(all(test, any(unix, windows)))]
pub(crate) use process_launch::validate_process_provider_ready;
#[cfg(all(test, any(unix, windows)))]
mod cache_tests;
#[cfg(any(unix, windows))]
mod projection_identity;
#[cfg(all(test, any(unix, windows)))]
mod projection_identity_tests;
#[cfg(any(unix, windows))]
pub(crate) use projection_identity::{
    ProcessProjectionBinding, ProcessProjectionTarget, ProcessProjectionTargetSet,
    ProjectionGeneration,
};

pub(crate) type ProjectionCleanup =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync + 'static>;

struct RunningProvider {
    // A failed launch can leave an unmanaged provider after its Child handle
    // has been consumed by the launch error path. Retaining the authenticated
    // control identity lets a blocked retry confirm that it is really gone.
    child: Option<tokio::process::Child>,
    control_path: PathBuf,
    token: String,
    stopped: bool,
}

struct ProjectionCleanupState {
    kernel: std::sync::Weak<Kernel>,
    binding: ProcessProjectionBinding,
    branch: ProjectionLeaseProvider,
    owner: ProjectionLeaseProvider,
    shared: Option<ProjectionLeaseProvider>,
    mount_root: PathBuf,
    cleaned: bool,
}

struct ProjectionLeaseProvider {
    running: RunningProvider,
    lease: ProjectionLeaseTarget,
}

struct ProjectionLeaseTarget {
    mount_id: StorageMountId,
    target: ProcessProjectionTarget,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ProcessProjectionKey {
    pub(crate) binding: ProcessProjectionBinding,
    pub(crate) read_write: bool,
}

impl ProcessProjectionKey {
    pub(crate) fn matches_projection(&self, projection: &CachedProcessProjection) -> bool {
        projection.binding.validate().is_ok() && self.binding == projection.binding
    }
}

pub(crate) struct CachedProcessProjection {
    pub(crate) binding: ProcessProjectionBinding,
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
        let generation = ProjectionGeneration::capture()?;
        let workspace_binding = service.bind(principal).await?;
        let principal_uid = kernel
            .principal_directory
            .uid_for(principal)
            .map_err(|error| format!("resolve principal process projection identity: {error}"))?;
        if principal_uid != workspace_binding.uid {
            return Err("workspace branch identity changed during process admission".to_owned());
        }
        let binding = ProcessProjectionBinding::new(
            workspace_binding.owner,
            principal_uid,
            generation,
            ProcessProjectionTargetSet::branch(
                workspace_binding.owner,
                principal_uid,
                workspace_binding.branch,
                match workspace_binding.owner {
                    StateOwner::Fleet(fleet_uid) => Some(fleet_uid),
                    _ => None,
                },
            )?,
        )?;
        let branch_view = match workspace_binding.owner {
            StateOwner::Principal(_) => StorageProviderViewV1::Principal(principal.clone()),
            StateOwner::Fleet(uid) => StorageProviderViewV1::Fleet(uid),
            StateOwner::System | StateOwner::User(_) => {
                return Err("system workspace owner is not process-mountable".to_owned());
            },
        };
        let access = StorageProviderAccessV1::ReadWrite;
        let key = ProcessProjectionKey {
            binding,
            read_write: matches!(access, StorageProviderAccessV1::ReadWrite),
        };
        if let Some(projection) = projections.get(&key).cloned() {
            if !key.matches_projection(&projection) {
                return Err("process projection identity mismatch".to_owned());
            }
            let retried = if projection.cleanup_failed.load(Ordering::Acquire) {
                // A failed last-close retains the projection in this cache so
                // a later authenticated mount request can retry STOP/reap,
                // lease revocation, and resource removal. Do not create a
                // second provider pair while any prior resources remain.
                if !retry_failed_projection(&projection, &mut projections, &key).await {
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
        if let Some(error) = blocked_projection_lease(&kernel, &key.binding) {
            return Err(error);
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
        let fleet_shared_mountpoint = if let StateOwner::Fleet(fleet_uid) = key.binding.owner {
            ensure_fleet_shared(&kernel, fleet_uid).await?;
            let path = mount_root.join("shared");
            astrid_core::platform_fs::ensure_private_directory(&path)
                .map_err(|error| format!("create Fleet shared mountpoint: {error}"))?;
            Some(path)
        } else {
            None
        };

        ensure_owner_home(&kernel, principal_uid).await?;

        // Generate every parent token before publishing the first lease. A
        // late token failure must not turn into a partial, live lease set.
        let branch_parent_token = random_parent_token()?;
        let owner_parent_token = random_parent_token()?;
        let shared_parent_token = if key.binding.targets.fleet_shared.is_some() {
            Some(random_parent_token()?)
        } else {
            None
        };
        let provider = platform_process_provider_name();
        let admission = MountAdmission::capture(&kernel, principal, MountOwnerScope::CallerOnly)?;
        let branch_target = key.binding.targets.workspace.durable_target();
        let branch_lease = issue_lease(
            &kernel,
            &admission,
            branch_view,
            branch_target,
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
            key.binding.targets.owner_home.durable_target(),
            access,
            provider.to_owned(),
            home_mountpoint.clone(),
        )
        .await
        {
            Ok(lease) => lease,
            Err(error) => {
                rollback_uncommitted_lease(
                    &kernel,
                    &key.binding,
                    &key.binding.targets.workspace,
                    branch_lease.mount_id,
                )
                .await;
                return Err(error);
            },
        };

        let shared_target = key
            .binding
            .targets
            .fleet_shared
            .as_ref()
            .map(ProcessProjectionTarget::durable_target);
        let shared_view = key
            .binding
            .targets
            .fleet_shared
            .as_ref()
            .map(|target| match target {
                ProcessProjectionTarget::FleetShared(fleet_uid) => {
                    StorageProviderViewV1::Fleet(*fleet_uid)
                },
                _ => unreachable!("validated target set contains only Fleet shared targets"),
            });
        let shared_lease = if let (Some(target), Some(view), Some(shared_mountpoint)) =
            (shared_target, shared_view, fleet_shared_mountpoint.as_ref())
        {
            match issue_lease(
                &kernel,
                &admission,
                view,
                target,
                access,
                provider.to_owned(),
                shared_mountpoint.clone(),
            )
            .await
            {
                Ok(lease) => Some(lease),
                Err(error) => {
                    rollback_uncommitted_lease(
                        &kernel,
                        &key.binding,
                        &key.binding.targets.owner_home,
                        owner_lease.mount_id,
                    )
                    .await;
                    rollback_uncommitted_lease(
                        &kernel,
                        &key.binding,
                        &key.binding.targets.workspace,
                        branch_lease.mount_id,
                    )
                    .await;
                    return Err(error);
                },
            }
        } else {
            None
        };

        let branch_control = branch_lease.resource_path.join("process-control.sock");
        let owner_control = owner_lease.resource_path.join("process-control.sock");
        let parent = StorageProviderParentLifetimeV1 {
            pid: key.binding.generation.parent_pid,
            start_identity: Some(key.binding.generation.start_identity.to_string()),
            token: branch_parent_token.clone(),
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
                start_identity: Some(key.binding.generation.start_identity.to_string()),
                token: owner_parent_token.clone(),
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
                let provider_stopped = error.cleanup_ok;
                let cleanup_state = ProjectionCleanupState {
                    kernel: Arc::downgrade(&kernel),
                    binding: key.binding.clone(),
                    branch: ProjectionLeaseProvider {
                        running: RunningProvider {
                            child: error.child.map(|child| *child),
                            control_path: branch_control.clone(),
                            token: branch_parent_token.clone(),
                            stopped: provider_stopped,
                        },
                        lease: ProjectionLeaseTarget {
                            mount_id: branch_lease.mount_id,
                            target: key.binding.targets.workspace.clone(),
                        },
                    },
                    owner: ProjectionLeaseProvider {
                        running: RunningProvider {
                            child: None,
                            control_path: owner_control.clone(),
                            token: owner_parent_token.clone(),
                            stopped: true,
                        },
                        lease: ProjectionLeaseTarget {
                            mount_id: owner_lease.mount_id,
                            target: key.binding.targets.owner_home.clone(),
                        },
                    },
                    shared: None,
                    mount_root: mount_root.clone(),
                    cleaned: false,
                };
                if !provider_stopped {
                    tracing::error!(
                        error = %error.message,
                        "native branch provider launch cleanup failed; revoking leases before retry"
                    );
                }
                rollback_uncommitted_lease(
                    &kernel,
                    &key.binding,
                    &key.binding.targets.owner_home,
                    owner_lease.mount_id,
                )
                .await;
                rollback_uncommitted_lease(
                    &kernel,
                    &key.binding,
                    &key.binding.targets.workspace,
                    branch_lease.mount_id,
                )
                .await;
                if !provider_stopped {
                    retain_failed_launch_projection(
                        &mut projections,
                        &key,
                        workspace_mountpoint.clone(),
                        home_mountpoint.clone(),
                        fleet_shared_mountpoint.clone(),
                        cleanup_state,
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
                let provider_stopped = branch_stopped && error.cleanup_ok;
                let cleanup_state = ProjectionCleanupState {
                    kernel: Arc::downgrade(&kernel),
                    binding: key.binding.clone(),
                    branch: ProjectionLeaseProvider {
                        running: RunningProvider {
                            child: Some(branch_child),
                            control_path: branch_control.clone(),
                            token: branch_parent_token.clone(),
                            stopped: branch_stopped,
                        },
                        lease: ProjectionLeaseTarget {
                            mount_id: branch_lease.mount_id,
                            target: key.binding.targets.workspace.clone(),
                        },
                    },
                    owner: ProjectionLeaseProvider {
                        running: RunningProvider {
                            child: error.child.map(|child| *child),
                            control_path: owner_control.clone(),
                            token: owner_parent_token.clone(),
                            stopped: error.cleanup_ok,
                        },
                        lease: ProjectionLeaseTarget {
                            mount_id: owner_lease.mount_id,
                            target: key.binding.targets.owner_home.clone(),
                        },
                    },
                    shared: None,
                    mount_root: mount_root.clone(),
                    cleaned: false,
                };
                rollback_uncommitted_lease(
                    &kernel,
                    &key.binding,
                    &key.binding.targets.owner_home,
                    owner_lease.mount_id,
                )
                .await;
                rollback_uncommitted_lease(
                    &kernel,
                    &key.binding,
                    &key.binding.targets.workspace,
                    branch_lease.mount_id,
                )
                .await;
                if !provider_stopped {
                    retain_failed_launch_projection(
                        &mut projections,
                        &key,
                        workspace_mountpoint.clone(),
                        home_mountpoint.clone(),
                        fleet_shared_mountpoint.clone(),
                        cleanup_state,
                    );
                    tracing::error!(
                        branch_stopped,
                        owner_stopped = error.cleanup_ok,
                        error = %error.message,
                        "native process provider launch rollback failed; retaining unreclaimed provider resources"
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
                    let provider_stopped = owner_stopped && branch_stopped && error.cleanup_ok;
                    let cleanup_state = ProjectionCleanupState {
                        kernel: Arc::downgrade(&kernel),
                        binding: key.binding.clone(),
                        branch: ProjectionLeaseProvider {
                            running: RunningProvider {
                                child: Some(branch_child),
                                control_path: branch_control.clone(),
                                token: branch_parent_token.clone(),
                                stopped: branch_stopped,
                            },
                            lease: ProjectionLeaseTarget {
                                mount_id: branch_lease.mount_id,
                                target: key.binding.targets.workspace.clone(),
                            },
                        },
                        owner: ProjectionLeaseProvider {
                            running: RunningProvider {
                                child: Some(owner_child),
                                control_path: owner_control.clone(),
                                token: owner_parent_token.clone(),
                                stopped: owner_stopped,
                            },
                            lease: ProjectionLeaseTarget {
                                mount_id: owner_lease.mount_id,
                                target: key.binding.targets.owner_home.clone(),
                            },
                        },
                        shared: shared_lease.as_ref().map(|lease| ProjectionLeaseProvider {
                            running: RunningProvider {
                                child: error.child.map(|child| *child),
                                control_path: lease.resource_path.join("process-control.sock"),
                                token: shared_parent_token
                                    .as_ref()
                                    .expect("shared lease has a parent token")
                                    .clone(),
                                stopped: error.cleanup_ok,
                            },
                            lease: ProjectionLeaseTarget {
                                mount_id: lease.mount_id,
                                target: key
                                    .binding
                                    .targets
                                    .fleet_shared
                                    .as_ref()
                                    .expect("shared lease has a Fleet target")
                                    .clone(),
                            },
                        }),
                        mount_root: mount_root.clone(),
                        cleaned: false,
                    };
                    rollback_uncommitted_lease(
                        &kernel,
                        &key.binding,
                        &key.binding.targets.owner_home,
                        owner_lease.mount_id,
                    )
                    .await;
                    rollback_uncommitted_lease(
                        &kernel,
                        &key.binding,
                        &key.binding.targets.workspace,
                        branch_lease.mount_id,
                    )
                    .await;
                    if let (Some(lease), Some(target)) = (
                        shared_lease.as_ref(),
                        key.binding.targets.fleet_shared.as_ref(),
                    ) {
                        rollback_uncommitted_lease(&kernel, &key.binding, target, lease.mount_id)
                            .await;
                    }
                    if !provider_stopped {
                        retain_failed_launch_projection(
                            &mut projections,
                            &key,
                            workspace_mountpoint.clone(),
                            home_mountpoint.clone(),
                            fleet_shared_mountpoint.clone(),
                            cleanup_state,
                        );
                        tracing::error!(
                            owner_stopped,
                            branch_stopped,
                            error = %error.message,
                            "Fleet shared provider launch rollback failed; retaining unreclaimed provider resources"
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
            binding: key.binding.clone(),
            branch: ProjectionLeaseProvider {
                running: RunningProvider {
                    child: Some(branch_child),
                    control_path: branch_control,
                    token: branch_launch.parent.token,
                    stopped: false,
                },
                lease: ProjectionLeaseTarget {
                    mount_id: branch_lease.mount_id,
                    target: key.binding.targets.workspace.clone(),
                },
            },
            owner: ProjectionLeaseProvider {
                running: RunningProvider {
                    child: Some(owner_child),
                    control_path: owner_control,
                    token: owner_launch.parent.token,
                    stopped: false,
                },
                lease: ProjectionLeaseTarget {
                    mount_id: owner_lease.mount_id,
                    target: key.binding.targets.owner_home.clone(),
                },
            },
            shared: shared_child
                .take()
                .map(|(child, launch)| ProjectionLeaseProvider {
                    running: RunningProvider {
                        child: Some(child),
                        control_path: launch.control_path,
                        token: launch.parent.token,
                        stopped: false,
                    },
                    lease: ProjectionLeaseTarget {
                        mount_id: shared_lease
                            .as_ref()
                            .expect("shared child has an issued lease")
                            .mount_id,
                        target: key
                            .binding
                            .targets
                            .fleet_shared
                            .clone()
                            .expect("shared child has a Fleet target"),
                    },
                }),
            mount_root: mount_root.clone(),
            cleaned: false,
        }));
        let cleanup_state_for_projection = Arc::clone(&cleanup_state);
        let cleanup: ProjectionCleanup = Arc::new(move || {
            let cleanup_state = Arc::clone(&cleanup_state_for_projection);
            Box::pin(async move { cleanup_projection_state(cleanup_state).await })
        });
        let projection = Arc::new(CachedProcessProjection {
            binding: key.binding.clone(),
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
        projections.insert(key.clone(), Arc::clone(&projection));
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

#[cfg(any(unix, windows))]
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

#[cfg(any(unix, windows))]
async fn unmanaged_provider_is_stopped(control_path: &Path) -> bool {
    match local_transport::connect_outcome(control_path).await {
        Ok(local_transport::ConnectOutcome::Absent | local_transport::ConnectOutcome::Stale) => {
            true
        },
        Ok(local_transport::ConnectOutcome::Connected(_)) | Err(_) => false,
    }
}

#[cfg(any(unix, windows))]
fn retain_failed_launch_projection(
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

async fn rollback_uncommitted_lease(
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

fn blocked_projection_lease(kernel: &Kernel, binding: &ProcessProjectionBinding) -> Option<String> {
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

#[cfg(any(unix, windows))]
async fn revoke_projection_leases(
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

#[cfg(any(unix, windows))]
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

#[cfg(any(unix, windows))]
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
    key: &ProcessProjectionKey,
) -> Result<astrid_capsule::context::ProcessStorageMount, String> {
    {
        let _guard = projections.lock().await;
        retain_cached_projection(&projection)?;
    }
    Ok(projection_mount(projection, projections, key.clone()))
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

#[cfg(any(unix, windows))]
fn random_parent_token() -> Result<String, String> {
    #[cfg(test)]
    loop {
        match PARENT_TOKEN_FAULTS.compare_exchange(0, 0, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(faults) => {
                if let Some(remaining) = faults.checked_sub(1) {
                    if PARENT_TOKEN_FAULTS
                        .compare_exchange(faults, remaining, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        return Err("injected parent token failure".to_owned());
                    }
                } else {
                    break;
                }
            },
        }
    }
    let (token, _) = generate_lease_token()?;
    Ok(token)
}

#[cfg(all(test, any(unix, windows)))]
static PARENT_TOKEN_FAULTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(all(test, any(unix, windows)))]
pub(crate) fn arm_parent_token_faults(count: usize) {
    PARENT_TOKEN_FAULTS.store(count, Ordering::Release);
}

#[cfg(all(test, any(unix, windows)))]
mod lease_cleanup_tests;

#[cfg(all(test, any(unix, windows)))]
mod lease_atomicity_tests;
