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
#[cfg(all(test, any(unix, windows)))]
use process_launch::abort_process_provider;
#[cfg(all(test, any(unix, windows)))]
pub(crate) use process_launch::arm_launch_failure;
#[cfg(any(unix, windows))]
use process_launch::launch_process_provider;
pub(crate) use process_launch::platform_process_provider_name;
#[cfg(all(test, any(unix, windows)))]
pub(crate) use process_launch::validate_process_provider_ready;
#[cfg(all(test, any(unix, windows)))]
mod cache_tests;
#[cfg(any(unix, windows))]
mod projection_identity;
#[cfg(any(unix, windows))]
mod projection_lifecycle;
#[cfg(all(test, any(unix, windows)))]
pub(crate) use projection_lifecycle::cached_projection_mount;
#[cfg(all(test, any(unix, windows)))]
pub(crate) use projection_lifecycle::{
    ParentTokenSlot, arm_parent_token_failure, retain_failed_launch_projection,
    revoke_projection_leases,
};
#[cfg(any(unix, windows))]
pub(crate) use projection_lifecycle::{
    ProjectionCleanupState, ProjectionLeaseProvider, ProjectionLeaseTarget, RunningProvider,
};
#[cfg(any(unix, windows))]
pub(crate) use projection_lifecycle::{
    blocked_projection_lease, cleanup_projection_state, generate_parent_tokens, projection_mount,
    retain_cached_projection, retain_locked_projection, retry_failed_projection,
    rollback_or_retain_failed_launch, rollback_uncommitted_lease,
};
#[cfg(all(test, any(unix, windows)))]
mod projection_identity_tests;
#[cfg(any(unix, windows))]
pub(crate) use projection_identity::{
    ProcessProjectionBinding, ProcessProjectionTarget, ProcessProjectionTargetSet,
    ProjectionGeneration,
};

pub(crate) type ProjectionCleanup =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync + 'static>;

#[cfg(all(test, any(unix, windows)))]
tokio::task_local! {
    static PROCESS_MOUNT_TEST_ID: u64;
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

        ensure_owner_home(&kernel, principal_uid).await?;
        if let StateOwner::Fleet(fleet_uid) = key.binding.owner {
            ensure_fleet_shared(&kernel, fleet_uid).await?;
        }

        // Generate every parent token before publishing the first lease. A
        // late token failure must not turn into a partial, live lease set or
        // allocate the random provider-service root.
        let parent_tokens = match generate_parent_tokens(&key.binding.targets) {
            Ok(tokens) => tokens,
            Err(error) => {
                return Err(error);
            },
        };
        let branch_parent_token = parent_tokens.branch;
        let owner_parent_token = parent_tokens.owner_home;
        let shared_parent_token = parent_tokens.fleet_shared;
        let provider = platform_process_provider_name();
        let admission = MountAdmission::capture(&kernel, principal, MountOwnerScope::CallerOnly)?;

        // A durable branch is an authority target, not a host mount identity.
        // The random root identifies this one provider-service incarnation;
        // all concurrent children over the same key share it. It is created
        // only after Fleet, HOME, token, and admission preparation succeeds.
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
        let fleet_shared_mountpoint = if matches!(key.binding.owner, StateOwner::Fleet(_)) {
            let path = mount_root.join("shared");
            astrid_core::platform_fs::ensure_private_directory(&path)
                .map_err(|error| format!("create Fleet shared mountpoint: {error}"))?;
            Some(path)
        } else {
            None
        };

        let branch_target = key.binding.targets.workspace.durable_target();
        let branch_lease = match issue_lease(
            &kernel,
            &admission,
            branch_view,
            branch_target,
            access,
            provider.to_owned(),
            workspace_mountpoint.clone(),
        )
        .await
        {
            Ok(lease) => lease,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&mount_root);
                return Err(error);
            },
        };
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
                let _ = std::fs::remove_dir_all(&mount_root);
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
                    let _ = std::fs::remove_dir_all(&mount_root);
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
        let branch_child = match launch_process_provider(&branch_launch).await {
            Ok(child) => child,
            Err(error) => {
                let cleanup_state = ProjectionCleanupState {
                    kernel: Arc::downgrade(&kernel),
                    binding: key.binding.clone(),
                    branch: ProjectionLeaseProvider {
                        running: RunningProvider {
                            child: error.child.map(|child| *child),
                            control_path: branch_control.clone(),
                            token: branch_parent_token.clone(),
                            stopped: error.cleanup_ok,
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
                    shared: shared_lease.as_ref().zip(shared_parent_token.as_ref()).map(
                        |(lease, token)| ProjectionLeaseProvider {
                            running: RunningProvider {
                                child: None,
                                control_path: lease.resource_path.join("process-control.sock"),
                                token: token.clone(),
                                stopped: true,
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
                        },
                    ),
                    mount_root: mount_root.clone(),
                    cleaned: false,
                };
                rollback_or_retain_failed_launch(
                    &mut projections,
                    &key,
                    workspace_mountpoint.clone(),
                    home_mountpoint.clone(),
                    fleet_shared_mountpoint.clone(),
                    cleanup_state,
                )
                .await;
                return Err(error.message);
            },
        };
        let owner_child = match launch_process_provider(&owner_launch).await {
            Ok(child) => child,
            Err(error) => {
                let cleanup_state = ProjectionCleanupState {
                    kernel: Arc::downgrade(&kernel),
                    binding: key.binding.clone(),
                    branch: ProjectionLeaseProvider {
                        running: RunningProvider {
                            child: Some(branch_child),
                            control_path: branch_control.clone(),
                            token: branch_parent_token.clone(),
                            stopped: false,
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
                    shared: shared_lease.as_ref().zip(shared_parent_token.as_ref()).map(
                        |(lease, token)| ProjectionLeaseProvider {
                            running: RunningProvider {
                                child: None,
                                control_path: lease.resource_path.join("process-control.sock"),
                                token: token.clone(),
                                stopped: true,
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
                        },
                    ),
                    mount_root: mount_root.clone(),
                    cleaned: false,
                };
                rollback_or_retain_failed_launch(
                    &mut projections,
                    &key,
                    workspace_mountpoint.clone(),
                    home_mountpoint.clone(),
                    fleet_shared_mountpoint.clone(),
                    cleanup_state,
                )
                .await;
                return Err(error.message);
            },
        };
        let mut shared_child = if let Some(shared_launch) = shared_launch.clone() {
            match launch_process_provider(&shared_launch).await {
                Ok(child) => Some((child, shared_launch)),
                Err(error) => {
                    let cleanup_state = ProjectionCleanupState {
                        kernel: Arc::downgrade(&kernel),
                        binding: key.binding.clone(),
                        branch: ProjectionLeaseProvider {
                            running: RunningProvider {
                                child: Some(branch_child),
                                control_path: branch_control.clone(),
                                token: branch_parent_token.clone(),
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
                                control_path: owner_control.clone(),
                                token: owner_parent_token.clone(),
                                stopped: false,
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
                    rollback_or_retain_failed_launch(
                        &mut projections,
                        &key,
                        workspace_mountpoint.clone(),
                        home_mountpoint.clone(),
                        fleet_shared_mountpoint.clone(),
                        cleanup_state,
                    )
                    .await;
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

#[cfg(all(test, any(unix, windows)))]
mod lease_cleanup_tests;

#[cfg(all(test, any(unix, windows)))]
mod lease_atomicity_tests;
