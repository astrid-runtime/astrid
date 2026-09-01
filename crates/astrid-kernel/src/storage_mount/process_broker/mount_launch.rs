//! Bounded launch and rollback of one provider-service incarnation.

use super::*;

pub(super) struct ProjectionLeaseBundle {
    pub(super) branch: StorageMountLeaseV1,
    pub(super) owner: StorageMountLeaseV1,
    pub(super) shared: Option<StorageMountLeaseV1>,
}

pub(super) struct ProjectionLaunchTokens {
    pub(super) branch: String,
    pub(super) owner: String,
    pub(super) shared: Option<String>,
}

pub(super) struct ProjectionMountPaths {
    pub(super) mount_root: PathBuf,
    pub(super) workspace: PathBuf,
    pub(super) owner: PathBuf,
    pub(super) fleet_shared: Option<PathBuf>,
}

impl ProjectionLeaseBundle {
    fn target_for(
        &self,
        key: &ProcessProjectionKey,
        lease: &StorageMountLeaseV1,
    ) -> ProcessProjectionTarget {
        if lease.mount_id == self.branch.mount_id {
            return key.binding.targets.workspace.clone();
        }
        if lease.mount_id == self.owner.mount_id {
            return key.binding.targets.owner_home.clone();
        }
        key.binding
            .targets
            .fleet_shared
            .clone()
            .expect("shared lease has a Fleet target")
    }

    fn failure_provider(
        &self,
        key: &ProcessProjectionKey,
        child: Option<tokio::process::Child>,
        control_path: PathBuf,
        token: String,
        cleanup_ok: bool,
        lease: &StorageMountLeaseV1,
    ) -> ProjectionLeaseProvider {
        ProjectionLeaseProvider {
            running: RunningProvider {
                child,
                control_path,
                token,
                stopped: cleanup_ok,
            },
            lease: ProjectionLeaseTarget {
                mount_id: lease.mount_id,
                target: self.target_for(key, lease),
            },
        }
    }

    fn successful_provider(
        &self,
        key: &ProcessProjectionKey,
        child: tokio::process::Child,
        control_path: PathBuf,
        token: String,
        lease: &StorageMountLeaseV1,
    ) -> ProjectionLeaseProvider {
        ProjectionLeaseProvider {
            running: RunningProvider {
                child: Some(child),
                control_path,
                token,
                stopped: false,
            },
            lease: ProjectionLeaseTarget {
                mount_id: lease.mount_id,
                target: self.target_for(key, lease),
            },
        }
    }
}

fn cleanup_state_for_failed_launch(
    kernel: &Arc<Kernel>,
    key: &ProcessProjectionKey,
    paths: &ProjectionMountPaths,
    branch_provider: ProjectionLeaseProvider,
    owner_provider: ProjectionLeaseProvider,
    shared_provider: Option<ProjectionLeaseProvider>,
) -> ProjectionCleanupState {
    ProjectionCleanupState {
        kernel: Arc::downgrade(kernel),
        stop_policy: kernel.process_stop_policy,
        binding: key.binding.clone(),
        branch: branch_provider,
        owner: owner_provider,
        shared: shared_provider,
        mount_root: paths.mount_root.clone(),
        cleaned: false,
    }
}

async fn rollback_failed_launch(
    projections: &mut std::collections::BTreeMap<
        ProcessProjectionKey,
        Arc<CachedProcessProjection>,
    >,
    key: &ProcessProjectionKey,
    paths: &ProjectionMountPaths,
    cleanup_state: ProjectionCleanupState,
) {
    rollback_or_retain_failed_launch(
        projections,
        key,
        paths.workspace.clone(),
        paths.owner.clone(),
        paths.fleet_shared.clone(),
        cleanup_state,
    )
    .await;
}

fn launch_descriptors(
    key: &ProcessProjectionKey,
    leases: &ProjectionLeaseBundle,
    tokens: &ProjectionLaunchTokens,
    paths: &ProjectionMountPaths,
) -> (
    StorageProviderServiceLaunchV1,
    StorageProviderServiceLaunchV1,
    Option<StorageProviderServiceLaunchV1>,
) {
    let branch_control = leases.branch.resource_path.join("process-control.sock");
    let owner_control = leases.owner.resource_path.join("process-control.sock");
    let parent = StorageProviderParentLifetimeV1 {
        pid: key.binding.generation.parent_pid,
        start_identity: Some(key.binding.generation.start_identity.to_string()),
        token: tokens.branch.clone(),
    };
    let branch_launch = StorageProviderServiceLaunchV1 {
        schema: STORAGE_FILESYSTEM_SERVICE_LAUNCH_SCHEMA_V1,
        lease: leases.branch.clone(),
        mountpoint: paths.workspace.clone(),
        control_path: branch_control.clone(),
        parent: parent.clone(),
    };
    let owner_launch = StorageProviderServiceLaunchV1 {
        schema: STORAGE_FILESYSTEM_SERVICE_LAUNCH_SCHEMA_V1,
        lease: leases.owner.clone(),
        mountpoint: paths.owner.clone(),
        control_path: owner_control.clone(),
        parent: StorageProviderParentLifetimeV1 {
            pid: parent.pid,
            start_identity: Some(key.binding.generation.start_identity.to_string()),
            token: tokens.owner.clone(),
        },
    };
    let shared_launch = leases
        .shared
        .as_ref()
        .zip(tokens.shared.as_ref())
        .map(|(lease, token)| StorageProviderServiceLaunchV1 {
            schema: STORAGE_FILESYSTEM_SERVICE_LAUNCH_SCHEMA_V1,
            lease: lease.clone(),
            mountpoint: paths
                .fleet_shared
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
    (branch_launch, owner_launch, shared_launch)
}

fn unlaunched_shared_provider(
    key: &ProcessProjectionKey,
    leases: &ProjectionLeaseBundle,
    tokens: &ProjectionLaunchTokens,
) -> Option<ProjectionLeaseProvider> {
    leases
        .shared
        .as_ref()
        .zip(tokens.shared.as_ref())
        .map(|(lease, token)| {
            leases.failure_provider(
                key,
                None,
                lease.resource_path.join("process-control.sock"),
                token.clone(),
                true,
                lease,
            )
        })
}

async fn rollback_launch_error(
    projections: &mut std::collections::BTreeMap<
        ProcessProjectionKey,
        Arc<CachedProcessProjection>,
    >,
    key: &ProcessProjectionKey,
    paths: &ProjectionMountPaths,
    cleanup_state: ProjectionCleanupState,
    error: process_launch::ProcessProviderLaunchError,
) -> String {
    rollback_failed_launch(projections, key, paths, cleanup_state).await;
    error.message
}

fn branch_failure_state(
    kernel: &Arc<Kernel>,
    key: &ProcessProjectionKey,
    leases: &ProjectionLeaseBundle,
    tokens: &ProjectionLaunchTokens,
    paths: &ProjectionMountPaths,
    error: &mut process_launch::ProcessProviderLaunchError,
) -> ProjectionCleanupState {
    let branch_control = leases.branch.resource_path.join("process-control.sock");
    let owner_control = leases.owner.resource_path.join("process-control.sock");
    cleanup_state_for_failed_launch(
        kernel,
        key,
        paths,
        leases.failure_provider(
            key,
            error.child.take().map(|child| *child),
            branch_control,
            tokens.branch.clone(),
            error.cleanup_ok,
            &leases.branch,
        ),
        leases.failure_provider(
            key,
            None,
            owner_control,
            tokens.owner.clone(),
            true,
            &leases.owner,
        ),
        unlaunched_shared_provider(key, leases, tokens),
    )
}

fn owner_failure_state(
    kernel: &Arc<Kernel>,
    key: &ProcessProjectionKey,
    leases: &ProjectionLeaseBundle,
    tokens: &ProjectionLaunchTokens,
    paths: &ProjectionMountPaths,
    branch_child: tokio::process::Child,
    error: &mut process_launch::ProcessProviderLaunchError,
) -> ProjectionCleanupState {
    let branch_control = leases.branch.resource_path.join("process-control.sock");
    let owner_control = leases.owner.resource_path.join("process-control.sock");
    cleanup_state_for_failed_launch(
        kernel,
        key,
        paths,
        leases.successful_provider(
            key,
            branch_child,
            branch_control,
            tokens.branch.clone(),
            &leases.branch,
        ),
        leases.failure_provider(
            key,
            error.child.take().map(|child| *child),
            owner_control,
            tokens.owner.clone(),
            error.cleanup_ok,
            &leases.owner,
        ),
        unlaunched_shared_provider(key, leases, tokens),
    )
}

fn shared_failure_state(
    kernel: &Arc<Kernel>,
    key: &ProcessProjectionKey,
    leases: &ProjectionLeaseBundle,
    tokens: &ProjectionLaunchTokens,
    paths: &ProjectionMountPaths,
    children: (tokio::process::Child, tokio::process::Child),
    error: &mut process_launch::ProcessProviderLaunchError,
) -> ProjectionCleanupState {
    let (branch_child, owner_child) = children;
    let branch_control = leases.branch.resource_path.join("process-control.sock");
    let owner_control = leases.owner.resource_path.join("process-control.sock");
    let shared_lease = leases
        .shared
        .as_ref()
        .expect("a shared launch error requires a shared lease");
    cleanup_state_for_failed_launch(
        kernel,
        key,
        paths,
        leases.successful_provider(
            key,
            branch_child,
            branch_control,
            tokens.branch.clone(),
            &leases.branch,
        ),
        leases.successful_provider(
            key,
            owner_child,
            owner_control,
            tokens.owner.clone(),
            &leases.owner,
        ),
        Some(
            leases.failure_provider(
                key,
                error.child.take().map(|child| *child),
                shared_lease.resource_path.join("process-control.sock"),
                tokens
                    .shared
                    .as_ref()
                    .expect("shared lease has a parent token")
                    .clone(),
                error.cleanup_ok,
                shared_lease,
            ),
        ),
    )
}

fn successful_cleanup_state(
    kernel: &Arc<Kernel>,
    key: &ProcessProjectionKey,
    leases: &ProjectionLeaseBundle,
    tokens: &ProjectionLaunchTokens,
    paths: &ProjectionMountPaths,
    children: (
        tokio::process::Child,
        tokio::process::Child,
        Option<tokio::process::Child>,
    ),
) -> Arc<tokio::sync::Mutex<ProjectionCleanupState>> {
    let (branch_child, owner_child, shared_child) = children;
    Arc::new(tokio::sync::Mutex::new(ProjectionCleanupState {
        kernel: Arc::downgrade(kernel),
        stop_policy: kernel.process_stop_policy,
        binding: key.binding.clone(),
        branch: leases.successful_provider(
            key,
            branch_child,
            leases.branch.resource_path.join("process-control.sock"),
            tokens.branch.clone(),
            &leases.branch,
        ),
        owner: leases.successful_provider(
            key,
            owner_child,
            leases.owner.resource_path.join("process-control.sock"),
            tokens.owner.clone(),
            &leases.owner,
        ),
        shared: shared_child
            .zip(tokens.shared.clone())
            .map(|(child, token)| {
                let lease = leases
                    .shared
                    .as_ref()
                    .expect("shared child has an issued lease");
                leases.successful_provider(
                    key,
                    child,
                    lease.resource_path.join("process-control.sock"),
                    token,
                    lease,
                )
            }),
        mount_root: paths.mount_root.clone(),
        cleaned: false,
    }))
}

pub(super) async fn launch_projection_providers(
    kernel: &Arc<Kernel>,
    projections: &mut std::collections::BTreeMap<
        ProcessProjectionKey,
        Arc<CachedProcessProjection>,
    >,
    key: &ProcessProjectionKey,
    leases: &ProjectionLeaseBundle,
    tokens: &ProjectionLaunchTokens,
    paths: &ProjectionMountPaths,
) -> Result<Arc<tokio::sync::Mutex<ProjectionCleanupState>>, String> {
    let (branch_launch, owner_launch, shared_launch) =
        launch_descriptors(key, leases, tokens, paths);
    let branch_child = match launch_process_provider(
        &branch_launch,
        process_launch::ProcessLaunchStage::Branch,
        kernel.process_stop_policy,
    )
    .await
    {
        Ok(child) => child,
        Err(mut error) => {
            let cleanup_state =
                branch_failure_state(kernel, key, leases, tokens, paths, &mut error);
            return Err(rollback_launch_error(projections, key, paths, cleanup_state, error).await);
        },
    };
    let owner_child = match launch_process_provider(
        &owner_launch,
        process_launch::ProcessLaunchStage::OwnerHome,
        kernel.process_stop_policy,
    )
    .await
    {
        Ok(child) => child,
        Err(mut error) => {
            let cleanup_state =
                owner_failure_state(kernel, key, leases, tokens, paths, branch_child, &mut error);
            return Err(rollback_launch_error(projections, key, paths, cleanup_state, error).await);
        },
    };
    let mut shared_child = match shared_launch {
        Some(shared_launch) => {
            match launch_process_provider(
                &shared_launch,
                process_launch::ProcessLaunchStage::FleetShared,
                kernel.process_stop_policy,
            )
            .await
            {
                Ok(child) => Some(child),
                Err(mut error) => {
                    let cleanup_state = shared_failure_state(
                        kernel,
                        key,
                        leases,
                        tokens,
                        paths,
                        (branch_child, owner_child),
                        &mut error,
                    );
                    return Err(rollback_launch_error(
                        projections,
                        key,
                        paths,
                        cleanup_state,
                        error,
                    )
                    .await);
                },
            }
        },
        None => None,
    };

    Ok(successful_cleanup_state(
        kernel,
        key,
        leases,
        tokens,
        paths,
        (branch_child, owner_child, shared_child.take()),
    ))
}
