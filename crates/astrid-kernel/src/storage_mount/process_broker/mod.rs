use super::*;
#[cfg(all(test, any(unix, windows)))]
pub(crate) use crate::storage_mount::lifecycle::force_revoke_projection_lease;

#[cfg(any(unix, windows))]
mod process_identity;
#[cfg(any(unix, windows))]
mod process_stop;
#[cfg(any(unix, windows))]
use process_stop::stop_process_provider;
mod mount_launch;
#[cfg(any(unix, windows))]
mod process_launch;
use mount_launch::{
    ProjectionLaunchTokens, ProjectionLeaseBundle, ProjectionMountPaths,
    launch_projection_providers,
};
#[cfg(all(test, any(unix, windows)))]
use process_launch::abort_process_provider;
#[cfg(all(test, any(unix, windows)))]
pub(crate) use process_launch::arm_launch_cleanup_failure;
#[cfg(all(test, any(unix, windows)))]
pub(crate) use process_launch::arm_launch_failure;
#[cfg(any(unix, windows))]
use process_launch::launch_process_provider;
pub(crate) use process_launch::platform_process_provider_name;
#[cfg(all(test, any(unix, windows)))]
pub(crate) use process_launch::validate_process_provider_ready;
pub(crate) use process_stop::ProcessStopPolicy;
#[cfg(all(test, any(unix, windows)))]
mod cache_tests;
#[cfg(any(unix, windows))]
mod projection_identity;
#[cfg(any(unix, windows))]
mod projection_lifecycle;
mod projection_root_removal;
#[cfg(all(test, any(unix, windows)))]
mod test_faults;
#[cfg(all(test, any(unix, windows)))]
pub(crate) use projection_lifecycle::cached_projection_mount;
#[cfg(any(unix, windows))]
#[cfg(test)]
pub(crate) use projection_lifecycle::retain_failed_launch_projection;
#[cfg(all(test, any(unix, windows)))]
pub(crate) use projection_lifecycle::{
    ParentTokenSlot, arm_parent_token_failure, arm_retain_reference_gate,
    arm_retain_validation_gate, revoke_projection_leases,
};
#[cfg(any(unix, windows))]
pub(crate) use projection_lifecycle::{
    ProjectionCleanupState, ProjectionLeaseProvider, ProjectionLeaseTarget, RunningProvider,
};
#[cfg(any(unix, windows))]
pub(crate) use projection_lifecycle::{
    RetainAdmissionFailure, RetainedIssuePaths, blocked_projection_lease, cleanup_projection_state,
    cleanup_uncommitted_issue_lease_set, generate_parent_tokens, invalidate_unhealthy_projection,
    projection_component_mount_ids, projection_leases_are_live, retain_failed_issue_projection,
    retain_locked_projection, retry_failed_projection, rollback_or_retain_failed_launch,
};
#[cfg(all(test, any(unix, windows)))]
pub(crate) use projection_root_removal::fail_next_root_removal_for_test;
use projection_root_removal::remove_projection_root;
#[cfg(all(test, any(unix, windows)))]
pub(crate) use test_faults::{
    arm_issue_root_removal_failure_for_test, arm_partial_issue_failure,
    arm_partial_issue_provider_error_for_test, arm_preparation_failure_for_test,
};
#[cfg(all(test, any(unix, windows)))]
use test_faults::{
    take_issue_root_removal_failure_for_test, take_partial_issue_failure,
    take_partial_issue_provider_error, take_preparation_failure_for_test,
};
#[cfg(all(test, any(unix, windows)))]
mod projection_identity_tests;
#[cfg(all(test, any(unix, windows)))]
mod retain_linearization_tests;
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
    pub(crate) component_mount_ids: Vec<StorageMountId>,
    pub(crate) workspace_mountpoint: PathBuf,
    pub(crate) home_mountpoint: PathBuf,
    pub(crate) fleet_shared_mountpoint: Option<PathBuf>,
    pub(crate) refs: AtomicU64,
    pub(crate) closing: AtomicBool,
    pub(crate) cleanup_failed: AtomicBool,
    pub(super) cleanup: ProjectionCleanup,
}

struct UncommittedIssueRollback {
    branch_mount_id: StorageMountId,
    owner_mount_id: Option<StorageMountId>,
    component_mount_ids: Vec<StorageMountId>,
    mount_root: PathBuf,
    workspace_mountpoint: PathBuf,
    home_mountpoint: PathBuf,
    fleet_shared_mountpoint: Option<PathBuf>,
    issue_error: String,
}

async fn rollback_issued_issue_leases(
    projections: &mut std::collections::BTreeMap<
        ProcessProjectionKey,
        Arc<CachedProcessProjection>,
    >,
    key: &ProcessProjectionKey,
    kernel: &Arc<Kernel>,
    rollback: UncommittedIssueRollback,
) -> String {
    let UncommittedIssueRollback {
        branch_mount_id,
        owner_mount_id,
        component_mount_ids,
        mount_root,
        workspace_mountpoint,
        home_mountpoint,
        fleet_shared_mountpoint,
        issue_error,
    } = rollback;
    let owner_target = owner_mount_id.map(|mount_id| ProjectionLeaseTarget {
        mount_id,
        target: key.binding.targets.owner_home.clone(),
    });
    let branch_target = ProjectionLeaseTarget {
        mount_id: branch_mount_id,
        target: key.binding.targets.workspace.clone(),
    };
    // `component_mount_ids` records only leases that were actually issued.
    // The branch target is the cleanup address for the zero-lease Branch exit.
    if cleanup_uncommitted_issue_lease_set(
        kernel,
        &key.binding,
        &branch_target,
        owner_target.as_ref(),
    )
    .await
    {
        if remove_projection_root(&mount_root).is_ok() {
            return issue_error;
        }
    } else {
        retain_failed_issue_projection(
            projections,
            key,
            kernel,
            component_mount_ids,
            RetainedIssuePaths {
                workspace: workspace_mountpoint,
                home: home_mountpoint,
                fleet_shared: fleet_shared_mountpoint,
            },
            branch_target,
            owner_target,
        );
        return format!("{issue_error}; issued lease cleanup failed and remains retained");
    }
    retain_failed_issue_projection(
        projections,
        key,
        kernel,
        component_mount_ids,
        RetainedIssuePaths {
            workspace: workspace_mountpoint,
            home: home_mountpoint,
            fleet_shared: fleet_shared_mountpoint,
        },
        branch_target,
        owner_target,
    );
    format!("{issue_error}; process mount root cleanup failed and remains retained")
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
#[derive(Clone)]
pub(crate) struct KernelProcessStorageMountBroker {
    pub(crate) kernel: std::sync::Weak<Kernel>,
    /// Serializes one provider-service incarnation without owning the cache.
    startup: Arc<tokio::sync::Mutex<()>>,
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
            startup: Arc::new(tokio::sync::Mutex::new(())),
            projections: Arc::new(tokio::sync::Mutex::new(std::collections::BTreeMap::new())),
        }
    }
}

struct ProjectionAdmission {
    key: ProcessProjectionKey,
    principal: PrincipalId,
    principal_uid: astrid_core::PrincipalUid,
    branch_view: StorageProviderViewV1,
    access: StorageProviderAccessV1,
}

enum CachedProjectionAdmission {
    Fresh,
    Healthy(Arc<CachedProcessProjection>),
}

struct IssuedProjectionLeases {
    bundle: ProjectionLeaseBundle,
    tokens: ProjectionLaunchTokens,
    paths: ProjectionMountPaths,
}

struct ProjectionIssueContext<'a> {
    admission: &'a ProjectionAdmission,
    mount_admission: &'a MountAdmission,
    paths: &'a ProjectionMountPaths,
}

#[cfg(any(unix, windows))]
#[async_trait::async_trait]
impl astrid_capsule::context::ProcessStorageMountBroker for KernelProcessStorageMountBroker {
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
        // Startup remains serialized across admission, issue, and launch. The
        // projection cache itself is never held across retain because retain's
        // invalidation path must acquire that cache to exact-clean and retry.
        let _startup = self.startup.lock().await;
        loop {
            let mut projections = self.projections.lock().await;
            let admission = resolve_projection_admission(&kernel, service, principal).await?;
            let cached = admit_cached_projection(&kernel, &mut projections, &admission.key).await?;
            let projection = match cached {
                CachedProjectionAdmission::Healthy(projection) => projection,
                CachedProjectionAdmission::Fresh => {
                    let issued =
                        issue_projection_leases(&kernel, &mut projections, &admission).await?;
                    publish_projection(&kernel, &mut projections, &admission.key, issued).await?
                },
            };
            drop(projections);
            match retain_locked_projection(
                &kernel,
                projection,
                Arc::clone(&self.projections),
                admission.key,
            )
            .await
            {
                Ok(mount) => return Ok(mount),
                Err(RetainAdmissionFailure::Retry) => {},
                Err(RetainAdmissionFailure::Blocked(error)) => return Err(error),
            }
        }
    }
}

async fn resolve_projection_admission(
    kernel: &Arc<Kernel>,
    service: &astrid_capsule::context::WorkspaceBranchService,
    principal: &PrincipalId,
) -> Result<ProjectionAdmission, String> {
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
    Ok(ProjectionAdmission {
        key: ProcessProjectionKey {
            binding,
            read_write: matches!(access, StorageProviderAccessV1::ReadWrite),
        },
        principal: principal.clone(),
        principal_uid,
        branch_view,
        access,
    })
}

async fn admit_cached_projection(
    kernel: &Arc<Kernel>,
    projections: &mut std::collections::BTreeMap<
        ProcessProjectionKey,
        Arc<CachedProcessProjection>,
    >,
    key: &ProcessProjectionKey,
) -> Result<CachedProjectionAdmission, String> {
    let Some(projection) = projections.get(key).cloned() else {
        return Ok(CachedProjectionAdmission::Fresh);
    };
    if !key.matches_projection(&projection) {
        return Err("process projection identity mismatch".to_owned());
    }
    if projection.cleanup_failed.load(Ordering::Acquire) {
        // A failed last-close stays cached so the next authenticated mount can
        // retry the exact STOP/reap, revoke, and resource-removal sequence.
        if !retry_failed_projection(&projection, projections, key).await {
            return Err(
                "native process storage projection requires administrative cleanup".to_owned(),
            );
        }
        return Ok(CachedProjectionAdmission::Fresh);
    }
    if !projection_leases_are_live(kernel, &projection) {
        // External revocation, expiry, or map drift must exact-clean before a
        // new provider incarnation can even be prepared.
        if !invalidate_unhealthy_projection(kernel, &projection, projections, key).await {
            return Err(
                "native process storage projection requires administrative cleanup".to_owned(),
            );
        }
        return Ok(CachedProjectionAdmission::Fresh);
    }
    Ok(CachedProjectionAdmission::Healthy(projection))
}

async fn issue_projection_leases(
    kernel: &Arc<Kernel>,
    projections: &mut std::collections::BTreeMap<
        ProcessProjectionKey,
        Arc<CachedProcessProjection>,
    >,
    admission: &ProjectionAdmission,
) -> Result<IssuedProjectionLeases, String> {
    let key = &admission.key;
    if let Some(error) = blocked_projection_lease(kernel, &key.binding) {
        return Err(error);
    }
    ensure_owner_home(kernel, admission.principal_uid).await?;
    if let StateOwner::Fleet(fleet_uid) = key.binding.owner {
        ensure_fleet_shared(kernel, fleet_uid).await?;
    }
    let tokens = generate_parent_tokens(&key.binding.targets)?;
    let mount_admission =
        MountAdmission::capture(kernel, &admission.principal, MountOwnerScope::CallerOnly)?;
    let paths = prepare_projection_paths(kernel, projections, key)?;
    let provider = platform_process_provider_name();
    let branch = issue_branch_lease(
        kernel,
        projections,
        &ProjectionIssueContext {
            admission,
            mount_admission: &mount_admission,
            paths: &paths,
        },
        provider,
    )
    .await?;
    let owner = issue_owner_lease(
        kernel,
        projections,
        &ProjectionIssueContext {
            admission,
            mount_admission: &mount_admission,
            paths: &paths,
        },
        provider,
        &branch,
    )
    .await?;
    let shared = issue_shared_lease(
        kernel,
        projections,
        &ProjectionIssueContext {
            admission,
            mount_admission: &mount_admission,
            paths: &paths,
        },
        provider,
        &branch,
        &owner,
    )
    .await?;
    Ok(IssuedProjectionLeases {
        bundle: ProjectionLeaseBundle {
            branch,
            owner,
            shared,
        },
        tokens: ProjectionLaunchTokens {
            branch: tokens.branch,
            owner: tokens.owner_home,
            shared: tokens.fleet_shared,
        },
        paths,
    })
}

fn prepare_projection_paths(
    kernel: &Arc<Kernel>,
    projections: &mut std::collections::BTreeMap<
        ProcessProjectionKey,
        Arc<CachedProcessProjection>,
    >,
    key: &ProcessProjectionKey,
) -> Result<ProjectionMountPaths, String> {
    // A durable branch is an authority target, not a host mount identity.
    // The random root identifies this one provider-service incarnation and is
    // allocated only after HOME, Fleet, token, and admission preparation.
    let process_root = kernel.astrid_home.run_dir().join("process-storage");
    astrid_core::platform_fs::ensure_private_directory(&process_root)
        .map_err(|error| format!("create process storage root: {error}"))?;
    let mount_root = process_root.join(uuid::Uuid::new_v4().simple().to_string());
    astrid_core::platform_fs::ensure_private_directory(&mount_root)
        .map_err(|error| format!("validate process storage mount root: {error}"))?;
    #[cfg(all(test, any(unix, windows)))]
    if take_issue_root_removal_failure_for_test() {
        fail_next_root_removal_for_test(mount_root.clone());
    }
    let workspace = mount_root.join("workspace");
    let owner = mount_root.join("owner");
    let mut paths = ProjectionMountPaths {
        mount_root: mount_root.clone(),
        workspace: workspace.clone(),
        owner: owner.clone(),
        fleet_shared: None,
    };
    #[cfg(not(windows))]
    {
        #[cfg(all(test, any(unix, windows)))]
        if take_preparation_failure_for_test(process_launch::ProcessLaunchStage::Branch) {
            return Err(retain_projection_path_failure(
                kernel,
                projections,
                key,
                &paths,
                "workspace mountpoint preparation fault",
            ));
        }
        astrid_core::platform_fs::ensure_private_directory(&workspace).map_err(|error| {
            retain_projection_path_failure(
                kernel,
                projections,
                key,
                &paths,
                format!("create workspace mountpoint: {error}"),
            )
        })?;
        #[cfg(all(test, any(unix, windows)))]
        if take_preparation_failure_for_test(process_launch::ProcessLaunchStage::OwnerHome) {
            return Err(retain_projection_path_failure(
                kernel,
                projections,
                key,
                &paths,
                "owner mountpoint preparation fault",
            ));
        }
        astrid_core::platform_fs::ensure_private_directory(&owner).map_err(|error| {
            retain_projection_path_failure(
                kernel,
                projections,
                key,
                &paths,
                format!("create owner mountpoint: {error}"),
            )
        })?;
    }
    let fleet_shared = if matches!(key.binding.owner, StateOwner::Fleet(_)) {
        let path = mount_root.join("shared");
        paths.fleet_shared = Some(path.clone());
        #[cfg(all(test, any(unix, windows)))]
        if take_preparation_failure_for_test(process_launch::ProcessLaunchStage::FleetShared) {
            return Err(retain_projection_path_failure(
                kernel,
                projections,
                key,
                &paths,
                "Fleet shared mountpoint preparation fault",
            ));
        }
        #[cfg(not(windows))]
        astrid_core::platform_fs::ensure_private_directory(&path).map_err(|error| {
            retain_projection_path_failure(
                kernel,
                projections,
                key,
                &paths,
                format!("create Fleet shared mountpoint: {error}"),
            )
        })?;
        Some(path)
    } else {
        None
    };
    paths.fleet_shared = fleet_shared;
    Ok(paths)
}

fn retain_projection_path_failure(
    kernel: &Arc<Kernel>,
    projections: &mut std::collections::BTreeMap<
        ProcessProjectionKey,
        Arc<CachedProcessProjection>,
    >,
    key: &ProcessProjectionKey,
    paths: &ProjectionMountPaths,
    error: impl Into<String>,
) -> String {
    retain_failed_issue_projection(
        projections,
        key,
        kernel,
        Vec::new(),
        RetainedIssuePaths {
            workspace: paths.workspace.clone(),
            home: paths.owner.clone(),
            fleet_shared: paths.fleet_shared.clone(),
        },
        ProjectionLeaseTarget {
            mount_id: StorageMountId::new(),
            target: key.binding.targets.workspace.clone(),
        },
        None,
    );
    format!(
        "{}; process storage path preparation failed and remains retained",
        error.into()
    )
}

async fn issue_branch_lease(
    kernel: &Arc<Kernel>,
    projections: &mut std::collections::BTreeMap<
        ProcessProjectionKey,
        Arc<CachedProcessProjection>,
    >,
    context: &ProjectionIssueContext<'_>,
    provider: &str,
) -> Result<StorageMountLeaseV1, String> {
    let ProjectionIssueContext {
        admission,
        mount_admission,
        paths,
    } = context;
    #[cfg(all(test, any(unix, windows)))]
    let provider = if take_partial_issue_provider_error(process_launch::ProcessLaunchStage::Branch)
    {
        "\t".to_owned()
    } else {
        provider.to_owned()
    };
    #[cfg(not(all(test, any(unix, windows))))]
    let provider = provider.to_owned();
    let branch = issue_lease(
        kernel,
        mount_admission,
        admission.branch_view.clone(),
        admission.key.binding.targets.workspace.durable_target(),
        admission.access,
        provider,
        paths.workspace.clone(),
    )
    .await;
    match branch {
        Ok(branch) => {
            #[cfg(all(test, any(unix, windows)))]
            process_launch::record_published_test_lease(
                process_launch::ProcessLaunchStage::Branch,
                branch.mount_id,
            );
            Ok(branch)
        },
        Err(error) => Err(rollback_issued_issue_leases(
            projections,
            &admission.key,
            kernel,
            UncommittedIssueRollback {
                branch_mount_id: StorageMountId::new(),
                owner_mount_id: None,
                component_mount_ids: Vec::new(),
                mount_root: paths.mount_root.clone(),
                workspace_mountpoint: paths.workspace.clone(),
                home_mountpoint: paths.owner.clone(),
                fleet_shared_mountpoint: paths.fleet_shared.clone(),
                issue_error: error,
            },
        )
        .await),
    }
}

async fn issue_owner_lease(
    kernel: &Arc<Kernel>,
    projections: &mut std::collections::BTreeMap<
        ProcessProjectionKey,
        Arc<CachedProcessProjection>,
    >,
    context: &ProjectionIssueContext<'_>,
    provider: &str,
    branch: &StorageMountLeaseV1,
) -> Result<StorageMountLeaseV1, String> {
    let ProjectionIssueContext {
        admission,
        mount_admission,
        paths,
    } = context;
    let provider = partial_issue_provider(
        provider,
        process_launch::ProcessLaunchStage::OwnerHome,
        kernel,
        &branch.mount_id,
    );
    let owner = issue_lease(
        kernel,
        mount_admission,
        // HOME is always the acting principal's owner-local root. Fleet gets a
        // private HOME even though its workspace branch is a separate view.
        StorageProviderViewV1::Principal(admission.principal.clone()),
        admission.key.binding.targets.owner_home.durable_target(),
        admission.access,
        provider,
        paths.owner.clone(),
    )
    .await;
    match owner {
        Ok(owner) => {
            #[cfg(all(test, any(unix, windows)))]
            process_launch::record_published_test_lease(
                process_launch::ProcessLaunchStage::OwnerHome,
                owner.mount_id,
            );
            Ok(owner)
        },
        Err(error) => Err(rollback_issued_issue_leases(
            projections,
            &admission.key,
            kernel,
            UncommittedIssueRollback {
                branch_mount_id: branch.mount_id,
                owner_mount_id: None,
                component_mount_ids: vec![branch.mount_id],
                mount_root: paths.mount_root.clone(),
                workspace_mountpoint: paths.workspace.clone(),
                home_mountpoint: paths.owner.clone(),
                fleet_shared_mountpoint: paths.fleet_shared.clone(),
                issue_error: error,
            },
        )
        .await),
    }
}

fn partial_issue_provider(
    provider: &str,
    stage: process_launch::ProcessLaunchStage,
    kernel: &Arc<Kernel>,
    branch_mount_id: &StorageMountId,
) -> String {
    #[cfg(not(all(test, any(unix, windows))))]
    {
        let _ = (stage, kernel, branch_mount_id);
        provider.to_owned()
    }
    #[cfg(all(test, any(unix, windows)))]
    {
        if take_partial_issue_provider_error(stage) {
            return "\t".to_owned();
        }
        if !take_partial_issue_failure(stage) {
            return provider.to_owned();
        }
        let faulted_state = Arc::clone(
            kernel
                .storage_mounts
                .get(branch_mount_id)
                .expect("branch lease before partial issue failure")
                .value(),
        );
        crate::storage_mount::inject_cleanup_fault_for_test(
            &faulted_state,
            crate::storage_mount::MountCleanupStage::Callback,
        );
        "\t".to_owned()
    }
}

async fn issue_shared_lease(
    kernel: &Arc<Kernel>,
    projections: &mut std::collections::BTreeMap<
        ProcessProjectionKey,
        Arc<CachedProcessProjection>,
    >,
    context: &ProjectionIssueContext<'_>,
    provider: &str,
    branch: &StorageMountLeaseV1,
    owner: &StorageMountLeaseV1,
) -> Result<Option<StorageMountLeaseV1>, String> {
    let ProjectionIssueContext {
        admission,
        mount_admission,
        paths,
    } = context;
    let Some(target) = admission.key.binding.targets.fleet_shared.as_ref() else {
        return Ok(None);
    };
    let view = match target {
        ProcessProjectionTarget::FleetShared(fleet_uid) => StorageProviderViewV1::Fleet(*fleet_uid),
        _ => return Err("validated target set contains only Fleet shared targets".to_owned()),
    };
    let Some(shared_mountpoint) = paths.fleet_shared.as_ref() else {
        return Err("Fleet target has no shared mountpoint".to_owned());
    };
    let provider = partial_issue_provider(
        provider,
        process_launch::ProcessLaunchStage::FleetShared,
        kernel,
        &owner.mount_id,
    );
    let shared = issue_lease(
        kernel,
        mount_admission,
        view,
        target.durable_target(),
        admission.access,
        provider,
        shared_mountpoint.clone(),
    )
    .await;
    match shared {
        Ok(shared) => {
            #[cfg(all(test, any(unix, windows)))]
            process_launch::record_published_test_lease(
                process_launch::ProcessLaunchStage::FleetShared,
                shared.mount_id,
            );
            Ok(Some(shared))
        },
        Err(error) => Err(rollback_issued_issue_leases(
            projections,
            &admission.key,
            kernel,
            UncommittedIssueRollback {
                branch_mount_id: branch.mount_id,
                owner_mount_id: Some(owner.mount_id),
                component_mount_ids: vec![branch.mount_id, owner.mount_id],
                mount_root: paths.mount_root.clone(),
                workspace_mountpoint: paths.workspace.clone(),
                home_mountpoint: paths.owner.clone(),
                fleet_shared_mountpoint: paths.fleet_shared.clone(),
                issue_error: error,
            },
        )
        .await),
    }
}

async fn publish_projection(
    kernel: &Arc<Kernel>,
    projections: &mut std::collections::BTreeMap<
        ProcessProjectionKey,
        Arc<CachedProcessProjection>,
    >,
    key: &ProcessProjectionKey,
    issued: IssuedProjectionLeases,
) -> Result<Arc<CachedProcessProjection>, String> {
    let cleanup_state = launch_projection_providers(
        kernel,
        projections,
        key,
        &issued.bundle,
        &issued.tokens,
        &issued.paths,
    )
    .await?;
    let cleanup_state_for_projection = Arc::clone(&cleanup_state);
    let cleanup: ProjectionCleanup = Arc::new(move || {
        let cleanup_state = Arc::clone(&cleanup_state_for_projection);
        Box::pin(async move { cleanup_projection_state(cleanup_state).await })
    });
    let projection = Arc::new(CachedProcessProjection {
        binding: key.binding.clone(),
        component_mount_ids: projection_component_mount_ids(
            &issued.bundle.branch.mount_id,
            Some(&issued.bundle.owner.mount_id),
            issued.bundle.shared.as_ref().map(|lease| &lease.mount_id),
        ),
        workspace_mountpoint: issued.paths.workspace,
        // The provider mounts the fixed `home` owner subtree directly. Adding
        // another `home` component would make `home://file` resolve one level
        // too deep and leave children unable to see the mounted subtree.
        home_mountpoint: issued.paths.owner,
        fleet_shared_mountpoint: issued.paths.fleet_shared,
        refs: AtomicU64::new(0),
        closing: AtomicBool::new(false),
        cleanup_failed: AtomicBool::new(false),
        cleanup,
    });
    projections.insert(key.clone(), Arc::clone(&projection));
    Ok(projection)
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
