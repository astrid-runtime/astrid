use std::collections::BTreeMap;
use std::sync::Arc;

use astrid_capsule::context::ProcessStorageMountBroker as _;
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::storage_provider::StorageProviderViewV1;
use astrid_storage::StateOwner;

use super::{
    KernelProcessStorageMountBroker, MountAdmission, MountOwnerScope, PROCESS_MOUNT_TEST_ID,
    ParentTokenSlot, ProcessProjectionBinding, ProcessProjectionTargetSet, ProjectionGeneration,
    arm_parent_token_failure, issue_lease, platform_process_provider_name,
    retain_failed_launch_projection, retry_failed_projection, rollback_or_retain_failed_launch,
};
use super::{abort_process_provider, arm_launch_failure, process_launch::ProcessLaunchStage};

fn binding(actor: astrid_core::PrincipalUid) -> ProcessProjectionBinding {
    binding_on(
        actor,
        StateOwner::Principal(actor),
        astrid_core::WorkspaceUid::from_bytes([0xD1; 16]),
        None,
    )
}

fn binding_on(
    actor: astrid_core::PrincipalUid,
    owner: StateOwner,
    workspace: astrid_core::WorkspaceUid,
    fleet_shared: Option<astrid_core::FleetUid>,
) -> ProcessProjectionBinding {
    ProcessProjectionBinding::new(
        owner,
        actor,
        ProjectionGeneration::capture().expect("valid projection generation"),
        ProcessProjectionTargetSet::branch(owner, actor, workspace, fleet_shared)
            .expect("valid target set"),
    )
    .expect("valid projection binding")
}

fn spawn_exited_child() -> tokio::process::Child {
    #[cfg(unix)]
    {
        tokio::process::Command::new("true")
            .spawn()
            .expect("spawn exited prior provider")
    }
    #[cfg(windows)]
    {
        tokio::process::Command::new("cmd")
            .args(["/C", "exit", "0"])
            .spawn()
            .expect("spawn exited prior provider")
    }
}

async fn issue_stage_leases(
    kernel: &Arc<crate::Kernel>,
    caller: astrid_core::PrincipalId,
    binding: &ProcessProjectionBinding,
    scratch: &tempfile::TempDir,
) -> (
    astrid_core::storage_filesystem::StorageMountLeaseV1,
    astrid_core::storage_filesystem::StorageMountLeaseV1,
    Option<astrid_core::storage_filesystem::StorageMountLeaseV1>,
) {
    let admission = MountAdmission::capture(kernel, &caller, MountOwnerScope::CallerOnly)
        .expect("stage test admission");
    let branch_view = match binding.owner {
        StateOwner::Fleet(fleet_uid) => StorageProviderViewV1::Fleet(fleet_uid),
        StateOwner::Principal(_) => StorageProviderViewV1::Principal(caller.clone()),
        StateOwner::System | StateOwner::User(_) => {
            panic!("stage fixture supports only principal and Fleet owners")
        },
    };
    let branch_lease = issue_lease(
        kernel,
        &admission,
        branch_view,
        binding.targets.workspace.durable_target(),
        astrid_core::storage_provider::StorageProviderAccessV1::ReadWrite,
        platform_process_provider_name().to_owned(),
        scratch.path().join("workspace"),
    )
    .await
    .expect("issue branch stage lease");
    let owner_lease = issue_lease(
        kernel,
        &admission,
        StorageProviderViewV1::Principal(caller.clone()),
        binding.targets.owner_home.durable_target(),
        astrid_core::storage_provider::StorageProviderAccessV1::ReadWrite,
        platform_process_provider_name().to_owned(),
        scratch.path().join("owner"),
    )
    .await
    .expect("issue owner stage lease");
    let shared_lease = match binding.targets.fleet_shared.as_ref() {
        Some(target) => Some(
            issue_lease(
                kernel,
                &admission,
                StorageProviderViewV1::Fleet(match target {
                    super::ProcessProjectionTarget::FleetShared(fleet_uid) => *fleet_uid,
                    _ => panic!("Fleet shared target has a Fleet identity"),
                }),
                target.durable_target(),
                astrid_core::storage_provider::StorageProviderAccessV1::ReadWrite,
                platform_process_provider_name().to_owned(),
                scratch.path().join("shared"),
            )
            .await
            .expect("issue Fleet shared stage lease"),
        ),
        None => None,
    };
    (branch_lease, owner_lease, shared_lease)
}

async fn stage_binding_on(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
) -> ProcessProjectionBinding {
    let actor = kernel
        .principal_directory
        .uid_for(caller)
        .expect("caller actor UID");
    let workspace = kernel
        .workspace_branches
        .as_ref()
        .expect("test workspace service")
        .bind(caller)
        .await
        .expect("bind test workspace");
    let fleet_shared = match workspace.owner {
        StateOwner::Fleet(fleet_uid) => Some(fleet_uid),
        StateOwner::Principal(_) => None,
        StateOwner::System | StateOwner::User(_) => {
            panic!("test workspace owner is not process-mountable")
        },
    };
    binding_on(actor, workspace.owner, workspace.branch, fleet_shared)
}

fn stopped_provider(
    child: Option<tokio::process::Child>,
    control_path: &std::path::Path,
    token: String,
    stopped: bool,
    lease: &astrid_core::storage_filesystem::StorageMountLeaseV1,
    target: super::ProcessProjectionTarget,
) -> super::ProjectionLeaseProvider {
    super::ProjectionLeaseProvider {
        running: super::RunningProvider {
            child,
            control_path: control_path.to_path_buf(),
            token,
            stopped,
        },
        lease: super::ProjectionLeaseTarget {
            mount_id: lease.mount_id,
            target,
        },
    }
}

fn retained_endpoint() -> (
    tempfile::TempDir,
    Arc<tokio::sync::Notify>,
    tokio::task::JoinHandle<()>,
) {
    use astrid_core::local_transport;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::Notify;

    #[cfg(unix)]
    let endpoint_root = tempfile::tempdir_in("/tmp").expect("create short endpoint root");
    #[cfg(windows)]
    let endpoint_root = tempfile::tempdir().expect("create retained endpoint root");
    let listener =
        local_transport::bind(&endpoint_root.path().join("c")).expect("bind retained endpoint");
    let release = Arc::new(Notify::new());
    let responder = tokio::spawn({
        let release = Arc::clone(&release);
        async move {
            for _ in 0..4 {
                let mut stream = local_transport::accept(&listener)
                    .await
                    .expect("accept retained stop request");
                let mut frame = Vec::new();
                while let Ok(byte) = stream.read_u8().await {
                    frame.push(byte);
                    if byte == b'\n' {
                        break;
                    }
                }
                if frame.ends_with(b"\n") {
                    stream
                        .write_all(b"{\"status\":\"ready\"}\n")
                        .await
                        .expect("write stop refusal");
                    let _ = stream.read_u8().await;
                }
            }
            release.notified().await;
        }
    });
    (endpoint_root, release, responder)
}

fn stage_retained_cleanup_state(
    stage: ProcessLaunchStage,
    kernel: &Arc<crate::Kernel>,
    binding: &ProcessProjectionBinding,
    leases: (
        &astrid_core::storage_filesystem::StorageMountLeaseV1,
        &astrid_core::storage_filesystem::StorageMountLeaseV1,
        Option<&astrid_core::storage_filesystem::StorageMountLeaseV1>,
    ),
    control_path: &std::path::Path,
    mount_root: &std::path::Path,
) -> super::ProjectionCleanupState {
    let (branch_lease, owner_lease, shared_lease) = leases;
    super::ProjectionCleanupState {
        kernel: Arc::downgrade(kernel),
        binding: binding.clone(),
        branch: stopped_provider(
            (stage == ProcessLaunchStage::Branch).then(spawn_exited_child),
            &(if stage == ProcessLaunchStage::Branch {
                control_path.to_path_buf()
            } else {
                branch_lease.resource_path.join("process-control.sock")
            }),
            branch_lease.lease_token.clone(),
            stage != ProcessLaunchStage::Branch,
            branch_lease,
            binding.targets.workspace.clone(),
        ),
        owner: stopped_provider(
            (stage == ProcessLaunchStage::OwnerHome).then(spawn_exited_child),
            &(if stage == ProcessLaunchStage::OwnerHome {
                control_path.to_path_buf()
            } else {
                owner_lease.resource_path.join("process-control.sock")
            }),
            owner_lease.lease_token.clone(),
            !matches!(
                stage,
                ProcessLaunchStage::OwnerHome | ProcessLaunchStage::FleetShared
            ),
            owner_lease,
            binding.targets.owner_home.clone(),
        ),
        shared: shared_lease.map(|lease| {
            stopped_provider(
                (stage == ProcessLaunchStage::FleetShared).then(spawn_exited_child),
                &(if stage == ProcessLaunchStage::FleetShared {
                    control_path.to_path_buf()
                } else {
                    lease.resource_path.join("process-control.sock")
                }),
                lease.lease_token.clone(),
                stage != ProcessLaunchStage::FleetShared,
                lease,
                binding
                    .targets
                    .fleet_shared
                    .clone()
                    .expect("shared lease has a Fleet target"),
            )
        }),
        mount_root: mount_root.to_path_buf(),
        cleaned: false,
    }
}

async fn assert_stage_launch_rollback(stage: ProcessLaunchStage) {
    let (temporary, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let binding = stage_binding_on(&kernel, &caller).await;
    let key = super::ProcessProjectionKey {
        binding: binding.clone(),
        read_write: true,
    };
    let (branch_lease, owner_lease, shared_lease) =
        issue_stage_leases(&kernel, caller.clone(), &binding, &temporary).await;
    let expected_leases = if shared_lease.is_some() { 3 } else { 2 };
    assert_eq!(kernel.storage_mounts.len(), expected_leases);

    let branch_control = branch_lease.resource_path.join("process-control.sock");
    let owner_control = owner_lease.resource_path.join("process-control.sock");
    let shared_control = shared_lease
        .as_ref()
        .map(|lease| lease.resource_path.join("process-control.sock"));
    let process_root = kernel.astrid_home.run_dir().join("process-storage");
    let mount_root = process_root.join("stage-mount-root");
    std::fs::create_dir_all(&mount_root).expect("create broker-owned stage mount root");
    let cleanup_state = super::ProjectionCleanupState {
        kernel: Arc::downgrade(&kernel),
        binding: binding.clone(),
        branch: stopped_provider(
            (stage != ProcessLaunchStage::Branch).then(spawn_exited_child),
            &branch_control,
            branch_lease.lease_token.clone(),
            false,
            &branch_lease,
            binding.targets.workspace.clone(),
        ),
        owner: stopped_provider(
            (stage == ProcessLaunchStage::FleetShared).then(spawn_exited_child),
            &owner_control,
            owner_lease.lease_token.clone(),
            false,
            &owner_lease,
            binding.targets.owner_home.clone(),
        ),
        shared: shared_lease.as_ref().map(|lease| {
            stopped_provider(
                None,
                &shared_control
                    .clone()
                    .expect("shared lease has a control endpoint"),
                lease.lease_token.clone(),
                false,
                lease,
                binding
                    .targets
                    .fleet_shared
                    .clone()
                    .expect("shared lease has a Fleet target"),
            )
        }),
        mount_root,
        cleaned: false,
    };
    let mut projections = std::collections::BTreeMap::new();
    rollback_or_retain_failed_launch(
        &mut projections,
        &key,
        temporary.path().join("workspace"),
        temporary.path().join("owner"),
        shared_lease
            .as_ref()
            .map(|_| temporary.path().join("shared")),
        cleanup_state,
    )
    .await;

    assert!(
        kernel.storage_mounts.is_empty(),
        "{stage:?} launch rollback must revoke every exact published lease"
    );
    assert!(
        projections.is_empty(),
        "{stage:?} must not retain a blocker"
    );
    assert!(
        process_root
            .read_dir()
            .expect("process storage root")
            .next()
            .is_none(),
        "{stage:?} cleanup must remove its UUID mount root"
    );
}

async fn assert_stage_launch_retains_blocker(stage: ProcessLaunchStage) {
    let (temporary, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let binding = stage_binding_on(&kernel, &caller).await;
    let key = super::ProcessProjectionKey {
        binding: binding.clone(),
        read_write: true,
    };
    let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    let (branch_lease, owner_lease, shared_lease) =
        issue_stage_leases(&kernel, caller.clone(), &binding, &temporary).await;
    let endpoint = retained_endpoint();
    let (endpoint_root, release, responder) = endpoint;
    let mount_root = endpoint_root.path().to_path_buf();
    let control_path = mount_root.join("c");
    let cleanup_state = stage_retained_cleanup_state(
        stage,
        &kernel,
        &binding,
        (&branch_lease, &owner_lease, shared_lease.as_ref()),
        &control_path,
        &mount_root,
    );
    let mut projections = std::collections::BTreeMap::new();
    rollback_or_retain_failed_launch(
        &mut projections,
        &key,
        temporary.path().join("workspace"),
        temporary.path().join("owner"),
        shared_lease
            .as_ref()
            .map(|_| temporary.path().join("shared")),
        cleanup_state,
    )
    .await;

    let projection = Arc::clone(projections.get(&key).expect("authoritative blocker"));
    assert!(
        projection
            .cleanup_failed
            .load(std::sync::atomic::Ordering::Acquire),
        "{stage:?} failed endpoint cleanup must retain the blocker"
    );
    assert!(
        !retry_failed_projection(&projection, &mut projections, &key).await,
        "{stage:?} authoritative retry must remain blocked by the live endpoint"
    );
    let Err(replacement_error) = PROCESS_MOUNT_TEST_ID
        .scope(9_000 + u64::from(stage.as_u8()), broker.mount(&caller))
        .await
    else {
        panic!("{stage:?} replacement must be denied while cleanup is retained");
    };
    assert!(
        replacement_error.starts_with("existing process projection lease "),
        "unexpected replacement denial for {stage:?}: {replacement_error}"
    );
    assert!(!projections.is_empty());

    release.notify_waiters();
    responder.await.expect("retained endpoint responder");
}

#[tokio::test]
async fn launch_failure_selector_is_stage_specific_and_single_shot() {
    let stages = [
        ProcessLaunchStage::Branch,
        ProcessLaunchStage::OwnerHome,
        ProcessLaunchStage::FleetShared,
    ];
    for stage in stages {
        let test_id = 9_100 + u64::from(stage.as_u8());
        arm_launch_failure(stage, test_id);
        let other_stage = match stage {
            ProcessLaunchStage::Branch => ProcessLaunchStage::OwnerHome,
            ProcessLaunchStage::OwnerHome => ProcessLaunchStage::FleetShared,
            ProcessLaunchStage::FleetShared => ProcessLaunchStage::Branch,
        };
        assert!(
            !super::process_launch::launch_failure_matches(other_stage, test_id),
            "an armed {stage:?} fault must not consume a {other_stage:?} launch"
        );
        assert!(
            super::process_launch::launch_failure_matches(stage, test_id),
            "the selected {stage:?} fault must consume exactly that launch"
        );
        assert!(
            !super::process_launch::launch_failure_matches(stage, test_id),
            "a launch fault must be single-shot"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stage_launch_faults_roll_back_published_leases_in_order() {
    for stage in [
        ProcessLaunchStage::Branch,
        ProcessLaunchStage::OwnerHome,
        ProcessLaunchStage::FleetShared,
    ] {
        assert_stage_launch_rollback(stage).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stage_launch_faults_retain_blockers_when_endpoint_cleanup_fails() {
    for stage in [
        ProcessLaunchStage::Branch,
        ProcessLaunchStage::OwnerHome,
        ProcessLaunchStage::FleetShared,
    ] {
        assert_stage_launch_retains_blocker(stage).await;
    }
}

async fn fleet_shared_kernel() -> (tempfile::TempDir, Arc<crate::Kernel>) {
    let temporary = tempfile::tempdir().expect("test home root");
    let home = AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = crate::test_kernel_with_home(home).await;
    let caller = PrincipalId::default();
    let actor = kernel
        .principal_directory
        .uid_for(&caller)
        .expect("caller actor UID");
    let ownership = kernel
        .ownership_store
        .load()
        .await
        .expect("load ownership graph");
    let assignment = ownership
        .principal_owner(actor)
        .expect("test kernel first-owner assignment");
    assert!(
        kernel
            .ownership_store
            .load()
            .await
            .expect("reload ownership graph")
            .fleet(assignment.fleet_uid)
            .is_some(),
        "test kernel must contain the Fleet shared owner"
    );
    (temporary, kernel)
}

#[cfg(unix)]
fn diagnostics_launch(
    scratch: &tempfile::TempDir,
    control_path: std::path::PathBuf,
) -> astrid_core::storage_filesystem::StorageProviderServiceLaunchV1 {
    use astrid_core::storage_filesystem::{
        STORAGE_FILESYSTEM_SERVICE_LAUNCH_SCHEMA_V1, StorageMountLeaseV1,
        StorageProviderParentLifetimeV1,
    };
    use astrid_core::storage_provider::{StorageProviderAccessV1, StorageProviderViewV1};

    let callback_path = scratch.path().join("callback.sock");
    astrid_core::storage_filesystem::StorageProviderServiceLaunchV1 {
        schema: STORAGE_FILESYSTEM_SERVICE_LAUNCH_SCHEMA_V1,
        lease: StorageMountLeaseV1 {
            mount_id: astrid_core::storage_provider::StorageMountId::new(),
            view: StorageProviderViewV1::Principal(PrincipalId::default()),
            access: StorageProviderAccessV1::ReadWrite,
            resource_path: scratch.path().join("resource"),
            callback_path,
            lease_token: "diagnostics-token".to_owned(),
            expires_at_epoch_secs: u64::MAX,
        },
        mountpoint: scratch.path().join("mountpoint"),
        control_path,
        parent: StorageProviderParentLifetimeV1 {
            pid: std::process::id(),
            start_identity: None,
            token: "diagnostics-token".to_owned(),
        },
    }
}

#[cfg(unix)]
async fn spawn_child_with_inherited_stderr(
    scratch: &tempfile::TempDir,
) -> (tokio::process::Child, u32) {
    let pid_path = scratch.path().join("stderr-holder.pid");
    let child = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("sleep 30 2>&1 & echo $! > \"$1\"")
        .arg("/bin/sh")
        .arg(&pid_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn child with inherited stderr");
    let pid = wait_for_reported_pid(&pid_path)
        .await
        .expect("child reported its stderr holder");
    (child, pid)
}

#[cfg(unix)]
async fn wait_for_reported_pid(pid_path: &std::path::Path) -> Result<u32, String> {
    use std::io::Read as _;

    let started = tokio::time::Instant::now();
    let timeout = std::time::Duration::from_secs(1);
    loop {
        if let Ok(mut file) = std::fs::File::open(pid_path) {
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .map_err(|error| format!("read stderr-holder PID: {error}"))?;
            if let Ok(pid) = contents.trim().parse::<u32>() {
                return Ok(pid);
            }
        }
        if started.elapsed() >= timeout {
            return Err("child did not report a parseable stderr-holder PID".to_owned());
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[cfg(unix)]
fn retained_cleanup_state(
    kernel: &Arc<crate::Kernel>,
    binding: &ProcessProjectionBinding,
    failed_child: Option<Box<tokio::process::Child>>,
    control_path: std::path::PathBuf,
    scratch: &tempfile::TempDir,
) -> super::ProjectionCleanupState {
    super::ProjectionCleanupState {
        kernel: Arc::downgrade(kernel),
        binding: binding.clone(),
        branch: super::ProjectionLeaseProvider {
            running: super::RunningProvider {
                child: failed_child.map(|child| *child),
                control_path,
                token: "diagnostics-token".to_owned(),
                stopped: false,
            },
            lease: super::ProjectionLeaseTarget {
                mount_id: astrid_core::storage_provider::StorageMountId::new(),
                target: binding.targets.owner_home.clone(),
            },
        },
        owner: super::ProjectionLeaseProvider {
            running: super::RunningProvider {
                child: None,
                control_path: scratch.path().join("absent.sock"),
                token: "unused".to_owned(),
                stopped: true,
            },
            lease: super::ProjectionLeaseTarget {
                mount_id: astrid_core::storage_provider::StorageMountId::new(),
                target: binding.targets.workspace.clone(),
            },
        },
        shared: None,
        mount_root: scratch.path().join("mount-root"),
        cleaned: false,
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_stop_returns_rollback_promptly_when_descendant_holds_stderr() {
    use tokio::io::AsyncWriteExt as _;

    let scratch = tempfile::tempdir().expect("diagnostics scratch");
    let (_home_root, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let actor = kernel
        .principal_directory
        .uid_for(&caller)
        .expect("caller actor UID");
    let binding = binding(actor);
    let key = super::ProcessProjectionKey {
        binding: binding.clone(),
        read_write: true,
    };
    let control_path = scratch.path().join("process-control.sock");
    let listener = tokio::net::UnixListener::bind(&control_path).expect("bind live endpoint");
    let responder = tokio::spawn(async move {
        for _ in 0..2 {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            if let Err(error) = stream.write_all(b"{\"status\":\"ready\"}\n").await
                && error.kind() != std::io::ErrorKind::BrokenPipe
            {
                panic!("write stop refusal: {error}");
            }
        }
    });
    let launch = diagnostics_launch(&scratch, control_path.clone());
    let (mut child, stderr_holder_pid) = spawn_child_with_inherited_stderr(&scratch).await;
    let stderr_task = child.stderr.take().map(|mut stderr| {
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt as _;

            let mut bytes = Vec::new();
            let _ = stderr.read_to_end(&mut bytes).await;
            bytes
        })
    });

    let started = tokio::time::Instant::now();
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        abort_process_provider(
            child,
            &launch,
            "diagnostics deadline".to_owned(),
            stderr_task,
        ),
    )
    .await
    .expect("failed STOP/reap must not wait for the unrelated stderr holder");
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "rollback input took {elapsed:?}"
    );
    assert!(!error.cleanup_ok, "the live endpoint must retain the child");
    assert!(error.child.is_some(), "failed STOP/reap retains the child");

    let cleanup_state = retained_cleanup_state(
        &kernel,
        &binding,
        error.child,
        control_path.clone(),
        &scratch,
    );
    let mut projections = BTreeMap::new();
    rollback_or_retain_failed_launch(
        &mut projections,
        &key,
        scratch.path().join("workspace"),
        scratch.path().join("owner"),
        None,
        cleanup_state,
    )
    .await;
    responder
        .await
        .expect("stop responder completed without a panic");
    let projection = Arc::clone(projections.get(&key).expect("authoritative blocker"));
    assert!(
        projection
            .cleanup_failed
            .load(std::sync::atomic::Ordering::Acquire)
    );

    let _ = std::process::Command::new("kill")
        .arg(stderr_holder_pid.to_string())
        .status();
}

#[cfg(unix)]
#[tokio::test]
async fn stderr_pid_readiness_ignores_an_initially_empty_file() {
    let scratch = tempfile::tempdir().expect("PID scratch");
    let pid_path = scratch.path().join("stderr-holder.pid");
    std::fs::write(&pid_path, b"").expect("create empty PID file");
    let writer = tokio::spawn({
        let pid_path = pid_path.clone();
        async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            std::fs::write(&pid_path, b"123\n").expect("write stderr-holder PID");
        }
    });

    let pid = wait_for_reported_pid(&pid_path)
        .await
        .expect("empty PID file is not ready content");
    writer.await.expect("PID writer");
    assert_eq!(pid, 123);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parent_token_failures_do_not_accumulate_uuid_mount_roots() {
    // The fault slot is process-global, so exercise the owner and Fleet
    // ordinals in one deterministic sequence instead of racing two tests.
    for slot in [ParentTokenSlot::OwnerHome, ParentTokenSlot::FleetShared] {
        assert_parent_token_rollback(slot).await;
    }
}

async fn assert_parent_token_rollback(slot: ParentTokenSlot) {
    let (_temporary, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));

    arm_parent_token_failure(slot, 1);
    let Err(error) = PROCESS_MOUNT_TEST_ID.scope(1, broker.mount(&caller)).await else {
        panic!("the selected parent token must fail before lease publication");
    };

    assert!(
        error.contains("injected parent token failure"),
        "unexpected mount error: {error}"
    );
    assert!(
        kernel.storage_mounts.is_empty(),
        "no branch, owner, or Fleet shared lease may survive"
    );
    let process_root = kernel.astrid_home.run_dir().join("process-storage");
    assert!(
        !process_root.exists(),
        "a pre-publication failure must not allocate or retain a mount-root parent"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_publication_launch_failure_revokes_branch_owner_and_fleet_leases() {
    let (_temporary, kernel) = fleet_shared_kernel().await;
    let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    let caller = PrincipalId::default();

    arm_launch_failure(ProcessLaunchStage::Branch, 2);
    let Err(error) = PROCESS_MOUNT_TEST_ID.scope(2, broker.mount(&caller)).await else {
        panic!("the injected launch-stage fault must fail provider startup");
    };

    assert!(
        error.contains("injected post-publication launch failure"),
        "unexpected launch error: {error}"
    );
    assert!(
        kernel.storage_mounts.is_empty(),
        "branch, owner-home, and Fleet-shared leases must all be revoked"
    );
    assert!(
        broker.projections.lock().await.is_empty(),
        "successful rollback must not retain a retry blocker"
    );
    let process_root = kernel.astrid_home.run_dir().join("process-storage");
    assert!(
        process_root
            .read_dir()
            .expect("process storage root")
            .next()
            .is_none(),
        "successful cleanup must remove the UUID mount root"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_stop_retains_blocker_until_provider_cleanup_succeeds() {
    use std::os::unix::net::UnixListener;

    use std::io::Write as _;

    use super::{ProjectionLeaseProvider, ProjectionLeaseTarget, RunningProvider};

    let temporary = tempfile::tempdir().expect("test home root");
    let home = AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = Arc::new(crate::test_kernel_with_home(home).await);
    let caller = PrincipalId::default();
    let actor = kernel
        .principal_directory
        .uid_for(&caller)
        .expect("caller actor UID");
    let binding = binding(actor);
    let key = super::ProcessProjectionKey {
        binding: binding.clone(),
        read_write: true,
    };
    let mount_root = temporary.path().join("process-mount");
    std::fs::create_dir_all(&mount_root).expect("create retained mount root");
    let control_path = mount_root.join("process-control.sock");
    let listener =
        Arc::new(UnixListener::bind(&control_path).expect("bind live provider endpoint"));
    let responder_listener = Arc::clone(&listener);
    let responder = tokio::task::spawn_blocking(move || {
        let (mut stream, _) = responder_listener.accept().expect("accept stop request");
        stream
            .write_all(b"{\"status\":\"ready\"}\n")
            .expect("write stop refusal");
    });
    let child = tokio::process::Command::new("true")
        .spawn()
        .expect("spawn exited test child");
    let cleanup_state = super::ProjectionCleanupState {
        kernel: Arc::downgrade(&kernel),
        binding: binding.clone(),
        branch: ProjectionLeaseProvider {
            running: RunningProvider {
                child: Some(child),
                control_path: control_path.clone(),
                token: "test-token".to_owned(),
                stopped: false,
            },
            lease: ProjectionLeaseTarget {
                mount_id: astrid_core::storage_provider::StorageMountId::new(),
                target: binding.targets.owner_home.clone(),
            },
        },
        owner: ProjectionLeaseProvider {
            running: RunningProvider {
                child: None,
                control_path: mount_root.join("absent.sock"),
                token: "test-token".to_owned(),
                stopped: true,
            },
            lease: ProjectionLeaseTarget {
                mount_id: astrid_core::storage_provider::StorageMountId::new(),
                target: binding.targets.workspace.clone(),
            },
        },
        shared: None,
        mount_root: mount_root.clone(),
        cleaned: false,
    };
    let mut projections = BTreeMap::new();
    retain_failed_launch_projection(
        &mut projections,
        &key,
        temporary.path().join("workspace"),
        temporary.path().join("owner"),
        None,
        cleanup_state,
    );

    let projection = Arc::clone(projections.get(&key).expect("retained blocker"));
    let mut guard = projections;
    let stopped = retry_failed_projection(&projection, &mut guard, &key).await;
    responder.await.expect("stop responder");
    assert!(!stopped, "a provider that remained ready must stay blocked");
    assert!(
        guard.contains_key(&key),
        "otherwise-successful lease cleanup must not remove the unreaped-provider blocker"
    );
    assert!(
        kernel.storage_mounts.is_empty(),
        "the blocker must remain authoritative without a live lease"
    );

    drop(std::fs::File::open(&control_path));
    std::fs::remove_file(&control_path).expect("remove stopped provider endpoint");
    assert!(
        retry_failed_projection(&projection, &mut guard, &key).await,
        "retry must complete after the provider endpoint is gone"
    );
    assert!(!guard.contains_key(&key));
    assert!(!mount_root.exists());
}
