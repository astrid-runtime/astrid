use std::collections::BTreeMap;
use std::sync::Arc;

use astrid_capsule::context::ProcessStorageMountBroker as _;
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::storage_filesystem::{
    STORAGE_FILESYSTEM_PROTOCOL_V1, StorageFilesystemOperationV1, StorageFilesystemResponseV1,
};
use astrid_core::storage_provider::StorageMountId;
use astrid_storage::StateOwner;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{
    KernelProcessStorageMountBroker, PROCESS_MOUNT_TEST_ID, ParentTokenSlot,
    ProcessProjectionBinding, ProcessProjectionKey, ProcessProjectionTargetSet,
    ProjectionGeneration, arm_parent_token_failure, blocked_projection_lease,
    retain_failed_launch_projection, retry_failed_projection, rollback_or_retain_failed_launch,
};

mod cache_invalidation_tests;
mod exact_fence_tests;
mod partial_issue_tests;
mod stopped_provider_tests;

pub(crate) use super::projection_lifecycle::fence_projection_leases_for_test;
pub(crate) use super::{
    ProjectionCleanupState, ProjectionLeaseProvider, ProjectionLeaseTarget, RunningProvider,
    arm_partial_issue_failure,
};
use super::{
    abort_process_provider, arm_launch_cleanup_failure, arm_launch_failure,
    process_launch::{
        ProcessLaunchStage, published_provider_leases, release_launch_cleanup_failure,
        spawned_provider_pids,
    },
};

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

fn expected_prior_stages(stage: ProcessLaunchStage) -> &'static [ProcessLaunchStage] {
    match stage {
        ProcessLaunchStage::Branch => unreachable!("branch cannot have prior provider stages"),
        ProcessLaunchStage::OwnerHome => &[ProcessLaunchStage::Branch],
        ProcessLaunchStage::FleetShared => {
            &[ProcessLaunchStage::Branch, ProcessLaunchStage::OwnerHome]
        },
    }
}

fn expected_lease_count(stage: ProcessLaunchStage) -> usize {
    // A Fleet projection publishes all three leases before provider launch.
    match stage {
        ProcessLaunchStage::Branch
        | ProcessLaunchStage::OwnerHome
        | ProcessLaunchStage::FleetShared => 3,
    }
}

#[cfg(unix)]
fn provider_pid_is_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .is_ok_and(|output| output.status.success())
}

#[cfg(windows)]
fn provider_pid_is_alive(pid: u32) -> bool {
    let Ok(output) = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
        .output()
    else {
        return false;
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    !stdout.contains("INFO:") && stdout.contains(&format!("\"{pid}\""))
}

fn assert_recorded_pids_reaped(stage: ProcessLaunchStage, test_id: u64) {
    let pids = spawned_provider_pids(test_id);
    assert_eq!(
        pids.len(),
        expected_prior_stages(stage).len(),
        "{stage:?} must record a PID for each prior real provider child"
    );
    assert_eq!(
        pids.keys().copied().collect::<Vec<_>>(),
        expected_prior_stages(stage),
        "{stage:?} must spawn exactly its prior stages"
    );
    for (prior_stage, pid) in pids {
        assert!(
            !provider_pid_is_alive(pid),
            "{prior_stage:?} prior provider PID {pid} must be reaped"
        );
    }
}

fn assert_published_leases_revoked(
    kernel: &Arc<crate::Kernel>,
    stage: ProcessLaunchStage,
    test_id: u64,
) {
    let published = published_provider_leases(test_id);
    assert_eq!(
        published.len(),
        expected_lease_count(stage),
        "{stage:?} must observe every published lease"
    );
    assert!(
        published
            .values()
            .all(|mount_id| !kernel.storage_mounts.contains_key(mount_id)),
        "{stage:?} launch rollback must revoke every exact published lease"
    );
    assert_eq!(
        kernel.storage_mounts.len(),
        0,
        "{stage:?} launch rollback must leave no other live lease"
    );
}

async fn assert_authenticated_callback_denied(
    kernel: &Arc<crate::Kernel>,
    mount_id: astrid_core::storage_provider::StorageMountId,
) {
    let (callback_path, token) = {
        let lease = kernel
            .storage_mounts
            .get(&mount_id)
            .expect("retained exact lease");
        lease.callback_identity_for_test()
    };
    let mut stream = astrid_core::local_transport::connect(&callback_path)
        .await
        .expect("connect retained lease callback");
    let request = astrid_core::storage_filesystem::StorageFilesystemRequestV1 {
        protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V1,
        request_id: "retained-authority-replay".to_owned(),
        lease_token: token,
        operation: StorageFilesystemOperationV1::Stat {
            path: String::new(),
        },
    };
    let bytes = serde_json::to_vec(&request).expect("encode retained callback replay");
    stream
        .write_all(
            &u32::try_from(bytes.len())
                .expect("bounded retained callback replay")
                .to_be_bytes(),
        )
        .await
        .expect("send retained callback replay");
    stream
        .write_all(&bytes)
        .await
        .expect("send retained callback payload");
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .await
        .expect("read retained callback response length");
    let mut payload = vec![0_u8; u32::from_be_bytes(length) as usize];
    stream
        .read_exact(&mut payload)
        .await
        .expect("read retained callback response");
    let response: StorageFilesystemResponseV1 =
        serde_json::from_slice(&payload).expect("decode retained callback response");
    assert!(
        matches!(
            response.outcome,
            astrid_core::storage_filesystem::StorageFilesystemOutcomeV1::Failure(
                ref failure
            ) if failure.code == "stale-lease"
        ),
        "retained authenticated callback must be stale-lease denied: {:?}",
        response.outcome
    );
}

async fn assert_real_launch_rollback(stage: ProcessLaunchStage, test_id: u64) {
    let (_temporary, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    let process_root = kernel.astrid_home.run_dir().join("process-storage");
    arm_launch_failure(stage, test_id);
    let Err(error) = PROCESS_MOUNT_TEST_ID
        .scope(test_id, broker.mount(&caller))
        .await
    else {
        panic!("the selected {stage:?} launch fault must fail provider startup");
    };
    assert!(
        error.contains("injected post-publication launch failure"),
        "unexpected {stage:?} launch error: {error}"
    );

    assert_recorded_pids_reaped(stage, test_id);
    assert_published_leases_revoked(&kernel, stage, test_id);
    assert!(
        broker.projections.lock().await.is_empty(),
        "{stage:?} successful rollback must not retain a blocker"
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

struct RetainedLaunchProof<'a> {
    kernel: &'a Arc<crate::Kernel>,
    broker: &'a KernelProcessStorageMountBroker,
    replacement_broker: &'a KernelProcessStorageMountBroker,
    caller: &'a PrincipalId,
    stage: ProcessLaunchStage,
    test_id: u64,
}

async fn assert_retained_authority_before_retry(
    proof: &RetainedLaunchProof<'_>,
    published: &BTreeMap<ProcessLaunchStage, StorageMountId>,
    published_ids: &[StorageMountId],
) -> ProcessProjectionKey {
    let stage = proof.stage;
    let kernel = proof.kernel;
    let broker = proof.broker;
    let replacement_broker = proof.replacement_broker;
    let caller = proof.caller;
    assert_eq!(
        published.len(),
        expected_lease_count(stage),
        "{stage:?} must retain every published lease when cleanup fails"
    );
    assert_eq!(
        kernel.storage_mounts.len(),
        expected_lease_count(stage),
        "{stage:?} retained failure must retain every exact revoked lease"
    );
    for mount_id in published_ids {
        assert_authenticated_callback_denied(kernel, *mount_id).await;
    }
    let process_root = kernel.astrid_home.run_dir().join("process-storage");
    assert_eq!(
        process_root
            .read_dir()
            .expect("retained process storage root")
            .count(),
        1,
        "{stage:?} retained failure must preserve the UUID root"
    );

    let projections = broker.projections.lock().await;
    assert_eq!(
        projections.len(),
        1,
        "{stage:?} failed cleanup must retain one authoritative blocker"
    );
    let projection = projections.values().next().expect("authoritative blocker");
    assert!(
        projection
            .cleanup_failed
            .load(std::sync::atomic::Ordering::Acquire),
        "{stage:?} failed endpoint cleanup must retain the blocker"
    );
    let key = projections
        .keys()
        .next()
        .expect("retained projection key")
        .clone();
    let projection = Arc::clone(projection);
    drop(projections);
    let mut retained_projections = broker.projections.lock().await.clone();
    assert!(
        !retry_failed_projection(&projection, &mut retained_projections, &key).await,
        "{stage:?} authoritative retry must remain blocked by the live endpoint"
    );

    let Err(replacement_error) = replacement_broker.mount(caller).await else {
        panic!("{stage:?} replacement must be denied while cleanup is retained");
    };
    assert!(
        replacement_error.starts_with("existing process projection lease "),
        "unexpected replacement denial for {stage:?}: {replacement_error}"
    );
    assert_eq!(
        kernel.storage_mounts.len(),
        expected_lease_count(stage),
        "{stage:?} denied replacement must retain revoked authority"
    );
    key
}

async fn assert_retry_releases_authority(
    proof: &RetainedLaunchProof<'_>,
    key: &ProcessProjectionKey,
    published: &BTreeMap<ProcessLaunchStage, StorageMountId>,
    published_ids: &[StorageMountId],
) {
    let stage = proof.stage;
    let kernel = proof.kernel;
    let broker = proof.broker;
    let caller = proof.caller;
    release_launch_cleanup_failure(proof.test_id).await;
    let failed_callback_path = {
        let lease = kernel
            .storage_mounts
            .get(published.get(&stage).expect("failed published lease"))
            .expect("failed exact lease remains retained until retry");
        lease.callback_identity_for_test().0
    };

    #[cfg(unix)]
    std::fs::remove_file(
        failed_callback_path
            .parent()
            .expect("failed provider resource root")
            .join("process-control.sock"),
    )
    .expect("release retained provider endpoint");
    #[cfg(windows)]
    assert!(
        !astrid_core::local_transport::endpoint_is_present(
            &failed_callback_path
                .parent()
                .expect("failed provider resource root")
                .join("process-control.sock"),
        )
        .expect("inspect released Windows provider endpoint"),
        "Windows provider endpoint must disappear when its responder drops"
    );
    let Err(retry_error) = broker.mount(caller).await else {
        panic!("retry must pass authority, then reach the absent unit-test provider");
    };
    assert!(
        retry_error.contains("inspect coinstalled storage provider"),
        "unexpected post-authority retry error for {stage:?}: {retry_error}"
    );
    assert!(
        broker.projections.lock().await.is_empty(),
        "{stage:?} successful retry must remove the retained blocker"
    );
    assert!(
        published_ids
            .iter()
            .all(|mount_id| !kernel.storage_mounts.contains_key(mount_id)),
        "{stage:?} successful retry must remove every exact revoked lease"
    );
    assert_eq!(
        kernel.storage_mounts.len(),
        0,
        "{stage:?} successful retry must leave no live authority"
    );
    assert!(
        blocked_projection_lease(kernel, &key.binding).is_none(),
        "{stage:?} replacement admission must no longer be blocked"
    );
    assert!(
        kernel
            .astrid_home
            .run_dir()
            .join("process-storage")
            .read_dir()
            .expect("process storage root after retry")
            .next()
            .is_none(),
        "{stage:?} successful retry must remove the retained UUID root"
    );
}

async fn assert_real_launch_retains_blocker(stage: ProcessLaunchStage, test_id: u64) {
    let (_temporary, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    let replacement_broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    arm_launch_cleanup_failure(stage, test_id);
    let Err(error) = PROCESS_MOUNT_TEST_ID
        .scope(test_id, broker.mount(&caller))
        .await
    else {
        panic!("the selected {stage:?} launch fault must fail provider startup");
    };
    assert!(
        error.contains("injected retained-endpoint launch failure"),
        "unexpected {stage:?} launch error: {error}"
    );
    assert_recorded_pids_reaped(stage, test_id);

    let published = published_provider_leases(test_id);
    let published_ids = published.values().copied().collect::<Vec<_>>();
    let proof = RetainedLaunchProof {
        kernel: &kernel,
        broker: &broker,
        replacement_broker: &replacement_broker,
        caller: &caller,
        stage,
        test_id,
    };
    let key = assert_retained_authority_before_retry(&proof, &published, &published_ids).await;
    assert_retry_releases_authority(&proof, &key, &published, &published_ids).await;
}

#[tokio::test]
async fn launch_failure_selector_is_stage_specific_and_single_shot() {
    arm_launch_failure(ProcessLaunchStage::FleetShared, 91);
    arm_launch_failure(ProcessLaunchStage::Branch, 92);

    assert!(
        !super::process_launch::launch_failure_matches(ProcessLaunchStage::OwnerHome, 91),
        "test 91's Fleet fault must not consume an OwnerHome launch"
    );
    assert!(
        !super::process_launch::launch_failure_matches(ProcessLaunchStage::Branch, 91),
        "test 91's Fleet fault must not consume a Branch launch"
    );
    assert!(
        super::process_launch::launch_failure_matches(ProcessLaunchStage::FleetShared, 91),
        "test 91's Fleet fault must consume only its own matching launch"
    );
    assert!(
        !super::process_launch::launch_failure_matches(ProcessLaunchStage::FleetShared, 91),
        "a launch fault must be single-shot"
    );
    assert!(
        super::process_launch::launch_failure_matches(ProcessLaunchStage::Branch, 92),
        "test 91 must not overwrite or consume test 92's Branch fault"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn branch_success_owner_home_fault_rolls_back_real_mount() {
    assert_real_launch_rollback(ProcessLaunchStage::OwnerHome, 201).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn branch_and_owner_success_fleet_shared_fault_rolls_back_real_mount() {
    assert_real_launch_rollback(ProcessLaunchStage::FleetShared, 202).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_home_cleanup_failure_retains_real_mount_blocker() {
    assert_real_launch_retains_blocker(ProcessLaunchStage::OwnerHome, 301).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fleet_shared_cleanup_failure_retains_real_mount_blocker() {
    assert_real_launch_retains_blocker(ProcessLaunchStage::FleetShared, 302).await;
}

struct ExactFenceFixture {
    kernel: Arc<crate::Kernel>,
    caller: PrincipalId,
    binding: ProcessProjectionBinding,
    branch: astrid_core::storage_filesystem::StorageMountLeaseV1,
    owner: astrid_core::storage_filesystem::StorageMountLeaseV1,
    shared: astrid_core::storage_filesystem::StorageMountLeaseV1,
    states: Vec<Arc<crate::storage_mount::StorageMountLeaseState>>,
    expiry_before: u64,
}

async fn exact_fence_fixture() -> ExactFenceFixture {
    let (temporary, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let actor = kernel
        .principal_directory
        .uid_for(&caller)
        .expect("caller actor UID");
    let workspace = kernel
        .workspace_branches
        .as_ref()
        .expect("workspace branch service")
        .bind(&caller)
        .await
        .expect("bind caller workspace")
        .branch;
    let fleet = kernel
        .ownership_store
        .load()
        .await
        .expect("load ownership graph")
        .principal_owner(actor)
        .expect("caller fleet assignment")
        .fleet_uid;
    let binding = binding_on(actor, StateOwner::Fleet(fleet), workspace, Some(fleet));
    let admission = crate::storage_mount::test_mount_admission(
        &kernel,
        &caller,
        crate::storage_mount::MountOwnerScope::CrossOwnerWrite,
    );
    let provider = super::process_launch::platform_process_provider_name().to_owned();
    let targets = &binding.targets;
    let mountpoints = [
        temporary.path().join("fence-branch"),
        temporary.path().join("fence-owner"),
        temporary.path().join("fence-shared"),
    ];
    let views = [
        astrid_core::storage_provider::StorageProviderViewV1::Fleet(fleet),
        astrid_core::storage_provider::StorageProviderViewV1::Principal(caller.clone()),
        astrid_core::storage_provider::StorageProviderViewV1::Fleet(fleet),
    ];
    let targets = [
        targets.workspace.durable_target(),
        targets.owner_home.durable_target(),
        targets
            .fleet_shared
            .as_ref()
            .expect("shared target")
            .durable_target(),
    ];
    let mut leases = Vec::new();
    for (((target, view), mountpoint), name) in targets
        .into_iter()
        .zip(views)
        .zip(mountpoints)
        .zip(["branch", "owner", "shared"])
    {
        leases.push(
            super::issue_lease(
                &kernel,
                &admission,
                view,
                target,
                astrid_core::storage_provider::StorageProviderAccessV1::ReadWrite,
                provider.clone(),
                mountpoint,
            )
            .await
            .unwrap_or_else(|error| panic!("issue {name} fence lease: {error}")),
        );
    }
    let states = leases
        .iter()
        .map(|lease| Arc::clone(kernel.storage_mounts.get(&lease.mount_id).unwrap().value()))
        .collect();
    let expiry_before = leases[1]
        .expires_at_epoch_secs
        .min(leases[2].expires_at_epoch_secs);
    ExactFenceFixture {
        kernel,
        caller,
        binding,
        branch: leases[0].clone(),
        owner: leases[1].clone(),
        shared: leases[2].clone(),
        states,
        expiry_before,
    }
}

async fn assert_exact_reads_and_renewals_denied(fixture: &ExactFenceFixture) {
    for state in &fixture.states {
        for operation in [
            StorageFilesystemOperationV1::Stat {
                path: String::new(),
            },
            StorageFilesystemOperationV1::Read {
                path: "denied".to_owned(),
                offset: 0,
                length: 8,
            },
            StorageFilesystemOperationV1::ReadDirectory {
                path: String::new(),
            },
        ] {
            let outcome = crate::storage_mount::execute_operation_for_test(
                fixture.kernel.as_ref(),
                state,
                operation,
            )
            .await;
            assert!(
                matches!(
                    outcome,
                    astrid_core::storage_filesystem::StorageFilesystemOutcomeV1::Failure(
                        ref failure
                    ) if failure.code == "stale-lease"
                ),
                "revoked read/stat/readdir must be denied: {outcome:?}"
            );
        }
    }
    for lease in [&fixture.owner, &fixture.shared] {
        let error = crate::storage_mount::lease_status(
            &fixture.kernel,
            &fixture.caller,
            crate::storage_mount::MountOwnerScope::CrossOwnerWrite,
            lease.mount_id,
        )
        .await
        .expect_err("revoked renewal must fail");
        assert!(error.contains("expired or revoked"), "{error}");
    }
    assert_eq!(
        fixture.states[1]
            .expires_at_epoch_secs
            .load(std::sync::atomic::Ordering::Acquire),
        fixture.expiry_before,
        "denied status must not renew"
    );
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
