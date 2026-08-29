use std::collections::BTreeMap;
use std::sync::Arc;

use astrid_capsule::context::ProcessStorageMountBroker as _;
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_storage::StateOwner;

use super::arm_launch_failure;
use super::{
    KernelProcessStorageMountBroker, PROCESS_MOUNT_TEST_ID, ParentTokenSlot,
    ProcessProjectionBinding, ProcessProjectionTargetSet, ProjectionGeneration,
    arm_parent_token_failure, retain_failed_launch_projection, retry_failed_projection,
};

fn binding(actor: astrid_core::PrincipalUid) -> ProcessProjectionBinding {
    let owner = StateOwner::Principal(actor);
    ProcessProjectionBinding::new(
        owner,
        actor,
        ProjectionGeneration::capture().expect("valid projection generation"),
        ProcessProjectionTargetSet::branch(
            owner,
            actor,
            astrid_core::WorkspaceUid::from_bytes([0xD1; 16]),
            None,
        )
        .expect("valid target set"),
    )
    .expect("valid projection binding")
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
        !process_root.exists()
            || process_root
                .read_dir()
                .expect("process storage root")
                .next()
                .is_none(),
        "a pre-publication failure must remove the ephemeral mount root"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_publication_launch_failure_revokes_branch_owner_and_fleet_leases() {
    let (_temporary, kernel) = fleet_shared_kernel().await;
    let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    let caller = PrincipalId::default();

    arm_launch_failure(2);
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
