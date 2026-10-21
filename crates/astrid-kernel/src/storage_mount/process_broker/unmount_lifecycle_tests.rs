//! Mount inspection failure must retain the root and permit a later exact retry.

use super::*;

#[tokio::test]
async fn inspection_failure_retains_projection_root_until_retry_succeeds() {
    let temporary = tempfile::tempdir().expect("test home");
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = crate::test_kernel_with_home(home).await;
    let actor = kernel
        .principal_directory
        .uid_for(&PrincipalId::default())
        .expect("default principal UID");
    let owner = StateOwner::Principal(actor);
    let binding = ProcessProjectionBinding::new(
        owner,
        actor,
        ProjectionGeneration::capture().expect("generation"),
        ProcessProjectionTargetSet::branch(
            owner,
            actor,
            astrid_core::WorkspaceUid::from_bytes([0x73; 16]),
            None,
        )
        .expect("targets"),
    )
    .expect("binding");
    let mount_root = temporary.path().join("projection");
    std::fs::create_dir(&mount_root).expect("projection root");
    let provider = |target, name| ProjectionLeaseProvider {
        running: RunningProvider {
            child: None,
            control_path: mount_root.join(name),
            token: "unused-after-stop".to_owned(),
            stopped: true,
        },
        lease: ProjectionLeaseTarget {
            mount_id: StorageMountId::new(),
            target,
        },
    };
    let state = Arc::new(tokio::sync::Mutex::new(ProjectionCleanupState {
        kernel: Arc::downgrade(&kernel),
        stop_policy: ProcessStopPolicy::default(),
        branch: provider(binding.targets.workspace.clone(), "branch.sock"),
        owner: provider(binding.targets.owner_home.clone(), "owner.sock"),
        shared: None,
        binding,
        paths: ProjectionMountPaths {
            mount_root: mount_root.clone(),
            // NUL cannot name a native mount. Inspect errors must not be
            // treated as absence, even after providers are confirmed stopped.
            workspace: PathBuf::from("invalid\0mount"),
            owner: mount_root.join("owner"),
            fleet_shared: None,
        },
        cleaned: false,
    }));
    assert!(
        !cleanup_projection_state(Arc::clone(&state)).await,
        "inspection error must block destructive cleanup"
    );
    assert!(
        mount_root.exists(),
        "failed inspection retains projection root"
    );
    assert!(
        !state.lock().await.cleaned,
        "failed cleanup remains retryable"
    );
    state.lock().await.paths.workspace = mount_root.join("workspace");
    assert!(
        cleanup_projection_state(state).await,
        "same stopped provider set is reclaimable after inspection succeeds"
    );
    assert!(
        !mount_root.exists(),
        "successful retry removes projection root"
    );
}
