//! STOP/reap failure retention for a real provider endpoint.

use std::collections::BTreeMap;
use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;

use super::{
    ProcessProjectionKey, ProjectionCleanupState, binding, retain_failed_launch_projection,
    retry_failed_projection,
};

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_stop_retains_blocker_until_provider_cleanup_succeeds() {
    use std::io::Write as _;
    use std::os::unix::net::UnixListener;

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
    let key = ProcessProjectionKey {
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
    let cleanup_state = ProjectionCleanupState {
        kernel: Arc::downgrade(&kernel),
        stop_policy: crate::storage_mount::process_broker::ProcessStopPolicy::default(),
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
