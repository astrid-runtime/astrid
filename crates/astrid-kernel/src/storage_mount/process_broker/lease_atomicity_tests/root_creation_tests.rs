//! A real UUID root that fails private validation remains an exact retry key.

use std::sync::Arc;

use astrid_capsule::context::ProcessStorageMountBroker as _;
use astrid_core::PrincipalId;

use super::super::{
    KernelProcessStorageMountBroker, PROCESS_MOUNT_TEST_ID,
    arm_mount_root_creation_failure_for_test, fail_next_root_removal_for_test,
};
use super::{fleet_shared_kernel, process_provider_test_lane_enabled};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn created_mount_root_failure_retains_and_admits_after_exact_retry() {
    if !process_provider_test_lane_enabled() {
        println!("skipping created-root retry admission: provider unavailable");
        return;
    }
    let test_id = 511_u64;
    let (_temporary, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    arm_mount_root_creation_failure_for_test(test_id);

    let Err(failure) = PROCESS_MOUNT_TEST_ID
        .scope(test_id, broker.mount(&caller))
        .await
    else {
        panic!("the created mount-root fault must fail admission");
    };
    assert!(
        failure.contains("injected post-creation mount-root validation failure"),
        "unexpected mount-root validation exit: {failure}"
    );
    assert!(failure.contains("process storage path preparation failed"));

    let process_root = kernel.astrid_home.run_dir().join("process-storage");
    let stale_root = sole_child(&process_root);
    assert_root_blocker(&broker, &kernel, &stale_root).await;

    fail_next_root_removal_for_test(stale_root.clone());
    let Err(denied) = broker.mount(&caller).await else {
        panic!("the retained root must deny replacement before exact cleanup");
    };
    assert!(
        denied.contains("requires administrative cleanup"),
        "unexpected retained-root denial: {denied}"
    );
    assert_root_blocker(&broker, &kernel, &stale_root).await;

    let replacement = PROCESS_MOUNT_TEST_ID
        .scope(test_id, broker.mount(&caller))
        .await
        .unwrap_or_else(|error| {
            panic!("exact root cleanup must admit a fresh projection: {error}")
        });
    assert_ne!(
        replacement.workspace_root.parent(),
        Some(stale_root.as_path())
    );
    assert!(!stale_root.exists());
    replacement.close_async().await;
    assert!(broker.projections.lock().await.is_empty());
    assert!(kernel.storage_mounts.is_empty());
    assert!(sole_child_option(&process_root).is_none());
}

async fn assert_root_blocker(
    broker: &KernelProcessStorageMountBroker,
    kernel: &Arc<crate::Kernel>,
    stale_root: &std::path::Path,
) {
    assert!(stale_root.is_dir(), "the failed UUID root must remain");
    assert!(
        kernel.storage_mounts.is_empty(),
        "a pre-issue root blocker must retain no component leases"
    );
    let projections = broker.projections.lock().await;
    assert_eq!(projections.len(), 1);
    let projection = projections.values().next().expect("root blocker");
    assert!(projection.component_mount_ids.is_empty());
    assert!(
        projection
            .cleanup_failed
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert_eq!(projection.workspace_mountpoint.parent(), Some(stale_root));
}

fn sole_child(root: &std::path::Path) -> std::path::PathBuf {
    sole_child_option(root).expect("one retained UUID root")
}

fn sole_child_option(root: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut entries = std::fs::read_dir(root)
        .expect("read process storage root")
        .map(|entry| entry.expect("process storage entry").path());
    let child = entries.next();
    assert!(
        entries.next().is_none(),
        "process storage root must stay exact"
    );
    child
}
