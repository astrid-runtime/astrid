//! UUID-root creation and mountpoint preparation failures remain retryable.

use std::sync::Arc;

use astrid_capsule::context::ProcessStorageMountBroker as _;
use astrid_core::PrincipalId;

use super::super::{
    KernelProcessStorageMountBroker, PROCESS_MOUNT_TEST_ID, ProcessLaunchStage,
    arm_preparation_failure_for_test, fleet_shared_kernel,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mountpoint_preparation_failure_retains_root_until_exact_retry() {
    if !super::super::process_provider_test_lane_enabled() {
        println!("skipping preparation retry: coinstalled native provider unavailable");
        return;
    }
    for (stage, test_id) in [
        (ProcessLaunchStage::Branch, 501_u64),
        (ProcessLaunchStage::OwnerHome, 502),
        (ProcessLaunchStage::FleetShared, 503),
    ] {
        let (_temporary, kernel) = fleet_shared_kernel().await;
        let caller = PrincipalId::default();
        let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
        arm_preparation_failure_for_test(stage, test_id);

        let Err(issue_error) = PROCESS_MOUNT_TEST_ID
            .scope(test_id, broker.mount(&caller))
            .await
        else {
            panic!("the {stage:?} preparation fault must fail admission");
        };
        assert!(
            issue_error.contains("preparation fault"),
            "{stage:?} must expose the production preparation exit: {issue_error}"
        );
        let process_root = kernel.astrid_home.run_dir().join("process-storage");
        let blocker_root = process_root
            .read_dir()
            .expect("process storage root")
            .next()
            .expect("retained UUID root")
            .unwrap()
            .path();
        assert_eq!(kernel.storage_mounts.len(), 0);
        assert!(blocker_root.is_dir());
        {
            let projections = broker.projections.lock().await;
            assert_eq!(projections.len(), 1);
            let projection = projections.values().next().expect("blocker");
            assert!(projection.component_mount_ids.is_empty());
            assert!(
                projection
                    .cleanup_failed
                    .load(std::sync::atomic::Ordering::Acquire)
            );
            assert_eq!(
                projection.workspace_mountpoint.parent(),
                Some(blocker_root.as_path())
            );
        }
        let Err(denied) = broker.mount(&caller).await else {
            panic!("{stage:?} retained preparation blocker must deny replacement");
        };
        assert!(denied.contains("requires administrative cleanup"));
        assert!(blocker_root.exists());

        let replacement_mount = PROCESS_MOUNT_TEST_ID
            .scope(test_id + 1000, broker.mount(&caller))
            .await
            .unwrap_or_else(|error| {
                panic!("{stage:?} exact retry must clear preparation blocker: {error}")
            });
        assert!(!blocker_root.exists());
        assert_eq!(kernel.storage_mounts.len(), 3);
        replacement_mount.close_async().await;
        assert!(broker.projections.lock().await.is_empty());
        assert!(kernel.storage_mounts.is_empty());
    }
}
