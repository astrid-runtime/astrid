//! Successful lease rollback followed by failed UUID-root removal.

use std::sync::Arc;

use astrid_capsule::context::ProcessStorageMountBroker as _;
use astrid_core::PrincipalId;

use super::super::super::fail_next_root_removal_for_test;
use super::super::{
    KernelProcessStorageMountBroker, PROCESS_MOUNT_TEST_ID, ProcessLaunchStage,
    arm_issue_root_removal_failure_for_test, arm_partial_issue_provider_error_for_test,
    fleet_shared_kernel,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_issue_root_removal_retains_a_bounded_retry_blocker() {
    for (stage, test_id) in [
        (ProcessLaunchStage::Branch, 411_u64),
        (ProcessLaunchStage::OwnerHome, 412),
        (ProcessLaunchStage::FleetShared, 413),
    ] {
        assert_root_removal_blocker(stage, test_id).await;
    }
}

async fn assert_root_removal_blocker(stage: ProcessLaunchStage, test_id: u64) {
    let (_temporary, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    arm_partial_issue_provider_error_for_test(stage, test_id);
    arm_issue_root_removal_failure_for_test(test_id);

    let Err(issue_error) = PROCESS_MOUNT_TEST_ID
        .scope(test_id, broker.mount(&caller))
        .await
    else {
        panic!("the selected {stage:?} issue error must enter production rollback");
    };
    assert!(issue_error.contains("native storage provider identity is invalid"));
    assert!(issue_error.contains("process mount root cleanup failed"));
    assert_eq!(kernel.storage_mounts.len(), 0);

    let stale_root = kernel
        .astrid_home
        .run_dir()
        .join("process-storage")
        .read_dir()
        .expect("process storage root")
        .next()
        .expect("root-faulted UUID projection")
        .unwrap()
        .path();
    {
        let projections = broker.projections.lock().await;
        assert_eq!(projections.len(), 1, "{stage:?} must retain one blocker");
        let projection = projections.values().next().expect("root blocker");
        assert!(
            projection
                .cleanup_failed
                .load(std::sync::atomic::Ordering::Acquire)
        );
        assert_eq!(
            projection.component_mount_ids.len(),
            expected_issue_lease_count(stage),
            "{stage:?} blocker must carry its exact issued component set"
        );
        assert!(stale_root.exists());
    }

    fail_next_root_removal_for_test(stale_root.clone());
    let Err(denied) = broker.mount(&caller).await else {
        panic!("{stage:?} retained root blocker must deny replacement");
    };
    assert!(denied.contains("requires administrative cleanup"));
    assert_eq!(kernel.storage_mounts.len(), 0);
    assert!(stale_root.exists());
    assert_eq!(broker.projections.lock().await.len(), 1);

    if !super::super::process_provider_test_lane_enabled() {
        let Err(retry_error) = broker.mount(&caller).await else {
            panic!("{stage:?} retry must require a provider for replacement admission");
        };
        assert!(retry_error.contains("inspect coinstalled storage provider"));
        assert!(!stale_root.exists());
        assert!(kernel.storage_mounts.is_empty());
        assert!(broker.projections.lock().await.is_empty());
        println!("skipping {stage:?} fresh replacement admission: provider unavailable");
        return;
    }
    let replacement_mount = PROCESS_MOUNT_TEST_ID
        .scope(test_id.saturating_add(1000), broker.mount(&caller))
        .await
        .unwrap_or_else(|error| {
            panic!("{stage:?} exact retry must clear the root and admit: {error}")
        });
    assert!(!stale_root.exists());
    assert_eq!(kernel.storage_mounts.len(), 3);
    replacement_mount.close_async().await;
    assert!(kernel.storage_mounts.is_empty());
    assert!(broker.projections.lock().await.is_empty());
}

fn expected_issue_lease_count(stage: ProcessLaunchStage) -> usize {
    match stage {
        ProcessLaunchStage::Branch => 0,
        ProcessLaunchStage::OwnerHome => 1,
        ProcessLaunchStage::FleetShared => 2,
    }
}
