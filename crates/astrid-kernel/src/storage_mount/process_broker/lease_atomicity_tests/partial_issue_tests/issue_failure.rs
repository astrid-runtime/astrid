//! Provider-identity failures after one or two leases are issued.

use std::sync::Arc;

use astrid_capsule::context::ProcessStorageMountBroker as _;
use astrid_core::PrincipalId;

use super::super::{
    KernelProcessStorageMountBroker, PROCESS_MOUNT_TEST_ID, ProcessLaunchStage,
    arm_partial_issue_failure, fleet_shared_kernel,
};
use super::fixtures::{assert_retained_issue_authority, expected_lease_count};

async fn assert_partial_issue_retains_exact_authority(stage: ProcessLaunchStage, test_id: u64) {
    if !super::super::process_provider_test_lane_enabled() {
        println!("skipping {stage:?} retained issue cleanup retry: provider unavailable");
        return;
    }
    let (_temporary, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    let replacement_broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    arm_partial_issue_failure(stage, test_id);

    let Err(issue_error) = PROCESS_MOUNT_TEST_ID
        .scope(test_id, broker.mount(&caller))
        .await
    else {
        panic!("the selected {stage:?} issue fault must fail admission");
    };
    assert!(
        issue_error.contains("native storage provider identity is invalid"),
        "unexpected {stage:?} issue error: {issue_error}"
    );
    assert_retained_issue_authority(&kernel, stage);

    {
        let projections = broker.projections.lock().await;
        assert_eq!(projections.len(), 1);
        let projection = projections.values().next().expect("authoritative blocker");
        assert!(
            projection
                .cleanup_failed
                .load(std::sync::atomic::Ordering::Acquire)
        );
    }
    let Err(blocked_retry) = broker.mount(&caller).await else {
        panic!("{stage:?} persistent cleanup fault must block the first retry");
    };
    assert!(
        blocked_retry.contains("requires administrative cleanup"),
        "unexpected persistent retry error: {blocked_retry}"
    );
    assert_eq!(
        kernel.storage_mounts.len(),
        expected_lease_count(stage),
        "a blocked retry must not unmap retained authority"
    );
    let Err(replacement_error) = replacement_broker.mount(&caller).await else {
        panic!("{stage:?} replacement must be denied while cleanup is retained");
    };
    assert!(replacement_error.starts_with("existing process projection lease "));

    for state in kernel
        .storage_mounts
        .iter()
        .map(|entry| entry.value().clone())
    {
        crate::storage_mount::clear_cleanup_fault_for_test(&state);
    }
    let replacement_mount = PROCESS_MOUNT_TEST_ID
        .scope(test_id, broker.mount(&caller))
        .await
        .unwrap_or_else(|error| {
            panic!("{stage:?} provider-lane cleanup retry must create a replacement: {error}")
        });
    assert_eq!(kernel.storage_mounts.len(), 3);
    replacement_mount.close_async().await;
    assert!(broker.projections.lock().await.is_empty());
    assert!(kernel.storage_mounts.is_empty());
    assert!(
        kernel
            .astrid_home
            .run_dir()
            .join("process-storage")
            .read_dir()
            .expect("process storage root after retry")
            .next()
            .is_none()
    );

    let independent_replacement = PROCESS_MOUNT_TEST_ID
        .scope(
            test_id.saturating_add(1000),
            replacement_broker.mount(&caller),
        )
        .await
        .unwrap_or_else(|error| {
            panic!("{stage:?} independent replacement must be admitted after cleanup: {error}")
        });
    assert_eq!(kernel.storage_mounts.len(), 3);
    independent_replacement.close_async().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_home_issue_failure_retains_and_retries_exact_cleanup() {
    assert_partial_issue_retains_exact_authority(ProcessLaunchStage::OwnerHome, 401).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fleet_shared_issue_failure_retains_and_retries_exact_cleanup() {
    assert_partial_issue_retains_exact_authority(ProcessLaunchStage::FleetShared, 402).await;
}
