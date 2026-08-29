//! Partial lease-issue rollback must retain retry authority.

use std::sync::Arc;

use astrid_capsule::context::ProcessStorageMountBroker as _;
use astrid_core::PrincipalId;

use super::{
    KernelProcessStorageMountBroker, PROCESS_MOUNT_TEST_ID, ProcessLaunchStage, fleet_shared_kernel,
};

fn expected_lease_count(stage: ProcessLaunchStage) -> usize {
    match stage {
        ProcessLaunchStage::OwnerHome => 1,
        ProcessLaunchStage::FleetShared => 2,
        ProcessLaunchStage::Branch => {
            unreachable!("the first issue cannot roll back a prior lease")
        },
    }
}

async fn assert_partial_issue_retains_exact_authority(stage: ProcessLaunchStage, test_id: u64) {
    let (_temporary, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    let replacement_broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    super::arm_partial_issue_failure(stage, test_id);

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
    assert_eq!(
        kernel.storage_mounts.len(),
        expected_lease_count(stage),
        "{stage:?} failed cleanup must retain every issued lease"
    );
    for entry in kernel.storage_mounts.iter() {
        let callback_path = entry.value().callback_identity_for_test().0;
        assert!(
            astrid_core::local_transport::endpoint_is_present(&callback_path).unwrap(),
            "cleanup-faulted callback endpoint must remain retained"
        );
    }
    assert_eq!(
        kernel
            .astrid_home
            .run_dir()
            .join("process-storage")
            .read_dir()
            .expect("process storage root")
            .count(),
        1,
        "{stage:?} failed cleanup must retain its exact provider root"
    );

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
    let Err(retry_error) = broker.mount(&caller).await else {
        panic!("{stage:?} cleanup retry must pass authority, then reach the absent provider");
    };
    assert!(
        retry_error.contains("inspect coinstalled storage provider"),
        "unexpected post-cleanup retry error: {retry_error}"
    );
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

    let Err(replacement_error) = replacement_broker.mount(&caller).await else {
        panic!("{stage:?} replacement must be admitted after successful exact cleanup");
    };
    assert!(
        replacement_error.contains("inspect coinstalled storage provider"),
        "replacement should reach provider discovery, not authority: {replacement_error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_home_issue_failure_retains_and_retries_exact_cleanup() {
    assert_partial_issue_retains_exact_authority(ProcessLaunchStage::OwnerHome, 401).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fleet_shared_issue_failure_retains_and_retries_exact_cleanup() {
    assert_partial_issue_retains_exact_authority(ProcessLaunchStage::FleetShared, 402).await;
}
