//! Partial lease-issue rollback must retain retry authority.

use std::sync::Arc;

use astrid_capsule::context::ProcessStorageMountBroker as _;
use astrid_core::PrincipalId;

use super::{
    KernelProcessStorageMountBroker, PROCESS_MOUNT_TEST_ID, ProcessLaunchStage,
    arm_issue_root_removal_failure_for_test, arm_partial_issue_provider_error_for_test,
    fleet_shared_kernel,
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

fn expected_issue_lease_count(stage: ProcessLaunchStage) -> usize {
    match stage {
        ProcessLaunchStage::Branch => 0,
        ProcessLaunchStage::OwnerHome => 1,
        ProcessLaunchStage::FleetShared => 2,
    }
}

fn assert_retained_issue_authority(kernel: &crate::Kernel, stage: ProcessLaunchStage) {
    assert_eq!(
        kernel.storage_mounts.len(),
        expected_lease_count(stage),
        "{stage:?} failed cleanup must retain every issued lease"
    );
    for entry in kernel.storage_mounts.iter() {
        let retained_lease = entry.value();
        assert!(
            retained_lease.is_revoked_for_test(),
            "cleanup-faulted lease must remain revoked"
        );

        // Unix socket pathnames may outlive their listener; Windows named
        // pipes vanish with the final server handle. Durable authority does
        // not depend on this transport-specific pathname.
        #[cfg(unix)]
        {
            let callback_path = retained_lease.callback_identity_for_test().0;
            assert!(
                astrid_core::local_transport::endpoint_is_present(&callback_path).unwrap(),
                "cleanup-faulted callback endpoint must remain retained"
            );
        }
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
}

async fn assert_partial_issue_retains_exact_authority(stage: ProcessLaunchStage, test_id: u64) {
    if !super::process_provider_test_lane_enabled() {
        println!(
            "skipping {stage:?} retained issue cleanup retry: coinstalled native process storage provider is unavailable"
        );
        return;
    }
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
    assert_eq!(
        kernel.storage_mounts.len(),
        3,
        "{stage:?} provider-lane replacement must publish its complete exact set"
    );
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
    assert_eq!(
        kernel.storage_mounts.len(),
        3,
        "{stage:?} independent replacement must publish its complete exact set"
    );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn failed_issue_root_removal_retains_a_bounded_retry_blocker() {
    for (stage, test_id) in [
        (ProcessLaunchStage::Branch, 411_u64),
        (ProcessLaunchStage::OwnerHome, 412),
        (ProcessLaunchStage::FleetShared, 413),
    ] {
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
        assert!(
            issue_error.contains("native storage provider identity is invalid"),
            "unexpected {stage:?} issue error: {issue_error}"
        );
        assert!(
            issue_error.contains("process mount root cleanup failed"),
            "{stage:?} successful lease cleanup must expose the root failure: {issue_error}"
        );
        assert_eq!(
            kernel.storage_mounts.len(),
            0,
            "{stage:?} all issued leases were cleaned before root removal"
        );

        let process_root = kernel.astrid_home.run_dir().join("process-storage");
        let stale_root = process_root
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

        crate::storage_mount::process_broker::fail_next_root_removal_for_test(stale_root.clone());
        let Err(denied) = broker.mount(&caller).await else {
            panic!("{stage:?} retained root blocker must deny replacement");
        };
        assert!(
            denied.contains("requires administrative cleanup"),
            "unexpected {stage:?} root denial: {denied}"
        );
        assert_eq!(kernel.storage_mounts.len(), 0);
        assert!(stale_root.exists());
        assert_eq!(broker.projections.lock().await.len(), 1);

        if !super::process_provider_test_lane_enabled() {
            let Err(retry_error) = broker.mount(&caller).await else {
                panic!("{stage:?} retry must require a provider for replacement admission");
            };
            assert!(
                retry_error.contains("inspect coinstalled storage provider"),
                "unexpected {stage:?} local retry error: {retry_error}"
            );
            assert!(!stale_root.exists());
            assert!(kernel.storage_mounts.is_empty());
            assert!(broker.projections.lock().await.is_empty());
            println!(
                "skipping {stage:?} fresh replacement admission: coinstalled native process storage provider is unavailable"
            );
            continue;
        }
        let replacement_mount = PROCESS_MOUNT_TEST_ID
            .scope(test_id + 1000, broker.mount(&caller))
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
}
