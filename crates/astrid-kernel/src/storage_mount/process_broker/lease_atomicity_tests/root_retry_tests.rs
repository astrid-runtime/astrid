//! Provider-lane regressions for retained roots and pre-latched worker panics.

use super::super::PROCESS_MOUNT_TEST_ID;
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn multi_worker_panic_blocks_projection_cleanup_until_settled_retry() {
    if !provider_lane_is_ready("multi_worker_panic_blocks_projection_cleanup_until_settled_retry") {
        return;
    }
    let (_temporary, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    let CachedMount {
        mount: stale_mount,
        projection: stale_projection,
    } = successful_fleet_mount(&kernel, &caller, &broker, 651).await;
    let stale_root = uuid_mount_root(&stale_mount);

    let create = |path: &'static str| {
        astrid_core::storage_filesystem::StorageFilesystemOperationV1::Create {
            path: path.to_owned(),
            kind: astrid_core::storage_filesystem::StorageFilesystemEntryKindV1::File,
        }
    };
    let mut workers = Vec::new();
    for (index, mount_id) in stale_projection.component_mount_ids.iter().enumerate() {
        let state = Arc::clone(
            kernel
                .storage_mounts
                .get(mount_id)
                .expect("projection component state")
                .value(),
        );
        state.set_drain_timeouts_for_test(std::time::Duration::from_millis(80));
        let gate = state
            .blocking_worker_gate_for_test()
            .expect("test worker gate");
        let kernel = Arc::clone(&kernel);
        workers.push(tokio::spawn(async move {
            crate::storage_mount::execute_operation_for_test(
                kernel,
                state,
                create(match index {
                    0 => "panic-branch.bin",
                    1 => "panic-owner.bin",
                    _ => "panic-shared.bin",
                }),
            )
            .await
        }));
        let entry_gate = Arc::clone(&gate);
        tokio::task::spawn_blocking(move || entry_gate.wait_entered(1))
            .await
            .expect("worker entry wait");
        gate.arm_panic_on_release();
        gate.release_workers();
        tokio::task::spawn_blocking(move || gate.wait_failed(1))
            .await
            .expect("worker panic wait");
    }

    stale_mount.close_async().await;
    assert!(
        stale_projection.cleanup_failed.load(Ordering::Acquire),
        "latched JoinFailed must retain the projection blocker"
    );
    assert!(stale_root.exists());
    assert!(
        stale_projection
            .component_mount_ids
            .iter()
            .all(|mount_id| kernel.storage_mounts.contains_key(mount_id)),
        "the complete retained set must remain mapped before retry"
    );
    let Err(denied) =
        tokio::time::timeout(std::time::Duration::from_secs(2), broker.mount(&caller))
            .await
            .expect("denied admission must not wait for startup")
    else {
        panic!("an unsettled retained panic must deny replacement");
    };
    assert!(denied.contains("administrative cleanup"), "{denied}");
    for worker in workers {
        let _ = worker.await;
    }

    let replacement_mount = PROCESS_MOUNT_TEST_ID
        .scope(652, broker.mount(&caller))
        .await
        .expect("settled exact retry must admit a replacement");
    assert_ne!(uuid_mount_root(&replacement_mount), stale_root);
    assert!(!stale_root.exists());
    assert!(
        stale_projection
            .component_mount_ids
            .iter()
            .all(|mount_id| !kernel.storage_mounts.contains_key(mount_id)),
    );
    {
        let projections = broker.projections.lock().await;
        assert_eq!(projections.len(), 1);
        let replacement_projection = projections.values().next().expect("replacement");
        assert!(!Arc::ptr_eq(replacement_projection, &stale_projection));
        assert_eq!(replacement_projection.refs.load(Ordering::Acquire), 1);
    }
    replacement_mount.close_async().await;
    assert!(kernel.storage_mounts.is_empty());
    assert!(broker.projections.lock().await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successful_lease_cleanup_with_failed_root_retains_retry_blocker() {
    if !provider_lane_is_ready("successful_lease_cleanup_with_failed_root_retains_retry_blocker") {
        return;
    }
    let (_temporary, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    let CachedMount {
        mount: stale_mount,
        projection: stale_projection,
    } = successful_fleet_mount(&kernel, &caller, &broker, 661).await;
    let stale_root = uuid_mount_root(&stale_mount);
    fail_next_root_removal_for_test(stale_root.clone());

    stale_mount.close_async().await;
    assert!(
        stale_projection.cleanup_failed.load(Ordering::Acquire),
        "failed UUID-root removal must retain the bounded retry"
    );
    assert!(
        stale_projection
            .component_mount_ids
            .iter()
            .all(|mount_id| !kernel.storage_mounts.contains_key(mount_id)),
        "zero lease maps must remain after successful exact-lease cleanup"
    );
    assert!(stale_root.exists());
    let Err(denied) =
        tokio::time::timeout(std::time::Duration::from_secs(2), broker.mount(&caller))
            .await
            .expect("root-blocked admission must not wait for startup")
    else {
        panic!("a retained root blocker must deny replacement");
    };
    assert!(denied.contains("administrative cleanup"), "{denied}");

    let replacement_mount = PROCESS_MOUNT_TEST_ID
        .scope(662, broker.mount(&caller))
        .await
        .expect("the exact retry must remove the root and admit");
    assert_ne!(uuid_mount_root(&replacement_mount), stale_root);
    assert!(!stale_root.exists());
    {
        let projections = broker.projections.lock().await;
        assert_eq!(projections.len(), 1);
        let replacement_projection = projections.values().next().expect("replacement");
        assert!(!Arc::ptr_eq(replacement_projection, &stale_projection));
        assert_eq!(replacement_projection.refs.load(Ordering::Acquire), 1);
    }
    replacement_mount.close_async().await;
    assert!(kernel.storage_mounts.is_empty());
    assert!(broker.projections.lock().await.is_empty());
}
