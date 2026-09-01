//! Provider-lane regressions for retained roots and pre-latched worker panics.

use std::sync::{Arc, atomic::Ordering};

use astrid_capsule::context::ProcessStorageMountBroker as _;
use astrid_core::{PrincipalId, storage_filesystem::StorageFilesystemOutcomeV1};

use super::*;
use crate::storage_mount::process_broker::PROCESS_MOUNT_TEST_ID;

type WorkerJobs = tokio::task::JoinSet<StorageFilesystemOutcomeV1>;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_worker_panics_block_cleanup_until_settled_retries() {
    if !provider_lane_is_ready("concurrent_worker_panics_block_cleanup_until_settled_retries") {
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

    let (mut workers, gates) = spawn_panicking_workers(&kernel, &stale_projection);
    fail_all_workers(&gates).await;
    await_join_failure_publication(&kernel, &stale_projection).await;
    stale_mount.close_async().await;
    assert_unsettled_blocker(&kernel, &broker, &caller, &stale_projection, &stale_root).await;
    while let Some(worker) = workers.join_next().await {
        let _ = worker.expect("worker task joined");
    }

    let mounts = retry_concurrently(&broker, &caller).await;
    assert_settled_replacement(&kernel, &broker, &stale_projection, &stale_root, &mounts);
    for mount in mounts {
        mount.close_async().await;
    }
    assert!(kernel.storage_mounts.is_empty());
    assert!(broker.projections.lock().await.is_empty());
}

fn spawn_panicking_workers(
    kernel: &Arc<crate::Kernel>,
    projection: &CachedProcessProjection,
) -> (
    WorkerJobs,
    Vec<Arc<crate::storage_mount::BlockingWorkerTestGate>>,
) {
    let create = |path: &'static str| {
        astrid_core::storage_filesystem::StorageFilesystemOperationV1::Create {
            path: path.to_owned(),
            kind: astrid_core::storage_filesystem::StorageFilesystemEntryKindV1::File,
        }
    };
    let mut workers = WorkerJobs::new();
    let mut gates = Vec::new();
    for (index, mount_id) in projection.component_mount_ids.iter().enumerate() {
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
        let kernel = Arc::clone(kernel);
        let operation = create(match index {
            0 => "panic-branch.bin",
            1 => "panic-owner.bin",
            _ => "panic-shared.bin",
        });
        workers.spawn(async move {
            crate::storage_mount::execute_operation_for_test(kernel, state, operation).await
        });
        gates.push(gate);
    }
    (workers, gates)
}

async fn fail_all_workers(gates: &[Arc<crate::storage_mount::BlockingWorkerTestGate>]) {
    let gates_for_entry = gates.to_vec();
    tokio::task::spawn_blocking(move || {
        for gate in &gates_for_entry {
            gate.wait_entered(1);
        }
    })
    .await
    .expect("worker entry wait");
    for gate in gates {
        gate.arm_panic_on_release();
    }
    for gate in gates {
        gate.release_workers();
    }
    for gate in gates {
        let gate = Arc::clone(gate);
        tokio::task::spawn_blocking(move || gate.wait_failed(1))
            .await
            .expect("worker panic wait");
    }
}

async fn await_join_failure_publication(
    kernel: &Arc<crate::Kernel>,
    projection: &CachedProcessProjection,
) {
    for mount_id in &projection.component_mount_ids {
        let state = kernel
            .storage_mounts
            .get(mount_id)
            .map(|entry| entry.value().clone())
            .expect("retained component");
        state.wait_join_failure_publication_for_test().await;
    }
}

async fn assert_unsettled_blocker(
    kernel: &Arc<crate::Kernel>,
    broker: &KernelProcessStorageMountBroker,
    caller: &PrincipalId,
    projection: &CachedProcessProjection,
    stale_root: &std::path::Path,
) {
    assert!(
        projection.cleanup_failed.load(Ordering::Acquire),
        "latched JoinFailed must retain the projection blocker"
    );
    assert!(stale_root.exists());
    assert!(
        projection
            .component_mount_ids
            .iter()
            .all(|mount_id| kernel.storage_mounts.contains_key(mount_id)),
        "the complete retained set must remain mapped before retry"
    );
    let Err(denied) = tokio::time::timeout(std::time::Duration::from_secs(2), broker.mount(caller))
        .await
        .expect("denied admission must not wait for startup")
    else {
        panic!("an unsettled retained panic must deny replacement");
    };
    assert!(denied.contains("administrative cleanup"), "{denied}");
}

async fn retry_concurrently(
    broker: &KernelProcessStorageMountBroker,
    caller: &PrincipalId,
) -> [astrid_capsule::context::ProcessStorageMount; 4] {
    let (first, second, third, fourth) = tokio::join!(
        PROCESS_MOUNT_TEST_ID.scope(652, broker.mount(caller)),
        PROCESS_MOUNT_TEST_ID.scope(653, broker.mount(caller)),
        PROCESS_MOUNT_TEST_ID.scope(654, broker.mount(caller)),
        PROCESS_MOUNT_TEST_ID.scope(655, broker.mount(caller)),
    );
    [
        first.expect("concurrent settled retry"),
        second.expect("concurrent settled retry"),
        third.expect("concurrent settled retry"),
        fourth.expect("concurrent settled retry"),
    ]
}

fn assert_settled_replacement(
    kernel: &Arc<crate::Kernel>,
    broker: &KernelProcessStorageMountBroker,
    stale_projection: &Arc<CachedProcessProjection>,
    stale_root: &std::path::Path,
    mounts: &[astrid_capsule::context::ProcessStorageMount],
) {
    assert_ne!(uuid_mount_root(&mounts[0]), stale_root);
    assert!(!stale_root.exists());
    assert!(
        stale_projection
            .component_mount_ids
            .iter()
            .all(|mount_id| !kernel.storage_mounts.contains_key(mount_id)),
    );
    let projections = broker
        .projections
        .try_lock()
        .expect("replacement cache is uncontaminated after admission");
    assert_eq!(projections.len(), 1);
    let replacement = projections.values().next().expect("replacement");
    assert!(!Arc::ptr_eq(replacement, stale_projection));
    assert_eq!(replacement.refs.load(Ordering::Acquire), 4);
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
