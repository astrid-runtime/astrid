//! Provider-lane regressions for retained roots and pre-latched worker panics.

use std::sync::{Arc, atomic::Ordering};

use astrid_capsule::context::ProcessStorageMountBroker as _;
use astrid_core::{
    PrincipalId,
    storage_filesystem::{StorageFilesystemOperationV1, StorageFilesystemOutcomeV1},
};

use super::*;
use crate::storage_mount::drain_state::DrainFailureKind;
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
    let (held_worker, failed_workers) = gates.split_last().expect("projection workers");
    let held_entry = Arc::clone(held_worker);
    tokio::task::spawn_blocking(move || held_entry.wait_entered(1))
        .await
        .expect("held worker entry");
    fail_workers(failed_workers).await;
    await_join_failure_publication(&kernel, &stale_projection, failed_workers.len()).await;
    stale_mount.close_async().await;
    let held_state = Arc::clone(
        kernel
            .storage_mounts
            .get(stale_projection.component_mount_ids.last().unwrap())
            .unwrap()
            .value(),
    );
    let held_timeout = observe_held_timeout(&held_state).await;
    assert_unsettled_blocker(&kernel, &broker, &caller, &stale_projection, &stale_root).await;
    let acknowledged_timeout = held_state.failure_observation_for_test().await;
    held_worker.arm_panic_on_release();
    held_worker.release_workers();
    await_join_failure_publication(&kernel, &stale_projection, gates.len()).await;
    while let Some(worker) = workers.join_next().await {
        let _ = worker.expect("worker task joined");
    }

    observe_listener_closure(&kernel, &stale_projection).await;
    held_timeout.expect("held actual worker causally published TimedOut");
    assert_eq!(
        acknowledged_timeout,
        (
            Some(DrainFailureKind::TimedOut),
            Some(DrainFailureKind::TimedOut)
        ),
        "public unsettled admission must acknowledge held TimedOut before release"
    );
    assert_public_join_upgrade(&kernel, &broker, &caller, &held_state).await;
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
    let mut workers = WorkerJobs::new();
    let mut gates = Vec::new();
    for mount_id in &projection.component_mount_ids {
        let state = Arc::clone(
            kernel
                .storage_mounts
                .get(mount_id)
                .expect("projection component state")
                .value(),
        );
        state.set_drain_timeouts_for_test(std::time::Duration::from_millis(80));
        let gate = state.arm_blocking_worker_gate_for_test();
        let kernel = Arc::clone(kernel);
        // Stat reaches the worker gate without taking the global namespace
        // mutation lock, so each component can enter before one is released.
        let operation = astrid_core::storage_filesystem::StorageFilesystemOperationV1::Stat {
            path: String::new(),
        };
        workers.spawn(async move {
            crate::storage_mount::execute_operation_for_test(kernel, state, operation).await
        });
        gates.push(gate);
    }
    (workers, gates)
}

async fn fail_workers(gates: &[Arc<crate::storage_mount::BlockingWorkerTestGate>]) {
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
    count: usize,
) {
    for mount_id in projection.component_mount_ids.iter().take(count) {
        let state = kernel
            .storage_mounts
            .get(mount_id)
            .map(|entry| entry.value().clone())
            .expect("retained component");
        state.wait_join_failure_classification_for_test().await;
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

// Observe, never consume, classifier state. The public broker owns refusals.
async fn observe_held_timeout(
    state: &Arc<crate::storage_mount::StorageMountLeaseState>,
) -> Result<(), String> {
    let mut changed = state.drain_failure_tx.subscribe();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let (failure, _) = state.failure_observation_for_test().await;
            if failure == Some(DrainFailureKind::TimedOut) {
                return Ok(());
            }
            if failure == Some(DrainFailureKind::JoinFailed) {
                return Err("held worker unexpectedly classified JoinFailed before release".into());
            }
            changed.changed().await.map_err(|e| e.to_string())?;
        }
    })
    .await
    .map_err(|_| "held timeout publication missing".to_owned())?
}

async fn observe_listener_closure(
    kernel: &Arc<crate::Kernel>,
    projection: &CachedProcessProjection,
) {
    for mount_id in &projection.component_mount_ids {
        let state = Arc::clone(kernel.storage_mounts.get(mount_id).unwrap().value());
        let mut closed = state.listener_closed_tx.subscribe();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !*closed.borrow_and_update() {
                closed.changed().await.unwrap();
            }
        })
        .await
        .expect("actual retained listener and endpoint settle");
    }
}

async fn assert_public_join_upgrade(
    kernel: &Arc<crate::Kernel>,
    broker: &KernelProcessStorageMountBroker,
    caller: &PrincipalId,
    held: &Arc<crate::storage_mount::StorageMountLeaseState>,
) {
    use crate::storage_mount::drain_state::DrainFailureKind;
    assert_eq!(
        held.failure_observation_for_test().await,
        (
            Some(DrainFailureKind::JoinFailed),
            Some(DrainFailureKind::TimedOut)
        ),
        "new JoinFailed severity must remain unacknowledged before public retry"
    );
    let (result, diagnostic) = crate::storage_mount::process_broker::retained_diagnostics::capture(
        PROCESS_MOUNT_TEST_ID.scope(656, broker.mount(caller)),
    )
    .await;
    let Err(error) = result else {
        panic!("new JoinFailed severity skipped public refusal");
    };
    assert!(
        error.contains("administrative cleanup"),
        "{error}; {diagnostic:?}"
    );
    assert_eq!(
        held.failure_observation_for_test().await,
        (
            Some(DrainFailureKind::JoinFailed),
            Some(DrainFailureKind::JoinFailed)
        ),
        "actual public admission must acknowledge the new severity"
    );
    assert!(
        kernel.storage_mounts.contains_key(&held.mount_id),
        "failed public retry must retain exact mapped authority"
    );
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
    fail_next_root_removal_for_test(stale_root.clone());
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicitly_armed_lease_gate_holds_actual_worker_until_release() {
    let fixture = super::super::exact_fence_fixture().await;
    let state = Arc::clone(&fixture.states[0]);
    let gate = state.arm_blocking_worker_gate_for_test();
    let worker_state = Arc::clone(&state);
    let worker_kernel = Arc::clone(&fixture.kernel);
    let worker = tokio::spawn(async move {
        crate::storage_mount::execute_operation_for_test(
            worker_kernel,
            worker_state,
            StorageFilesystemOperationV1::Stat {
                path: String::new(),
            },
        )
        .await
    });
    let entered = Arc::clone(&gate);
    tokio::task::spawn_blocking(move || entered.wait_entered(1))
        .await
        .expect("worker entry");
    assert!(
        !worker.is_finished(),
        "the armed lease must hold its actual native worker"
    );
    gate.release_workers();
    assert!(matches!(
        worker.await.expect("worker join"),
        StorageFilesystemOutcomeV1::Success(_)
    ));
    for lease in [&fixture.branch, &fixture.owner, &fixture.shared] {
        revoke_lease(
            &fixture.kernel,
            &fixture.caller,
            MountOwnerScope::CrossOwnerWrite,
            lease.mount_id,
        )
        .await
        .expect("fixture cleanup");
    }
}
