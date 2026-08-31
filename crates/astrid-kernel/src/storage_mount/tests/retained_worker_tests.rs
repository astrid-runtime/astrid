//! Retained callback filesystem workers and typed drain retries.

use super::*;

use std::time::Duration;

async fn worker_fixture(
    temporary: &tempfile::TempDir,
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    name: &str,
) -> (
    StorageMountLeaseV1,
    Arc<StorageMountLeaseState>,
    Arc<BlockingWorkerTestGate>,
) {
    let lease = issue_lease(
        kernel,
        &test_mount_admission(kernel, caller, MountOwnerScope::CrossOwnerWrite),
        StorageProviderViewV1::Admin,
        StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadWrite,
        "test-provider".to_owned(),
        temporary.path().join(name),
    )
    .await
    .unwrap();
    let state = Arc::clone(kernel.storage_mounts.get(&lease.mount_id).unwrap().value());
    state.set_drain_timeouts_for_test(Duration::from_millis(80));
    let gate = Arc::new(BlockingWorkerTestGate::new());
    *state.blocking_worker_test_gate.lock().unwrap() = Some(Arc::clone(&gate));
    (lease, state, gate)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_drain_timeout_preserves_a_latched_join_failure() {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = Arc::new(crate::test_kernel_with_home(home).await);
    let caller = PrincipalId::default();
    let (lease, state, _gate) =
        worker_fixture(&temporary, &kernel, &caller, "timeout-keeps-join-failure").await;
    state.set_drain_timeouts_for_test(Duration::from_millis(20));
    state.latch_join_failure_without_shutdown_for_test();

    let first = state.await_listener_settlement().await;
    assert!(
        matches!(
            first,
            crate::storage_mount::drain_state::DrainSettlement::Failure(
                crate::storage_mount::drain_state::DrainFailureKind::JoinFailed
            )
        ),
        "the latched severity must be returned first: {first:?}"
    );

    let timed_out_attempt = state.await_listener_settlement().await;
    assert!(
        matches!(
            timed_out_attempt,
            crate::storage_mount::drain_state::DrainSettlement::Failure(
                crate::storage_mount::drain_state::DrainFailureKind::JoinFailed
            )
        ),
        "the timeout must not downgrade the stored maximum: {timed_out_attempt:?}"
    );

    revoke(&kernel, &caller, lease.mount_id)
        .await
        .expect("the settled listener permits the exact cleanup retry");
    assert!(!kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(!lease.resource_path.exists());
}

async fn revoke(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    mount_id: StorageMountId,
) -> Result<(), String> {
    revoke_lease(kernel, caller, MountOwnerScope::CrossOwnerWrite, mount_id).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn revocation_waits_for_multiple_running_filesystem_workers() {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = Arc::new(crate::test_kernel_with_home(home).await);
    let caller = PrincipalId::default();
    let (lease, state, gate) =
        worker_fixture(&temporary, &kernel, &caller, "concurrent-workers").await;

    let mutation_lease = lease.clone();
    let mutation = tokio::spawn(async move {
        callback(
            &mutation_lease,
            &mutation_lease.lease_token,
            create("concurrent.bin"),
        )
        .await
    });
    let read_kernel = Arc::clone(kernel.as_ref());
    let read_state = Arc::clone(&state);
    let read = tokio::spawn(async move {
        execute_operation_for_test(
            read_kernel,
            read_state,
            StorageFilesystemOperationV1::Stat {
                path: String::new(),
            },
        )
        .await
    });
    let gate_for_wait = Arc::clone(&gate);
    tokio::task::spawn_blocking(move || gate_for_wait.wait_entered(2))
        .await
        .unwrap();

    let revoke_kernel = Arc::clone(&kernel);
    let revoke_caller = caller.clone();
    let revocation =
        tokio::spawn(async move { revoke(&revoke_kernel, &revoke_caller, lease.mount_id).await });
    while !state.revoked.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }
    let error = tokio::time::timeout(Duration::from_secs(2), revocation)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(
        error.contains("cleanup failed at drain"),
        "expected typed drain cleanup failure, got {error}"
    );
    assert!(kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(lease.resource_path.exists());
    assert_eq!(state.in_flight_mutations.load(Ordering::Acquire), 1);

    gate.release_workers();
    let outcomes = tokio::join!(mutation, read);
    // Revocation aborts the accepted callback connection while its
    // authenticated blocking worker remains retained; EOF is not job death.
    let _ = outcomes.0;
    assert!(matches!(
        outcomes.1.unwrap(),
        StorageFilesystemOutcomeV1::Success(_)
    ));
    tokio::time::timeout(Duration::from_secs(2), async {
        while !state.wait_listener_closed().await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both retained workers and the listener must settle");

    revoke(&kernel, &caller, lease.mount_id)
        .await
        .expect("exact retry after both workers finish");
    assert!(state.dirty.load(Ordering::Acquire));
    assert_eq!(state.in_flight_mutations.load(Ordering::Acquire), 0);
    assert!(!kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(!lease.resource_path.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn panicking_filesystem_worker_remains_a_retryable_drain_failure() {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = Arc::new(crate::test_kernel_with_home(home).await);
    let caller = PrincipalId::default();
    let (lease, state, gate) =
        worker_fixture(&temporary, &kernel, &caller, "panicking-worker").await;

    let mutation_lease = lease.clone();
    let mutation = tokio::spawn(async move {
        callback(
            &mutation_lease,
            &mutation_lease.lease_token,
            create("panic.bin"),
        )
        .await
    });
    let gate_for_wait = Arc::clone(&gate);
    tokio::task::spawn_blocking(move || gate_for_wait.wait_entered(1))
        .await
        .unwrap();

    gate.arm_panic_on_release();
    gate.release_workers();
    gate.wait_failed(1);
    tokio::time::timeout(
        Duration::from_secs(2),
        state.wait_join_failure_publication_for_test(),
    )
    .await
    .expect("the production panic classifier must publish JoinFailed");
    assert!(
        state.join_failure_is_published_for_test(),
        "the production classifier must own authoritative JoinFailed publication"
    );
    let revoke_kernel = Arc::clone(&kernel);
    let revoke_caller = caller.clone();
    let revocation =
        tokio::spawn(async move { revoke(&revoke_kernel, &revoke_caller, lease.mount_id).await });
    while !state.revoked.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }
    let error = tokio::time::timeout(Duration::from_secs(2), revocation)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.contains("cleanup failed at drain"), "{error}");
    assert!(
        error.contains("retained filesystem worker join failed"),
        "expected typed Drain/JoinFailed classification, got {error}"
    );
    assert!(kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(lease.resource_path.exists());

    let _ = mutation.await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while !state.wait_listener_closed().await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("panicking retained job must still join before listener closure");

    revoke(&kernel, &caller, lease.mount_id)
        .await
        .expect("join failure retains bounded retry authority");
    assert!(!state.dirty.load(Ordering::Acquire));
    assert!(!kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(!lease.resource_path.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_later_join_failure_upgrades_a_latched_drain_timeout() {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = Arc::new(crate::test_kernel_with_home(home).await);
    let caller = PrincipalId::default();
    let (lease, state, gate) =
        worker_fixture(&temporary, &kernel, &caller, "timeout-upgrade-worker").await;
    state.set_drain_timeouts_for_test(Duration::from_millis(20));

    let mutation_lease = lease.clone();
    let mutation = tokio::spawn(async move {
        callback(
            &mutation_lease,
            &mutation_lease.lease_token,
            create("timeout-panic.bin"),
        )
        .await
    });
    let gate_for_wait = Arc::clone(&gate);
    tokio::task::spawn_blocking(move || gate_for_wait.wait_entered(1))
        .await
        .unwrap();

    let revoke_kernel = Arc::clone(&kernel);
    let revoke_caller = caller.clone();
    let first_revoke =
        tokio::spawn(async move { revoke(&revoke_kernel, &revoke_caller, lease.mount_id).await });
    while !state.revoked.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }
    let first_error = tokio::time::timeout(Duration::from_secs(2), first_revoke)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(
        first_error.contains("did not finish within"),
        "{first_error}"
    );
    assert!(
        !first_error.contains("retained filesystem worker join failed"),
        "the first bounded attempt must exercise TimedOut: {first_error}"
    );

    gate.arm_panic_on_release();
    gate.release_workers();
    gate.wait_failed(1);
    assert!(
        state.join_failure_is_published_for_test(),
        "the failed-worker wakeup must observe published JoinFailed state"
    );
    let error = revoke(&kernel, &caller, lease.mount_id).await.unwrap_err();
    assert!(
        error.contains("retained filesystem worker join failed"),
        "JoinFailed must deterministically upgrade TimedOut, got {error}"
    );
    assert!(kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(lease.resource_path.exists());

    let _ = mutation.await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while !state.wait_listener_closed_for_test().await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the upgraded retained worker must still close the listener");

    revoke(&kernel, &caller, lease.mount_id)
        .await
        .expect("the settled exact retry must remove retained authority");
    assert!(!kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(!lease.resource_path.exists());
}
