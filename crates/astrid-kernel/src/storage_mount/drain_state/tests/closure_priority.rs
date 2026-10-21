//! Closure cannot hide a previously unacknowledged worker failure.

use super::{
    Arc, DrainFailureKind, DrainSettlement, Duration, MountOwnerScope, ObservationGate,
    StorageFilesystemTargetV1, StorageProviderAccessV1, StorageProviderViewV1, issue_lease,
    revoke_lease, test_mount_admission,
};

async fn failure_published_before_closure_is_acknowledged(escalation: bool) {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = Arc::new(crate::test_kernel_with_home(home).await);
    let caller = astrid_core::PrincipalId::default();
    let lease = issue_lease(
        &kernel,
        &test_mount_admission(&kernel, &caller, MountOwnerScope::CrossOwnerWrite),
        StorageProviderViewV1::Admin,
        StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadWrite,
        "test-provider".to_owned(),
        temporary.path().join("closure-priority"),
    )
    .await
    .unwrap();
    let state = Arc::clone(kernel.storage_mounts.get(&lease.mount_id).unwrap().value());
    if escalation {
        state.record_drain_failure(crate::storage_mount::BlockingJobDrain::TimedOut);
        assert_eq!(
            state.await_listener_settlement().await,
            DrainSettlement::Failure(DrainFailureKind::TimedOut)
        );
    }
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
    state.drain_attempts.lock().await.after_sample = Some(ObservationGate {
        entered: entered_tx,
        resume: resume_rx,
    });
    let waiting_state = Arc::clone(&state);
    let waiter = tokio::spawn(async move { waiting_state.await_listener_settlement().await });
    tokio::time::timeout(Duration::from_secs(5), entered_rx)
        .await
        .expect("consumer sampled the original failure state")
        .unwrap();
    state.latch_join_failure_without_shutdown_for_test();
    let mut closed = state.listener_closed_tx.subscribe();
    state.shutdown_tx.send_replace(true);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !*closed.borrow_and_update() {
            closed.changed().await.unwrap();
        }
    })
    .await
    .expect("real listener closes after the failure publication");
    resume_tx.send(()).unwrap();
    let first = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("closure settles promptly")
        .unwrap();
    let next = state.await_listener_settlement().await;
    // Even the negative control arms its skipped failure on the second call;
    // perform exact cleanup before checking first-observation semantics.
    revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CrossOwnerWrite,
        lease.mount_id,
    )
    .await
    .expect("acknowledged failure permits the exact cleanup retry");
    assert!(!kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(!lease.resource_path.exists());
    assert_eq!(
        first,
        DrainSettlement::Failure(DrainFailureKind::JoinFailed)
    );
    assert_eq!(next, DrainSettlement::Closed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closure_does_not_skip_a_new_join_failure() {
    failure_published_before_closure_is_acknowledged(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closure_does_not_skip_an_escalated_join_failure() {
    failure_published_before_closure_is_acknowledged(true).await;
}
