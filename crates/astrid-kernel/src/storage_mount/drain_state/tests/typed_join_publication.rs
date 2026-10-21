//! An earlier timeout is not authoritative `JoinFailed` classification/closure.
use super::*;
use std::future::Future as _;
use std::task::Poll;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_join_wait_does_not_accept_timeout_and_upgrade_needs_one_refusal() {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = Arc::new(crate::test_kernel_with_home(home).await);
    let caller = astrid_core::principal::PrincipalId::default();
    let lease = issue_lease(
        &kernel,
        &test_mount_admission(&kernel, &caller, MountOwnerScope::CrossOwnerWrite),
        StorageProviderViewV1::Admin,
        StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadWrite,
        "test-provider".to_owned(),
        temporary.path().join("typed-publication"),
    )
    .await
    .unwrap();
    let state = Arc::clone(kernel.storage_mounts.get(&lease.mount_id).unwrap().value());
    // Even an unexpected assertion/panic must release the actual owned listener.
    let _shutdown = ShutdownOnDrop(state.shutdown_tx.clone());
    state.record_drain_failure(crate::storage_mount::BlockingJobDrain::TimedOut);
    state.wait_join_failure_publication_for_test().await;
    let initial = state.await_listener_settlement().await;
    let mut typed = Box::pin(state.wait_join_failure_classification_for_test());
    let first_poll = std::future::poll_fn(|cx| Poll::Ready(typed.as_mut().poll(cx))).await;
    let was_pending = first_poll.is_pending();
    // Causally publish upgrade; no sleep or arbitrary timeout manufactures it.
    state.latch_join_failure_without_shutdown_for_test();
    let classified = if was_pending {
        tokio::time::timeout(Duration::from_secs(2), typed).await
    } else {
        // A negative control may complete it on the first poll; never repoll it.
        drop(typed);
        Ok(())
    };
    let still_open = !*state.listener_closed_tx.borrow();
    let upgraded = state.await_listener_settlement().await;
    // Cleanup proceeds even if a negative control made either observation wrong.
    state.shutdown_tx.send_replace(true);
    let mut closed = state.listener_closed_tx.subscribe();
    let closure = tokio::time::timeout(Duration::from_secs(2), async {
        while !*closed.borrow_and_update() {
            closed.changed().await.map_err(|e| e.to_string())?;
        }
        Ok::<(), String>(())
    })
    .await;
    let final_settlement = state.await_listener_settlement().await;
    let cleanup = revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CrossOwnerWrite,
        lease.mount_id,
    )
    .await;
    // Observations are asserted only AFTER attempted actual shutdown and cleanup.
    assert!(
        closure.is_ok_and(|result| result.is_ok()),
        "actual listener endpoint closes"
    );
    cleanup.expect("exact cleanup after actual listener closure");
    assert!(
        classified.is_ok(),
        "typed JoinFailed classification was not published"
    );
    assert_eq!(
        initial,
        DrainSettlement::Failure(DrainFailureKind::TimedOut)
    );
    assert_eq!(final_settlement, DrainSettlement::Closed);
    assert!(
        was_pending,
        "boolean prior timeout satisfied typed JoinFailed wait"
    );
    assert!(
        still_open,
        "typed classification was mistaken for listener closure"
    );
    assert_eq!(
        upgraded,
        DrainSettlement::Failure(DrainFailureKind::JoinFailed)
    );
}

struct ShutdownOnDrop(tokio::sync::watch::Sender<bool>);
impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}
