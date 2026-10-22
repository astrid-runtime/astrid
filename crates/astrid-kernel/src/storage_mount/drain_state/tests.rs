//! Publications in the former sample-to-subscribe gap must remain observable.

use std::sync::Arc;
use std::time::Duration;

use super::{DrainFailureKind, DrainSettlement, ObservationGate};
use crate::storage_mount::lifecycle::revoke_lease;
use crate::storage_mount::{
    MountOwnerScope, StorageFilesystemTargetV1, StorageProviderAccessV1, StorageProviderViewV1,
    issue_lease, test_mount_admission,
};

async fn publication_between_observation_and_wait(is_failure: bool) {
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
        temporary.path().join("observation-gap"),
    )
    .await
    .unwrap();
    let state = Arc::clone(kernel.storage_mounts.get(&lease.mount_id).unwrap().value());
    // The external watchdog is deliberately shorter than the production timeout.
    state.set_drain_timeouts_for_test(Duration::from_secs(30));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
    state.drain_attempts.lock().await.before_wait = Some(ObservationGate {
        entered: entered_tx,
        resume: resume_rx,
    });
    let waiting_state = Arc::clone(&state);
    let waiter = tokio::spawn(async move { waiting_state.await_listener_settlement().await });
    tokio::time::timeout(Duration::from_secs(5), entered_rx)
        .await
        .expect("settlement reached the observation gap")
        .unwrap();
    let mut closed = state.listener_closed_tx.subscribe();
    if is_failure {
        state.latch_join_failure_without_shutdown_for_test();
    } else {
        state.shutdown_tx.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !*closed.borrow_and_update() {
                closed.changed().await.unwrap();
            }
        })
        .await
        .expect("real listener completed shutdown");
    }
    resume_tx.send(()).unwrap();
    let mut waiter = waiter;
    let observed = tokio::time::timeout(Duration::from_secs(2), &mut waiter).await;
    // Always release the owned listener and consumer, including negative controls.
    if observed.is_err() {
        waiter.abort();
        let _ = waiter.await;
    }
    state.shutdown_tx.send_replace(true);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !*closed.borrow_and_update() {
            closed.changed().await.unwrap();
        }
    })
    .await
    .expect("owned listener shuts down for cleanup");
    if observed.is_err() && is_failure {
        assert_eq!(
            state.await_listener_settlement().await,
            DrainSettlement::Failure(DrainFailureKind::JoinFailed)
        );
    }
    revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CrossOwnerWrite,
        lease.mount_id,
    )
    .await
    .expect("exact lease cleanup succeeds");
    assert!(!kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(!lease.resource_path.exists());
    let expected = if is_failure {
        DrainSettlement::Failure(DrainFailureKind::JoinFailed)
    } else {
        DrainSettlement::Closed
    };
    assert_eq!(
        observed.expect("publication was not missed").unwrap(),
        expected
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closure_in_observation_gap_is_not_missed() {
    publication_between_observation_and_wait(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failure_in_observation_gap_is_not_missed() {
    publication_between_observation_and_wait(true).await;
}

mod closure_priority;
