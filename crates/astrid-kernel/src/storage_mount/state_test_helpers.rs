//! Test-only accessors kept out of the lease-state production module.

use super::*;

impl StorageMountLeaseState {
    pub(crate) async fn wait_listener_closed_for_test(&self) -> bool {
        self.wait_listener_closed().await
    }

    pub(crate) fn set_drain_timeouts_for_test(&self, timeout: std::time::Duration) {
        *self
            .drain_timeouts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = DrainTimeouts {
            accepted_task: timeout,
            listener_shutdown: timeout,
        };
    }

    pub(crate) fn is_revoked_for_test(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    #[cfg(any(unix, windows))]
    pub(crate) fn callback_identity_for_test(&self) -> (std::path::PathBuf, String) {
        (self.callback_path.clone(), self.token_for_test.clone())
    }

    #[cfg(any(unix, windows))]
    pub(crate) fn blocking_worker_gate_for_test(&self) -> Option<Arc<BlockingWorkerTestGate>> {
        self.blocking_worker_test_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    #[cfg(any(unix, windows))]
    pub(crate) fn arm_stale_join_failure_for_test(&self) {
        self.record_drain_failure(BlockingJobDrain::JoinFailed);
        let _ = self.shutdown_tx.send(true);
    }

    #[cfg(any(unix, windows))]
    pub(crate) fn latch_join_failure_without_shutdown_for_test(&self) {
        self.record_drain_failure(BlockingJobDrain::JoinFailed);
    }

    #[cfg(any(unix, windows))]
    pub(crate) async fn wait_join_failure_publication_for_test(&self) {
        let mut published = self.drain_failure_tx.subscribe();
        while !*published.borrow() {
            published
                .changed()
                .await
                .expect("drain failure publication sender");
        }
    }

    /// Wait for the production classifier's typed `JoinFailed` publication.
    /// The boolean drain watch cannot distinguish a prior timeout from this.
    #[cfg(all(test, any(unix, windows)))]
    pub(crate) async fn wait_join_failure_classification_for_test(&self) {
        let mut classified = self.join_failure_tx.subscribe();
        while !matches!(*classified.borrow(), Some(DrainFailureKind::JoinFailed)) {
            classified
                .changed()
                .await
                .expect("join failure classification sender");
        }
    }

    #[cfg(any(unix, windows))]
    pub(crate) fn join_failure_is_published_for_test(&self) -> bool {
        *self.drain_failure_tx.subscribe().borrow()
    }

    #[cfg(all(test, any(unix, windows)))]
    pub(super) fn record_join_failure_for_test(&self, failure: DrainFailureKind) {
        if failure == DrainFailureKind::JoinFailed {
            self.join_failure_tx.send_replace(Some(failure));
        }
    }

    pub(crate) fn in_flight_mutations_for_test(&self) -> u64 {
        self.in_flight_mutations.load(Ordering::Acquire)
    }
}
