//! Serialized, monotonic settlement for retained filesystem workers.

use super::{BlockingJobDrain, StorageMountLeaseState};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum DrainFailureKind {
    TimedOut,
    JoinFailed,
}

impl From<BlockingJobDrain> for DrainFailureKind {
    fn from(outcome: BlockingJobDrain) -> Self {
        match outcome {
            BlockingJobDrain::JoinFailed => Self::JoinFailed,
            BlockingJobDrain::TimedOut => Self::TimedOut,
            BlockingJobDrain::Completed => {
                unreachable!("completed work is not retained as a drain failure")
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DrainSettlement {
    Closed,
    Failure(DrainFailureKind),
}

#[derive(Default)]
pub(super) struct DrainAttemptState {
    retry_armed: Option<DrainFailureKind>,
    #[cfg(test)]
    before_wait: Option<ObservationGate>,
    #[cfg(test)]
    after_sample: Option<ObservationGate>,
}

#[cfg(test)]
struct ObservationGate {
    entered: tokio::sync::oneshot::Sender<()>,
    resume: tokio::sync::oneshot::Receiver<()>,
}

impl StorageMountLeaseState {
    pub(super) async fn await_listener_settlement(&self) -> DrainSettlement {
        let mut attempt = self.drain_attempts.lock().await;
        // Subscribe before sampling: a publication between sampling and waiting
        // must remain unseen by the receiver rather than become its baseline.
        let mut failure_changed = self.drain_failure_tx.subscribe();
        let mut closed = self.listener_closed_tx.subscribe();
        if let Some(failure) = self.sample_failure()
            && attempt.retry_armed.is_none_or(|armed| armed < failure)
        {
            attempt.retry_armed = Some(failure);
            return DrainSettlement::Failure(failure);
        }
        #[cfg(test)]
        if let Some(gate) = attempt.after_sample.take() {
            let _ = gate.entered.send(());
            let _ = gate.resume.await;
        }
        if self.listener_is_closed() {
            return self.closed_settlement(&mut attempt);
        }

        #[cfg(test)]
        if let Some(gate) = attempt.before_wait.take() {
            let _ = gate.entered.send(());
            let _ = gate.resume.await;
        }
        let wait = async {
            loop {
                tokio::select! {
                    biased;
                    changed = failure_changed.changed() => {
                        if changed.is_err() {
                            return if self.listener_is_closed() {
                                self.closed_settlement(&mut attempt)
                            } else {
                                DrainSettlement::Failure(DrainFailureKind::TimedOut)
                            };
                        }
                        if let Some(failure) = self.sample_failure() {
                            remember_retry_failure(&mut attempt, failure);
                            return DrainSettlement::Failure(failure);
                        }
                    },
                    _changed = closed.changed() => {
                        if self.listener_is_closed() {
                            return self.closed_settlement(&mut attempt);
                        }
                    },
                }
            }
        };
        if let Ok(settlement) =
            tokio::time::timeout(self.drain_timeouts().listener_shutdown, wait).await
        {
            settlement
        } else {
            self.record_drain_failure(BlockingJobDrain::TimedOut);
            let failure = self.sample_failure().unwrap_or(DrainFailureKind::TimedOut);
            remember_retry_failure(&mut attempt, failure);
            DrainSettlement::Failure(failure)
        }
    }

    // A true closure publication follows worker settlement, so sample its
    // preceding failure only after observing closure, before authorizing cleanup.
    fn closed_settlement(&self, attempt: &mut DrainAttemptState) -> DrainSettlement {
        if let Some(failure) = self.sample_failure()
            && attempt.retry_armed.is_none_or(|armed| armed < failure)
        {
            remember_retry_failure(attempt, failure);
            return DrainSettlement::Failure(failure);
        }
        DrainSettlement::Closed
    }

    fn sample_failure(&self) -> Option<DrainFailureKind> {
        *self
            .drain_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn listener_is_closed(&self) -> bool {
        *self.listener_closed_tx.borrow()
    }

    /// Retire a latched failure only after a retry has proven cleanup complete.
    pub(super) fn complete_drain_retry(&self) {
        let mut latch = self
            .drain_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if latch.take().is_some() {
            self.drain_failure_tx.send_replace(false);
        }
    }

    /// A failed settlement authorizes the next exact retry while still
    /// serialized with every other drain consumer.
    pub(super) async fn drain_is_settled_for_cleanup(&self) -> bool {
        match self.await_listener_settlement().await {
            DrainSettlement::Closed => true,
            DrainSettlement::Failure(_) => false,
        }
    }
}

fn remember_retry_failure(attempt: &mut DrainAttemptState, failure: DrainFailureKind) {
    if attempt.retry_armed.is_none_or(|armed| armed < failure) {
        attempt.retry_armed = Some(failure);
    }
}

#[cfg(test)]
mod tests;
