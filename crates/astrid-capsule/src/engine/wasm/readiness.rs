//! Run-loop readiness wait for [`super::WasmEngine`].
//!
//! The latch is false→true only. A warm peek of `borrow() == true` on every
//! worker matches `wait_for(|&v| v)`, including signaled-then-exited. Any
//! still-false worker uses the existing clone-all + one shared timeout.

use std::time::Duration;

use tokio::sync::{Mutex, watch};

use crate::capsule::ReadyStatus;

/// Wait until every run-loop worker has latched ready, or the shared budget expires.
///
/// Empty `ready_rxs` is Ready (non-run-loop or post-unload).
pub(super) async fn wait_ready(
    ready_rxs: &[Mutex<watch::Receiver<bool>>],
    timeout: Duration,
) -> ReadyStatus {
    if ready_rxs.is_empty() {
        return ReadyStatus::Ready;
    }
    if all_workers_latched(ready_rxs).await {
        return ReadyStatus::Ready;
    }
    wait_with_shared_timeout(ready_rxs, timeout).await
}

/// Peek each stored receiver without cloning or starting a timer.
///
/// Use `borrow()`, not `has_changed`/`is_closed`: tokio watch reports a closed
/// sender as `Err` even after `signal_ready`, which would turn a
/// signaled-then-exited worker into [`ReadyStatus::Crashed`]. Drop the
/// `borrow()` `Ref` (and the mutex) before the next `.await`.
async fn all_workers_latched(ready_rxs: &[Mutex<watch::Receiver<bool>>]) -> bool {
    for rx_mutex in ready_rxs {
        let latched = {
            let rx = rx_mutex.lock().await;
            *rx.borrow()
        };
        if !latched {
            return false;
        }
    }
    true
}

/// Clone each worker's receiver under its lock, then wait for every worker
/// within one shared timeout. Ready only once all workers signaled; Crashed
/// if any worker's sender dropped first (its run task died before signaling).
async fn wait_with_shared_timeout(
    ready_rxs: &[Mutex<watch::Receiver<bool>>],
    timeout: Duration,
) -> ReadyStatus {
    let mut rxs = Vec::with_capacity(ready_rxs.len());
    for rx_mutex in ready_rxs {
        rxs.push(rx_mutex.lock().await.clone());
    }
    let wait_all = async {
        for rx in &mut rxs {
            if rx.wait_for(|&v| v).await.is_err() {
                return ReadyStatus::Crashed; // sender dropped before signaling
            }
        }
        ReadyStatus::Ready
    };
    match tokio::time::timeout(timeout, wait_all).await {
        Ok(status) => status,
        Err(_) => ReadyStatus::Timeout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap(
        rxs: impl IntoIterator<Item = watch::Receiver<bool>>,
    ) -> Vec<Mutex<watch::Receiver<bool>>> {
        rxs.into_iter().map(Mutex::new).collect()
    }

    #[tokio::test]
    async fn empty_receivers_are_ready() {
        let status = wait_ready(&[], Duration::from_millis(10)).await;
        assert_eq!(status, ReadyStatus::Ready);
    }

    #[tokio::test]
    async fn warm_latch_all_true_is_ready() {
        let (tx, rx) = watch::channel(false);
        let _ = tx.send(true);
        let rxs = wrap([rx]);
        let status = wait_ready(&rxs, Duration::from_millis(100)).await;
        assert_eq!(status, ReadyStatus::Ready);
    }

    #[tokio::test]
    async fn warm_latch_every_worker_true_is_ready() {
        let (tx0, rx0) = watch::channel(false);
        let (tx1, rx1) = watch::channel(false);
        let _ = tx0.send(true);
        let _ = tx1.send(true);
        let rxs = wrap([rx0, rx1]);
        let status = wait_ready(&rxs, Duration::from_millis(100)).await;
        assert_eq!(status, ReadyStatus::Ready);
    }

    #[tokio::test]
    async fn closed_after_true_is_ready() {
        let (tx, rx) = watch::channel(false);
        let _ = tx.send(true);
        drop(tx);
        let rxs = wrap([rx]);
        let status = wait_ready(&rxs, Duration::from_millis(100)).await;
        assert_eq!(status, ReadyStatus::Ready);
    }

    #[tokio::test]
    async fn closed_before_true_is_crashed() {
        let (tx, rx) = watch::channel(false);
        drop(tx);
        let rxs = wrap([rx]);
        let status = wait_ready(&rxs, Duration::from_millis(100)).await;
        assert_eq!(status, ReadyStatus::Crashed);
    }

    #[tokio::test]
    async fn partial_workers_do_not_peek_ready() {
        let (tx0, rx0) = watch::channel(false);
        let (_tx1, rx1) = watch::channel(false);
        let _ = tx0.send(true);
        let rxs = wrap([rx0, rx1]);
        let status = wait_ready(&rxs, Duration::from_millis(10)).await;
        assert_eq!(status, ReadyStatus::Timeout);
    }

    #[tokio::test]
    async fn partial_workers_ready_after_second_signal() {
        let (tx0, rx0) = watch::channel(false);
        let (tx1, rx1) = watch::channel(false);
        let _ = tx0.send(true);
        let _tx0 = tx0;
        let rxs = wrap([rx0, rx1]);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = tx1.send(true);
        });
        let status = wait_ready(&rxs, Duration::from_millis(500)).await;
        assert_eq!(status, ReadyStatus::Ready);
    }

    #[tokio::test]
    async fn partial_workers_crashed_if_unsignaled_sender_dropped() {
        let (tx0, rx0) = watch::channel(false);
        let (tx1, rx1) = watch::channel(false);
        let _ = tx0.send(true);
        drop(tx1);
        let _tx0 = tx0;
        let rxs = wrap([rx0, rx1]);
        let status = wait_ready(&rxs, Duration::from_millis(100)).await;
        assert_eq!(status, ReadyStatus::Crashed);
    }

    #[tokio::test]
    async fn live_false_times_out() {
        let (_tx, rx) = watch::channel(false);
        let rxs = wrap([rx]);
        let status = wait_ready(&rxs, Duration::from_millis(10)).await;
        assert_eq!(status, ReadyStatus::Timeout);
    }

    #[tokio::test]
    async fn fallback_ready_when_signaled_after_delay() {
        let (tx, rx) = watch::channel(false);
        let rxs = wrap([rx]);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = tx.send(true);
        });
        let status = wait_ready(&rxs, Duration::from_millis(500)).await;
        assert_eq!(status, ReadyStatus::Ready);
    }
}
