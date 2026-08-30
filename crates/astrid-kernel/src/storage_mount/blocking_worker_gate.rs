//! Test-only synchronization for filesystem workers inside `spawn_blocking`.

use std::sync::mpsc;

/// Coordinates workers after the blocking closure starts, so revocation tests
/// prove the job was already executing rather than merely queued.
pub(super) struct BlockingWorkerTestGate {
    entered_tx: mpsc::Sender<()>,
    entered_rx: std::sync::Mutex<mpsc::Receiver<()>>,
    failed_tx: mpsc::Sender<()>,
    failed_rx: std::sync::Mutex<mpsc::Receiver<()>>,
    release_txs: std::sync::Mutex<Vec<mpsc::SyncSender<()>>>,
    panic_on_release: std::sync::atomic::AtomicBool,
}

impl BlockingWorkerTestGate {
    pub(super) fn new() -> Self {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (failed_tx, failed_rx) = mpsc::channel();
        Self {
            entered_tx,
            entered_rx: std::sync::Mutex::new(entered_rx),
            failed_tx,
            failed_rx: std::sync::Mutex::new(failed_rx),
            release_txs: std::sync::Mutex::new(Vec::new()),
            panic_on_release: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(super) fn wait_entered(&self, worker_count: usize) {
        let receiver = self
            .entered_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for index in 0..worker_count {
            receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap_or_else(|_| panic!("filesystem worker {index} did not enter"));
        }
    }

    pub(super) fn release_workers(&self) {
        let senders = self
            .release_txs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
            .collect::<Vec<_>>();
        for sender in senders {
            let _ = sender.send(());
        }
    }

    pub(super) fn arm_panic_on_release(&self) {
        self.panic_on_release
            .store(true, std::sync::atomic::Ordering::Release);
    }

    pub(super) fn wait_failed(&self, worker_count: usize) {
        let receiver = self
            .failed_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for index in 0..worker_count {
            receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap_or_else(|_| panic!("filesystem worker {index} did not fail"));
        }
    }

    pub(super) fn run_worker(&self) {
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        self.release_txs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(release_tx);
        let _ = self.entered_tx.send(());
        if release_rx.recv().is_err() {
            return;
        }
        if self
            .panic_on_release
            .load(std::sync::atomic::Ordering::Acquire)
        {
            let _ = self.failed_tx.send(());
            panic!("filesystem worker failed after revocation");
        }
    }
}
