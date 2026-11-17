//! Cancellation-safe channel ownership for blocked-commit handoff tests.
//!
//! Pair with `DurableEngine::gate_next_group_drain_channel`: the drain worker
//! `try_send`s entry then `recv`s release. Owning `_release_tx` means Drop
//! always closes the release channel, so late entry after abandon cannot
//! strand the worker.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::time::Duration;

/// Bound for observing drain entry after the blocked commit has been started.
pub(super) const ENTRY_OBSERVE_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug)]
pub(super) enum EntryObserveError {
    TimedOut,
    Disconnected,
}

impl std::fmt::Display for EntryObserveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimedOut => write!(
                formatter,
                "timed out waiting for drain-gate entry after starting blocked commit"
            ),
            Self::Disconnected => write!(
                formatter,
                "drain-gate entry channel disconnected before entry"
            ),
        }
    }
}

/// Parent-side channel drain gate. Field drop always releases the worker.
pub(super) struct BlockedCommitGate {
    entered_rx: Receiver<()>,
    _release_tx: SyncSender<()>,
    entered: bool,
}

impl BlockedCommitGate {
    pub(super) fn from_channel_gate(entered_rx: Receiver<()>, release_tx: SyncSender<()>) -> Self {
        Self {
            entered_rx,
            _release_tx: release_tx,
            entered: false,
        }
    }

    pub(super) fn wait_for_entry(&mut self, timeout: Duration) -> Result<(), EntryObserveError> {
        match self.entered_rx.recv_timeout(timeout) {
            Ok(()) => {
                self.entered = true;
                Ok(())
            },
            Err(RecvTimeoutError::Timeout) => Err(EntryObserveError::TimedOut),
            Err(RecvTimeoutError::Disconnected) => Err(EntryObserveError::Disconnected),
        }
    }

    pub(super) fn entered(&self) -> bool {
        self.entered
    }

    /// Explicit release by dropping the owned release sender.
    pub(super) fn release(self) {
        drop(self);
    }
}

#[test]
fn late_entry_after_parent_guard_drop_does_not_strand_worker() {
    // Parent can abandon observation before the worker reaches the gate.
    let (entered_tx, entered_rx) = mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(0);
    let gate = BlockedCommitGate::from_channel_gate(entered_rx, release_tx);
    assert!(!gate.entered());
    drop(gate);

    let worker = std::thread::spawn(move || {
        let _ = entered_tx.try_send(());
        let _ = release_rx.recv();
    });
    worker
        .join()
        .expect("late drain worker must complete after parent release drop");
}

#[test]
fn entry_observe_timeout_still_releases_on_drop() {
    let (entered_tx, entered_rx) = mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(0);
    let mut gate = BlockedCommitGate::from_channel_gate(entered_rx, release_tx);
    let err = gate
        .wait_for_entry(Duration::from_millis(20))
        .expect_err("no worker yet");
    assert!(matches!(err, EntryObserveError::TimedOut));
    assert!(!gate.entered());
    drop(gate);

    let worker = std::thread::spawn(move || {
        let _ = entered_tx.try_send(());
        let _ = release_rx.recv();
    });
    worker
        .join()
        .expect("worker arriving after observe timeout must not strand");
}

#[test]
fn explicit_release_unblocks_entered_worker() {
    let (entered_tx, entered_rx) = mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(0);
    let mut gate = BlockedCommitGate::from_channel_gate(entered_rx, release_tx);
    let worker = std::thread::spawn(move || {
        entered_tx
            .try_send(())
            .expect("entered buffer accepts one signal");
        let _ = release_rx.recv();
    });
    gate.wait_for_entry(ENTRY_OBSERVE_TIMEOUT)
        .expect("parent must observe entry before release");
    assert!(gate.entered());
    gate.release();
    worker
        .join()
        .expect("entered worker must complete after explicit release");
}
