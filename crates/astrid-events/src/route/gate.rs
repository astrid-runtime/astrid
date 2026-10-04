//! Shared publication gate for staged routed subscriptions.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Admission gate shared by every routed subscription owned by one runtime.
///
/// A staged runtime can create its subscriptions and become internally ready
/// while this gate is closed. Publishing the runtime opens the same atomic gate
/// for every route without rebuilding subscriptions or draining a pre-publish
/// backlog (closed routes reject events at enqueue time).
#[derive(Clone, Debug)]
pub struct RouteAdmissionGate {
    published: Arc<AtomicBool>,
    commit: Arc<parking_lot::Mutex<()>>,
}

/// Short synchronous publication guard. Never retain it across an admission
/// wait or invoke external observers while holding it.
pub struct RouteCommitGuard {
    _guard: parking_lot::ArcMutexGuard<parking_lot::RawMutex, ()>,
}

impl RouteAdmissionGate {
    /// Construct a gate for an already-published runtime.
    #[must_use]
    pub fn published() -> Self {
        Self {
            published: Arc::new(AtomicBool::new(true)),
            commit: Arc::new(parking_lot::Mutex::new(())),
        }
    }

    /// Construct a closed gate for a staged runtime.
    #[must_use]
    pub fn staged() -> Self {
        Self {
            published: Arc::new(AtomicBool::new(false)),
            commit: Arc::new(parking_lot::Mutex::new(())),
        }
    }

    /// Atomically admit future matching events on every route sharing this gate.
    pub fn publish(&self) {
        let _guard = self.commit.lock();
        self.published.store(true, Ordering::Release);
    }

    /// Atomically reject all future events for a retiring runtime.
    pub fn retire(&self) {
        let _guard = self.commit.lock();
        self.published.store(false, Ordering::Release);
    }

    /// Whether this runtime's routes currently admit external events.
    #[must_use]
    pub fn is_published(&self) -> bool {
        self.published.load(Ordering::Acquire)
    }

    /// Fence a reserved publication against concurrent retirement. A closed
    /// generation cannot be replaced by another generation's gate.
    #[must_use]
    pub fn commit_guard(&self) -> Option<RouteCommitGuard> {
        let guard = self.commit.lock_arc();
        self.is_published()
            .then_some(RouteCommitGuard { _guard: guard })
    }
}

impl Default for RouteAdmissionGate {
    fn default() -> Self {
        Self::published()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retirement_waits_for_short_commit_guard_and_then_refuses_new_commits() {
        let gate = RouteAdmissionGate::published();
        let guard = gate.commit_guard().expect("published generation");
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (retired_tx, retired_rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                entered_tx.send(()).unwrap();
                gate.retire();
                retired_tx.send(()).unwrap();
            });
            entered_rx.recv().unwrap();
            assert!(
                retired_rx
                    .recv_timeout(std::time::Duration::from_millis(10))
                    .is_err()
            );
            drop(guard);
            retired_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
        });
        assert!(!gate.is_published());
        assert!(gate.commit_guard().is_none());
    }
}
