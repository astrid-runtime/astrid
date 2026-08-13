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
}

impl RouteAdmissionGate {
    /// Construct a gate for an already-published runtime.
    #[must_use]
    pub fn published() -> Self {
        Self {
            published: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Construct a closed gate for a staged runtime.
    #[must_use]
    pub fn staged() -> Self {
        Self {
            published: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Atomically admit future matching events on every route sharing this gate.
    pub fn publish(&self) {
        self.published.store(true, Ordering::Release);
    }

    /// Atomically reject all future events for a retiring runtime.
    pub fn retire(&self) {
        self.published.store(false, Ordering::Release);
    }

    /// Whether this runtime's routes currently admit external events.
    #[must_use]
    pub fn is_published(&self) -> bool {
        self.published.load(Ordering::Acquire)
    }
}

impl Default for RouteAdmissionGate {
    fn default() -> Self {
        Self::published()
    }
}
