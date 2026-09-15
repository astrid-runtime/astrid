//! Small route-state primitives shared by enqueue and bus allocation.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use super::entry::PrincipalQueue;

impl PrincipalQueue {
    pub(crate) fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            bytes: 0,
            head_enqueued_at: None,
            deficit: 0,
        }
    }
}

/// Monotonic subscription-rep allocator shared across `EventBus` clones.
#[derive(Debug, Default)]
pub(crate) struct SubscriptionRepAllocator(AtomicU64);

impl SubscriptionRepAllocator {
    pub(crate) fn next(&self) -> u64 {
        // Skip zero so it can sentinel "unallocated" if a debug path needs.
        let value = self.0.fetch_add(1, Ordering::Relaxed);
        value.saturating_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_increments_monotonically() {
        let allocator = SubscriptionRepAllocator::default();
        let first = allocator.next();
        let second = allocator.next();
        assert_eq!(second, first.saturating_add(1));
    }
}
