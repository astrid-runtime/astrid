//! Monotonic control for one owned checkpoint job. A clean close drains already
//! scheduled maintenance; abandonment/recovery cancels unpublished work.

use std::sync::atomic::{AtomicU8, Ordering};

#[repr(u8)]
enum CheckpointMode {
    Run,
    Drain,
    Cancel,
}

/// A fresh control is created for each job. No operation resets a stopped job
/// to Run, and Drain and Cancel cannot be asserted as independent flags.
pub(in crate::engine::durable) struct CheckpointControl {
    mode: AtomicU8,
}

impl CheckpointControl {
    pub(in crate::engine::durable) const fn running() -> Self {
        Self {
            mode: AtomicU8::new(CheckpointMode::Run as u8),
        }
    }

    /// The closer holds publication custody until joining the worker. Cancel
    /// wins if an abandoning owner has already requested it.
    pub(in crate::engine::durable) fn request_drain(&self) {
        let _ = self.mode.compare_exchange(
            CheckpointMode::Run as u8,
            CheckpointMode::Drain as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub(in crate::engine::durable) fn cancel(&self) {
        self.mode
            .store(CheckpointMode::Cancel as u8, Ordering::Release);
    }

    pub(in crate::engine::durable) fn is_draining(&self) -> bool {
        self.mode.load(Ordering::Acquire) == CheckpointMode::Drain as u8
    }

    pub(in crate::engine::durable) fn is_cancelled(&self) -> bool {
        self.mode.load(Ordering::Acquire) >= CheckpointMode::Cancel as u8
    }
}

/// Physical proofs need only cancellation, not the engine's handoff policy.
pub(in crate::engine::durable) trait CheckpointCancellation {
    fn is_cancelled(&self) -> bool;
}

impl CheckpointCancellation for CheckpointControl {
    fn is_cancelled(&self) -> bool {
        Self::is_cancelled(self)
    }
}

#[cfg(test)]
impl CheckpointCancellation for std::sync::atomic::AtomicBool {
    fn is_cancelled(&self) -> bool {
        self.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_continues_proofs_and_cancel_cannot_be_reset_by_drain() {
        let control = CheckpointControl::running();
        assert!(!control.is_cancelled());
        assert!(!control.is_draining());
        control.request_drain();
        assert!(control.is_draining());
        assert!(!control.is_cancelled());
        control.request_drain();
        assert!(control.is_draining());
        control.cancel();
        assert!(control.is_cancelled());
        assert!(!control.is_draining());
        control.request_drain();
        assert!(control.is_cancelled());
        assert!(!control.is_draining());
    }
}
