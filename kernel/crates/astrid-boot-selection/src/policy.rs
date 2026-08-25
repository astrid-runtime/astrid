//! Independent boot-policy floors.

use crate::types::CandidateFacts;

/// Maximum number of attempts for one pending candidate. This is a fixed
/// journal protocol ceiling, not an operator knob: the frame stores one byte
/// and bounded retries are required for deterministic recovery.
pub const MAX_ATTEMPTS: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectionPolicy {
    min_generation: u64,
    min_rollback_floor: u64,
    min_kernel_floor: u64,
    min_sysgen_floor: u64,
}

impl SelectionPolicy {
    pub const fn new(
        min_generation: u64,
        min_rollback_floor: u64,
        min_kernel_floor: u64,
        min_sysgen_floor: u64,
    ) -> Self {
        Self {
            min_generation,
            min_rollback_floor,
            min_kernel_floor,
            min_sysgen_floor,
        }
    }

    pub(crate) const fn accepts(self, facts: &CandidateFacts) -> bool {
        facts.generation() >= self.min_generation
            && facts.rollback_floor() >= self.min_rollback_floor
            && facts.kernel_floor() >= self.min_kernel_floor
            && facts.sysgen_floor() >= self.min_sysgen_floor
    }
}
