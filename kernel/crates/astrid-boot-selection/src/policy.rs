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
    min_policy_generation: u64,
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
            min_policy_generation: 0,
        }
    }

    /// Construct a policy from an authenticated loader handoff. The policy
    /// generation is a separate replay floor; it is never inferred from a
    /// descriptor generation or either closure floor.
    // This constructor is intentionally private until the selector is wired
    // to the real boot path; public callers retain `new` compatibility.
    #[allow(dead_code)]
    pub(crate) const fn from_authenticated(
        min_generation: u64,
        min_rollback_floor: u64,
        min_kernel_floor: u64,
        min_sysgen_floor: u64,
        min_policy_generation: u64,
    ) -> Self {
        Self {
            min_generation,
            min_rollback_floor,
            min_kernel_floor,
            min_sysgen_floor,
            min_policy_generation,
        }
    }

    pub(crate) const fn accepts(self, facts: &CandidateFacts) -> bool {
        facts.generation() >= self.min_generation
            && facts.rollback_floor() >= self.min_rollback_floor
            && facts.kernel_floor() >= self.min_kernel_floor
            && facts.sysgen_floor() >= self.min_sysgen_floor
            && self.accepts_authenticated_generation(facts.policy_generation())
    }

    pub(crate) const fn accepts_authenticated_generation(self, generation: u64) -> bool {
        generation >= self.min_policy_generation
    }
}
