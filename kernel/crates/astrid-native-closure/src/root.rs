//! Explicit root input for the authenticated policy-handoff fixture.
//!
//! The root verifier is supplied by the caller. This crate does not contain a
//! production root key, perform firmware enrollment, or select a root from
//! the handoff bytes.

use crate::error::ClosureError;
use crate::types::{GenerationFloor, PolicyGeneration};

/// Authenticated expectations used to verify one loader policy handoff.
///
/// The root key and rollback minima are inputs to verification, never
/// advertisements accepted from the envelope. The root signature authorizes
/// the subordinate keys carried by each handoff, so a later policy can rotate
/// them without recompiling this verifier. Artifact floors remain independent:
/// each handoff floor must meet its corresponding root minimum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootVerifier {
    root_verify: [u8; 32],
    kernel_min: GenerationFloor,
    sysgen_min: GenerationFloor,
    min_policy_generation: PolicyGeneration,
}

impl RootVerifier {
    /// Construct explicit root expectations.
    pub const fn try_new(
        root_verify: [u8; 32],
        kernel_min: GenerationFloor,
        sysgen_min: GenerationFloor,
        min_policy_generation: PolicyGeneration,
    ) -> Result<Self, ClosureError> {
        Ok(Self {
            root_verify,
            kernel_min,
            sysgen_min,
            min_policy_generation,
        })
    }

    pub const fn root_verify(self) -> [u8; 32] {
        self.root_verify
    }

    pub const fn kernel_min(self) -> GenerationFloor {
        self.kernel_min
    }

    pub const fn sysgen_min(self) -> GenerationFloor {
        self.sysgen_min
    }

    pub const fn min_policy_generation(self) -> PolicyGeneration {
        self.min_policy_generation
    }
}
