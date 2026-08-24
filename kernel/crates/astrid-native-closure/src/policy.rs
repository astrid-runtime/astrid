//! Trust policy is external to the untrusted closure table.
//!
//! Ring 0 compiles emulator-fixture *public* keys and independent minimum
//! floors. The table cannot choose verifying keys or rollback policy.
//! Authenticated loader handoff is not available; this is not a firmware
//! root of trust and not self-measurement. Fixture private keys are absent.

use crate::error::ClosureError;
use crate::types::GenerationFloor;

/// blake3/ed25519 verifying key for the emulator-fixture kernel signer.
/// Computed from the host-only fixture seed; the seed itself is not here.
pub const EMULATOR_KERNEL_VERIFY_KEY: [u8; 32] = [
    0x25, 0x2f, 0x25, 0xe8, 0xe0, 0x9b, 0x12, 0x48, 0x0c, 0x90, 0xe0, 0xd5, 0x1b, 0x55, 0x6a, 0x13,
    0x4d, 0x7d, 0xe0, 0xdd, 0xcb, 0xba, 0x7b, 0xfa, 0x38, 0x15, 0xc2, 0x68, 0x0a, 0x2e, 0x37, 0x79,
];

/// blake3/ed25519 verifying key for the emulator-fixture sysgen signer.
pub const EMULATOR_SYSGEN_VERIFY_KEY: [u8; 32] = [
    0x44, 0x25, 0x8a, 0x20, 0x57, 0x06, 0xf2, 0x64, 0x68, 0xd5, 0x7e, 0xe2, 0xc2, 0x68, 0x1e, 0x62,
    0x8c, 0x9b, 0xd5, 0x15, 0x10, 0x8a, 0xe7, 0xb2, 0x2a, 0xb4, 0x10, 0x77, 0x59, 0xd1, 0xbf, 0x31,
];

/// Expected kernel and System Generation verifying keys plus independent floors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedPolicy {
    kernel_verify: [u8; 32],
    sysgen_verify: [u8; 32],
    kernel_min: GenerationFloor,
    sysgen_min: GenerationFloor,
}

impl TrustedPolicy {
    /// Construct a policy. The two verifying keys must be distinct.
    pub const fn try_new(
        kernel_verify: [u8; 32],
        sysgen_verify: [u8; 32],
        kernel_min: GenerationFloor,
        sysgen_min: GenerationFloor,
    ) -> Result<Self, ClosureError> {
        if keys_equal(&kernel_verify, &sysgen_verify) {
            return Err(ClosureError::SameKey);
        }
        Ok(Self {
            kernel_verify,
            sysgen_verify,
            kernel_min,
            sysgen_min,
        })
    }

    /// Emulator-proof policy: compiled fixture public keys and `CURRENT_FLOOR`
    /// as both independent minima.
    pub const fn emulator_fixture() -> Self {
        match Self::try_new(
            EMULATOR_KERNEL_VERIFY_KEY,
            EMULATOR_SYSGEN_VERIFY_KEY,
            crate::types::CURRENT_FLOOR,
            crate::types::CURRENT_FLOOR,
        ) {
            Ok(policy) => policy,
            Err(_) => panic!("emulator fixture keys are distinct"),
        }
    }

    pub const fn kernel_verify(self) -> [u8; 32] {
        self.kernel_verify
    }

    pub const fn sysgen_verify(self) -> [u8; 32] {
        self.sysgen_verify
    }

    pub const fn kernel_min(self) -> GenerationFloor {
        self.kernel_min
    }

    pub const fn sysgen_min(self) -> GenerationFloor {
        self.sysgen_min
    }
}

const fn keys_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < 32 {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
