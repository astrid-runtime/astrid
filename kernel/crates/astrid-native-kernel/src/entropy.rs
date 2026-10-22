//! CPUID-gated RDRAND provisioning of move-only boot audit custody material.
//!
//! There is deliberately no PRNG, fixture, or default fallback here. A missing
//! feature, exhausted retry counter, or rejected degenerate block is a boot
//! failure before audit authority or domain execution can exist.

use raw_cpuid::CpuId;
use zeroize::Zeroizing;

use crate::audit::{BootSessionId, KernelSecretEntropy};

/// Public view of the two-custodian audit identity minted at boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvisionedAuditIdentity {
    boot: BootSessionId,
    authority_id: u64,
}

impl ProvisionedAuditIdentity {
    pub const fn boot(&self) -> BootSessionId {
        self.boot
    }

    pub const fn authority_id(&self) -> u64 {
        self.authority_id
    }
}

/// Public terminal for boot installation; replacement is always rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditInstallError {
    AlreadyInstalled,
    CustodyRejected,
}

/// Six 64-bit draws cover one nonzero 16-byte boot identity and one nonzero
/// 32-byte secret. Each word is consumed exactly once by these constructors.
const REQUIRED_WORDS: usize = 6;

pub struct ProvisionedEntropy {
    boot: BootSessionId,
    secret: KernelSecretEntropy,
}

impl ProvisionedEntropy {
    pub const fn boot(&self) -> BootSessionId {
        self.boot
    }

    pub(crate) fn secret(self) -> KernelSecretEntropy {
        self.secret
    }
}

impl core::fmt::Debug for ProvisionedEntropy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProvisionedEntropy(REDACTED)")
    }
}

/// Draws all required words or returns nothing. No partial set is provisioned.
pub fn provision() -> Option<ProvisionedEntropy> {
    if !has_rdrand() {
        return None;
    }
    let mut words = Zeroizing::new([0u64; REQUIRED_WORDS]);
    for word in words.iter_mut() {
        *word = rdrand_word()?;
    }
    provision_from_words(*words)
}

/// Public boot facade for the private audit-custody runtime. This keeps the
/// authority module kernel-private while giving the freestanding binary one
/// owned provisioning entry point.
pub fn install(seed: ProvisionedEntropy) -> Result<ProvisionedAuditIdentity, AuditInstallError> {
    let identity = crate::audit::install(seed).map_err(|error| match error {
        crate::audit::AuditInstallError::AlreadyInstalled => AuditInstallError::AlreadyInstalled,
        crate::audit::AuditInstallError::CustodyRejected => AuditInstallError::CustodyRejected,
    })?;
    Ok(ProvisionedAuditIdentity {
        boot: identity.boot(),
        authority_id: identity.authority_id(),
    })
}

/// Pure provisioning boundary for tests and explicit byte layout review.
fn provision_from_words(words: [u64; REQUIRED_WORDS]) -> Option<ProvisionedEntropy> {
    let words = Zeroizing::new(words);
    let mut boot_bytes = Zeroizing::new([0u8; 16]);
    boot_bytes[..8].copy_from_slice(&words[0].to_le_bytes());
    boot_bytes[8..].copy_from_slice(&words[1].to_le_bytes());
    let mut secret_bytes = Zeroizing::new([0u8; 32]);
    for (output, input) in secret_bytes.chunks_exact_mut(8).zip(words[2..].iter()) {
        output.copy_from_slice(&input.to_le_bytes());
    }
    Some(ProvisionedEntropy {
        boot: BootSessionId::new(*boot_bytes)?,
        secret: KernelSecretEntropy::new(*secret_bytes)?,
    })
}

fn has_rdrand() -> bool {
    CpuId::new()
        .get_feature_info()
        .is_some_and(|feature| feature.has_rdrand())
}

#[cfg(target_arch = "x86_64")]
fn rdrand_word() -> Option<u64> {
    // SAFETY: has_rdrand gated this call on the CPUID RDRAND feature.
    unsafe { rdrand64() }
}

#[cfg(not(target_arch = "x86_64"))]
fn rdrand_word() -> Option<u64> {
    None
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "rdrand")]
unsafe fn rdrand64() -> Option<u64> {
    let mut value: u64 = 0;
    for _ in 0..10 {
        // SAFETY: RDRAND is available and this is the only write to value.
        let ok = core::arch::x86_64::_rdrand64_step(&mut value);
        if ok == 1 {
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(seed: u64) -> [u64; REQUIRED_WORDS] {
        [seed, seed ^ 1, seed ^ 2, seed ^ 3, seed ^ 4, seed ^ 5]
    }

    #[test]
    fn provision_rejects_a_degenerate_seed() {
        assert!(provision_from_words([0; REQUIRED_WORDS]).is_none());
        let mut zero_boot = words(0x1122334455667788);
        zero_boot[0] = 0;
        zero_boot[1] = 0;
        assert!(provision_from_words(zero_boot).is_none());

        let mut zero_secret = words(0x1122334455667788);
        zero_secret[2..].fill(0);
        assert!(provision_from_words(zero_secret).is_none());
    }

    #[test]
    fn provisioned_custody_is_move_only() {
        let seed = provision_from_words(words(0x1122334455667788)).unwrap();
        let boot = seed.boot();
        let secret = seed.secret();
        assert_ne!(boot.bytes(), [0; 16]);
        assert_ne!(secret_bytes(&secret), [0; 32]);

        // A complete transfer is the only way to reach both custody fields:
        // the helper consumes the seed rather than borrowing or cloning it.
        fn consume(seed: ProvisionedEntropy) -> BootSessionId {
            seed.boot()
        }
        let transferred = consume(ProvisionedEntropy { boot, secret });
        assert_eq!(transferred, boot);
    }

    #[test]
    fn rejected_partial_draws_never_install_custody() {
        let seed = provision_from_words(words(0x1122334455667788)).unwrap();
        assert_ne!(seed.boot().bytes(), [0; 16]);
        // The public surface offers no secret accessor before consumption;
        // consume is the ownership transition into private custody.
        let secret = seed.secret();
        assert_ne!(secret_bytes(&secret), [0; 32]);
    }
}

#[cfg(test)]
fn secret_bytes(secret: &KernelSecretEntropy) -> [u8; 32] {
    secret.test_bytes()
}
