//! Entropy seed via RDRAND, CPUID-gated. Never substitutes a PRNG: absence is
//! reported honestly as `entropy.unavailable` (threat model: no silent entropy
//! fallback).

use raw_cpuid::CpuId;

/// Attempt to draw one hardware random word. Returns `true` iff RDRAND is
/// present per CPUID and produced a value.
pub fn seed() -> bool {
    let has_rdrand = CpuId::new()
        .get_feature_info()
        .is_some_and(|f| f.has_rdrand());
    if !has_rdrand {
        return false;
    }
    // SAFETY: guarded by the CPUID feature check above.
    unsafe { rdrand64().is_some() }
}

#[target_feature(enable = "rdrand")]
unsafe fn rdrand64() -> Option<u64> {
    let mut value: u64 = 0;
    for _ in 0..10 {
        // SAFETY: RDRAND is available (CPUID-gated by the caller); the
        // intrinsic writes `value` and returns 1 on success. The enclosing
        // `unsafe fn` body is the unsafe context (edition 2021).
        let ok = core::arch::x86_64::_rdrand64_step(&mut value);
        if ok == 1 {
            return Some(value);
        }
    }
    None
}
