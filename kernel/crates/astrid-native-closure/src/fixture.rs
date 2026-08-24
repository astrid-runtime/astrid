//! Emulator-only fixture keys. Not production, not first-owner, not a
//! distribution root. Secrets are derived and never logged.

use ed25519_dalek::SigningKey;

/// Which fixture key to derive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureRole {
    KernelBootstrap,
    SystemGeneration,
}

/// Derive an emulator-stub signing key for `role`.
///
/// The domain string is not a product seed and must not be reused as owner
/// material.
pub fn fixture_signing_key(role: FixtureRole) -> SigningKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"astrid.native.dual-closure.fixture.v1");
    hasher.update(match role {
        FixtureRole::KernelBootstrap => b"kernel-bootstrap",
        FixtureRole::SystemGeneration => b"system-generation",
    });
    SigningKey::from_bytes(hasher.finalize().as_bytes())
}
