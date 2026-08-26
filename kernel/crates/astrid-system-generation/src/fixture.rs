//! Emulator-only fixture values; never a product owner key.

/// Plan digest bound to the descriptor fixture. This is a compiled test value,
/// not a digest of a live service plan.
pub const EMULATOR_PLAN_DIGEST: [u8; 32] = [0x11; 32];

/// Object-root digest bound to the descriptor fixture.
pub const EMULATOR_OBJECT_ROOT: [u8; 32] = [0x22; 32];

/// Closure-root digest bound to the descriptor fixture.
pub const EMULATOR_CLOSURE_ROOT: [u8; 32] = [0x33; 32];

/// System Generation floor for the emulator descriptor, independent of the
/// dual-closure rollback floors.
pub const EMULATOR_GENERATION_FLOOR: u64 = 1;

/// The emulator has no wall-clock authority; zero keeps the fixture unexpired.
pub const EMULATOR_NOW_UNIX_SECONDS: u64 = 0;

/// Fixed descriptor size claims shared by host signing and ring-0 admission.
pub const EMULATOR_MANIFEST_SIZES: crate::ManifestSizes = crate::ManifestSizes::new(1, 2, 3, 4);

/// The emulator descriptor carries no component/service entries.
pub const EMULATOR_COMPONENTS: crate::ComponentSet = crate::ComponentSet::empty();

#[cfg(any(test, feature = "sign"))]
use ed25519_dalek::SigningKey;

#[cfg(any(test, feature = "sign"))]
pub fn fixture_signing_key() -> SigningKey {
    let mut hasher = blake3::Hasher::new_derive_key("astrid.system-generation.fixture.v1");
    hasher.update(b"system-generation");
    SigningKey::from_bytes(hasher.finalize().as_bytes())
}
