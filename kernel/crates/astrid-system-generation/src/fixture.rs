//! Emulator-only fixture key derivation; never a product owner key.

use ed25519_dalek::SigningKey;

pub fn fixture_signing_key() -> SigningKey {
    let mut hasher = blake3::Hasher::new_derive_key("astrid.system-generation.fixture.v1");
    hasher.update(b"system-generation");
    SigningKey::from_bytes(hasher.finalize().as_bytes())
}
