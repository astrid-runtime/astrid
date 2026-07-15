//! Domain-separated BLAKE3 identifiers.
//!
//! [`ContentHash`](crate::ContentHash) identifies bytes as content. This
//! module covers identifiers derived from values for a particular purpose,
//! such as a token verifier or public-key fingerprint. Keeping the two types
//! distinct prevents equal-width digests from being used across protocols.

use std::fmt;

use crate::{CryptoResult, PublicKey};

/// A domain-separated BLAKE3 identifier.
///
/// The default representation is the full 32-byte identifier. The generic
/// parameter supports typed wrappers without changing the derivation API.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdentifierHash<T = [u8; 32]>(T);

impl<T> IdentifierHash<T> {
    /// Borrow the wrapped representation.
    #[must_use]
    pub const fn as_inner(&self) -> &T {
        &self.0
    }

    /// Consume the identifier and return its wrapped representation.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Transform the representation while preserving the identifier's domain.
    ///
    /// This is the safe construction path for non-default generic
    /// specializations: callers first derive or validate an identifier, then
    /// map its representation without reinterpreting unrelated bytes.
    #[must_use]
    pub fn map<U>(self, map: impl FnOnce(T) -> U) -> IdentifierHash<U> {
        IdentifierHash(map(self.0))
    }
}

impl IdentifierHash<[u8; 32]> {
    /// Derive an identifier within a fixed application context.
    ///
    /// Callers must use a stable, purpose-specific context constant. BLAKE3's
    /// derive-key mode provides the domain separation; callers do not need to
    /// construct ad-hoc byte prefixes.
    #[must_use]
    pub fn derive(context: &'static str, value: &[u8]) -> Self {
        Self(blake3::derive_key(context, value))
    }

    /// Create an identifier from its full byte representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the full byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encode the identifier as lowercase hexadecimal.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Encode as `blake3:<lowercase hex>`.
    #[must_use]
    pub fn to_prefixed_hex(&self) -> String {
        format!("blake3:{}", self.to_hex())
    }
}

impl fmt::Debug for IdentifierHash<[u8; 32]> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdentifierHash({})", self.to_prefixed_hex())
    }
}

impl fmt::Display for IdentifierHash<[u8; 32]> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_prefixed_hex())
    }
}

impl AsRef<[u8]> for IdentifierHash<[u8; 32]> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A full BLAKE3 fingerprint for an Ed25519 public key.
///
/// This is deliberately distinct from [`IdentifierHash`] at API boundaries:
/// a public-key fingerprint must not be accepted where a token verifier or
/// another identifier happens to have the same representation.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKeyFingerprint<T = String>(T);

impl<T> PublicKeyFingerprint<T> {
    /// Borrow the wrapped representation.
    #[must_use]
    pub const fn as_inner(&self) -> &T {
        &self.0
    }

    /// Consume the fingerprint and return its wrapped representation.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Transform the representation of a validated fingerprint.
    ///
    /// This constructs non-default generic specializations without exposing an
    /// unchecked constructor for the semantic fingerprint type.
    #[must_use]
    pub fn map<U>(self, map: impl FnOnce(T) -> U) -> PublicKeyFingerprint<U> {
        PublicKeyFingerprint(map(self.0))
    }
}

impl PublicKeyFingerprint<String> {
    /// Derive a fingerprint from a validated Ed25519 public key.
    #[must_use]
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        const CONTEXT: &str = "astrid.runtime.ed25519-public-key.fingerprint.v1";
        Self(IdentifierHash::derive(CONTEXT, public_key.as_bytes()).to_prefixed_hex())
    }

    /// Parse a bare or `ed25519:`-prefixed hexadecimal key and fingerprint it.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is not a 32-byte Ed25519 public key.
    pub fn from_ed25519_hex(value: &str) -> CryptoResult<Self> {
        let hex = value.strip_prefix("ed25519:").unwrap_or(value);
        let public_key = PublicKey::from_hex(hex)?;
        Ok(Self::from_public_key(&public_key))
    }

    /// Borrow the `blake3:<lowercase hex>` representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PublicKeyFingerprint<String> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKeyFingerprint({})", self.0)
    }
}

impl fmt::Display for PublicKeyFingerprint<String> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for PublicKeyFingerprint<String> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_produce_distinct_identifiers() {
        let value = b"same input";
        let invite = IdentifierHash::derive("Astrid invite token 2026-07-15 v1", value);
        let pair = IdentifierHash::derive("Astrid pair token 2026-07-15 v1", value);
        assert_ne!(invite, pair);
        assert_eq!(invite.to_hex().len(), 64);
        let encoded = invite.map(hex::encode);
        assert_eq!(encoded.as_inner().len(), 64);
    }

    #[test]
    fn public_key_fingerprint_normalizes_supported_hex_forms() {
        let key = "ab".repeat(32);
        let bare = PublicKeyFingerprint::from_ed25519_hex(&key).unwrap();
        let prefixed = PublicKeyFingerprint::from_ed25519_hex(&format!("ed25519:{key}")).unwrap();
        assert_eq!(bare, prefixed);
        assert_eq!(
            bare.as_str(),
            "blake3:bfae897f0bf656d68f50c4fde6fc273a7d6c8a28feb8c127f7d2cf9bb54d18b8"
        );
        assert_eq!(bare.as_str().len(), 71);
        let bytes = bare.map(String::into_bytes);
        assert_eq!(bytes.as_inner().len(), 71);
    }

    #[test]
    fn public_key_fingerprint_rejects_invalid_keys() {
        assert!(PublicKeyFingerprint::from_ed25519_hex("abcd").is_err());
        assert!(PublicKeyFingerprint::from_ed25519_hex(&"zz".repeat(32)).is_err());
    }
}
