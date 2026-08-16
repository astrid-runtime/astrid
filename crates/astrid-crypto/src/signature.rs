//! Ed25519 signatures.
//!
//! Provides signature types and verification for:
//! - Capability token signing
//! - Audit entry signing
//! - User identity verification

use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::error::{CryptoError, CryptoResult};

/// An Ed25519 signature (64 bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Create from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Try to create from a slice.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidSignatureLength`] if the slice is not exactly 64 bytes.
    pub fn try_from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != 64 {
            return Err(CryptoError::InvalidSignatureLength {
                expected: 64,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Get the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Encode as hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Decode from hex string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not valid hex or not 64 bytes.
    pub fn from_hex(s: &str) -> CryptoResult<Self> {
        let bytes = hex::decode(s).map_err(|_| CryptoError::InvalidHexEncoding)?;
        Self::try_from_slice(&bytes)
    }

    /// Encode as base64 string.
    #[must_use]
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }

    /// Decode from base64 string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not valid base64 or not 64 bytes.
    pub fn from_base64(s: &str) -> CryptoResult<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|_| CryptoError::InvalidBase64Encoding)?;
        Self::try_from_slice(&bytes)
    }

    /// Verify this signature against a message and public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the public key is invalid or signature verification fails.
    pub fn verify(&self, message: &[u8], public_key: &[u8; 32]) -> CryptoResult<()> {
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

        let sig = DalekSignature::from_bytes(&self.0);

        verifying_key
            .verify(message, &sig)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    /// Convert to the underlying dalek signature type.
    #[must_use]
    pub fn to_dalek(&self) -> DalekSignature {
        DalekSignature::from_bytes(&self.0)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({}...)", &self.to_hex()[..16])
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_base64(&s).map_err(serde::de::Error::custom)
    }
}

impl From<DalekSignature> for Signature {
    fn from(sig: DalekSignature) -> Self {
        Self(sig.to_bytes())
    }
}

impl From<Signature> for DalekSignature {
    fn from(sig: Signature) -> Self {
        DalekSignature::from_bytes(&sig.0)
    }
}

impl From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

impl From<Signature> for [u8; 64] {
    fn from(sig: Signature) -> Self {
        sig.0
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    #[test]
    fn test_signature_encoding() {
        let keypair = KeyPair::generate();
        let message = b"test message";
        let sig = keypair.sign(message);

        // Hex roundtrip
        let hex = sig.to_hex();
        let decoded = Signature::from_hex(&hex).unwrap();
        assert_eq!(sig, decoded);

        // Base64 roundtrip
        let b64 = sig.to_base64();
        let decoded = Signature::from_base64(&b64).unwrap();
        assert_eq!(sig, decoded);
    }

    #[test]
    fn signature_base64_wire_format_remains_standard_padded() {
        let signature = Signature::try_from_slice(&[0u8; 64]).unwrap();
        assert_eq!(
            signature.to_base64(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
        );
        assert_eq!(
            Signature::from_base64(&signature.to_base64()).unwrap(),
            signature
        );
    }

    #[test]
    fn test_signature_verification() {
        let keypair = KeyPair::generate();
        let message = b"test message";
        let sig = keypair.sign(message);

        // Should verify with correct public key
        assert!(sig.verify(message, keypair.public_key_bytes()).is_ok());

        // Should fail with wrong message
        assert!(
            sig.verify(b"wrong message", keypair.public_key_bytes())
                .is_err()
        );

        // Should fail with wrong public key
        let other_keypair = KeyPair::generate();
        assert!(
            sig.verify(message, other_keypair.public_key_bytes())
                .is_err()
        );
    }

    #[test]
    fn test_invalid_signature_length() {
        let result = Signature::try_from_slice(&[0u8; 63]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidSignatureLength { .. })
        ));
    }
}
