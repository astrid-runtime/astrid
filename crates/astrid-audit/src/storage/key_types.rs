//! Domain types for durable audit-storage keys and sequence values.
//!
//! Audit projections use several string-shaped keys in different namespaces.
//! Keeping those keys as distinct types makes it harder to pass a session
//! index key to a chain projection (or a segment key to a sequence
//! projection), while the transparent serde representation preserves the
//! existing on-disk append-intent format.

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

/// A monotonically increasing session-entry sequence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct SessionSequence(u64);

impl SessionSequence {
    pub(super) const ZERO: Self = Self(0);

    pub(super) fn checked_next(self) -> Result<Self, &'static str> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or("audit session sequence exhausted")
    }

    pub(super) const fn value(self) -> u64 {
        self.0
    }

    pub(super) const fn bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    pub(super) fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let encoded: [u8; 8] = bytes
            .try_into()
            .map_err(|_| "invalid audit session sequence encoding")?;
        Ok(Self(u64::from_be_bytes(encoded)))
    }
}

/// Exact durable encoding of a session sequence.
///
/// This remains a JSON byte array, matching the pre-existing `Vec<u8>` field
/// in append intents, but cannot represent a malformed sequence in memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub(super) struct SessionSequenceBytes([u8; 8]);

impl SessionSequenceBytes {
    pub(super) const fn from_sequence(sequence: SessionSequence) -> Self {
        Self(sequence.bytes())
    }

    pub(super) fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        Ok(Self::from_sequence(SessionSequence::from_bytes(bytes)?))
    }

    pub(super) const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn validate_key(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("audit storage key cannot be empty");
    }
    if value.len() > 4096 {
        return Err("audit storage key exceeds its bounded length");
    }
    if value
        .bytes()
        .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err("audit storage key contains a control character");
    }
    Ok(())
}

macro_rules! key_type {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub(super) struct $name(String);

        impl $name {
            pub(super) fn new(value: impl Into<String>) -> Result<Self, &'static str> {
                let value = value.into();
                validate_key(&value)?;
                Ok(Self(value))
            }

            pub(super) fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(D::Error::custom)
            }
        }
    };
}

key_type!(ChainKey);
key_type!(SessionKey);
key_type!(SessionIndexKey);
key_type!(SegmentIndexKey);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_sequence_encoding_requires_exactly_eight_bytes() {
        assert!(SessionSequence::from_bytes(&[0; 7]).is_err());
        assert!(SessionSequenceBytes::from_bytes(&[0; 9]).is_err());

        let sequence = SessionSequence::from_bytes(&1_u64.to_be_bytes()).expect("valid sequence");
        assert_eq!(sequence.value(), 1);
        assert_eq!(
            SessionSequenceBytes::from_sequence(sequence).as_bytes(),
            [0, 0, 0, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn durable_key_types_reject_empty_and_control_values() {
        assert!(ChainKey::new("").is_err());
        assert!(SessionKey::new("session\nkey").is_err());
        assert!(SessionIndexKey::new("session:key").is_ok());
    }

    #[test]
    fn sequence_bytes_keep_legacy_json_shape() {
        let bytes = serde_json::to_vec(&SessionSequenceBytes::from_sequence(SessionSequence::ZERO))
            .expect("serialize sequence");
        assert_eq!(bytes, b"[0,0,0,0,0,0,0,0]");
        let decoded: SessionSequenceBytes =
            serde_json::from_slice(&bytes).expect("decode sequence");
        assert_eq!(decoded.as_bytes(), &[0; 8]);
        assert!(serde_json::from_slice::<SessionSequenceBytes>(b"[0,0]").is_err());
    }
}
