//! Validated quantities for durable principal-home migration receipts.
//!
//! These types keep the existing JSON field shapes: hex strings stay strings,
//! counts stay numbers. Constructors reject the values that later receipt
//! checks already treat as non-canonical.

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

const BLAKE3_HEX_LEN: usize = 64;

/// Supported principal-home receipt schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub(super) struct ReceiptSchema(u32);

impl ReceiptSchema {
    pub(super) const V2: Self = Self(2);

    pub(super) const fn get(self) -> u32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for ReceiptSchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        if value != Self::V2.0 {
            return Err(D::Error::custom(
                "principal-home receipt schema is not supported",
            ));
        }
        Ok(Self(value))
    }
}

/// Blake3 digest of one inventoried file, or empty for a directory marker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub(super) struct ContentDigest(String);

impl ContentDigest {
    pub(super) fn empty() -> Self {
        Self(String::new())
    }

    pub(super) fn from_blake3(hash: blake3::Hash) -> Self {
        Self(hash.to_hex().to_string())
    }

    pub(super) fn from_hex(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        validate_optional_blake3_hex(&value)?;
        Ok(Self(value))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ContentDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(value).map_err(D::Error::custom)
    }
}

/// Blake3 digest of the complete inventory, never empty.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub(super) struct InventoryDigest(String);

impl InventoryDigest {
    pub(super) fn from_blake3(hash: blake3::Hash) -> Self {
        Self(hash.to_hex().to_string())
    }

    pub(super) fn from_hex(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        validate_blake3_hex(&value)?;
        Ok(Self(value))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for InventoryDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(value).map_err(D::Error::custom)
    }
}

macro_rules! count_type {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub(super) struct $name(u64);

        impl $name {
            pub(super) const ZERO: Self = Self(0);

            pub(super) const fn new(value: u64) -> Self {
                Self(value)
            }

            pub(super) const fn get(self) -> u64 {
                self.0
            }

            pub(super) fn checked_add(self, other: Self) -> Option<Self> {
                self.0.checked_add(other.0).map(Self)
            }
        }

        impl From<u64> for $name {
            fn from(value: u64) -> Self {
                Self(value)
            }
        }

        impl PartialEq<u64> for $name {
            fn eq(&self, other: &u64) -> bool {
                self.0 == *other
            }
        }

        impl PartialEq<$name> for u64 {
            fn eq(&self, other: &$name) -> bool {
                *self == other.0
            }
        }

        impl PartialOrd<u64> for $name {
            fn partial_cmp(&self, other: &u64) -> Option<std::cmp::Ordering> {
                self.0.partial_cmp(other)
            }
        }

        impl PartialOrd<$name> for u64 {
            fn partial_cmp(&self, other: &$name) -> Option<std::cmp::Ordering> {
                self.partial_cmp(&other.0)
            }
        }
    };
}

count_type!(ByteCount);
count_type!(EntryCount);
count_type!(PageCount);

fn validate_optional_blake3_hex(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Ok(());
    }
    validate_blake3_hex(value)
}

fn validate_blake3_hex(value: &str) -> Result<(), &'static str> {
    if value.len() != BLAKE3_HEX_LEN {
        return Err("digest must be 64 lowercase hex characters");
    }
    if !value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("digest is not canonical lowercase hex");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_digest_accepts_empty_directory_marker() {
        let digest = ContentDigest::from_hex("").expect("empty digest");
        assert_eq!(digest.as_str(), "");
        assert_eq!(
            serde_json::from_str::<ContentDigest>("\"\"").expect("json empty"),
            digest
        );
    }

    #[test]
    fn content_digest_accepts_canonical_blake3_hex() {
        let hex = "a".repeat(64);
        let digest = ContentDigest::from_hex(hex.clone()).expect("hex digest");
        assert_eq!(digest.as_str(), hex);
        assert_eq!(
            serde_json::to_string(&digest).expect("serialize"),
            format!("\"{hex}\"")
        );
    }

    #[test]
    fn content_digest_rejects_uppercase_prefix_and_odd_length() {
        assert!(ContentDigest::from_hex("A".repeat(64)).is_err());
        assert!(ContentDigest::from_hex(format!("0x{}", "a".repeat(64))).is_err());
        assert!(ContentDigest::from_hex("abc").is_err());
        assert!(serde_json::from_str::<ContentDigest>("\"ABC\"").is_err());
    }

    #[test]
    fn inventory_digest_rejects_empty() {
        assert!(InventoryDigest::from_hex("").is_err());
        assert!(serde_json::from_str::<InventoryDigest>("\"\"").is_err());
        let hex = "b".repeat(64);
        assert_eq!(
            InventoryDigest::from_hex(hex.clone())
                .expect("inventory hex")
                .as_str(),
            hex
        );
    }

    #[test]
    fn receipt_schema_rejects_unknown_versions() {
        assert_eq!(ReceiptSchema::V2.get(), 2);
        assert_eq!(
            serde_json::from_str::<ReceiptSchema>("2").expect("schema 2"),
            ReceiptSchema::V2
        );
        assert!(serde_json::from_str::<ReceiptSchema>("1").is_err());
        assert!(serde_json::from_str::<ReceiptSchema>("3").is_err());
    }

    #[test]
    fn counts_compare_with_raw_u64_without_changing_json() {
        let bytes = ByteCount::new(12);
        assert_eq!(bytes, 12);
        assert!(bytes > 11);
        assert_eq!(serde_json::to_string(&bytes).expect("json"), "12");
        assert_eq!(
            serde_json::from_str::<ByteCount>("12").expect("parse"),
            bytes
        );
        assert_eq!(
            EntryCount::ZERO.checked_add(EntryCount::new(1)),
            Some(EntryCount::new(1))
        );
        assert_eq!(
            PageCount::ZERO.checked_add(PageCount::new(1)),
            Some(PageCount::new(1))
        );
    }
}
