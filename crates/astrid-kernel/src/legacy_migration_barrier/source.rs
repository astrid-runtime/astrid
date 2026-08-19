//! Validated source identity for the layout-migration ledger.
//!
//! Durable JSON still uses `digest`, `entries`, `bytes`, and `present`.
//! Constructors and serde reject the combinations the ledger already treated
//! as invalid: a present source with digest `absent`, an absent source with a
//! real digest, or a digest that is neither `absent` nor canonical hex.

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use std::io;

const BLAKE3_HEX_LEN: usize = 64;

/// Digest of one inventoried legacy source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub(super) struct SourceDigest(String);

impl SourceDigest {
    pub(super) const ABSENT: &'static str = "absent";

    pub(super) fn absent() -> Self {
        Self(Self::ABSENT.to_owned())
    }

    pub(super) fn from_hex(hex: impl Into<String>) -> Result<Self, &'static str> {
        let hex = hex.into();
        validate_blake3_hex(&hex)?;
        Ok(Self(hex))
    }

    pub(super) fn from_blake3(hash: blake3::Hash) -> Self {
        Self(hash.to_hex().to_string())
    }

    pub(super) fn parse(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value == Self::ABSENT {
            return Ok(Self::absent());
        }
        // Distro and lock receipts store `blake3:<hex>`. Host-path snapshots
        // store bare hex. Keep whichever canonical form arrived; stripping
        // the prefix would break source-bound destination proofs.
        if let Some(hex) = value.strip_prefix("blake3:") {
            validate_blake3_hex(hex)?;
            return Ok(Self(value));
        }
        Self::from_hex(value)
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }

    pub(super) fn is_absent(&self) -> bool {
        self.0 == Self::ABSENT
    }
}

impl std::fmt::Display for SourceDigest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for SourceDigest {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for SourceDigest {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for SourceDigest {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl<'de> Deserialize<'de> for SourceDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

pub(super) fn is_canonical_blake3_hex(value: &str) -> bool {
    value.len() == BLAKE3_HEX_LEN
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn validate_blake3_hex(value: &str) -> Result<(), &'static str> {
    if value.len() != BLAKE3_HEX_LEN {
        return Err("source digest must be 64 lowercase hex characters");
    }
    if !is_canonical_blake3_hex(value) {
        return Err("source digest is not canonical lowercase hex");
    }
    Ok(())
}

/// Count of inventoried source entries or bytes.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub(super) struct SourceCount(u64);

impl SourceCount {
    pub(super) const ZERO: Self = Self(0);

    pub(super) const fn new(value: u64) -> Self {
        Self(value)
    }

    pub(super) const fn get(self) -> u64 {
        self.0
    }

    pub(super) fn checked_add(self, other: u64) -> Option<Self> {
        self.0.checked_add(other).map(Self)
    }
}

impl PartialEq<u64> for SourceCount {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl PartialOrd<u64> for SourceCount {
    fn partial_cmp(&self, other: &u64) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

/// Snapshot of one named legacy source.
///
/// JSON remains `{digest, entries, bytes, present}`. Construction rejects
/// present+absent and absent+digest combinations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(super) struct SourceIdentity {
    pub(super) digest: SourceDigest,
    pub(super) entries: SourceCount,
    pub(super) bytes: SourceCount,
    pub(super) present: bool,
}

impl SourceIdentity {
    pub(super) fn absent() -> Self {
        Self {
            digest: SourceDigest::absent(),
            entries: SourceCount::ZERO,
            bytes: SourceCount::ZERO,
            present: false,
        }
    }

    pub(super) fn present(
        digest: SourceDigest,
        entries: SourceCount,
        bytes: SourceCount,
    ) -> Result<Self, &'static str> {
        if digest.is_absent() {
            return Err("present migration source has absent digest");
        }
        Ok(Self {
            digest,
            entries,
            bytes,
            present: true,
        })
    }

    fn validated(self) -> Result<Self, &'static str> {
        match (self.present, self.digest.is_absent()) {
            (true, true) => Err("present migration source has absent digest"),
            (false, false) => Err("absent migration source has a digest"),
            (false, true)
                if self.entries != SourceCount::ZERO || self.bytes != SourceCount::ZERO =>
            {
                Err("absent migration source has a non-zero inventory")
            },
            _ => Ok(self),
        }
    }

    pub(super) fn from_snapshot_fields(
        digest: &str,
        entries: u64,
        bytes: u64,
        present: bool,
    ) -> io::Result<Self> {
        if !present {
            return Ok(Self::absent());
        }
        Self::present(
            SourceDigest::parse(digest.to_owned())
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            SourceCount::new(entries),
            SourceCount::new(bytes),
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}

impl<'de> Deserialize<'de> for SourceIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            digest: SourceDigest,
            entries: SourceCount,
            bytes: SourceCount,
            present: bool,
        }
        let raw = Raw::deserialize(deserializer)?;
        SourceIdentity {
            digest: raw.digest,
            entries: raw.entries,
            bytes: raw.bytes,
            present: raw.present,
        }
        .validated()
        .map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_source_round_trips() {
        let identity = SourceIdentity::absent();
        let json = serde_json::to_string(&identity).expect("json");
        assert!(json.contains("\"digest\":\"absent\""));
        assert!(json.contains("\"present\":false"));
        assert_eq!(
            serde_json::from_str::<SourceIdentity>(&json).expect("parse"),
            identity
        );
    }

    #[test]
    fn present_source_rejects_absent_digest() {
        assert!(
            SourceIdentity::present(
                SourceDigest::absent(),
                SourceCount::new(1),
                SourceCount::new(1)
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<SourceIdentity>(
                r#"{"digest":"absent","entries":1,"bytes":1,"present":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn absent_source_rejects_real_digest() {
        let hex = "a".repeat(64);
        assert!(
            serde_json::from_str::<SourceIdentity>(&format!(
                r#"{{"digest":"{hex}","entries":0,"bytes":0,"present":false}}"#
            ))
            .is_err()
        );
    }

    #[test]
    fn digest_accepts_bare_or_prefixed_hex_and_rejects_uppercase() {
        let hex = "ab".repeat(32);
        assert_eq!(
            SourceDigest::parse(hex.clone()).expect("bare").as_str(),
            hex
        );
        assert_eq!(
            SourceDigest::parse(format!("blake3:{hex}"))
                .expect("prefixed")
                .as_str(),
            format!("blake3:{hex}")
        );
        assert!(SourceDigest::parse("AB".repeat(32)).is_err());
        assert!(SourceDigest::parse("").is_err());
    }
}
