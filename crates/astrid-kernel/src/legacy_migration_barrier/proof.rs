//! Validated destination receipt for the layout-migration ledger.
//!
//! Durable JSON still stores a single string. Constructors and serde reject
//! newlines and unknown prefixes, but they do not rewrite the stored text.
//! Distro-init proofs bind `source-digest=blake3:<hex>`; stripping that
//! prefix would break source-bound discard receipts. Component pairing
//! (copy-on-write, secrets, distro-init) stays in `validate_ledger_shape`.

use super::source::is_canonical_blake3_hex;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use std::io;

/// Receipt that a named destination exists, was verified empty, or was
/// explicitly discarded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub(super) struct DestinationProof(String);

impl DestinationProof {
    pub(super) const ABSENT: &'static str = "absent";
    pub(super) const FRESH_LAYOUT: &'static str =
        "fresh-layout-v1:initialized-without-legacy-sources";

    pub(super) fn absent() -> Self {
        Self(Self::ABSENT.to_owned())
    }

    pub(super) fn fresh_layout() -> Self {
        Self(Self::FRESH_LAYOUT.to_owned())
    }

    pub(super) fn from_hashed_bytes(bytes: &[u8]) -> Self {
        Self(format!("blake3:{}", blake3::hash(bytes).to_hex()))
    }

    pub(super) fn parse(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.contains('\n') {
            return Err("destination proof must not contain a newline");
        }
        if value == Self::ABSENT {
            return Ok(Self::absent());
        }
        if let Some(hex) = value.strip_prefix("blake3:") {
            if !is_canonical_blake3_hex(hex) {
                return Err("destination proof blake3 digest is not 64 lowercase hex characters");
            }
            return Ok(Self(value));
        }
        let known_prefix = value.starts_with("verified-empty-v1:")
            || value.starts_with("verified-quarantine-v1:")
            || value.starts_with("verified-discard-v1:")
            || value.starts_with("verified-capsule-authority-v1:")
            || value.starts_with("verified-system-env-v1:")
            || value.starts_with("verified-secret-import-v1:")
            || value.starts_with("fresh-layout-v1:");
        if !known_prefix {
            return Err("unknown destination proof prefix");
        }
        let rest = value
            .split_once(':')
            .map(|(_, rest)| rest)
            .unwrap_or_default();
        if rest.is_empty() {
            return Err("destination proof is missing its payload");
        }
        Ok(Self(value))
    }

    pub(super) fn from_stored(value: impl Into<String>) -> io::Result<Self> {
        Self::parse(value).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    pub(super) fn is_absent(&self) -> bool {
        self.0 == Self::ABSENT
    }
}

impl std::fmt::Display for DestinationProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for DestinationProof {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for DestinationProof {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<str> for DestinationProof {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for DestinationProof {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for DestinationProof {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl std::str::FromStr for DestinationProof {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl<'de> Deserialize<'de> for DestinationProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}
