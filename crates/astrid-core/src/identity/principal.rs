//! Stable principal identity independent of mutable display names and keys.
//!
//! [`PrincipalId`](crate::PrincipalId) remains the validated, human-facing
//! alias used by command and configuration surfaces. [`PrincipalUid`] is the
//! opaque identity used by durable authority records. A UID is bound once to a
//! canonical [`PrincipalGenesis`] record and never changes when an alias or
//! active authentication key changes.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

const PRINCIPAL_UID_DERIVE_KEY: &str = "astrid principal uid v1";
const PRINCIPAL_GENESIS_VERSION: u16 = 1;
const ED25519_ALGORITHM: u16 = 1;
const ED25519_PUBLIC_KEY_BYTES: u32 = 32;

/// Stable opaque identity of one Astrid principal.
///
/// The bytes are the domain-separated digest of a canonical
/// [`PrincipalGenesis`] record. Text form is exactly 64 lowercase hexadecimal
/// characters; non-canonical spellings are rejected.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalUid([u8; 32]);

impl PrincipalUid {
    /// Construct a UID from its exact durable bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the exact durable bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for PrincipalUid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for PrincipalUid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PrincipalUid")
            .field(&self.to_string())
            .finish()
    }
}

impl FromStr for PrincipalUid {
    type Err = PrincipalIdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(PrincipalIdentityError::InvalidUidText);
        }
        let decoded = hex::decode(value).map_err(|_| PrincipalIdentityError::InvalidUidText)?;
        let bytes =
            <[u8; 32]>::try_from(decoded).map_err(|_| PrincipalIdentityError::InvalidUidText)?;
        Ok(Self(bytes))
    }
}

impl Serialize for PrincipalUid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PrincipalUid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

/// Immutable creation record from which a [`PrincipalUid`] is derived.
///
/// The identity UUID distinguishes two principals created with the same
/// authentication key at the same instant. The initial key remains historical
/// identity material after rotation; current authentication policy lives
/// elsewhere and may remove it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalGenesis {
    /// Canonical genesis-record grammar.
    pub format_version: u16,
    /// UUID of the authoritative identity record.
    pub identity_id: Uuid,
    /// Whole UTC seconds since the Unix epoch.
    pub created_at_seconds: i64,
    /// Nanosecond fraction in `0..1_000_000_000`.
    pub created_at_nanoseconds: u32,
    /// Initial Ed25519 public key, encoded as canonical lowercase hex.
    #[serde(
        serialize_with = "serialize_public_key",
        deserialize_with = "deserialize_public_key"
    )]
    pub initial_public_key: [u8; 32],
}

impl PrincipalGenesis {
    /// Construct a new immutable principal genesis record.
    #[must_use]
    pub fn new(initial_public_key: [u8; 32], created_at: DateTime<Utc>) -> Self {
        Self::from_parts(Uuid::new_v4(), created_at, initial_public_key)
    }

    /// Construct a genesis record from explicit, reproducible inputs.
    #[must_use]
    pub fn from_parts(
        identity_id: Uuid,
        created_at: DateTime<Utc>,
        initial_public_key: [u8; 32],
    ) -> Self {
        Self {
            format_version: PRINCIPAL_GENESIS_VERSION,
            identity_id,
            created_at_seconds: created_at.timestamp(),
            created_at_nanoseconds: created_at.nanosecond(),
            initial_public_key,
        }
    }

    /// Validate the record and derive its stable UID.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalIdentityError`] for an unknown format version or an
    /// invalid nanosecond fraction.
    pub fn uid(&self) -> Result<PrincipalUid, PrincipalIdentityError> {
        let canonical = self.canonical_bytes()?;
        let mut hasher = blake3::Hasher::new_derive_key(PRINCIPAL_UID_DERIVE_KEY);
        hasher.update(&canonical);
        Ok(PrincipalUid(*hasher.finalize().as_bytes()))
    }

    /// Return the byte-exact genesis encoding hashed into the UID.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalIdentityError`] when the record is outside the
    /// version-one grammar.
    pub fn canonical_bytes(&self) -> Result<[u8; 68], PrincipalIdentityError> {
        if self.format_version != PRINCIPAL_GENESIS_VERSION {
            return Err(PrincipalIdentityError::UnsupportedGenesisVersion(
                self.format_version,
            ));
        }
        if self.created_at_nanoseconds >= 1_000_000_000 {
            return Err(PrincipalIdentityError::InvalidNanoseconds(
                self.created_at_nanoseconds,
            ));
        }
        let mut bytes = [0_u8; 68];
        bytes[0..2].copy_from_slice(&self.format_version.to_le_bytes());
        bytes[2..4].copy_from_slice(&ED25519_ALGORITHM.to_le_bytes());
        bytes[4..8].copy_from_slice(&ED25519_PUBLIC_KEY_BYTES.to_le_bytes());
        bytes[8..24].copy_from_slice(self.identity_id.as_bytes());
        bytes[24..32].copy_from_slice(&self.created_at_seconds.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.created_at_nanoseconds.to_le_bytes());
        bytes[36..68].copy_from_slice(&self.initial_public_key);
        Ok(bytes)
    }
}

/// Immutable identity record stored beside the mutable principal alias.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalIdentity {
    /// Stable UID repeated explicitly so corruption is detected on load.
    pub uid: PrincipalUid,
    /// Canonical creation record that must derive `uid`.
    pub genesis: PrincipalGenesis,
}

impl PrincipalIdentity {
    /// Bind a canonical genesis record to its derived UID.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalIdentityError`] if the genesis record is invalid.
    pub fn from_genesis(genesis: PrincipalGenesis) -> Result<Self, PrincipalIdentityError> {
        let uid = genesis.uid()?;
        Ok(Self { uid, genesis })
    }

    /// Verify that the repeated UID matches the canonical genesis record.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalIdentityError::UidMismatch`] on disagreement.
    pub fn validate(&self) -> Result<(), PrincipalIdentityError> {
        let computed = self.genesis.uid()?;
        if computed != self.uid {
            return Err(PrincipalIdentityError::UidMismatch {
                declared: self.uid,
                computed,
            });
        }
        Ok(())
    }
}

/// Rejection raised by canonical principal-identity handling.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PrincipalIdentityError {
    /// Text was not the one canonical lowercase-hex UID spelling.
    #[error("principal uid must be exactly 64 lowercase hexadecimal characters")]
    InvalidUidText,
    /// The genesis grammar version is unknown.
    #[error("unsupported principal genesis version {0}")]
    UnsupportedGenesisVersion(u16),
    /// The timestamp fraction is not a valid nanosecond value.
    #[error("principal genesis nanoseconds must be below one billion, got {0}")]
    InvalidNanoseconds(u32),
    /// The declared UID does not match the canonical genesis record.
    #[error("principal uid mismatch: declared {declared}, computed {computed}")]
    UidMismatch {
        /// UID carried by the persisted record.
        declared: PrincipalUid,
        /// UID derived from the canonical genesis bytes.
        computed: PrincipalUid,
    },
}

fn serialize_public_key<S>(key: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(key))
}

fn deserialize_public_key<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(serde::de::Error::custom(
            "initial public key must be exactly 64 lowercase hexadecimal characters",
        ));
    }
    let decoded = hex::decode(value).map_err(serde::de::Error::custom)?;
    <[u8; 32]>::try_from(decoded)
        .map_err(|_| serde::de::Error::custom("initial public key must contain 32 bytes"))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn genesis() -> PrincipalGenesis {
        PrincipalGenesis::from_parts(
            Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            Utc.timestamp_opt(1_700_000_000, 123_456_789)
                .single()
                .unwrap(),
            [0x5a; 32],
        )
    }

    #[test]
    fn uid_is_stable_and_canonical() {
        let identity = PrincipalIdentity::from_genesis(genesis()).unwrap();
        assert_eq!(
            identity.uid.to_string(),
            "c2bcce8a2372c53b60ad922845ffd591b475e15f4005de34bf4039198d5b6987"
        );
        assert_eq!(identity.uid.to_string().parse(), Ok(identity.uid));
        assert_eq!(identity.validate(), Ok(()));
    }

    #[test]
    fn uid_text_rejects_alternate_representations() {
        let uid = PrincipalIdentity::from_genesis(genesis()).unwrap().uid;
        assert!(
            uid.to_string()
                .to_uppercase()
                .parse::<PrincipalUid>()
                .is_err()
        );
        assert!(format!("0{uid}").parse::<PrincipalUid>().is_err());
    }

    #[test]
    fn identity_rejects_a_substituted_uid() {
        let mut identity = PrincipalIdentity::from_genesis(genesis()).unwrap();
        identity.uid = PrincipalUid::from_bytes([0x11; 32]);
        assert!(matches!(
            identity.validate(),
            Err(PrincipalIdentityError::UidMismatch { .. })
        ));
    }

    #[test]
    fn serde_round_trip_keeps_canonical_text() {
        let identity = PrincipalIdentity::from_genesis(genesis()).unwrap();
        let encoded = toml::to_string(&identity).unwrap();
        assert!(encoded.contains(&format!("uid = \"{}\"", identity.uid)));
        assert!(encoded.contains(&format!("initial_public_key = \"{}\"", "5a".repeat(32))));
        let decoded: PrincipalIdentity = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded, identity);
        decoded.validate().unwrap();
    }

    #[test]
    fn genesis_rejects_invalid_timestamp_fraction() {
        let mut value = genesis();
        value.created_at_nanoseconds = 1_000_000_000;
        assert_eq!(
            value.uid(),
            Err(PrincipalIdentityError::InvalidNanoseconds(1_000_000_000))
        );
    }
}
