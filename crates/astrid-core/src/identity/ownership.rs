//! Durable human authority and fleet ownership identities.
//!
//! A [`UserUid`] names human authority independently of login frontends and
//! mutable display names. A [`FleetUid`] names an ownership boundary. Runtime
//! principals remain execution identities and may be attached to one fleet
//! through [`PrincipalOwnership`]. Capability groups are intentionally
//! outside this model: they remain reusable permission bundles.

use std::fmt;
use std::str::FromStr;

use astrid_resource_types::OwnerId;
use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use super::PrincipalUid;

const USER_UID_DERIVE_KEY: &str = "astrid user uid v1";
const FLEET_UID_DERIVE_KEY: &str = "astrid fleet uid v1";
const GENESIS_VERSION: u16 = 1;
const ED25519_ALGORITHM: u16 = 1;
const ED25519_PUBLIC_KEY_BYTES: u32 = 32;

macro_rules! opaque_uid {
    ($name:ident, $label:literal) => {
        #[doc = concat!("Stable opaque identity of one Astrid ", $label, ".")]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Construct an identity from its exact durable bytes.
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.to_string())
                    .finish()
            }
        }

        impl FromStr for $name {
            type Err = OwnershipIdentityError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                if value.len() != 64
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                {
                    return Err(OwnershipIdentityError::InvalidUidText($label));
                }
                let decoded = hex::decode(value)
                    .map_err(|_| OwnershipIdentityError::InvalidUidText($label))?;
                let bytes = <[u8; 32]>::try_from(decoded)
                    .map_err(|_| OwnershipIdentityError::InvalidUidText($label))?;
                Ok(Self(bytes))
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::from_str(&value).map_err(serde::de::Error::custom)
            }
        }
    };
}

opaque_uid!(UserUid, "user");
opaque_uid!(FleetUid, "fleet");

impl From<FleetUid> for OwnerId {
    fn from(uid: FleetUid) -> Self {
        Self::fleet(*uid.as_bytes())
    }
}

impl TryFrom<OwnerId> for FleetUid {
    type Error = OwnerId;

    fn try_from(owner: OwnerId) -> Result<Self, Self::Error> {
        if let OwnerId::Fleet(bytes) = owner {
            Ok(Self::from_bytes(bytes))
        } else {
            Err(owner)
        }
    }
}

/// Immutable creation record from which a [`UserUid`] is derived.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserGenesis {
    /// Canonical genesis-record grammar.
    pub format_version: u16,
    /// UUID of the authoritative human identity record.
    pub identity_id: Uuid,
    /// Whole UTC seconds since the Unix epoch.
    pub created_at_seconds: i64,
    /// Nanosecond fraction in `0..1_000_000_000`.
    pub created_at_nanoseconds: u32,
    /// Initial human-controlled Ed25519 public key.
    #[serde(
        serialize_with = "serialize_public_key",
        deserialize_with = "deserialize_public_key"
    )]
    pub initial_public_key: [u8; 32],
}

impl UserGenesis {
    /// Construct a new immutable user genesis record.
    #[must_use]
    pub fn new(initial_public_key: [u8; 32], created_at: DateTime<Utc>) -> Self {
        Self::from_parts(Uuid::new_v4(), created_at, initial_public_key)
    }

    /// Construct a user genesis record from reproducible inputs.
    #[must_use]
    pub fn from_parts(
        identity_id: Uuid,
        created_at: DateTime<Utc>,
        initial_public_key: [u8; 32],
    ) -> Self {
        Self {
            format_version: GENESIS_VERSION,
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
    /// Returns [`OwnershipIdentityError`] when the record is non-canonical.
    pub fn uid(&self) -> Result<UserUid, OwnershipIdentityError> {
        let canonical = self.canonical_bytes()?;
        let mut hasher = blake3::Hasher::new_derive_key(USER_UID_DERIVE_KEY);
        hasher.update(&canonical);
        Ok(UserUid(*hasher.finalize().as_bytes()))
    }

    /// Return the byte-exact genesis encoding hashed into the UID.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipIdentityError`] when the record is non-canonical.
    pub fn canonical_bytes(&self) -> Result<[u8; 68], OwnershipIdentityError> {
        validate_genesis(self.format_version, self.created_at_nanoseconds, "user")?;
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

/// Durable record for one human authority identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserIdentity {
    /// Stable UID repeated so storage corruption is detected on load.
    pub uid: UserUid,
    /// Canonical creation record that must derive `uid`.
    pub genesis: UserGenesis,
}

impl UserIdentity {
    /// Bind a canonical genesis record to its derived UID.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipIdentityError`] if the genesis record is invalid.
    pub fn from_genesis(genesis: UserGenesis) -> Result<Self, OwnershipIdentityError> {
        let uid = genesis.uid()?;
        Ok(Self { uid, genesis })
    }

    /// Verify the repeated UID against the canonical genesis record.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipIdentityError::UserUidMismatch`] on disagreement.
    pub fn validate(&self) -> Result<(), OwnershipIdentityError> {
        let computed = self.genesis.uid()?;
        if computed != self.uid {
            return Err(OwnershipIdentityError::UserUidMismatch {
                declared: self.uid,
                computed,
            });
        }
        Ok(())
    }
}

/// Immutable creation record from which a [`FleetUid`] is derived.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetGenesis {
    /// Canonical genesis-record grammar.
    pub format_version: u16,
    /// UUID of the authoritative fleet record.
    pub identity_id: Uuid,
    /// Whole UTC seconds since the Unix epoch.
    pub created_at_seconds: i64,
    /// Nanosecond fraction in `0..1_000_000_000`.
    pub created_at_nanoseconds: u32,
    /// Human authority that created the fleet.
    pub created_by: UserUid,
}

impl FleetGenesis {
    /// Construct a new immutable fleet genesis record.
    #[must_use]
    pub fn new(created_by: UserUid, created_at: DateTime<Utc>) -> Self {
        Self::from_parts(Uuid::new_v4(), created_at, created_by)
    }

    /// Construct a fleet genesis record from reproducible inputs.
    #[must_use]
    pub fn from_parts(identity_id: Uuid, created_at: DateTime<Utc>, created_by: UserUid) -> Self {
        Self {
            format_version: GENESIS_VERSION,
            identity_id,
            created_at_seconds: created_at.timestamp(),
            created_at_nanoseconds: created_at.nanosecond(),
            created_by,
        }
    }

    /// Validate the record and derive its stable UID.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipIdentityError`] when the record is non-canonical.
    pub fn uid(&self) -> Result<FleetUid, OwnershipIdentityError> {
        let canonical = self.canonical_bytes()?;
        let mut hasher = blake3::Hasher::new_derive_key(FLEET_UID_DERIVE_KEY);
        hasher.update(&canonical);
        Ok(FleetUid(*hasher.finalize().as_bytes()))
    }

    /// Return the byte-exact genesis encoding hashed into the UID.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipIdentityError`] when the record is non-canonical.
    pub fn canonical_bytes(&self) -> Result<[u8; 64], OwnershipIdentityError> {
        validate_genesis(self.format_version, self.created_at_nanoseconds, "fleet")?;
        let mut bytes = [0_u8; 64];
        bytes[0..2].copy_from_slice(&self.format_version.to_le_bytes());
        bytes[2..4].copy_from_slice(&0_u16.to_le_bytes());
        bytes[4..20].copy_from_slice(self.identity_id.as_bytes());
        bytes[20..28].copy_from_slice(&self.created_at_seconds.to_le_bytes());
        bytes[28..32].copy_from_slice(&self.created_at_nanoseconds.to_le_bytes());
        bytes[32..64].copy_from_slice(self.created_by.as_bytes());
        Ok(bytes)
    }
}

/// Durable record for one fleet ownership boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetIdentity {
    /// Stable UID repeated so storage corruption is detected on load.
    pub uid: FleetUid,
    /// Canonical creation record that must derive `uid`.
    pub genesis: FleetGenesis,
}

impl FleetIdentity {
    /// Bind a canonical genesis record to its derived UID.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipIdentityError`] if the genesis record is invalid.
    pub fn from_genesis(genesis: FleetGenesis) -> Result<Self, OwnershipIdentityError> {
        let uid = genesis.uid()?;
        Ok(Self { uid, genesis })
    }

    /// Verify the repeated UID against the canonical genesis record.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipIdentityError::FleetUidMismatch`] on disagreement.
    pub fn validate(&self) -> Result<(), OwnershipIdentityError> {
        let computed = self.genesis.uid()?;
        if computed != self.uid {
            return Err(OwnershipIdentityError::FleetUidMismatch {
                declared: self.uid,
                computed,
            });
        }
        Ok(())
    }
}

/// A user's administrative relationship to a fleet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetRole {
    /// Controls ownership, membership, and principal assignment.
    Owner,
    /// Manages non-owner members and principals; owner membership is owner-controlled.
    Administrator,
    /// Uses fleet resources without changing ownership.
    Member,
}

impl FleetRole {
    /// Whether this role may manage fleet membership and principals.
    #[must_use]
    pub const fn can_manage(self) -> bool {
        matches!(self, Self::Owner | Self::Administrator)
    }
}

/// One user's membership in one fleet.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetMembership {
    /// Fleet containing the membership.
    pub fleet_uid: FleetUid,
    /// Human authority receiving the role.
    pub user_uid: UserUid,
    /// Permission level inside the fleet ownership boundary.
    pub role: FleetRole,
    /// Human authority that granted the membership.
    pub granted_by: UserUid,
}

/// Durable assignment of an executable principal to one fleet.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalOwnership {
    /// Executable principal receiving an owner.
    pub principal_uid: PrincipalUid,
    /// Sole fleet that owns the principal.
    pub fleet_uid: FleetUid,
    /// Human authority that made the assignment.
    pub assigned_by: UserUid,
}

/// Rejection raised by canonical user and fleet identity handling.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OwnershipIdentityError {
    /// Text was not the canonical lowercase-hex UID spelling.
    #[error("{0} uid must be exactly 64 lowercase hexadecimal characters")]
    InvalidUidText(&'static str),
    /// The genesis grammar version is unknown.
    #[error("unsupported {kind} genesis version {version}")]
    UnsupportedGenesisVersion {
        /// Kind of identity being validated.
        kind: &'static str,
        /// Unsupported version carried by the record.
        version: u16,
    },
    /// The timestamp fraction is not a valid nanosecond value.
    #[error("{kind} genesis nanoseconds must be below one billion, got {value}")]
    InvalidNanoseconds {
        /// Kind of identity being validated.
        kind: &'static str,
        /// Invalid nanosecond value.
        value: u32,
    },
    /// A user record's repeated UID did not match its genesis.
    #[error("user uid mismatch: declared {declared}, computed {computed}")]
    UserUidMismatch {
        /// UID carried by the persisted record.
        declared: UserUid,
        /// UID derived from canonical genesis bytes.
        computed: UserUid,
    },
    /// A fleet record's repeated UID did not match its genesis.
    #[error("fleet uid mismatch: declared {declared}, computed {computed}")]
    FleetUidMismatch {
        /// UID carried by the persisted record.
        declared: FleetUid,
        /// UID derived from canonical genesis bytes.
        computed: FleetUid,
    },
}

fn validate_genesis(
    version: u16,
    nanoseconds: u32,
    kind: &'static str,
) -> Result<(), OwnershipIdentityError> {
    if version != GENESIS_VERSION {
        return Err(OwnershipIdentityError::UnsupportedGenesisVersion { kind, version });
    }
    if nanoseconds >= 1_000_000_000 {
        return Err(OwnershipIdentityError::InvalidNanoseconds {
            kind,
            value: nanoseconds,
        });
    }
    Ok(())
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

    fn created_at() -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000, 123_456_789)
            .single()
            .unwrap()
    }

    fn user() -> UserIdentity {
        UserIdentity::from_genesis(UserGenesis::from_parts(
            Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            created_at(),
            [0x5a; 32],
        ))
        .unwrap()
    }

    #[test]
    fn user_uid_is_stable_and_canonical() {
        let identity = user();
        assert_eq!(
            identity.uid.to_string(),
            "4678a23b161f8867c20b32adbca86e58754aaf5fc225d64286563e790077b535"
        );
        assert_eq!(identity.uid.to_string().parse(), Ok(identity.uid));
        assert_eq!(identity.validate(), Ok(()));
        assert!(
            identity
                .uid
                .to_string()
                .to_uppercase()
                .parse::<UserUid>()
                .is_err()
        );
    }

    #[test]
    fn fleet_uid_binds_creator_and_genesis() {
        let creator = user().uid;
        let identity = FleetIdentity::from_genesis(FleetGenesis::from_parts(
            Uuid::parse_str("ffeeddcc-bbaa-9988-7766-554433221100").unwrap(),
            created_at(),
            creator,
        ))
        .unwrap();
        assert_eq!(
            identity.uid.to_string(),
            "c46c84da942d4c7fe48e04e6f298e4cf39285a1c5b096cb4985c01bdcfec3709"
        );
        assert_eq!(identity.validate(), Ok(()));

        let other_creator = UserUid::from_bytes([0x11; 32]);
        let mut altered = identity.clone();
        altered.genesis.created_by = other_creator;
        assert!(matches!(
            altered.validate(),
            Err(OwnershipIdentityError::FleetUidMismatch { .. })
        ));

        let owner = OwnerId::from(identity.uid);
        assert_eq!(FleetUid::try_from(owner), Ok(identity.uid));
        assert!(FleetUid::try_from(OwnerId::System).is_err());
    }

    #[test]
    fn serde_rejects_non_canonical_uid_text() {
        let encoded = serde_json::to_string(&user()).unwrap();
        let upper = encoded.replace(
            &user().uid.to_string(),
            &user().uid.to_string().to_uppercase(),
        );
        assert!(serde_json::from_str::<UserIdentity>(&upper).is_err());
    }

    #[test]
    fn administrator_can_manage_but_member_cannot() {
        assert!(FleetRole::Owner.can_manage());
        assert!(FleetRole::Administrator.can_manage());
        assert!(!FleetRole::Member.can_manage());
    }
}
