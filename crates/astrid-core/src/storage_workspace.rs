//! Typed identities for Astrid's authoritative workspace branches.
//!
//! A workspace branch is an owner-internal content view.  It has no host path
//! and must not be confused with a project directory selected by a native
//! portal.  Keeping the identity in `astrid-core` lets kernel, capsule, and
//! native-provider contracts share the same opaque value without importing the
//! native storage implementation into the wire-contract crate.

use std::fmt;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const UID_BYTES: usize = 16;
const HEX_BYTES: usize = UID_BYTES * 2;
const LABEL_PREFIX: &str = "workspace/";

/// Opaque identity for one owner-internal authoritative workspace branch.
///
/// The bytes carry no principal or host-path meaning.  Authorization binds a
/// branch to the owner selected by a kernel-issued lease or runtime context.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkspaceUid([u8; UID_BYTES]);

impl WorkspaceUid {
    /// Construct an identity from opaque bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; UID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh branch identity.
    #[must_use]
    pub fn random() -> Self {
        Self(uuid::Uuid::new_v4().into_bytes())
    }

    /// Return the opaque identity bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; UID_BYTES] {
        self.0
    }
}

impl fmt::Display for WorkspaceUid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{LABEL_PREFIX}{}", hex::encode(self.0))
    }
}

impl FromStr for WorkspaceUid {
    type Err = WorkspaceUidParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.strip_prefix(LABEL_PREFIX).unwrap_or(value);
        if value.len() != HEX_BYTES {
            return Err(WorkspaceUidParseError::Length);
        }
        let mut bytes = [0_u8; UID_BYTES];
        hex::decode_to_slice(value, &mut bytes).map_err(|_| WorkspaceUidParseError::Hex)?;
        Ok(Self(bytes))
    }
}

/// Failure to parse a serialized workspace identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceUidParseError {
    /// The value was not exactly sixteen bytes encoded as hexadecimal.
    Length,
    /// The value contained a non-hexadecimal character.
    Hex,
}

impl fmt::Display for WorkspaceUidParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length => formatter.write_str("workspace UID must contain 32 hex characters"),
            Self::Hex => formatter.write_str("workspace UID contains non-hex characters"),
        }
    }
}

impl std::error::Error for WorkspaceUidParseError {}

impl Serialize for WorkspaceUid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for WorkspaceUid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_uid_has_stable_wire_form() {
        let uid = WorkspaceUid::from_bytes([0xabu8; UID_BYTES]);
        assert_eq!(
            uid.to_string(),
            "workspace/abababababababababababababababab"
        );
        assert_eq!(
            serde_json::to_string(&uid).unwrap(),
            "\"abababababababababababababababab\""
        );
        assert_eq!(
            serde_json::from_str::<WorkspaceUid>("\"abababababababababababababababab\"").unwrap(),
            uid
        );
        assert_eq!(
            "workspace/abababababababababababababababab"
                .parse::<WorkspaceUid>()
                .unwrap(),
            uid
        );
    }

    #[test]
    fn malformed_uid_is_rejected() {
        assert!(serde_json::from_str::<WorkspaceUid>("\"too-short\"").is_err());
    }
}
