//! Durable restoration staging scope shared by receipt and private writer.

use std::ffi::OsStr;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Random 128-bit restoration staging scope recorded once with RETIRING intent.
///
/// Wire form is exactly 32 lowercase hexadecimal characters. This type is
/// naming and session authority only; discard still requires same-root RETIRING
/// inventory, catalogue absence, private-file contract, and rooted removal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StagingScope([u8; 16]);

impl StagingScope {
    /// Mint a fresh opaque staging scope.
    #[must_use]
    pub fn new() -> Self {
        Self(*uuid::Uuid::new_v4().as_bytes())
    }

    /// Return the canonical 32-character lowercase hex encoding.
    #[must_use]
    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a canonical 32-character hexadecimal scope.
    ///
    /// # Errors
    /// Returns an error when the input is not exactly 32 ASCII hex digits.
    pub fn parse(value: &str) -> Result<Self, StagingScopeError> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(StagingScopeError::InvalidHex);
        }
        let mut bytes = [0_u8; 16];
        let decoded = hex::decode(value).map_err(|_| StagingScopeError::InvalidHex)?;
        bytes.copy_from_slice(&decoded);
        Ok(Self(bytes))
    }

    /// Build a private writer temporary basename for this scope.
    ///
    /// Nonce is a fixed 32-lowercase-hex UUID so authority spelling stays closed.
    #[must_use]
    pub fn temporary_basename(&self) -> String {
        format!(
            ".astrid-private-{}-{}",
            self.as_hex(),
            uuid::Uuid::new_v4().simple()
        )
    }

    /// Return whether `name` is a temporary basename authorized by this scope.
    #[must_use]
    pub fn matches_temporary_basename(&self, name: &OsStr) -> bool {
        staging_name_scope(name).is_some_and(|scope| scope == *self)
    }
}

impl Default for StagingScope {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for StagingScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_hex())
    }
}

impl FromStr for StagingScope {
    type Err = StagingScopeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for StagingScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_hex())
    }
}

impl<'de> Deserialize<'de> for StagingScope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// Invalid staging-scope encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StagingScopeError {
    /// Input was not exactly 32 ASCII hexadecimal characters.
    InvalidHex,
}

impl fmt::Display for StagingScopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHex => {
                formatter.write_str("staging scope must be exactly 32 hexadecimal characters")
            },
        }
    }
}

impl std::error::Error for StagingScopeError {}

fn is_hex32(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Recognize the legacy Unix private atomic writer basename.
///
/// Exactly `.astrid-private-{32 hex}` with no epoch delimiter. This remains the
/// narrow stopped-recovery `etc/` shape recognizer. Scoped names use
/// [`is_scoped_private_staging_name`] instead; recognition is never discard
/// authority.
#[must_use]
pub fn is_private_atomic_staging_name(name: &OsStr) -> bool {
    cfg!(unix)
        && name.to_str().is_some_and(|name| {
            let Some(rest) = name.strip_prefix(".astrid-private-") else {
                return false;
            };
            rest.len() == 32 && rest.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

/// Recognize an intent-scoped private staging basename.
///
/// Exactly `.astrid-private-{scope32}-{nonce32}`. Separate from the legacy
/// recognizer so stopped `etc/` legacy cleanup cannot inherit new names.
#[must_use]
pub fn is_scoped_private_staging_name(name: &OsStr) -> bool {
    staging_name_scope(name).is_some()
}

/// Parse the durable scope embedded in a scoped staging basename.
#[must_use]
pub fn staging_name_scope(name: &OsStr) -> Option<StagingScope> {
    // Scoped restoration temps are cross-platform; legacy atomic recognition
    // remains Unix-only via is_private_atomic_staging_name.
    let text = name.to_str()?;
    let rest = text.strip_prefix(".astrid-private-")?;
    let (scope, nonce) = rest.split_once('-')?;
    if !is_hex32(scope) || !is_hex32(nonce) {
        return None;
    }
    StagingScope::parse(scope).ok()
}

/// Structural staging basename used by stopped projection recognition only.
///
/// Admits legacy and scoped spellings so interrupted restoration residue stays
/// recognizable. Storage cleanup must still gate legacy vs exact-scope paths
/// separately; this helper confers no deletion authority.
#[must_use]
pub fn is_structural_private_staging_name(name: &OsStr) -> bool {
    is_private_atomic_staging_name(name) || is_scoped_private_staging_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_round_trips_canonical_hex() {
        let scope = StagingScope::parse("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(scope.as_hex(), "0123456789abcdef0123456789abcdef");
        let encoded = serde_json::to_string(&scope).unwrap();
        assert_eq!(encoded, "\"0123456789abcdef0123456789abcdef\"");
        let decoded: StagingScope = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, scope);
    }

    #[test]
    fn rejects_malformed_hex() {
        for value in [
            "",
            "abc",
            "0123456789abcdef0123456789abcdeg",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(StagingScope::parse(value).is_err(), "{value}");
        }
    }

    #[test]
    fn legacy_and_scoped_recognizers_stay_split() {
        let scope = StagingScope::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let other = StagingScope::parse("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        let scoped = scope.temporary_basename();
        let legacy = ".astrid-private-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        // Legacy temporary names remain Unix-specific. Receipt-scoped names
        // are recognized across targets, including the native Windows writer.
        let recognized = cfg!(unix);
        assert_eq!(
            is_private_atomic_staging_name(OsStr::new(legacy)),
            recognized
        );
        let uppercase = ".astrid-private-ABCDEF0123456789ABCDEF0123456789";
        assert_eq!(
            is_private_atomic_staging_name(OsStr::new(uppercase)),
            recognized
        );
        assert!(!is_scoped_private_staging_name(OsStr::new(uppercase)));
        assert!(!scope.matches_temporary_basename(OsStr::new(uppercase)));
        assert!(!is_private_atomic_staging_name(OsStr::new(&scoped)));
        assert!(is_scoped_private_staging_name(OsStr::new(&scoped)));
        assert!(!is_scoped_private_staging_name(OsStr::new(legacy)));
        assert!(is_structural_private_staging_name(OsStr::new(&scoped)));
        assert_eq!(
            is_structural_private_staging_name(OsStr::new(legacy)),
            recognized
        );

        assert_eq!(
            scope.matches_temporary_basename(OsStr::new(&scoped)),
            recognized
        );
        assert!(!other.matches_temporary_basename(OsStr::new(&scoped)));
        assert!(!scope.matches_temporary_basename(OsStr::new(legacy)));
        assert_eq!(
            staging_name_scope(OsStr::new(&scoped)),
            recognized.then_some(scope)
        );
        assert_eq!(staging_name_scope(OsStr::new(legacy)), None);
    }
}
