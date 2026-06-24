//! Newtypes for validated [`PrincipalProfile`](super::PrincipalProfile) fields.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::capability_grammar::{CapabilityGrammarError, validate_capability};

use super::{MAX_CAPSULE_GRANT_LEN, MAX_GROUP_NAME_LEN};

/// Error returned when a profile field newtype rejects an input string.
#[derive(Debug, Error)]
pub enum ProfileFieldError {
    /// A group name failed the profile group-name grammar.
    #[error("group name rejected: {0}")]
    InvalidGroupName(String),
    /// A direct grant or revoke failed the capability grammar.
    #[error("capability pattern rejected: {0}")]
    InvalidCapabilityPattern(#[from] CapabilityGrammarError),
    /// A capsule grant failed the profile capsule-grant grammar.
    #[error("capsule grant rejected: {0}")]
    InvalidCapsuleGrant(String),
}

/// Validated group name in a principal profile.
///
/// Wire format is still a bare string, but the in-memory profile can no
/// longer confuse group names with capability patterns or capsule grants.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct GroupName(String);

impl GroupName {
    /// Create a validated group name.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileFieldError::InvalidGroupName`] when the name is empty,
    /// too long, or contains a character outside `[a-zA-Z0-9_-]`.
    pub fn new(name: impl Into<String>) -> Result<Self, ProfileFieldError> {
        let name = name.into();
        validate_group_name_str(&name)?;
        Ok(Self(name))
    }

    /// Borrow the validated group name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the owned string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

/// Validated capability pattern in a principal profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CapabilityPattern(String);

impl CapabilityPattern {
    /// Create a validated capability pattern.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileFieldError::InvalidCapabilityPattern`] when the string
    /// does not satisfy Astrid's capability grammar.
    pub fn new(pattern: impl Into<String>) -> Result<Self, ProfileFieldError> {
        let pattern = pattern.into();
        validate_capability(&pattern)?;
        Ok(Self(pattern))
    }

    /// Borrow the validated capability pattern.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the owned string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

/// Validated capsule grant in a principal profile.
///
/// This intentionally mirrors the profile's grant grammar, not the
/// `astrid-capsule` crate's `CapsuleId`, so `astrid-core` keeps no dependency
/// on capsule loading internals.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CapsuleGrant(String);

impl CapsuleGrant {
    /// Create a validated capsule grant.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileFieldError::InvalidCapsuleGrant`] when the grant is
    /// empty, too long, or contains a character outside `[a-z0-9-]`.
    pub fn new(id: impl Into<String>) -> Result<Self, ProfileFieldError> {
        let id = id.into();
        validate_capsule_grant_str(&id)?;
        Ok(Self(id))
    }

    /// Borrow the validated capsule grant.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the owned string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

macro_rules! impl_string_newtype {
    ($ty:ty, $err:ty) => {
        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl From<$ty> for String {
            fn from(value: $ty) -> Self {
                value.into_inner()
            }
        }

        impl TryFrom<String> for $ty {
            type Error = $err;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl FromStr for $ty {
            type Err = $err;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl PartialEq<str> for $ty {
            fn eq(&self, other: &str) -> bool {
                self.as_str() == other
            }
        }

        impl PartialEq<&str> for $ty {
            fn eq(&self, other: &&str) -> bool {
                self.as_str() == *other
            }
        }

        impl PartialEq<String> for $ty {
            fn eq(&self, other: &String) -> bool {
                self.as_str() == other
            }
        }

        impl PartialEq<&String> for $ty {
            fn eq(&self, other: &&String) -> bool {
                self.as_str() == other.as_str()
            }
        }
    };
}

impl_string_newtype!(GroupName, ProfileFieldError);
impl_string_newtype!(CapabilityPattern, ProfileFieldError);
impl_string_newtype!(CapsuleGrant, ProfileFieldError);

pub(super) fn validate_group_name_str(name: &str) -> Result<(), ProfileFieldError> {
    if name.is_empty() {
        return Err(ProfileFieldError::InvalidGroupName(
            "groups entries must be non-empty".into(),
        ));
    }
    if name.len() > MAX_GROUP_NAME_LEN {
        return Err(ProfileFieldError::InvalidGroupName(format!(
            "groups entry exceeds {MAX_GROUP_NAME_LEN} characters: {name:?}",
        )));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && *c != '-' && *c != '_')
    {
        return Err(ProfileFieldError::InvalidGroupName(format!(
            "groups entry {name:?} contains invalid character {bad:?} (allowed: a-z, A-Z, 0-9, -, _)",
        )));
    }
    Ok(())
}

pub(super) fn validate_capsule_grant_str(id: &str) -> Result<(), ProfileFieldError> {
    if id.is_empty() {
        return Err(ProfileFieldError::InvalidCapsuleGrant(
            "capsules entries must be non-empty".into(),
        ));
    }
    if id.len() > MAX_CAPSULE_GRANT_LEN {
        return Err(ProfileFieldError::InvalidCapsuleGrant(format!(
            "capsules entry exceeds {MAX_CAPSULE_GRANT_LEN} characters: {id:?}",
        )));
    }
    if let Some(bad) = id
        .chars()
        .find(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit() && *c != '-')
    {
        return Err(ProfileFieldError::InvalidCapsuleGrant(format!(
            "capsules entry {id:?} contains invalid character {bad:?} (allowed: a-z, 0-9, -)",
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newtypes_keep_string_wire_shape() {
        let group = GroupName::new("ops_team").unwrap();
        let json = serde_json::to_string(&group).unwrap();
        assert_eq!(json, "\"ops_team\"");
        let back: GroupName = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_str(), "ops_team");
    }

    #[test]
    fn group_name_rejects_path_separator() {
        assert!(matches!(
            GroupName::new("ops/team"),
            Err(ProfileFieldError::InvalidGroupName(_))
        ));
    }

    #[test]
    fn capability_pattern_rejects_invalid_grammar() {
        assert!(matches!(
            CapabilityPattern::new("system:shutdown;rm"),
            Err(ProfileFieldError::InvalidCapabilityPattern(_))
        ));
    }

    #[test]
    fn capsule_grant_rejects_uppercase() {
        assert!(matches!(
            CapsuleGrant::new("Identity"),
            Err(ProfileFieldError::InvalidCapsuleGrant(_))
        ));
    }
}
