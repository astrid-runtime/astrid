//! Newtypes for validated [`PrincipalProfile`](super::PrincipalProfile) fields.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::capability_grammar::{CapabilityGrammarError, validate_capability};

use super::{
    MAX_CAPSULE_GRANT_LEN, MAX_GROUP_NAME_LEN, PrincipalProfile, ProfileError, ProfileResult,
};

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
/// The public profile and wire formats stay string-shaped, while internal
/// callers can use this wrapper at validation and authorization edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupName<S = String>(S);

impl<S: AsRef<str>> GroupName<S> {
    /// Create a validated group name.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileFieldError::InvalidGroupName`] when the name is empty,
    /// too long, or contains a character outside `[a-zA-Z0-9_-]`.
    pub fn new(name: S) -> Result<Self, ProfileFieldError> {
        validate_group_name_str(name.as_ref())?;
        Ok(Self(name))
    }

    /// Borrow the validated group name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl GroupName<String> {
    /// Consume the wrapper and return the owned string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl GroupName<&str> {
    /// Return an owned validated group name.
    #[must_use]
    pub fn to_owned(self) -> GroupName<String> {
        GroupName(self.0.to_string())
    }
}

/// Validated capability pattern in a principal profile.
///
/// The public profile and wire formats stay string-shaped, while internal
/// callers can use this wrapper at validation and authorization edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapabilityPattern<S = String>(S);

impl<S: AsRef<str>> CapabilityPattern<S> {
    /// Create a validated capability pattern.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileFieldError::InvalidCapabilityPattern`] when the string
    /// does not satisfy Astrid's capability grammar.
    pub fn new(pattern: S) -> Result<Self, ProfileFieldError> {
        validate_capability(pattern.as_ref())?;
        Ok(Self(pattern))
    }

    /// Borrow the validated capability pattern.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl CapabilityPattern<String> {
    /// Consume the wrapper and return the owned string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl CapabilityPattern<&str> {
    /// Return an owned validated capability pattern.
    #[must_use]
    pub fn to_owned(self) -> CapabilityPattern<String> {
        CapabilityPattern(self.0.to_string())
    }
}

/// Validated capsule grant in a principal profile.
///
/// This intentionally mirrors the profile's grant grammar, not the
/// `astrid-capsule` crate's `CapsuleId`, so `astrid-core` keeps no dependency
/// on capsule loading internals. The public profile and wire formats stay
/// string-shaped, while internal callers can use this wrapper at validation
/// and authorization edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapsuleGrant<S = String>(S);

impl<S: AsRef<str>> CapsuleGrant<S> {
    /// Create a validated capsule grant.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileFieldError::InvalidCapsuleGrant`] when the grant is
    /// empty, too long, or contains a character outside `[a-z0-9-]`.
    pub fn new(id: S) -> Result<Self, ProfileFieldError> {
        validate_capsule_grant_str(id.as_ref())?;
        Ok(Self(id))
    }

    /// Borrow the validated capsule grant.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl CapsuleGrant<String> {
    /// Consume the wrapper and return the owned string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl CapsuleGrant<&str> {
    /// Return an owned validated capsule grant.
    #[must_use]
    pub fn to_owned(self) -> CapsuleGrant<String> {
        CapsuleGrant(self.0.to_string())
    }
}

macro_rules! impl_string_newtype {
    ($ty:ident, $err:ty) => {
        impl<S: AsRef<str>> AsRef<str> for $ty<S> {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl<S: AsRef<str>> fmt::Display for $ty<S> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl From<$ty<String>> for String {
            fn from(value: $ty<String>) -> Self {
                value.into_inner()
            }
        }

        impl TryFrom<String> for $ty<String> {
            type Error = $err;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl FromStr for $ty<String> {
            type Err = $err;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s.to_string())
            }
        }

        impl<S: AsRef<str>> PartialEq<str> for $ty<S> {
            fn eq(&self, other: &str) -> bool {
                self.as_str() == other
            }
        }

        impl<S: AsRef<str>> PartialEq<&str> for $ty<S> {
            fn eq(&self, other: &&str) -> bool {
                self.as_str() == *other
            }
        }

        impl<S: AsRef<str>> PartialEq<String> for $ty<S> {
            fn eq(&self, other: &String) -> bool {
                self.as_str() == other
            }
        }

        impl<S: AsRef<str>> PartialEq<&String> for $ty<S> {
            fn eq(&self, other: &&String) -> bool {
                self.as_str() == other.as_str()
            }
        }

        impl<S: AsRef<str>> Serialize for $ty<S> {
            fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
            where
                Ser: serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $ty<String> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

impl_string_newtype!(GroupName, ProfileFieldError);
impl_string_newtype!(CapabilityPattern, ProfileFieldError);
impl_string_newtype!(CapsuleGrant, ProfileFieldError);

/// Borrowed typed view over a string-shaped [`PrincipalProfile`].
///
/// `PrincipalProfile` remains the public/wire struct for TOML, JSON, and
/// external callers. Internal policy code can convert at the edge to this view
/// when it needs to distinguish group names, capability patterns, and capsule
/// grants in the type system without cloning profile strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedProfileFields<'a> {
    /// Validated group memberships.
    pub groups: Vec<GroupName<&'a str>>,
    /// Validated direct grants.
    pub grants: Vec<CapabilityPattern<&'a str>>,
    /// Validated direct revokes.
    pub revokes: Vec<CapabilityPattern<&'a str>>,
    /// Validated capsule grants.
    pub capsules: Vec<CapsuleGrant<&'a str>>,
}

impl PrincipalProfile {
    /// Convert this public string-shaped profile into a borrowed typed view.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Invalid`] if any profile field violates the
    /// corresponding newtype grammar.
    pub fn typed_fields(&self) -> ProfileResult<ValidatedProfileFields<'_>> {
        ValidatedProfileFields::try_from(self)
    }
}

impl<'a> TryFrom<&'a PrincipalProfile> for ValidatedProfileFields<'a> {
    type Error = ProfileError;

    fn try_from(profile: &'a PrincipalProfile) -> Result<Self, Self::Error> {
        Ok(Self {
            groups: profile
                .groups
                .iter()
                .map(|value| GroupName::new(value.as_str()).map_err(|e| profile_field_error(&e)))
                .collect::<ProfileResult<_>>()?,
            grants: profile
                .grants
                .iter()
                .map(|value| {
                    CapabilityPattern::new(value.as_str()).map_err(|e| profile_field_error(&e))
                })
                .collect::<ProfileResult<_>>()?,
            revokes: profile
                .revokes
                .iter()
                .map(|value| {
                    CapabilityPattern::new(value.as_str()).map_err(|e| profile_field_error(&e))
                })
                .collect::<ProfileResult<_>>()?,
            capsules: profile
                .capsules
                .iter()
                .map(|value| CapsuleGrant::new(value.as_str()).map_err(|e| profile_field_error(&e)))
                .collect::<ProfileResult<_>>()?,
        })
    }
}

fn profile_field_error(error: &ProfileFieldError) -> ProfileError {
    ProfileError::Invalid(error.to_string())
}

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
