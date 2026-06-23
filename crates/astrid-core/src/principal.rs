//! Principal identity for multi-user deployments.
//!
//! A [`PrincipalId`] identifies a user (human or agent) within the Astrid
//! runtime. Each principal gets an isolated home directory under
//! `~/.astrid/home/{principal}/` with its own capsules, KV data, audit
//! chain, and capability tokens.

use std::fmt;
use std::str::FromStr;

/// Validated principal identifier.
///
/// ASCII alphanumeric, hyphens, and underscores only. 1–64 characters.
/// The default principal is `"default"` (single-user mode).
#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PrincipalId(String);

/// Error returned when a [`PrincipalId`] string fails validation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PrincipalIdError {
    /// The input was empty.
    #[error("principal id must not be empty")]
    Empty,
    /// The input exceeded the 64-character limit.
    #[error("principal id exceeds 64 characters")]
    TooLong,
    /// The input contained a character outside `[a-zA-Z0-9_-]`.
    #[error("principal id contains invalid character '{0}' (allowed: a-z, A-Z, 0-9, -, _)")]
    InvalidChar(char),
}

impl PrincipalId {
    /// Create a new `PrincipalId`, validating the input.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalIdError`] if the input is empty, longer than 64
    /// characters, or contains characters outside `[a-zA-Z0-9_-]`.
    pub fn new(id: impl Into<String>) -> Result<Self, PrincipalIdError> {
        let id = id.into();
        if id.is_empty() {
            return Err(PrincipalIdError::Empty);
        }
        if id.len() > 64 {
            return Err(PrincipalIdError::TooLong);
        }
        if let Some(ch) = id
            .chars()
            .find(|c| !c.is_ascii_alphanumeric() && *c != '-' && *c != '_')
        {
            return Err(PrincipalIdError::InvalidChar(ch));
        }
        Ok(Self(id))
    }

    /// Return the underlying string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The reserved, no-capability identity stamped on an unauthenticated
    /// (unbound) socket connection (issue #45/#852). It has no profile, so a
    /// capability check fails closed — an unauthenticated client can never act
    /// as a privileged principal. `agent create` refuses this name, so it can
    /// never be granted capabilities.
    #[must_use]
    pub fn anonymous() -> Self {
        Self("anonymous".to_string())
    }

    /// If this is a reserved principal that must not be created through the
    /// admin surface, the human-readable reason; otherwise `None`. `default` is
    /// the single-tenant bootstrap anchor; `anonymous` is the no-capability
    /// identity stamped on unauthenticated connections (issue #45/#852) — both
    /// must never become real, grantable profiles.
    #[must_use]
    pub fn reserved_reason(&self) -> Option<&'static str> {
        match self.0.as_str() {
            "default" => Some("reserved for single-tenant bootstrap"),
            "anonymous" => Some("reserved (the unauthenticated no-capability identity)"),
            _ => None,
        }
    }

    /// Consume the id and return the owned inner string, moving it out without
    /// re-allocating (unlike `to_string()`, which copies).
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Default for PrincipalId {
    fn default() -> Self {
        Self("default".to_string())
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrincipalId({:?})", self.0)
    }
}

impl AsRef<str> for PrincipalId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for PrincipalId {
    type Err = PrincipalIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl From<PrincipalId> for String {
    fn from(id: PrincipalId) -> Self {
        id.0
    }
}

impl TryFrom<String> for PrincipalId {
    type Error = PrincipalIdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ids() {
        assert!(PrincipalId::new("default").is_ok());
        assert!(PrincipalId::new("alice").is_ok());
        assert!(PrincipalId::new("agent-007").is_ok());
        assert!(PrincipalId::new("system_admin").is_ok());
        assert!(PrincipalId::new("A").is_ok());
        assert!(PrincipalId::new("a".repeat(64)).is_ok());
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(PrincipalId::new(""), Err(PrincipalIdError::Empty)));
    }

    #[test]
    fn rejects_too_long() {
        assert!(matches!(
            PrincipalId::new("a".repeat(65)),
            Err(PrincipalIdError::TooLong)
        ));
    }

    #[test]
    fn rejects_invalid_chars() {
        assert!(matches!(
            PrincipalId::new("foo bar"),
            Err(PrincipalIdError::InvalidChar(' '))
        ));
        assert!(matches!(
            PrincipalId::new("foo/bar"),
            Err(PrincipalIdError::InvalidChar('/'))
        ));
        assert!(matches!(
            PrincipalId::new("foo.bar"),
            Err(PrincipalIdError::InvalidChar('.'))
        ));
        assert!(matches!(
            PrincipalId::new("../escape"),
            Err(PrincipalIdError::InvalidChar('.'))
        ));
    }

    #[test]
    fn default_is_default() {
        let id = PrincipalId::default();
        assert_eq!(id.as_str(), "default");
    }

    #[test]
    fn display_and_debug() {
        let id = PrincipalId::new("alice").unwrap();
        assert_eq!(id.to_string(), "alice");
        assert_eq!(format!("{id:?}"), "PrincipalId(\"alice\")");
    }

    #[test]
    fn from_str_roundtrip() {
        let id: PrincipalId = "bob".parse().unwrap();
        assert_eq!(id.as_str(), "bob");
        let s: String = id.into();
        assert_eq!(s, "bob");
    }

    #[test]
    fn serde_roundtrip() {
        let id = PrincipalId::new("charlie").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"charlie\"");
        let back: PrincipalId = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_str(), "charlie");
    }

    #[test]
    fn serde_rejects_invalid() {
        let result: Result<PrincipalId, _> = serde_json::from_str("\"foo/bar\"");
        assert!(result.is_err());
    }
}
