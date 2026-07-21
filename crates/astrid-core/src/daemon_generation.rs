//! Exact identity for one daemon executable generation.
//!
//! Semantic version alone cannot distinguish two process images built from
//! different source revisions.  A product distributor may therefore set
//! [`DAEMON_GENERATION_ENV`] for every bundled runtime process.  Standalone
//! builds fall back to the immutable crate release identity.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Process environment variable carrying the exact expected/runtime daemon
/// generation.
pub const DAEMON_GENERATION_ENV: &str = "ASTRID_DAEMON_GENERATION";

/// Product policy requiring every client to present an exact expected daemon
/// generation. Standalone Astrid leaves this unset for legacy compatibility;
/// distributors that perform atomic runtime cutovers should set it to `1`.
pub const REQUIRE_DAEMON_GENERATION_ENV: &str = "ASTRID_REQUIRE_DAEMON_GENERATION";

/// Maximum encoded daemon-generation length.
pub const MAX_DAEMON_GENERATION_LEN: usize = 256;

/// Exact identity of one Astrid daemon executable generation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DaemonGeneration(String);

impl DaemonGeneration {
    /// Parse a generation supplied by a product or launcher.
    ///
    /// # Errors
    /// Returns an error for an empty, oversized, or non-canonical identity.
    pub fn parse(value: impl Into<String>) -> Result<Self, DaemonGenerationError> {
        let value = value.into();
        if value.is_empty() {
            return Err(DaemonGenerationError::Empty);
        }
        if value.len() > MAX_DAEMON_GENERATION_LEN {
            return Err(DaemonGenerationError::TooLong {
                actual: value.len(),
            });
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-' | b':' | b'+' | b'@' | b'/')
        }) {
            return Err(DaemonGenerationError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Resolve the generation expected by this process.
    ///
    /// A distributor override binds the runtime to its signed release source.
    /// Without one, crates.io's immutable package version is the release
    /// identity; source builds may additionally inject `ASTRID_GIT_COMMIT`.
    ///
    /// # Errors
    /// Returns an error when [`DAEMON_GENERATION_ENV`] is present but invalid.
    pub fn current() -> Result<Self, DaemonGenerationError> {
        match std::env::var(DAEMON_GENERATION_ENV) {
            Ok(value) => Self::parse(value),
            Err(std::env::VarError::NotPresent) => Ok(Self::built_in()),
            Err(std::env::VarError::NotUnicode(_)) => Err(DaemonGenerationError::NotUnicode),
        }
    }

    /// Identity embedded in a standalone Astrid build.
    #[must_use]
    pub fn built_in() -> Self {
        let release = option_env!("ASTRID_GIT_COMMIT").unwrap_or("crate-release");
        // All components are compile-time canonical ASCII.
        Self(format!("astrid:{}:{release}", env!("CARGO_PKG_VERSION")))
    }

    /// Borrow the canonical encoded identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DaemonGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Resolve whether this daemon must reject clients that do not present an
/// exact expected generation.
///
/// # Errors
/// Returns an error when [`REQUIRE_DAEMON_GENERATION_ENV`] is present but is
/// neither `0`, `1`, `false`, nor `true`, or is not valid UTF-8. Invalid
/// policy is fail-closed rather than silently weakening an upgrade boundary.
pub fn daemon_generation_required() -> Result<bool, DaemonGenerationPolicyError> {
    match std::env::var(REQUIRE_DAEMON_GENERATION_ENV) {
        Ok(value) => parse_generation_requirement(&value),
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(std::env::VarError::NotUnicode(_)) => Err(DaemonGenerationPolicyError::NotUnicode),
    }
}

fn parse_generation_requirement(value: &str) -> Result<bool, DaemonGenerationPolicyError> {
    match value {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(DaemonGenerationPolicyError::InvalidValue(value.to_owned())),
    }
}

/// Invalid exact-generation enforcement policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DaemonGenerationPolicyError {
    /// The process policy was not valid UTF-8.
    #[error("{REQUIRE_DAEMON_GENERATION_ENV} is not valid UTF-8")]
    NotUnicode,
    /// The process policy used an unsupported value.
    #[error("{REQUIRE_DAEMON_GENERATION_ENV} must be one of 0, 1, false, or true (found {0:?})")]
    InvalidValue(String),
}

/// Invalid daemon-generation identity.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DaemonGenerationError {
    /// The identity was empty.
    #[error("daemon generation must not be empty")]
    Empty,
    /// The identity exceeded the bounded wire and readiness-file size.
    #[error("daemon generation is {actual} bytes; maximum is {MAX_DAEMON_GENERATION_LEN} bytes")]
    TooLong {
        /// Actual encoded length.
        actual: usize,
    },
    /// The identity contained whitespace, control data, or punctuation outside
    /// the canonical release-identity alphabet.
    #[error("daemon generation contains a non-canonical character")]
    InvalidCharacter,
    /// The process override was not valid UTF-8.
    #[error("{DAEMON_GENERATION_ENV} is not valid UTF-8")]
    NotUnicode,
}

/// Typed refusal to attach to a daemon from another executable generation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "daemon generation mismatch (expected {expected}, found {actual}); restart the daemon or this host session"
)]
pub struct DaemonGenerationMismatch {
    /// Generation required by the client or launcher.
    pub expected: DaemonGeneration,
    /// Generation exposed by the daemon, or `unknown` for a legacy daemon.
    pub actual: DaemonGenerationDisplay,
}

impl DaemonGenerationMismatch {
    /// Build a mismatch from an optional daemon-reported identity.
    #[must_use]
    pub fn new(expected: DaemonGeneration, actual: Option<DaemonGeneration>) -> Self {
        Self {
            expected,
            actual: actual.into(),
        }
    }

    /// Return the daemon-reported identity when one was available.
    #[must_use]
    pub fn actual_generation(&self) -> Option<&DaemonGeneration> {
        match &self.actual {
            DaemonGenerationDisplay::Known(generation) => Some(generation),
            DaemonGenerationDisplay::Unknown => None,
        }
    }
}

/// Display-safe representation of a reported or legacy daemon generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonGenerationDisplay {
    /// A generation was reported.
    Known(DaemonGeneration),
    /// A legacy daemon did not expose a generation.
    Unknown,
}

impl From<Option<DaemonGeneration>> for DaemonGenerationDisplay {
    fn from(value: Option<DaemonGeneration>) -> Self {
        value.map_or(Self::Unknown, Self::Known)
    }
}

impl fmt::Display for DaemonGenerationDisplay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(generation) => generation.fmt(formatter),
            Self::Unknown => formatter.write_str("unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_generation_round_trips() {
        let generation =
            DaemonGeneration::parse("astrid:0.10.5:b6bf5d1d579915eb5d3c944857d84e62a4fcc878")
                .unwrap();
        assert_eq!(
            generation.as_str(),
            "astrid:0.10.5:b6bf5d1d579915eb5d3c944857d84e62a4fcc878"
        );
    }

    #[test]
    fn unsafe_generation_is_rejected() {
        assert_eq!(
            DaemonGeneration::parse("astrid:0.10.5\nforged").unwrap_err(),
            DaemonGenerationError::InvalidCharacter
        );
        assert_eq!(
            DaemonGeneration::parse("").unwrap_err(),
            DaemonGenerationError::Empty
        );
    }

    #[test]
    fn missing_reported_generation_is_typed_as_unknown() {
        let expected = DaemonGeneration::built_in();
        let mismatch = DaemonGenerationMismatch::new(expected.clone(), None);
        assert_eq!(mismatch.expected, expected);
        assert!(mismatch.actual_generation().is_none());
        assert!(mismatch.to_string().contains("found unknown"));
    }

    #[test]
    fn generation_requirement_accepts_only_explicit_boolean_values() {
        assert_eq!(parse_generation_requirement("1"), Ok(true));
        assert_eq!(parse_generation_requirement("true"), Ok(true));
        assert_eq!(parse_generation_requirement("0"), Ok(false));
        assert_eq!(parse_generation_requirement("false"), Ok(false));
        assert!(matches!(
            parse_generation_requirement("yes"),
            Err(DaemonGenerationPolicyError::InvalidValue(value)) if value == "yes"
        ));
    }
}
