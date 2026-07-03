//! The stable capsule identifier.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{CapsuleError, CapsuleResult};

/// Unique, stable, human-readable capsule identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct CapsuleId(String);

impl<'de> Deserialize<'de> for CapsuleId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

impl CapsuleId {
    pub fn new(id: impl Into<String>) -> CapsuleResult<Self> {
        let id = id.into();
        Self::validate(&id)?;
        Ok(Self(id))
    }

    #[must_use]
    pub fn from_static(id: &str) -> Self {
        Self(id.to_string())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(id: &str) -> CapsuleResult<()> {
        if id.is_empty() {
            return Err(CapsuleError::UnsupportedEntryPoint(
                "capsule id must not be empty".into(),
            ));
        }
        if !id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(CapsuleError::UnsupportedEntryPoint(format!(
                "capsule id must contain only lowercase alphanumeric characters and hyphens, got: {id}"
            )));
        }
        Ok(())
    }
}

impl fmt::Display for CapsuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for CapsuleId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
