use std::collections::HashMap;

/// Which configuration layer a value came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigLayer {
    /// Compiled-in defaults (`defaults.toml`).
    Defaults,
    /// System-wide configuration (`/etc/astrid/config.toml`).
    System,
    /// User-level configuration (`~/.astrid/config.toml`).
    User,
    /// Workspace-level configuration under selected project state.
    Workspace,
    /// Environment variable fallback.
    Environment,
}

impl std::fmt::Display for ConfigLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Defaults => write!(f, "defaults"),
            Self::System => write!(f, "system (/etc/astrid/config.toml)"),
            Self::User => write!(f, "user (~/.astrid/config.toml)"),
            Self::Workspace => write!(f, "workspace config"),
            Self::Environment => write!(f, "environment variable"),
        }
    }
}

/// Tracks which layer set each field's value.
pub type FieldSources = HashMap<String, ConfigLayer>;
