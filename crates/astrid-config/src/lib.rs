//! Unified configuration system for the Astrid runtime.
//!
//! This crate provides a single [`Config`] type that consolidates all
//! configuration previously scattered across `RuntimeConfig`, `BudgetConfig`,
//! `ServersConfig`, `GatewayConfig`, and `HooksConfig`.
//!
//! # Usage
//!
//! ```rust,no_run
//! use astrid_config::Config;
//!
//! // Load with full precedence chain (defaults → system → user → workspace → env).
//! let resolved = Config::load(Some(std::path::Path::new("."))).unwrap();
//! let config = resolved.config;
//! println!("Using model: {}", config.model.model);
//! ```
//!
//! # Configuration Precedence
//!
//! From highest to lowest priority:
//!
//! 1. **Workspace** (`{workspace}/.astrid/config.toml`) — can only *tighten* security
//! 2. **User** (`~/.astrid/config.toml`)
//! 3. **System** (`/etc/astrid/config.toml`)
//! 4. **Environment variables** (`ASTRID_*`, `ANTHROPIC_*`) — fallback only
//! 5. **Embedded defaults** (`defaults.toml` compiled into binary)
//!
//! # Design
//!
//! This crate has **no dependencies on other internal astrid crates**. It only
//! depends on `serde`, `toml`, `thiserror`, `tracing`, and `directories`.
//! Conversion from config types to domain types happens at the integration
//! boundary (CLI startup, gateway init) via bridge modules.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

/// Environment variable fallback resolution.
pub mod env;
/// Configuration error types.
pub mod error;
/// Configuration file discovery and loading.
pub mod loader;
/// Layered configuration merging with precedence.
pub mod merge;
/// Resolved configuration display and serialization.
pub mod show;
/// Configuration struct definitions.
pub mod types;
/// Configuration validation rules.
pub mod validate;

// Re-export primary types at the crate root.
pub use error::{ConfigError, ConfigResult};
pub use show::{ResolvedConfig, ShowFormat};
pub use types::*;

impl Config {
    /// Load configuration with full precedence chain.
    ///
    /// See [`loader::load`] for the full algorithm.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] if any config file is malformed or the final
    /// configuration fails validation.
    pub fn load(workspace_root: Option<&std::path::Path>) -> ConfigResult<ResolvedConfig> {
        loader::load(workspace_root, None)
    }

    /// Load configuration with an explicit home directory override.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] if any config file is malformed or the final
    /// configuration fails validation.
    pub fn load_with_home(
        workspace_root: Option<&std::path::Path>,
        astrid_home: &std::path::Path,
    ) -> ConfigResult<ResolvedConfig> {
        loader::load(workspace_root, Some(astrid_home))
    }

    /// Load configuration from a single file (no layering).
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] if the file cannot be read, parsed, or fails
    /// validation.
    pub fn load_file(path: &std::path::Path) -> ConfigResult<Self> {
        loader::load_file(path)
    }
}
