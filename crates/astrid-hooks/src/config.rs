//! Hook configuration.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for the hooks system.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[expect(clippy::struct_excessive_bools)]
pub(crate) struct HooksConfig {
    /// Whether hooks are enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Default timeout for hooks in seconds.
    #[serde(default = "default_timeout")]
    pub default_timeout_secs: u64,

    /// Maximum number of hooks that can be registered.
    #[serde(default = "default_max_hooks")]
    pub max_hooks: usize,

    /// Directories to search for hooks.
    #[serde(default)]
    pub hook_directories: Vec<PathBuf>,

    /// Profile to use (if any).
    #[serde(default)]
    pub profile: Option<String>,

    /// Whether to allow async (fire-and-forget) hooks.
    #[serde(default = "default_true")]
    pub allow_async_hooks: bool,

    /// Whether to allow WASM hooks.
    #[serde(default)]
    pub allow_wasm_hooks: bool,

    /// Whether to allow agent (LLM) hooks.
    #[serde(default)]
    pub allow_agent_hooks: bool,

    /// Whether to allow HTTP webhook hooks.
    #[serde(default = "default_true")]
    pub allow_http_hooks: bool,

    /// Whether to allow command hooks.
    #[serde(default = "default_true")]
    pub allow_command_hooks: bool,

    /// Environment variables to pass to all command hooks.
    #[serde(default)]
    pub global_env: std::collections::HashMap<String, String>,

    /// Working directory for command hooks (if not specified per-hook).
    #[serde(default)]
    pub default_working_dir: Option<PathBuf>,
}

fn default_enabled() -> bool {
    true
}

fn default_timeout() -> u64 {
    30
}

fn default_max_hooks() -> usize {
    100
}

fn default_true() -> bool {
    true
}

impl Default for HooksConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_timeout_secs: 30,
            max_hooks: 100,
            hook_directories: Vec::new(),
            profile: None,
            allow_async_hooks: true,
            allow_wasm_hooks: false,
            allow_agent_hooks: false,
            allow_http_hooks: true,
            allow_command_hooks: true,
            global_env: std::collections::HashMap::new(),
            default_working_dir: None,
        }
    }
}

impl HooksConfig {
    /// Create a new hooks configuration with defaults.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Create a disabled hooks configuration.
    #[must_use]
    pub(crate) fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Create a minimal configuration for testing.
    #[must_use]
    pub(crate) fn minimal() -> Self {
        Self {
            enabled: true,
            default_timeout_secs: 5,
            max_hooks: 10,
            allow_async_hooks: false,
            allow_wasm_hooks: false,
            allow_agent_hooks: false,
            allow_http_hooks: false,
            allow_command_hooks: true,
            ..Default::default()
        }
    }

    /// Set the default timeout.
    #[must_use]
    pub(crate) fn with_timeout(mut self, secs: u64) -> Self {
        self.default_timeout_secs = secs;
        self
    }

    /// Add a hook directory.
    #[must_use]
    pub(crate) fn with_directory(mut self, dir: PathBuf) -> Self {
        self.hook_directories.push(dir);
        self
    }

    /// Set the profile.
    #[must_use]
    pub(crate) fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Enable WASM hooks.
    #[must_use]
    pub(crate) fn enable_wasm(mut self) -> Self {
        self.allow_wasm_hooks = true;
        self
    }

    /// Add a global environment variable.
    #[must_use]
    pub(crate) fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.global_env.insert(key.into(), value.into());
        self
    }

    /// Check if a handler type is allowed.
    #[must_use]
    pub(crate) fn is_handler_allowed(&self, handler: &crate::hook::HookHandler) -> bool {
        use crate::hook::HookHandler;

        match handler {
            HookHandler::Command { .. } => self.allow_command_hooks,
            HookHandler::Http { .. } => self.allow_http_hooks,
            HookHandler::Wasm { .. } => self.allow_wasm_hooks,
        }
    }

    /// Validate a hook against this configuration.
    ///
    /// # Errors
    ///
    /// Returns an error message if the hook is invalid per this configuration.
    pub(crate) fn validate_hook(&self, hook: &crate::hook::Hook) -> Result<(), String> {
        if !self.enabled {
            return Err("Hooks are disabled".to_string());
        }

        if !self.is_handler_allowed(&hook.handler) {
            return Err(format!(
                "Handler type {:?} is not allowed",
                std::mem::discriminant(&hook.handler)
            ));
        }

        if hook.async_mode && !self.allow_async_hooks {
            return Err("Async hooks are not allowed".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::{Hook, HookEvent, HookHandler};

    #[test]
    fn test_config_default() {
        let config = HooksConfig::default();
        assert!(config.enabled);
        assert_eq!(config.default_timeout_secs, 30);
        assert!(config.allow_command_hooks);
        assert!(!config.allow_wasm_hooks);
    }

    #[test]
    fn test_config_disabled() {
        let config = HooksConfig::disabled();
        assert!(!config.enabled);
    }

    #[test]
    fn test_config_minimal() {
        let config = HooksConfig::minimal();
        assert!(config.enabled);
        assert_eq!(config.default_timeout_secs, 5);
        assert!(!config.allow_async_hooks);
    }

    #[test]
    fn test_config_builder() {
        let config = HooksConfig::new()
            .with_timeout(60)
            .with_profile("security")
            .enable_wasm()
            .with_env("MY_VAR", "my_value");

        assert_eq!(config.default_timeout_secs, 60);
        assert_eq!(config.profile, Some("security".to_string()));
        assert!(config.allow_wasm_hooks);
        assert_eq!(
            config.global_env.get("MY_VAR"),
            Some(&"my_value".to_string())
        );
    }

    #[test]
    fn test_is_handler_allowed() {
        let config = HooksConfig::minimal();

        assert!(config.is_handler_allowed(&HookHandler::command("echo")));
        assert!(!config.is_handler_allowed(&HookHandler::http("http://example.com")));
        assert!(!config.is_handler_allowed(&HookHandler::wasm("/path/to/module.wasm")));
    }

    #[test]
    fn test_validate_hook() {
        let config = HooksConfig::minimal();

        // Valid hook
        let valid_hook =
            Hook::new(HookEvent::SessionStart).with_handler(HookHandler::command("echo"));
        assert!(config.validate_hook(&valid_hook).is_ok());

        // Invalid: HTTP not allowed
        let http_hook = Hook::new(HookEvent::SessionStart)
            .with_handler(HookHandler::http("http://example.com"));
        assert!(config.validate_hook(&http_hook).is_err());

        // Invalid: async not allowed
        let async_hook = Hook::new(HookEvent::SessionStart)
            .with_handler(HookHandler::command("echo"))
            .async_mode();
        assert!(config.validate_hook(&async_hook).is_err());
    }
}
