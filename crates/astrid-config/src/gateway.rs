//! Gateway and MCP listener configuration.

use serde::{Deserialize, Serialize};

/// Gateway daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewaySection {
    /// Authenticated loopback Streamable HTTP endpoint settings.
    pub mcp_http: McpHttpSection,
    /// Directory for gateway runtime state (PID file, socket). `None` uses
    /// the platform default (e.g. `$XDG_STATE_HOME/astrid`).
    pub state_dir: Option<String>,
    /// Path to a secrets file for credential management.
    pub secrets_file: Option<String>,
    /// Whether to watch configuration files and reload on change.
    pub hot_reload: bool,
    /// Whether to watch plugin directories and hot-reload on file changes.
    pub watch_plugins: bool,
    /// Interval (in seconds) between health checks for managed servers.
    pub health_interval_secs: u64,
    /// Grace period (in seconds) for a clean shutdown before force-killing
    /// child processes.
    pub shutdown_timeout_secs: u64,
    /// MCP gateway grace period after its final host connection closes.
    /// Open connections are never considered idle solely for lack of traffic.
    pub idle_shutdown_secs: u64,
    /// Interval (in seconds) between stale session cleanup sweeps.
    pub session_cleanup_interval_secs: u64,
    /// When `true`, `send_input` publishes a `user.prompt` IPC event to the
    /// capsule pipeline instead of running the monolithic runtime turn.
    /// Default: `false`. Use for testing the capsule pipeline.
    pub use_capsule_pipeline: bool,
}

impl Default for GatewaySection {
    fn default() -> Self {
        Self {
            mcp_http: McpHttpSection::default(),
            state_dir: None,
            secrets_file: None,
            hot_reload: true,
            watch_plugins: true,
            health_interval_secs: 30,
            shutdown_timeout_secs: 30,
            idle_shutdown_secs: 30,
            session_cleanup_interval_secs: 60,
            use_capsule_pipeline: false,
        }
    }
}

/// Configuration for the explicitly started `astrid mcp http` listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct McpHttpSection {
    /// Loopback bind address. Remote exposure requires a separately managed tunnel.
    pub listen: std::net::SocketAddr,
    /// Private bearer credential file; no unauthenticated default is provided.
    pub token_file: Option<std::path::PathBuf>,
}

impl Default for McpHttpSection {
    fn default() -> Self {
        Self {
            listen: std::net::SocketAddr::from(([127, 0, 0, 1], 8081)),
            token_file: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Config;

    #[test]
    fn mcp_http_defaults_are_loopback_and_have_no_implicit_credential() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.gateway.mcp_http.listen.to_string(), "127.0.0.1:8081");
        assert!(config.gateway.mcp_http.token_file.is_none());
    }

    #[test]
    fn mcp_http_configuration_survives_serialization() {
        let config: Config = toml::from_str(
            "[gateway.mcp_http]\nlisten = '[::1]:9000'\ntoken_file = '/private/token'\n",
        )
        .unwrap();
        let encoded = toml::to_string(&config).unwrap();
        let decoded: Config = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded.gateway.mcp_http.listen.to_string(), "[::1]:9000");
        assert_eq!(
            decoded.gateway.mcp_http.token_file.unwrap(),
            std::path::PathBuf::from("/private/token")
        );
    }
}
