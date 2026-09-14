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
    /// OAuth 2.1 protected-resource validation. Mutually exclusive with [`Self::token_file`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<McpHttpOauthSection>,
}

impl Default for McpHttpSection {
    fn default() -> Self {
        Self {
            listen: std::net::SocketAddr::from(([127, 0, 0, 1], 8081)),
            token_file: None,
            oauth: None,
        }
    }
}

/// OAuth 2.1 protected-resource settings for `astrid mcp http`.
///
/// Missing `resource`, `issuer`, or `jwks_url` fails configuration parse.
/// URLs must be HTTPS without userinfo. This is not an authorization server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpHttpOauthSection {
    /// Canonical HTTPS resource identifier advertised in RFC 9728 metadata.
    pub resource: String,
    /// HTTPS authorization-server issuer; JWT `iss` must match exactly.
    pub issuer: String,
    /// HTTPS JWKS URL used to fetch asymmetric verification keys.
    pub jwks_url: String,
    /// Required token scopes. Empty means no scope constraint.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// JWT claim that must equal the process principal. Defaults to `sub`.
    #[serde(default = "default_principal_claim")]
    pub principal_claim: String,
    /// Optional authorized-party allowlist. Empty means `azp` is not checked.
    #[serde(default)]
    pub allowed_azp: Vec<String>,
}

fn default_principal_claim() -> String {
    "sub".to_owned()
}

/// True when `value` is an HTTPS URL with a host and without userinfo.
#[must_use]
pub(crate) fn https_url_is_valid(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

#[cfg(test)]
mod tests {
    use super::{McpHttpOauthSection, https_url_is_valid};
    use crate::Config;
    use crate::validate::validate;

    fn oauth_section(resource: &str, issuer: &str, jwks_url: &str) -> McpHttpOauthSection {
        McpHttpOauthSection {
            resource: resource.to_owned(),
            issuer: issuer.to_owned(),
            jwks_url: jwks_url.to_owned(),
            scopes: Vec::new(),
            principal_claim: "sub".to_owned(),
            allowed_azp: Vec::new(),
        }
    }

    #[test]
    fn mcp_http_defaults_are_loopback_and_have_no_implicit_credential() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.gateway.mcp_http.listen.to_string(), "127.0.0.1:8081");
        assert!(config.gateway.mcp_http.token_file.is_none());
        assert!(config.gateway.mcp_http.oauth.is_none());
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
        assert!(decoded.gateway.mcp_http.oauth.is_none());
    }

    #[test]
    fn mcp_http_oauth_roundtrip_preserves_required_https_fields() {
        let config: Config = toml::from_str(
            "[gateway.mcp_http.oauth]\n\
             resource = 'https://mcp.example.com/mcp'\n\
             issuer = 'https://issuer.example.com'\n\
             jwks_url = 'https://issuer.example.com/jwks'\n",
        )
        .unwrap();
        let encoded = toml::to_string(&config).unwrap();
        let decoded: Config = toml::from_str(&encoded).unwrap();
        let oauth = decoded.gateway.mcp_http.oauth.as_ref().unwrap();
        assert_eq!(oauth.resource, "https://mcp.example.com/mcp");
        assert_eq!(oauth.issuer, "https://issuer.example.com");
        assert_eq!(oauth.jwks_url, "https://issuer.example.com/jwks");
        assert_eq!(oauth.principal_claim, "sub");
        assert!(oauth.scopes.is_empty());
        assert!(oauth.allowed_azp.is_empty());
        assert!(validate(&decoded).is_ok());
    }

    #[test]
    fn mcp_http_oauth_rejects_http_and_userinfo() {
        assert!(!https_url_is_valid("http://mcp.example.com/mcp"));
        assert!(!https_url_is_valid("https://user@mcp.example.com/mcp"));
        assert!(!https_url_is_valid("https://mcp.example.com/mcp#fragment"));
        assert!(!https_url_is_valid("https://mcp.example.com:bad/mcp"));
        assert!(!https_url_is_valid("https://"));
        assert!(https_url_is_valid("https://mcp.example.com/mcp"));
        let mut config = Config::default();
        config.gateway.mcp_http.oauth = Some(oauth_section(
            "http://mcp.example.com/mcp",
            "https://issuer.example.com",
            "https://issuer.example.com/jwks",
        ));
        assert!(validate(&config).is_err());
        config.gateway.mcp_http.oauth = Some(oauth_section(
            "https://user@mcp.example.com/mcp",
            "https://issuer.example.com",
            "https://issuer.example.com/jwks",
        ));
        assert!(validate(&config).is_err());
    }

    #[test]
    fn mcp_http_token_file_and_oauth_are_mutually_exclusive() {
        let mut config = Config::default();
        config.gateway.mcp_http.token_file = Some(std::path::PathBuf::from("/private/token"));
        config.gateway.mcp_http.oauth = Some(oauth_section(
            "https://mcp.example.com/mcp",
            "https://issuer.example.com",
            "https://issuer.example.com/jwks",
        ));
        let err = validate(&config).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("token_file"), "{message}");
        assert!(message.contains("oauth"), "{message}");
    }

    #[test]
    fn mcp_http_oauth_requires_complete_table() {
        let parsed = toml::from_str::<Config>(
            "[gateway.mcp_http.oauth]\nresource = 'https://mcp.example.com/mcp'\n",
        );
        assert!(parsed.is_err());
    }
}
