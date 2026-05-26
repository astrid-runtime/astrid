//! Gateway runtime configuration.
//!
//! Loaded from `$ASTRID_HOME/etc/gateway-http.toml` by the daemon at
//! boot. Distinct path from the legacy `etc/gateway.toml` (which
//! holds the unrelated `GatewaySection` daemon-runtime knobs) — the
//! issue's "gateway" is an HTTP front, not a daemon-runtime layer.
//! Both files can co-exist.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Default listen address — localhost only. Anything beyond
/// host-local needs an explicit decision (reverse proxy, host
/// firewall) because the gateway speaks plain HTTP.
const DEFAULT_LISTEN: &str = "127.0.0.1:7777";

/// Default session token lifetime. Long enough to outlast a typical
/// dashboard session, short enough that revocation only requires
/// waiting out the existing token rather than maintaining a
/// revocation list.
const DEFAULT_SESSION_LIFETIME_SECS: u64 = 60 * 60 * 8;

/// Default minimum interval between invite-redeem attempts from the
/// same source IP. Defends against brute-force scans against the
/// 192-bit token space — even a 1-second interval keeps attacker
/// throughput orders of magnitude below the redeem budget.
const DEFAULT_REDEEM_RATE_LIMIT_SECS: u64 = 1;

/// Gateway HTTP configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct GatewayConfig {
    /// Whether the daemon should spawn the gateway at startup.
    /// Default `false` — single-tenant deployments don't need an
    /// HTTP front, and gating on an explicit flag avoids surprising
    /// existing installs.
    pub enabled: bool,
    /// Bind address (e.g. `"127.0.0.1:7777"`). Plain TCP; terminate
    /// TLS upstream.
    pub listen: String,
    /// Path to the deployment's `Distro.toml`. The gateway loads it
    /// once at startup and reflects it through `/api/distribution`.
    /// `None` means single-tenant: the discovery endpoint returns
    /// stub metadata indicating no public registration.
    pub distro_path: Option<PathBuf>,
    /// Session-token lifetime in seconds. Tokens are short-lived
    /// signed bearers; refresh is a separate explicit request.
    pub session_lifetime_secs: u64,
    /// Per-IP redeem rate limit (seconds between redeems). `0`
    /// disables — only safe for tests.
    pub redeem_rate_limit_secs: u64,
    /// CORS allow-list. Empty = browser dashboards on the same
    /// origin only. Each entry is a literal origin (`https://foo`),
    /// matched verbatim.
    pub cors_allow_origins: Vec<String>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: DEFAULT_LISTEN.to_string(),
            distro_path: None,
            session_lifetime_secs: DEFAULT_SESSION_LIFETIME_SECS,
            redeem_rate_limit_secs: DEFAULT_REDEEM_RATE_LIMIT_SECS,
            cors_allow_origins: Vec::new(),
        }
    }
}

impl GatewayConfig {
    /// Convenience getter for the session lifetime as a `Duration`.
    #[must_use]
    pub const fn session_lifetime(&self) -> Duration {
        Duration::from_secs(self.session_lifetime_secs)
    }

    /// Convenience getter for the redeem rate-limit interval.
    #[must_use]
    pub const fn redeem_rate_limit(&self) -> Duration {
        Duration::from_secs(self.redeem_rate_limit_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disabled() {
        let cfg = GatewayConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.listen, "127.0.0.1:7777");
    }

    #[test]
    fn round_trips_through_toml() {
        let cfg = GatewayConfig {
            enabled: true,
            listen: "127.0.0.1:8080".into(),
            distro_path: Some(PathBuf::from("/var/astrid/Distro.toml")),
            session_lifetime_secs: 3600,
            redeem_rate_limit_secs: 0,
            cors_allow_origins: vec!["https://example.invalid".into()],
        };
        let text = toml::to_string_pretty(&cfg).unwrap();
        let back: GatewayConfig = toml::from_str(&text).unwrap();
        assert_eq!(back.listen, cfg.listen);
        assert_eq!(back.cors_allow_origins, cfg.cors_allow_origins);
    }
}
