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
    /// Reverse-proxy IPs the gateway trusts to forward client IPs
    /// in `X-Forwarded-For` / `X-Real-IP` headers. Used by the
    /// redeem rate limiter to attribute attempts to the real client
    /// rather than the proxy. Empty = no forwarded-header trust
    /// (peer IP is used directly).
    ///
    /// **Operators MUST set this when the gateway is behind a
    /// reverse proxy** — otherwise the rate limiter sees every
    /// request as coming from the proxy's IP, and one abusive
    /// client locks out every legitimate user globally.
    ///
    /// Example: `["127.0.0.1", "10.0.0.1"]`.
    pub trust_forwarded_from: Vec<std::net::IpAddr>,
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
            trust_forwarded_from: Vec::new(),
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

    /// Post-deserialisation validation. Catches misconfigurations that
    /// would otherwise silently no-op at runtime — most importantly,
    /// CORS entries that don't parse as a `scheme://host[:port]`
    /// origin. The gateway used to read the field and never wire it
    /// into the router; the router now does the wiring, so refusing
    /// to boot on bad origins is what makes the config honest.
    pub fn validate(&self) -> anyhow::Result<()> {
        for raw in &self.cors_allow_origins {
            validate_cors_origin(raw)?;
        }
        Ok(())
    }
}

/// Validate a single CORS origin string. Origins MUST be of the form
/// `scheme://host[:port]` with no path, query, or fragment — that's
/// what the browser sends in `Origin:` and what the response's
/// `Access-Control-Allow-Origin:` is byte-matched against. A
/// `https://app.example/` (trailing slash) would silently fail to
/// match a real preflight; rejecting it here is what makes that
/// surfacable.
fn validate_cors_origin(raw: &str) -> anyhow::Result<()> {
    let parsed = url::Url::parse(raw)
        .map_err(|e| anyhow::anyhow!("CORS origin {raw:?} doesn't parse as a URL: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {},
        other => anyhow::bail!(
            "CORS origin {raw:?} uses scheme {other:?}; only http/https are valid for browser origins"
        ),
    }
    if parsed.host_str().is_none() {
        anyhow::bail!("CORS origin {raw:?} has no host component");
    }
    if parsed.path() != "" && parsed.path() != "/" {
        anyhow::bail!(
            "CORS origin {raw:?} carries a path ({:?}); origins are scheme+host+port only",
            parsed.path()
        );
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        anyhow::bail!(
            "CORS origin {raw:?} carries a query/fragment; origins are scheme+host+port only"
        );
    }
    // Disallow trailing-slash forms — browsers send `https://app.example`
    // (no slash) in `Origin:` and the response header is byte-matched.
    if raw.ends_with('/') {
        anyhow::bail!(
            "CORS origin {raw:?} has a trailing slash; remove it (browsers send `Origin:` without one)"
        );
    }
    Ok(())
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

    fn cfg_with_cors(origins: Vec<&str>) -> GatewayConfig {
        GatewayConfig {
            cors_allow_origins: origins.into_iter().map(String::from).collect(),
            ..GatewayConfig::default()
        }
    }

    #[test]
    fn validate_accepts_well_formed_origins() {
        let cfg = cfg_with_cors(vec![
            "https://app.example",
            "http://localhost:5173",
            "https://staging.example.com",
        ]);
        cfg.validate().expect("well-formed origins must pass");
    }

    #[test]
    fn validate_rejects_origin_with_path() {
        let cfg = cfg_with_cors(vec!["https://app.example/dashboard"]);
        let err = cfg
            .validate()
            .expect_err("origin with path must be rejected");
        assert!(
            format!("{err:#}").contains("path"),
            "error mentions path: {err:#}"
        );
    }

    #[test]
    fn validate_rejects_origin_with_trailing_slash() {
        let cfg = cfg_with_cors(vec!["https://app.example/"]);
        let err = cfg.validate().expect_err("trailing slash must be rejected");
        assert!(
            format!("{err:#}").contains("trailing slash"),
            "error mentions trailing slash: {err:#}"
        );
    }

    #[test]
    fn validate_rejects_non_http_scheme() {
        let cfg = cfg_with_cors(vec!["ftp://files.example"]);
        let err = cfg
            .validate()
            .expect_err("non-http scheme must be rejected");
        assert!(
            format!("{err:#}").contains("scheme") || format!("{err:#}").contains("ftp"),
            "error mentions scheme: {err:#}"
        );
    }

    #[test]
    fn validate_rejects_garbage() {
        let cfg = cfg_with_cors(vec!["not-a-url"]);
        cfg.validate()
            .expect_err("unparseable origin must be rejected");
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
            trust_forwarded_from: vec!["10.0.0.1".parse().unwrap()],
        };
        let text = toml::to_string_pretty(&cfg).unwrap();
        let back: GatewayConfig = toml::from_str(&text).unwrap();
        assert_eq!(back.listen, cfg.listen);
        assert_eq!(back.cors_allow_origins, cfg.cors_allow_origins);
    }
}
