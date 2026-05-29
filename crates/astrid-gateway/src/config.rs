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
///
/// Port `2787` is the phone-keypad mnemonic for `ASTR` (A=2, S=7,
/// T=8, R=7). Chosen over the old `7777`, which collides in practice
/// with Terraria and assorted dev tooling.
const DEFAULT_LISTEN: &str = "127.0.0.1:2787";

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
    /// Bind address (e.g. `"127.0.0.1:2787"`). Plain TCP; terminate
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
    /// TLS termination directly in the gateway. `None` (the default)
    /// keeps the plain-HTTP posture and delegates TLS to an upstream
    /// proxy. `Some(...)` switches to native rustls termination —
    /// useful for single-box installs, Tailscale-fronted deployments,
    /// or anyone deploying without a reverse-proxy ops layer.
    ///
    /// Default `None` so an upgrade from v0.7.0 keeps its existing
    /// shape (`enabled = true` + no TLS = same plain-HTTP behaviour
    /// the daemon already had).
    pub tls: Option<TlsConfig>,
}

/// Native TLS configuration for the gateway. Backed by rustls
/// (no openssl dependency anywhere in the workspace).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TlsConfig {
    /// Filesystem path to the PEM-encoded server certificate chain.
    /// Must be readable by the daemon process. Live cert rotation is
    /// not yet wired (the daemon only handles SIGINT / SIGTERM);
    /// today, restart the daemon to pick up new bytes.
    pub cert_path: PathBuf,
    /// Filesystem path to the PEM-encoded private key (PKCS#8 or
    /// RSA). Must be 0600 perms on Unix; the gateway logs a warning
    /// on boot if the key is group- or world-readable.
    pub key_path: PathBuf,
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
            tls: None,
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

    /// Post-deserialisation validation. Catches misconfigurations
    /// that would otherwise silently no-op at runtime or fail with a
    /// cryptic error deep inside rustls / `tower-http`:
    ///
    /// * **CORS origins** are checked against the `scheme://host[:port]`
    ///   shape so an operator who typoed a trailing slash, fragment,
    ///   IDN, etc., fails boot with a clear message rather than
    ///   silently never matching a browser preflight.
    /// * **TLS** cert/key paths must exist as regular files and not
    ///   collide with each other — both common misconfigurations
    ///   that the rustls PEM parser would surface as bewildering
    ///   downstream errors.
    pub fn validate(&self) -> anyhow::Result<()> {
        for raw in &self.cors_allow_origins {
            validate_cors_origin(raw)?;
        }
        if let Some(tls) = &self.tls {
            // `is_file()` catches both "doesn't exist" and "points
            // at a directory". `exists()` alone would pass for a
            // directory and fail later inside rustls with a less
            // clear error.
            if !tls.cert_path.is_file() {
                anyhow::bail!(
                    "tls.cert-path {} is not a regular file — refusing to boot the gateway",
                    tls.cert_path.display()
                );
            }
            if !tls.key_path.is_file() {
                anyhow::bail!(
                    "tls.key-path {} is not a regular file — refusing to boot the gateway",
                    tls.key_path.display()
                );
            }
            // Defensive: catch the copy-paste typo where cert+key
            // point at the same file. The rustls PEM parser will
            // happily try to load a private key out of the cert chain
            // and produce a cryptic error; surface the problem here.
            if tls.cert_path == tls.key_path {
                anyhow::bail!(
                    "tls.cert-path and tls.key-path resolve to the same file ({}); separate them",
                    tls.cert_path.display()
                );
            }
            crate::tls::warn_if_key_is_too_open(&tls.key_path);
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
    // Browsers strip userinfo before sending `Origin:`, so a config
    // entry with embedded credentials can never match a real
    // preflight. Reject so operators don't silently misconfigure.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!(
            "CORS origin {raw:?} carries userinfo (user:password); browsers strip it before sending `Origin:` so this can never match"
        );
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
    // Reject a raw IDN — browsers transmit the Punycode (ASCII)
    // form in `Origin:`, so the bytes wouldn't match anyway. The
    // `Url` parser already normalizes the host to its ASCII form on
    // parse; if the *raw* string contained a non-ASCII character,
    // the parsed `origin()` ASCII-serialization won't equal `raw`.
    let parsed_ascii = parsed.origin().ascii_serialization();
    if parsed_ascii != raw {
        anyhow::bail!(
            "CORS origin {raw:?} must be ASCII-only (Punycode); browsers send the Punycoded form in `Origin:`. Use {parsed_ascii:?} instead."
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
        assert_eq!(cfg.listen, "127.0.0.1:2787");
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
    fn validate_rejects_origin_with_userinfo() {
        let cfg = cfg_with_cors(vec!["https://user:pass@app.example"]);
        let err = cfg.validate().expect_err("userinfo must be rejected");
        assert!(
            format!("{err:#}").contains("userinfo"),
            "error mentions userinfo: {err:#}"
        );
    }

    #[test]
    fn validate_rejects_raw_idn() {
        // Non-ASCII / raw IDN — browsers send the Punycoded form
        // in `Origin:` so a raw IDN can never match.
        let cfg = cfg_with_cors(vec!["https://äpp.example"]);
        let err = cfg.validate().expect_err("raw IDN must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Punycode") || msg.contains("ASCII"),
            "error suggests Punycode form: {msg}"
        );
        // And the error should suggest the ASCII (Punycode) form.
        assert!(
            msg.contains("xn--"),
            "error should propose the Punycode form: {msg}"
        );
    }

    #[test]
    fn validate_accepts_punycode_form() {
        let cfg = cfg_with_cors(vec!["https://xn--pp-eka.example"]);
        cfg.validate()
            .expect("the Punycode form of an IDN must validate");
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
            tls: Some(TlsConfig {
                cert_path: PathBuf::from("/etc/astrid/tls/cert.pem"),
                key_path: PathBuf::from("/etc/astrid/tls/key.pem"),
            }),
        };
        let text = toml::to_string_pretty(&cfg).unwrap();
        let back: GatewayConfig = toml::from_str(&text).unwrap();
        assert_eq!(back.listen, cfg.listen);
        assert_eq!(back.cors_allow_origins, cfg.cors_allow_origins);
        assert_eq!(
            back.tls.as_ref().map(|t| t.cert_path.clone()),
            cfg.tls.as_ref().map(|t| t.cert_path.clone())
        );
    }

    #[test]
    fn validate_rejects_missing_cert_path() {
        let cfg = GatewayConfig {
            tls: Some(TlsConfig {
                cert_path: PathBuf::from("/dev/null/does/not/exist.pem"),
                key_path: PathBuf::from("/dev/null/does/not/exist.key"),
            }),
            ..GatewayConfig::default()
        };
        let err = cfg.validate().expect_err("missing cert must reject");
        assert!(
            format!("{err:#}").contains("cert-path"),
            "error mentions cert-path: {err:#}"
        );
    }

    #[test]
    fn validate_rejects_missing_key_path() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let cfg = GatewayConfig {
            tls: Some(TlsConfig {
                cert_path: tmp.path().to_path_buf(),
                key_path: PathBuf::from("/dev/null/does/not/exist.key"),
            }),
            ..GatewayConfig::default()
        };
        let err = cfg.validate().expect_err("missing key must reject");
        assert!(
            format!("{err:#}").contains("key-path"),
            "error mentions key-path: {err:#}"
        );
    }

    #[test]
    fn validate_rejects_directory_as_cert_path() {
        // `exists()` on a directory returns true; `is_file()` is what
        // catches the copy-paste-a-dir typo. Use the parent of a
        // tempfile so we have a real directory at hand.
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let key = tempfile::NamedTempFile::new().expect("key tempfile");
        let cfg = GatewayConfig {
            tls: Some(TlsConfig {
                cert_path: tmpdir.path().to_path_buf(),
                key_path: key.path().to_path_buf(),
            }),
            ..GatewayConfig::default()
        };
        let err = cfg.validate().expect_err("directory must reject");
        assert!(
            format!("{err:#}").contains("not a regular file"),
            "error mentions regular file: {err:#}"
        );
    }

    #[test]
    fn validate_rejects_same_file_for_cert_and_key() {
        // Common copy-paste typo: cert and key both point at the same
        // path. Surface it here rather than letting rustls' PEM
        // parser produce a cryptic "no private key found".
        let same = tempfile::NamedTempFile::new().expect("tempfile");
        let cfg = GatewayConfig {
            tls: Some(TlsConfig {
                cert_path: same.path().to_path_buf(),
                key_path: same.path().to_path_buf(),
            }),
            ..GatewayConfig::default()
        };
        let err = cfg.validate().expect_err("same-file must reject");
        assert!(
            format!("{err:#}").contains("same file"),
            "error mentions same file: {err:#}"
        );
    }

    #[test]
    fn validate_passes_for_existing_cert_and_key() {
        let cert = tempfile::NamedTempFile::new().expect("cert tempfile");
        let key = tempfile::NamedTempFile::new().expect("key tempfile");
        let cfg = GatewayConfig {
            tls: Some(TlsConfig {
                cert_path: cert.path().to_path_buf(),
                key_path: key.path().to_path_buf(),
            }),
            ..GatewayConfig::default()
        };
        cfg.validate()
            .expect("existing cert+key files should pass validation");
    }

    #[test]
    fn validate_no_tls_block_is_a_noop() {
        let cfg = GatewayConfig::default();
        assert!(cfg.tls.is_none());
        cfg.validate().expect("no-tls config must pass");
    }
}
