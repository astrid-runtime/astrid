//! SSRF airlock for the HTTP host: DNS-resolution filtering, IP-literal
//! pre-flight, operator local-egress allowlist + runtime consent, and per-hop
//! redirect re-validation. Version-agnostic — both `astrid:http@1.0.0` and
//! `@1.1.0` share this one airlock.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::engine::wasm::host_state::HostState;
use crate::security::net_connect_pattern_matches;

use super::ErrorCode;

/// Maximum redirect hops followed before the request is stopped. Matches
/// reqwest's historical default; redirect targets are airlocked per hop
/// (see [`classify_redirect`]).
pub(super) const MAX_HTTP_REDIRECTS: usize = 10;

/// A DNS resolver that prevents SSRF by blocking resolution to local,
/// private, or multicast IP addresses.
///
/// `tripped` is set when resolution is blocked *because* every resolved
/// address failed the airlock (as opposed to an ordinary resolution
/// failure), so the caller can surface the typed `airlock-rejected` error
/// instead of a generic connection error.
#[derive(Clone)]
pub(super) struct SafeDnsResolver {
    pub(super) tripped: Arc<AtomicBool>,
    /// The exact request hostname that the operator allowlist exempts from
    /// the airlock (decided at pre-flight, where the port is known). When the
    /// name being resolved equals this, private/loopback addresses are kept.
    /// `None` = no exemption. Scoped to the one allow-listed host so redirect
    /// hops to other hostnames are still airlocked.
    pub(super) exempt_host: Option<Arc<str>>,
}

impl reqwest::dns::Resolve for SafeDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let name_str = name.as_str().to_string();
        let tripped = self.tripped.clone();
        let exempt = self
            .exempt_host
            .as_deref()
            .is_some_and(|h| h.eq_ignore_ascii_case(&name_str));
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((name_str.as_str(), 0))
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

            let (safe_addrs, saw_unsafe) = filter_safe_addrs(addrs, exempt);

            if safe_addrs.is_empty() {
                // All resolved addresses failed the airlock: a genuine SSRF
                // block. Mark `tripped` so the caller can emit the typed
                // `airlock-rejected` instead of a generic connection error.
                if saw_unsafe {
                    tripped.store(true, Ordering::Relaxed);
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "DNS resolved to an unauthorized private or local IP address",
                    ))
                        as Box<dyn std::error::Error + Send + Sync>);
                }
                // No addresses at all: an ordinary resolution miss, not an
                // airlock block — surface it as such (do NOT trip the airlock).
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "host did not resolve to any address",
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            let iter: reqwest::dns::Addrs = Box::new(safe_addrs.into_iter());
            Ok(iter)
        })
    }
}

/// Partition resolved addresses into the airlock-safe set, reporting
/// whether any address was dropped as unsafe. An all-unsafe result (empty
/// safe set with `saw_unsafe == true`) is an airlock rejection; an empty
/// input is an ordinary resolution miss.
///
/// `exempt` (the operator allowlist matched this host:port at pre-flight)
/// keeps every resolved address — the sanctioned local-endpoint case.
pub(super) fn filter_safe_addrs(
    addrs: impl Iterator<Item = SocketAddr>,
    exempt: bool,
) -> (Vec<SocketAddr>, bool) {
    if exempt {
        return (addrs.collect(), false);
    }
    let mut safe = Vec::new();
    let mut saw_unsafe = false;
    for addr in addrs {
        if is_safe_ip(addr.ip()) {
            safe.push(addr);
        } else {
            saw_unsafe = true;
        }
    }
    (safe, saw_unsafe)
}

/// Test-only SSRF bypass: honored ONLY in `cfg(test)` builds, where the unit
/// tests need to exercise the egress path against loopback addresses. This is
/// gated so the daemon's **release binary never reads `ASTRID_TEST_ALLOW_LOCAL_IP`**
/// — a stray test env var in production can never silently disable the airlock
/// (and with it the per-capsule local-egress consent gate). The non-test
/// definition is a `const false`, so the entire env-var read is compiled out of
/// every release/non-test build.
#[cfg(test)]
fn test_env_bypass() -> bool {
    if std::env::var("ASTRID_TEST_ALLOW_LOCAL_IP").is_ok() {
        tracing::warn!(
            "ASTRID_TEST_ALLOW_LOCAL_IP is set - SSRF protection disabled for ALL capsules (test-only)"
        );
        return true;
    }
    false
}

/// Production builds never honor the test bypass: the env var is not even read.
#[cfg(not(test))]
const fn test_env_bypass() -> bool {
    false
}

/// Cached SSRF escape-hatch check. Evaluated once per process.
static SSRF_BYPASS: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
    if test_env_bypass() {
        return true;
    }
    // DEPRECATED. `ASTRID_ALLOW_LOCAL_IPS` is still recognized in production
    // (operators/CI may rely on it) but is on a removal path. The one-time
    // warning is HONEST about the blast radius: this is not a scoped exemption,
    // it disables the SSRF airlock for EVERY loaded capsule AND — because the
    // airlock is the gate the per-capsule local-egress *consent* check runs
    // behind — it exposes loopback/private endpoints to REMOTE (`RemoteGateway`)
    // API callers, bypassing the operator-consent gate entirely. Operators
    // should migrate to the per-capsule `[security.capsule_local_egress]`
    // allowlist, which exempts a named capsule for a named `host:port` only.
    // Slated for removal in a future release.
    if std::env::var("ASTRID_ALLOW_LOCAL_IPS").is_ok() {
        tracing::warn!(
            "ASTRID_ALLOW_LOCAL_IPS is set and is DEPRECATED. It disables the SSRF airlock \
             for ALL capsules and exposes local/loopback endpoints to REMOTE API callers, \
             bypassing the per-capsule local-egress consent gate. Migrate to the per-capsule \
             [security.capsule_local_egress] allowlist; this escape hatch will be removed in a \
             future release."
        );
        return true;
    }
    false
});

/// True if a capsule may reach `ip` over the network — i.e. it is NOT in the
/// SSRF block set (loopback / private / link-local / CGNAT / site-local /
/// transition-embedded private).
///
/// The block-set predicate lives in [`astrid_core::net::ip_is_blocked`] so the
/// airlock and the CLI guided pre-bless (`astrid-cli` `local_egress`) share one
/// source of truth and cannot drift. The `ASTRID_ALLOW_LOCAL_IPS` deprecated
/// escape hatch is layered here, on the airlock side only — the pure shared
/// predicate has no env-var bypass, so the CLI bless prompt is never suppressed
/// by a test/CI env var.
pub(crate) fn is_safe_ip(ip: IpAddr) -> bool {
    if *SSRF_BYPASS {
        return true;
    }
    !astrid_core::net::ip_is_blocked(ip)
}

/// Parse a URL host string into an IP literal, if it is one.
///
/// [`reqwest::Url::host_str`] returns IPv6 literals bracketed (`[::1]`);
/// the brackets are stripped before parsing. A domain name returns `None`
/// — it will be resolved (and airlocked) by [`SafeDnsResolver`].
pub(super) fn literal_ip(host: &str) -> Option<IpAddr> {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    IpAddr::from_str(bare).ok()
}

/// True if `host:port` matches any pattern in this capsule's operator
/// local-egress allowlist. Entries use the same `host:port` / `host:*`
/// semantics as a manifest `net_connect` entry.
pub(super) fn egress_allowed(allowlist: &[String], host: &str, port: u16) -> bool {
    allowlist
        .iter()
        .any(|entry| net_connect_pattern_matches(entry, host, port))
}

/// Pre-flight the request URL against the SSRF airlock and this capsule's
/// operator local-egress allowlist.
///
/// - `Ok(Some(host))` — the operator allowlisted this `host:port`; the
///   request is exempt. The host is propagated to [`SafeDnsResolver`] so a
///   hostname endpoint (e.g. `localhost:1234`) resolves through to its
///   loopback address. Port-specificity is enforced here, where the port is
///   known — the resolver only ever sees the host.
/// - `Ok(None)` — not exempt; proceed normally (hostnames are airlocked at
///   resolution; public IP literals are allowed).
/// - `Err(AirlockRejected)` — an IP-literal URL to a private/loopback
///   address that is NOT allowlisted. reqwest never runs the resolver on a
///   literal, so this pre-flight is the only place it can be caught.
///
/// The allowlist check runs first so an operator-sanctioned private literal
/// (`127.0.0.1:1234`) is permitted rather than airlock-rejected.
pub(super) fn egress_decision(
    allowlist: &[String],
    url: &str,
) -> Result<Option<Arc<str>>, ErrorCode> {
    let parsed = reqwest::Url::parse(url).map_err(|_| ErrorCode::InvalidRequest)?;
    let host = parsed.host_str().ok_or(ErrorCode::InvalidRequest)?;
    if let Some(port) = parsed.port_or_known_default()
        && egress_allowed(allowlist, host, port)
    {
        return Ok(Some(Arc::from(host)));
    }
    if let Some(ip) = literal_ip(host)
        && !is_safe_ip(ip)
    {
        return Err(ErrorCode::AirlockRejected);
    }
    Ok(None)
}

/// Parse a URL's host and resolved port for the consent prompt. Returns `None`
/// (declining consent, fail-closed) if the URL is unparseable or has no host /
/// known-default port — the same shapes `egress_decision` already rejects.
fn url_host_port(url: &str) -> Option<(String, u16)> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_string();
    let port = parsed.port_or_known_default()?;
    Some((host, port))
}

impl HostState {
    /// Resolve the egress disposition for `url`, eliciting runtime operator
    /// consent on an airlock rejection for an IP-literal local endpoint.
    ///
    /// Wraps [`egress_decision`]:
    /// - `Ok(Some(host))` / `Ok(None)` pass through unchanged (the endpoint is
    ///   operator pre-blessed, or not local at all).
    /// - `Err(AirlockRejected)` — a local IP-literal that is NOT pre-blessed —
    ///   is where runtime consent runs. [`consent_local_egress`](Self::consent_local_egress)
    ///   gates on transport origin (`LocalSocket` only) and prompts the
    ///   operator. On grant, the endpoint is treated as **exempt** — the exact
    ///   same `Ok(Some(host))` an operator pre-bless produces — so the resolver
    ///   keeps its private address AND the redirect policy refuses to follow any
    ///   hop, identical to a pre-blessed endpoint. On refusal/timeout/non-local
    ///   origin the rejection stands.
    ///
    /// V1 covers only the IP-literal airlock-rejected arm: a hostname endpoint
    /// (`localhost:1234`) returns `Ok(None)` from `egress_decision` and is left
    /// to the resolver airlock — it is NOT consent-granted here and still
    /// requires a pre-bless.
    pub(super) fn egress_decision_with_consent(
        &mut self,
        url: &str,
    ) -> Result<Option<Arc<str>>, ErrorCode> {
        match egress_decision(&self.local_egress, url) {
            Err(ErrorCode::AirlockRejected) => {
                let Some((host, port)) = url_host_port(url) else {
                    return Err(ErrorCode::AirlockRejected);
                };
                if self.consent_local_egress(&host, port) {
                    // Consent granted: re-enter the EXEMPT path. The host is
                    // propagated to `SafeDnsResolver.exempt_host` and
                    // `build_redirect_policy(exempt = true)`, so a
                    // consent-granted endpoint behaves identically to a
                    // pre-blessed one (keeps its private literal, refuses
                    // redirects).
                    Ok(Some(Arc::from(host.as_str())))
                } else {
                    Err(ErrorCode::AirlockRejected)
                }
            },
            other => other,
        }
    }
}

/// What to do with a redirect hop.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum RedirectAction {
    /// IP-literal target failed the airlock — refuse to follow.
    Block,
    /// Hop limit reached — stop following, return the last response.
    Stop,
    /// Safe to follow (hostname targets are airlocked at resolution).
    Follow,
}

/// Decide a redirect hop's fate. An IP-literal `Location` never reaches
/// the DNS resolver, so a public, allow-listed host could otherwise
/// bounce a capsule onto a loopback/internal service — re-apply the
/// airlock here. Hostname targets are left to [`SafeDnsResolver`].
pub(super) fn classify_redirect(host: Option<&str>, prior_hops: usize) -> RedirectAction {
    if let Some(ip) = host.and_then(literal_ip)
        && !is_safe_ip(ip)
    {
        return RedirectAction::Block;
    }
    if prior_hops >= MAX_HTTP_REDIRECTS {
        RedirectAction::Stop
    } else {
        RedirectAction::Follow
    }
}

/// Choose the typed error for a failed request. An airlock rejection
/// (resolver or redirect policy tripped) takes precedence over the
/// generic reqwest classification, so a blocked local/private endpoint
/// surfaces as `airlock-rejected` rather than a vague `connection-error`.
pub(super) fn airlock_or(tripped: &AtomicBool, e: &reqwest::Error) -> ErrorCode {
    if tripped.load(Ordering::Relaxed) {
        ErrorCode::AirlockRejected
    } else {
        super::backend::map_reqwest_err(e)
    }
}
