//! `astrid:http@1.0.0` host implementation.
//!
//! HTTP client with SSRF protection. Buffered `http_request` is fully
//! implemented; the `http_stream` resource is scaffolded but its
//! per-method bodies are stubbed pending the resource-table integration.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use wasmtime::component::Resource;

use crate::engine::wasm::bindings::astrid::http::host::{
    self as http, ErrorCode, HostHttpStream, HttpMethod, HttpRequestData, HttpResponseData,
    HttpStream, KeyValuePair,
};
use crate::engine::wasm::bindings::astrid::io::streams::InputStream;
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;
use crate::security::net_connect_pattern_matches;
use wasmtime_wasi::p2::DynPollable;

// ── SSRF prevention ──────────────────────────────────────────────────

/// Maximum redirect hops followed before the request is stopped. Matches
/// reqwest's historical default; redirect targets are airlocked per hop
/// (see [`classify_redirect`]).
const MAX_HTTP_REDIRECTS: usize = 10;

/// A DNS resolver that prevents SSRF by blocking resolution to local,
/// private, or multicast IP addresses.
///
/// `tripped` is set when resolution is blocked *because* every resolved
/// address failed the airlock (as opposed to an ordinary resolution
/// failure), so the caller can surface the typed `airlock-rejected` error
/// instead of a generic connection error.
#[derive(Clone)]
struct SafeDnsResolver {
    tripped: Arc<AtomicBool>,
    /// The exact request hostname that the operator allowlist exempts from
    /// the airlock (decided at pre-flight, where the port is known). When the
    /// name being resolved equals this, private/loopback addresses are kept.
    /// `None` = no exemption. Scoped to the one allow-listed host so redirect
    /// hops to other hostnames are still airlocked.
    exempt_host: Option<Arc<str>>,
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
fn filter_safe_addrs(
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

/// Cached SSRF escape-hatch check. Evaluated once per process.
static SSRF_BYPASS: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
    if std::env::var("ASTRID_TEST_ALLOW_LOCAL_IP").is_ok() {
        tracing::warn!(
            "ASTRID_TEST_ALLOW_LOCAL_IP is set - SSRF protection disabled for ALL capsules"
        );
        return true;
    }
    if std::env::var("ASTRID_ALLOW_LOCAL_IPS").is_ok() {
        tracing::warn!(
            "ASTRID_ALLOW_LOCAL_IPS is set - SSRF protection disabled for ALL capsules. \
             Private/loopback IP ranges are reachable by every loaded capsule."
        );
        return true;
    }
    false
});

/// Build an [`Ipv4Addr`] from two big-endian IPv6 segments (the low 32
/// bits of an address).
fn v4_from_segments(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo))
}

/// True if an IPv4 address must never be reached by a capsule: loopback,
/// unspecified, multicast/broadcast, RFC 1918 private, link-local
/// (169.254/16), CGNAT (100.64/10), or the `0.0.0.0/8` / `127.0.0.0/8`
/// blocks.
fn ipv4_blocked(ip: Ipv4Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    let o = ip.octets();
    o[0] == 10
        || o[0] == 0
        || o[0] == 255
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || o[0] == 127
}

/// True if an IPv6 address is loopback, unspecified, multicast, ULA
/// (`fc00::/7`), link-local (`fe80::/10`), or deprecated site-local
/// (`fec0::/10`).
fn ipv6_blocked(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    let s = ip.segments();
    (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xffc0) == 0xfec0
}

/// Extract every IPv4 address embedded in an IPv6 transition/translation
/// address. A NAT64, 6to4, or Teredo gateway would translate these
/// straight to the embedded IPv4, so an embedded private/loopback address
/// is as dangerous as a bare one and must be airlocked. Covers the NAT64
/// well-known prefix (`64:ff9b::/96`, RFC 6052), 6to4 (`2002::/16`, RFC
/// 3056), and Teredo (`2001:0::/32`, RFC 4380 — server plus the
/// bitwise-NOT-obfuscated client).
fn embedded_ipv4s(segs: [u16; 8]) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    if segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2..6].iter().all(|&s| s == 0) {
        out.push(v4_from_segments(segs[6], segs[7]));
    }
    if segs[0] == 0x2002 {
        out.push(v4_from_segments(segs[1], segs[2]));
    }
    if segs[0] == 0x2001 && segs[1] == 0x0000 {
        out.push(v4_from_segments(segs[2], segs[3]));
        out.push(v4_from_segments(!segs[6], !segs[7]));
    }
    out
}

pub(super) fn is_safe_ip(mut ip: IpAddr) -> bool {
    if *SSRF_BYPASS {
        return true;
    }

    // Normalize IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible
    // (`::a.b.c.d`) IPv6 forms to their IPv4 address so the encoding can't
    // slip a private address past the IPv4 checks.
    if let IpAddr::V6(ipv6) = ip {
        if let Some(ipv4) = ipv6.to_ipv4_mapped() {
            ip = IpAddr::V4(ipv4);
        } else {
            let segs = ipv6.segments();
            if segs[..6].iter().all(|&s| s == 0) {
                ip = IpAddr::V4(v4_from_segments(segs[6], segs[7]));
            }
        }
    }

    match ip {
        IpAddr::V4(ipv4) => !ipv4_blocked(ipv4),
        IpAddr::V6(ipv6) => {
            // A transition address embedding a private/loopback IPv4 is
            // reachable via a NAT64/6to4/Teredo gateway — reject it.
            if embedded_ipv4s(ipv6.segments())
                .into_iter()
                .any(ipv4_blocked)
            {
                return false;
            }
            !ipv6_blocked(ipv6)
        },
    }
}

/// Parse a URL host string into an IP literal, if it is one.
///
/// [`reqwest::Url::host_str`] returns IPv6 literals bracketed (`[::1]`);
/// the brackets are stripped before parsing. A domain name returns `None`
/// — it will be resolved (and airlocked) by [`SafeDnsResolver`].
fn literal_ip(host: &str) -> Option<IpAddr> {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    IpAddr::from_str(bare).ok()
}

/// True if `host:port` matches any pattern in this capsule's operator
/// local-egress allowlist. Entries use the same `host:port` / `host:*`
/// semantics as a manifest `net_connect` entry.
fn egress_allowed(allowlist: &[String], host: &str, port: u16) -> bool {
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
fn egress_decision(allowlist: &[String], url: &str) -> Result<Option<Arc<str>>, ErrorCode> {
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
    ///   hop ([`build_redirect_policy`] `exempt = true`), identical to a
    ///   pre-blessed endpoint. On refusal/timeout/non-local origin the rejection
    ///   stands.
    ///
    /// V1 covers only the IP-literal airlock-rejected arm: a hostname endpoint
    /// (`localhost:1234`) returns `Ok(None)` from `egress_decision` and is left
    /// to the resolver airlock — it is NOT consent-granted here and still
    /// requires a pre-bless.
    fn egress_decision_with_consent(&mut self, url: &str) -> Result<Option<Arc<str>>, ErrorCode> {
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
enum RedirectAction {
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
fn classify_redirect(host: Option<&str>, prior_hops: usize) -> RedirectAction {
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

/// Marker error returned by the redirect policy when a hop is airlocked.
#[derive(Debug)]
struct RedirectAirlock;

impl std::fmt::Display for RedirectAirlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("redirect target blocked by SSRF airlock")
    }
}

impl std::error::Error for RedirectAirlock {}

/// Redirect policy that re-applies the airlock to every hop and records a
/// rejection in `tripped` so the caller can surface `airlock-rejected`.
fn airlock_redirect_policy(tripped: Arc<AtomicBool>) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        match classify_redirect(attempt.url().host_str(), attempt.previous().len()) {
            RedirectAction::Block => {
                tripped.store(true, Ordering::Relaxed);
                attempt.error(RedirectAirlock)
            },
            RedirectAction::Stop => attempt.stop(),
            RedirectAction::Follow => attempt.follow(),
        }
    })
}

/// Build the redirect policy for a request.
///
/// An operator-allowlisted (`exempt`) request must **not** follow redirects:
/// the resolver exemption is host-only, so a `30x` to a *different port* on
/// the same host (or to another allow-listed host) would escape the
/// port-scoped allowlist. A sanctioned local LLM endpoint has no reason to
/// redirect, so exempt requests refuse to follow any. Non-exempt requests
/// use the per-hop [`airlock_redirect_policy`].
fn build_redirect_policy(exempt: bool, tripped: Arc<AtomicBool>) -> reqwest::redirect::Policy {
    if exempt {
        reqwest::redirect::Policy::none()
    } else {
        airlock_redirect_policy(tripped)
    }
}

/// Choose the typed error for a failed request. An airlock rejection
/// (resolver or redirect policy tripped) takes precedence over the
/// generic reqwest classification, so a blocked local/private endpoint
/// surfaces as `airlock-rejected` rather than a vague `connection-error`.
fn airlock_or(tripped: &AtomicBool, e: &reqwest::Error) -> ErrorCode {
    if tripped.load(Ordering::Relaxed) {
        ErrorCode::AirlockRejected
    } else {
        map_reqwest_err(e)
    }
}

// ── Shared helpers ───────────────────────────────────────────────────

/// Map an [`HttpMethod`] WIT variant to a `reqwest::Method`.
fn map_method(m: &HttpMethod) -> Result<reqwest::Method, ErrorCode> {
    Ok(match m {
        HttpMethod::Get => reqwest::Method::GET,
        HttpMethod::Head => reqwest::Method::HEAD,
        HttpMethod::Post => reqwest::Method::POST,
        HttpMethod::Put => reqwest::Method::PUT,
        HttpMethod::Delete => reqwest::Method::DELETE,
        HttpMethod::Connect => reqwest::Method::CONNECT,
        HttpMethod::Options => reqwest::Method::OPTIONS,
        HttpMethod::Trace => reqwest::Method::TRACE,
        HttpMethod::Patch => reqwest::Method::PATCH,
        HttpMethod::Other(s) => {
            reqwest::Method::from_bytes(s.as_bytes()).map_err(|_| ErrorCode::InvalidRequest)?
        },
    })
}

/// Method name as a header-safe string for security-gate checks.
fn method_name(m: &HttpMethod) -> &str {
    match m {
        HttpMethod::Get => "GET",
        HttpMethod::Head => "HEAD",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Connect => "CONNECT",
        HttpMethod::Options => "OPTIONS",
        HttpMethod::Trace => "TRACE",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Other(s) => s.as_str(),
    }
}

fn build_headers(raw: &[KeyValuePair]) -> Result<HeaderMap, ErrorCode> {
    let mut headers = HeaderMap::new();
    for kv in raw {
        let h_name =
            HeaderName::from_bytes(kv.key.as_bytes()).map_err(|_| ErrorCode::InvalidRequest)?;
        let h_value = HeaderValue::from_str(&kv.value).map_err(|_| ErrorCode::InvalidRequest)?;
        headers.insert(h_name, h_value);
    }
    Ok(headers)
}

async fn check_http_security(
    security: &Option<Arc<dyn crate::security::CapsuleSecurityGate>>,
    capsule_id: String,
    url: &str,
    method: &str,
    io_semaphore: &Arc<tokio::sync::Semaphore>,
) -> Result<(), ErrorCode> {
    if let Some(gate) = security {
        let url_obj = reqwest::Url::parse(url).map_err(|_| ErrorCode::InvalidRequest)?;
        let _ = url_obj.host_str().ok_or(ErrorCode::InvalidRequest)?;

        let full_url = url.to_string();
        let m = method.to_string();
        let gate = gate.clone();
        let check = util::bounded_await(io_semaphore, async move {
            gate.check_http_request(&capsule_id, &m, &full_url).await
        })
        .await;
        if check.is_err() {
            return Err(ErrorCode::CapabilityDenied);
        }
    }
    Ok(())
}

/// Per-capsule hard ceiling on concurrent HTTP streaming responses.
pub(crate) const MAX_ACTIVE_HTTP_STREAMS: usize = 4;

/// A live HTTP streaming response pinned to the principal that opened it.
#[derive(Debug, Clone)]
pub struct ActiveHttpStream {
    pub response: Arc<tokio::sync::Mutex<reqwest::Response>>,
    pub creator: astrid_core::principal::PrincipalId,
    pub status: u16,
    pub headers: Vec<KeyValuePair>,
}

const HTTP_STREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-chunk read timeout for streaming HTTP responses. Kept as a
/// named constant so per-principal timeout tuning has a single edit
/// point.
const HTTP_STREAM_READ_TIMEOUT: Duration = Duration::from_secs(120);

impl http::Host for HostState {
    async fn http_request(
        &mut self,
        request: HttpRequestData,
    ) -> Result<HttpResponseData, ErrorCode> {
        let capsule_id = self.capsule_id.as_str().to_owned();
        let security = self.security.clone();
        let io_semaphore = self.io_semaphore.clone();

        check_http_security(
            &security,
            capsule_id,
            &request.url,
            method_name(&request.method),
            &io_semaphore,
        )
        .await?;

        let exempt_host = self.egress_decision_with_consent(&request.url)?;

        let tripped = Arc::new(AtomicBool::new(false));
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(build_redirect_policy(
                exempt_host.is_some(),
                tripped.clone(),
            ))
            .dns_resolver(Arc::new(SafeDnsResolver {
                tripped: tripped.clone(),
                exempt_host,
            }))
            .build()
            .map_err(|e| ErrorCode::Unknown(format!("client: {e}")))?;

        let method = map_method(&request.method)?;
        let headers = build_headers(&request.headers)?;

        let mut request_builder = client.request(method, &request.url).headers(headers);

        if let Some(body) = request.body {
            request_builder = request_builder.body(body);
        }

        let response =
            util::bounded_await(&io_semaphore, async move { request_builder.send().await })
                .await
                .map_err(|e| airlock_or(&tripped, &e))?;

        let status = response.status().as_u16();

        let mut resp_headers = Vec::new();
        for (k, v) in response.headers() {
            if let Ok(v_str) = v.to_str() {
                resp_headers.push(KeyValuePair {
                    key: k.as_str().to_string(),
                    value: v_str.to_string(),
                });
            }
        }

        let body = util::bounded_await(&io_semaphore, async move {
            let mut response = response;
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|e| map_reqwest_err(&e))? {
                if bytes.len() + chunk.len() > util::MAX_GUEST_PAYLOAD_LEN as usize {
                    return Err(ErrorCode::BodyTooLarge);
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(bytes)
        })
        .await?;

        Ok(HttpResponseData {
            status,
            headers: resp_headers,
            body,
        })
    }

    async fn http_stream_start(
        &mut self,
        request: HttpRequestData,
    ) -> Result<Resource<HttpStream>, ErrorCode> {
        let principal = self.effective_principal();
        let per_principal_count = self
            .active_http_streams
            .values()
            .filter(|s| s.creator == principal)
            .count();
        if per_principal_count >= MAX_ACTIVE_HTTP_STREAMS
            || self.active_http_streams.len() >= MAX_ACTIVE_HTTP_STREAMS
        {
            return Err(ErrorCode::Quota);
        }

        let capsule_id = self.capsule_id.as_str().to_owned();
        let security = self.security.clone();
        let io_semaphore = self.io_semaphore.clone();

        check_http_security(
            &security,
            capsule_id,
            &request.url,
            method_name(&request.method),
            &io_semaphore,
        )
        .await?;

        let exempt_host = self.egress_decision_with_consent(&request.url)?;

        let tripped = Arc::new(AtomicBool::new(false));
        let client = reqwest::Client::builder()
            .connect_timeout(HTTP_STREAM_CONNECT_TIMEOUT)
            .redirect(build_redirect_policy(
                exempt_host.is_some(),
                tripped.clone(),
            ))
            .dns_resolver(Arc::new(SafeDnsResolver {
                tripped: tripped.clone(),
                exempt_host,
            }))
            .build()
            .map_err(|e| ErrorCode::Unknown(format!("client: {e}")))?;

        let method = map_method(&request.method)?;
        let headers = build_headers(&request.headers)?;

        let mut request_builder = client.request(method, &request.url).headers(headers);
        if let Some(body) = request.body {
            request_builder = request_builder.body(body);
        }

        let response =
            util::bounded_await(&io_semaphore, async move { request_builder.send().await })
                .await
                .map_err(|e| airlock_or(&tripped, &e))?;

        let status = response.status().as_u16();

        let mut resp_headers = Vec::new();
        for (k, v) in response.headers() {
            if let Ok(v_str) = v.to_str() {
                resp_headers.push(KeyValuePair {
                    key: k.as_str().to_string(),
                    value: v_str.to_string(),
                });
            }
        }

        // Allocate a Component Model resource handle in the store's
        // resource table. We track the raw rep in `active_http_streams`
        // keyed by the resource's u32 rep, so the resource methods can
        // look up the underlying `reqwest::Response`.
        let active = ActiveHttpStream {
            response: Arc::new(tokio::sync::Mutex::new(response)),
            creator: principal,
            status,
            headers: resp_headers,
        };
        let resource = self
            .resource_table
            .push(active)
            .map_err(|e| ErrorCode::Unknown(format!("resource table: {e}")))?;

        // wasmtime's bindgen-generated `HttpStream` is a zero-sized marker
        // type — the runtime identifies the resource by its rep, so we
        // re-tag the `Resource<ActiveHttpStream>` returned by the table as
        // a `Resource<HttpStream>` via `rep` round-trip.
        Ok(Resource::new_own(resource.rep()))
    }
}

impl HostHttpStream for HostState {
    fn status(&mut self, self_: Resource<HttpStream>) -> u16 {
        let rep = self_.rep();
        self.resource_table
            .get::<ActiveHttpStream>(&Resource::new_borrow(rep))
            .map(|s| s.status)
            .unwrap_or(0)
    }

    fn headers(&mut self, self_: Resource<HttpStream>) -> Vec<KeyValuePair> {
        let rep = self_.rep();
        self.resource_table
            .get::<ActiveHttpStream>(&Resource::new_borrow(rep))
            .map(|s| s.headers.clone())
            .unwrap_or_default()
    }

    async fn read_chunk(&mut self, self_: Resource<HttpStream>) -> Result<Vec<u8>, ErrorCode> {
        let rep = self_.rep();
        let stream = self
            .resource_table
            .get::<ActiveHttpStream>(&Resource::new_borrow(rep))
            .map_err(|_| ErrorCode::Closed)?;
        let response_arc = stream.response.clone();
        let cancel = self.cancel_token.clone();
        let sem = self.io_semaphore.clone();
        let started = std::time::Instant::now();
        let result = util::bounded_await_cancellable(&sem, &cancel, async {
            let mut resp = response_arc.lock().await;
            tokio::time::timeout(HTTP_STREAM_READ_TIMEOUT, resp.chunk()).await
        })
        .await;
        let bytes_result: Result<Vec<u8>, ErrorCode> = match result {
            None => Ok(Vec::new()), // cancelled
            Some(Err(_)) => Err(ErrorCode::Timeout),
            Some(Ok(Err(e))) => Err(map_reqwest_err(&e)),
            Some(Ok(Ok(Some(bytes)))) => Ok(bytes.to_vec()),
            Some(Ok(Ok(None))) => Ok(Vec::new()), // EOF
        };
        let bytes = bytes_result.as_ref().map(|v| v.len() as u64).unwrap_or(0);
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let capsule_id = self.capsule_id.as_str();
        let principal = self.effective_principal();
        match &bytes_result {
            Ok(_) => tracing::debug!(
                target: "astrid.audit.http",
                %capsule_id,
                %principal,
                fn = "astrid:http/host.http-stream.read-chunk",
                bytes,
                elapsed_ms,
                "audit",
            ),
            Err(e) => tracing::debug!(
                target: "astrid.audit.http",
                %capsule_id,
                %principal,
                fn = "astrid:http/host.http-stream.read-chunk",
                error = ?e,
                elapsed_ms,
                "audit",
            ),
        }
        bytes_result
    }

    fn close(&mut self, self_: Resource<HttpStream>) -> Result<(), ErrorCode> {
        let _ = self
            .resource_table
            .delete::<ActiveHttpStream>(Resource::new_own(self_.rep()));
        Ok(())
    }

    fn subscribe_readable(&mut self, _self_: Resource<HttpStream>) -> Resource<DynPollable> {
        // Real pollable wiring (sourced from the reqwest response's
        // chunk readiness) lands with the dedicated stream-adapter
        // commit. Always-ready sentinel until then; guests poll, then
        // read-chunk returns the next chunk or EOF.
        super::stubs::always_ready_pollable(&mut self.resource_table)
    }

    fn body_stream(&mut self, _self_: Resource<HttpStream>) -> Resource<InputStream> {
        // The real adapter wraps reqwest::Response as a wasmtime-wasi-io
        // InputStream; until that lands, capsules get a closed-on-read
        // sentinel and must use `read-chunk` directly.
        super::stubs::closed_input_stream(&mut self.resource_table)
    }

    fn drop(&mut self, rep: Resource<HttpStream>) -> wasmtime::Result<()> {
        let _ = self
            .resource_table
            .delete::<ActiveHttpStream>(Resource::new_own(rep.rep()));
        Ok(())
    }
}

/// Classify a reqwest error into the typed `http::ErrorCode`.
fn map_reqwest_err(e: &reqwest::Error) -> ErrorCode {
    if e.is_timeout() {
        ErrorCode::Timeout
    } else if e.is_connect() {
        ErrorCode::ConnectionError
    } else if e.is_request() {
        ErrorCode::InvalidRequest
    } else if e.is_body() || e.is_decode() {
        ErrorCode::Protocol(e.to_string())
    } else {
        ErrorCode::Unknown(e.to_string())
    }
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
