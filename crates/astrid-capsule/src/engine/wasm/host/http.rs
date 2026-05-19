use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::sync::Arc;
use std::time::Duration;

use crate::engine::wasm::bindings::astrid::capsule::http;
use crate::engine::wasm::bindings::astrid::capsule::types::{
    HttpRequestData, HttpResponseData, HttpStreamStartResponse, KeyValuePair,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;

// ── SSRF prevention ──────────────────────────────────────────────────

/// A DNS resolver that prevents SSRF by blocking resolution to local,
/// private, or multicast IP addresses.
#[derive(Clone)]
struct SafeDnsResolver;

impl reqwest::dns::Resolve for SafeDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let name_str = name.as_str().to_string();
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((name_str.as_str(), 0))
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

            let mut safe_addrs = Vec::new();
            for addr in addrs {
                if is_safe_ip(addr.ip()) {
                    safe_addrs.push(addr);
                }
            }

            if safe_addrs.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "DNS resolved to an unauthorized private or local IP address",
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            let iter: reqwest::dns::Addrs = Box::new(safe_addrs.into_iter());
            Ok(iter)
        })
    }
}

/// Checks if an IP address is safe to connect to (not local, private, or multicast).
/// Cached SSRF escape-hatch check. Evaluated once per process; logs a
/// warning on first access if either env var is set.
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

pub(super) fn is_safe_ip(mut ip: std::net::IpAddr) -> bool {
    if *SSRF_BYPASS {
        return true;
    }

    if let std::net::IpAddr::V6(ipv6) = ip {
        if let Some(ipv4) = ipv6.to_ipv4_mapped() {
            ip = std::net::IpAddr::V4(ipv4);
        } else if ipv6.segments()[..6].iter().all(|&s| s == 0) {
            // IPv4-compatible addresses (::x.x.x.x) are deprecated by RFC 4291
            // but must still be blocked (e.g. ::127.0.0.1 is loopback).
            let [.., hi, lo] = ipv6.segments();
            let [a, b] = hi.to_be_bytes();
            let [c, d] = lo.to_be_bytes();
            ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d));
        }
    }

    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }

    match ip {
        std::net::IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            let is_private = octets[0] == 10
                || octets[0] == 0       // 0.0.0.0/8
                || octets[0] == 255     // Broadcast
                || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 169 && octets[1] == 254)
                || (octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127)
                || octets[0] == 127;
            !is_private
        },
        std::net::IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            let is_private = (segments[0] & 0xfe00) == 0xfc00 || (segments[0] & 0xffc0) == 0xfe80;
            !is_private
        },
    }
}

// ── Shared helpers ───────────────────────────────────────────────────

/// Parse and validate an HTTP method string.
fn parse_method(method: &str) -> Result<reqwest::Method, String> {
    match method.to_uppercase().as_str() {
        "GET" => Ok(reqwest::Method::GET),
        "POST" => Ok(reqwest::Method::POST),
        "PUT" => Ok(reqwest::Method::PUT),
        "DELETE" => Ok(reqwest::Method::DELETE),
        "PATCH" => Ok(reqwest::Method::PATCH),
        "HEAD" => Ok(reqwest::Method::HEAD),
        "OPTIONS" => Ok(reqwest::Method::OPTIONS),
        other => Err(format!("unsupported http method: {other}")),
    }
}

/// Build a `HeaderMap` from a list of key-value pairs.
fn build_headers(raw: &[KeyValuePair]) -> Result<HeaderMap, String> {
    let mut headers = HeaderMap::new();
    for kv in raw {
        let h_name = HeaderName::from_bytes(kv.key.as_bytes())
            .map_err(|e| format!("invalid header name {}: {e}", kv.key))?;
        let h_value = HeaderValue::from_str(&kv.value)
            .map_err(|e| format!("invalid header value {}: {e}", kv.value))?;
        headers.insert(h_name, h_value);
    }
    Ok(headers)
}

/// Run the security gate check for an HTTP request.
fn check_http_security(
    security: &Option<Arc<dyn crate::security::CapsuleSecurityGate>>,
    capsule_id: String,
    url: &str,
    method: &str,
    runtime_handle: &tokio::runtime::Handle,
    host_semaphore: &Arc<tokio::sync::Semaphore>,
) -> Result<(), String> {
    if let Some(gate) = security {
        let url_obj = reqwest::Url::parse(url).map_err(|e| format!("invalid url {url}: {e}"))?;
        let _ = url_obj
            .host_str()
            .ok_or_else(|| "URL missing host".to_string())?;

        let full_url = url.to_string();
        let m = method.to_string();
        let gate = gate.clone();
        let check = util::bounded_block_on(runtime_handle, host_semaphore, async move {
            gate.check_http_request(&capsule_id, &m, &full_url).await
        });
        if let Err(reason) = check {
            return Err(format!("security denied network access: {reason}"));
        }
    }
    Ok(())
}

/// Per-capsule hard ceiling on concurrent HTTP streaming responses.
///
/// Defense-in-depth cap applied on top of the per-principal profile value:
/// the effective per-principal cap is `min(profile, MAX_ACTIVE_HTTP_STREAMS)`.
pub(crate) const MAX_ACTIVE_HTTP_STREAMS: usize = 4;

/// A live HTTP streaming response pinned to the principal that opened it.
///
/// The principal is recorded so `http_stream_start` can charge its
/// per-principal sub-budget — a principal holding its cap must not block
/// another principal on the same capsule from opening new streams.
#[derive(Debug, Clone)]
pub struct ActiveHttpStream {
    /// Shared handle on the streaming body. `Arc<Mutex<>>` because readers
    /// may be interleaved across host-fn calls and must serialize.
    pub response: Arc<tokio::sync::Mutex<reqwest::Response>>,
    /// Principal that started this stream.
    pub creator: astrid_core::principal::PrincipalId,
}
/// Connect timeout for streaming HTTP requests (time to first byte).
const HTTP_STREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Per-chunk read timeout for streaming HTTP responses.
const HTTP_STREAM_READ_TIMEOUT: Duration = Duration::from_secs(120);

impl http::Host for HostState {
    fn http_request(&mut self, request: HttpRequestData) -> Result<HttpResponseData, String> {
        let capsule_id = self.capsule_id.as_str().to_owned();
        let security = self.security.clone();
        let runtime_handle = self.runtime_handle.clone();
        let host_semaphore = self.host_semaphore.clone();

        check_http_security(
            &security,
            capsule_id,
            &request.url,
            &request.method,
            &runtime_handle,
            &host_semaphore,
        )?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .dns_resolver(Arc::new(SafeDnsResolver))
            .build()
            .map_err(|e| format!("failed to build http client: {e}"))?;

        let method = parse_method(&request.method)?;
        let headers = build_headers(&request.headers)?;

        let mut request_builder = client.request(method, &request.url).headers(headers);

        if let Some(body) = request.body {
            request_builder = request_builder.body(body);
        }

        let response = util::bounded_block_on(&runtime_handle, &host_semaphore, async move {
            request_builder.send().await
        })
        .map_err(|e| format!("http request failed: {e}"))?;

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

        let body_result = util::bounded_block_on(&runtime_handle, &host_semaphore, async move {
            let mut response = response;
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
                if bytes.len() + chunk.len() > util::MAX_GUEST_PAYLOAD_LEN as usize {
                    return Err(format!(
                        "HTTP response exceeded maximum payload limit ({} bytes)",
                        util::MAX_GUEST_PAYLOAD_LEN
                    ));
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(bytes)
        });

        let body = body_result.map_err(|e| format!("failed to read http response body: {e}"))?;

        Ok(HttpResponseData {
            status,
            headers: resp_headers,
            body,
        })
    }

    fn http_stream_start(
        &mut self,
        request: HttpRequestData,
    ) -> Result<HttpStreamStartResponse, String> {
        // Per-principal sub-budget against the per-capsule hard ceiling.
        // Layer 2's `Quotas` has no dedicated `max_http_streams` dial, so
        // each principal gets up to `MAX_ACTIVE_HTTP_STREAMS` streams — the
        // per-capsule hard ceiling still fires first if total load across
        // principals saturates it, but principal-keyed counting means a
        // future Layer-2 `max_http_streams` field drops in as a
        // single-expression change here.
        let principal = self.effective_principal();
        let per_principal_count = self
            .active_http_streams
            .values()
            .filter(|s| s.creator == principal)
            .count();
        if per_principal_count >= MAX_ACTIVE_HTTP_STREAMS
            || self.active_http_streams.len() >= MAX_ACTIVE_HTTP_STREAMS
        {
            return Err(format!(
                "HTTP stream cap reached for principal '{principal}' \
                 ({per_principal_count}/{MAX_ACTIVE_HTTP_STREAMS}, \
                 per-capsule total {}/{MAX_ACTIVE_HTTP_STREAMS})",
                self.active_http_streams.len()
            ));
        }

        let capsule_id = self.capsule_id.as_str().to_owned();
        let security = self.security.clone();
        let runtime_handle = self.runtime_handle.clone();
        let host_semaphore = self.host_semaphore.clone();

        check_http_security(
            &security,
            capsule_id,
            &request.url,
            &request.method,
            &runtime_handle,
            &host_semaphore,
        )?;

        let client = reqwest::Client::builder()
            .connect_timeout(HTTP_STREAM_CONNECT_TIMEOUT)
            .dns_resolver(Arc::new(SafeDnsResolver))
            .build()
            .map_err(|e| format!("failed to build http client: {e}"))?;

        let method = parse_method(&request.method)?;
        let headers = build_headers(&request.headers)?;

        let mut request_builder = client.request(method, &request.url).headers(headers);
        if let Some(body) = request.body {
            request_builder = request_builder.body(body);
        }

        // Send request and wait for headers (not body).
        let response = util::bounded_block_on(&runtime_handle, &host_semaphore, async move {
            request_builder.send().await
        })
        .map_err(|e| format!("http stream request failed: {e}"))?;

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

        // Store the response body stream and allocate a handle.
        let handle_id = self.next_http_stream_id;
        self.next_http_stream_id = self
            .next_http_stream_id
            .checked_add(1)
            .ok_or_else(|| "HTTP stream handle ID space exhausted".to_string())?;

        debug_assert!(
            !self.active_http_streams.contains_key(&handle_id),
            "HTTP stream handle ID collision"
        );
        self.active_http_streams.insert(
            handle_id,
            ActiveHttpStream {
                response: Arc::new(tokio::sync::Mutex::new(response)),
                creator: principal,
            },
        );

        Ok(HttpStreamStartResponse {
            handle: handle_id,
            status,
            headers: resp_headers,
        })
    }

    fn http_stream_read(&mut self, stream_handle: u64) -> Result<Vec<u8>, String> {
        let response_arc = self
            .active_http_streams
            .get(&stream_handle)
            .ok_or_else(|| "HTTP stream handle not found".to_string())?
            .response
            .clone();

        let rt_handle = self.runtime_handle.clone();
        let cancel_token = self.cancel_token.clone();
        let host_semaphore = self.host_semaphore.clone();

        let result =
            util::bounded_block_on_cancellable(&rt_handle, &host_semaphore, &cancel_token, async {
                let mut resp = response_arc.lock().await;
                tokio::time::timeout(HTTP_STREAM_READ_TIMEOUT, resp.chunk()).await
            });

        let chunk_data = match result {
            // Cancelled (capsule unloading).
            None => Vec::new(),
            // Timeout waiting for next chunk.
            Some(Err(_elapsed)) => {
                return Err(format!(
                    "HTTP stream read timed out after {}s",
                    HTTP_STREAM_READ_TIMEOUT.as_secs()
                ));
            },
            // Network/body error.
            Some(Ok(Err(e))) => {
                return Err(format!("HTTP stream read error: {e}"));
            },
            // Got a chunk.
            Some(Ok(Ok(Some(bytes)))) => bytes.to_vec(),
            // EOF — stream exhausted.
            Some(Ok(Ok(None))) => Vec::new(),
        };

        Ok(chunk_data)
    }

    fn http_stream_close(&mut self, stream_handle: u64) -> Result<(), String> {
        // Idempotent: silently ignore if the handle was already removed.
        let _ = self.active_http_streams.remove(&stream_handle);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn safe_public_ips() {
        assert!(is_safe_ip(IpAddr::from_str("8.8.8.8").unwrap()));
        assert!(is_safe_ip(IpAddr::from_str("1.1.1.1").unwrap()));
        assert!(is_safe_ip(IpAddr::from_str("198.51.100.1").unwrap()));
        assert!(is_safe_ip(
            IpAddr::from_str("2001:4860:4860::8888").unwrap()
        ));
    }

    #[test]
    fn blocks_loopback_and_unspecified() {
        assert!(!is_safe_ip(IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("::1").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("0.0.0.0").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("::").unwrap()));
    }

    #[test]
    fn blocks_zero_block() {
        assert!(!is_safe_ip(IpAddr::from_str("0.0.0.1").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("0.255.255.255").unwrap()));
    }

    #[test]
    fn blocks_rfc1918_private() {
        assert!(!is_safe_ip(IpAddr::from_str("10.0.0.1").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("10.255.255.255").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("172.16.0.1").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("172.31.255.255").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("192.168.0.1").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("192.168.255.255").unwrap()));
    }

    #[test]
    fn blocks_link_local_and_cgnat() {
        assert!(!is_safe_ip(IpAddr::from_str("169.254.169.254").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("100.64.0.1").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("100.127.255.255").unwrap()));
    }

    #[test]
    fn blocks_private_ipv6() {
        assert!(!is_safe_ip(IpAddr::from_str("fc00::1").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("fd00::1").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("fe80::1").unwrap()));
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_bypass() {
        assert!(!is_safe_ip(IpAddr::from_str("::ffff:127.0.0.1").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("::ffff:10.0.0.1").unwrap()));
        assert!(!is_safe_ip(
            IpAddr::from_str("::ffff:169.254.169.254").unwrap()
        ));
    }

    #[test]
    fn blocks_ipv4_compatible_ipv6_bypass() {
        // IPv4-compatible (deprecated RFC 4291, no ::ffff prefix).
        // These exercise the explicit segment extraction that replaced
        // the deprecated Ipv6Addr::to_ipv4().
        assert!(!is_safe_ip(IpAddr::from_str("::127.0.0.1").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("::10.0.0.1").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("::169.254.169.254").unwrap()));
        // ::1 is IPv6 loopback; after compatible-branch extraction it
        // becomes 0.0.0.1, blocked by the 0.0.0.0/8 check (not loopback).
        assert!(!is_safe_ip(IpAddr::from_str("::0.0.0.1").unwrap()));
    }
}
