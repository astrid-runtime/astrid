//! `astrid:http@1.0.0` host implementation.
//!
//! HTTP client with SSRF protection. Buffered `http_request` is fully
//! implemented; the `http_stream` resource is scaffolded but its
//! per-method bodies are stubbed pending the resource-table integration.

use std::sync::Arc;
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
use wasmtime_wasi::p2::DynPollable;

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

pub(super) fn is_safe_ip(mut ip: std::net::IpAddr) -> bool {
    if *SSRF_BYPASS {
        return true;
    }

    if let std::net::IpAddr::V6(ipv6) = ip {
        if let Some(ipv4) = ipv6.to_ipv4_mapped() {
            ip = std::net::IpAddr::V4(ipv4);
        } else if ipv6.segments()[..6].iter().all(|&s| s == 0) {
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
                || octets[0] == 0
                || octets[0] == 255
                || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 169 && octets[1] == 254)
                || (octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127)
                || octets[0] == 127;
            !is_private
        },
        std::net::IpAddr::V6(ipv6) => {
            let segs = ipv6.segments();
            let is_private = (segs[0] & 0xfe00) == 0xfc00 || (segs[0] & 0xffc0) == 0xfe80;
            !is_private
        },
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
    host_semaphore: &Arc<tokio::sync::Semaphore>,
) -> Result<(), ErrorCode> {
    if let Some(gate) = security {
        let url_obj = reqwest::Url::parse(url).map_err(|_| ErrorCode::InvalidRequest)?;
        let _ = url_obj.host_str().ok_or(ErrorCode::InvalidRequest)?;

        let full_url = url.to_string();
        let m = method.to_string();
        let gate = gate.clone();
        let check = util::bounded_await(host_semaphore, async move {
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
        let host_semaphore = self.host_semaphore.clone();

        check_http_security(
            &security,
            capsule_id,
            &request.url,
            method_name(&request.method),
            &host_semaphore,
        )
        .await?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .dns_resolver(Arc::new(SafeDnsResolver))
            .build()
            .map_err(|e| ErrorCode::Unknown(format!("client: {e}")))?;

        let method = map_method(&request.method)?;
        let headers = build_headers(&request.headers)?;

        let mut request_builder = client.request(method, &request.url).headers(headers);

        if let Some(body) = request.body {
            request_builder = request_builder.body(body);
        }

        let response =
            util::bounded_await(&host_semaphore, async move { request_builder.send().await })
                .await
                .map_err(|e| map_reqwest_err(&e))?;

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

        let body = util::bounded_await(&host_semaphore, async move {
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
        let host_semaphore = self.host_semaphore.clone();

        check_http_security(
            &security,
            capsule_id,
            &request.url,
            method_name(&request.method),
            &host_semaphore,
        )
        .await?;

        let client = reqwest::Client::builder()
            .connect_timeout(HTTP_STREAM_CONNECT_TIMEOUT)
            .dns_resolver(Arc::new(SafeDnsResolver))
            .build()
            .map_err(|e| ErrorCode::Unknown(format!("client: {e}")))?;

        let method = map_method(&request.method)?;
        let headers = build_headers(&request.headers)?;

        let mut request_builder = client.request(method, &request.url).headers(headers);
        if let Some(body) = request.body {
            request_builder = request_builder.body(body);
        }

        let response =
            util::bounded_await(&host_semaphore, async move { request_builder.send().await })
                .await
                .map_err(|e| map_reqwest_err(&e))?;

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
        let sem = self.host_semaphore.clone();
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
        assert!(!is_safe_ip(IpAddr::from_str("::127.0.0.1").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("::10.0.0.1").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("::169.254.169.254").unwrap()));
        assert!(!is_safe_ip(IpAddr::from_str("::0.0.0.1").unwrap()));
    }
}
