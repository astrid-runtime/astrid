//! Shared HTTP backend behind both `astrid:http@1.0.0` and `@1.1.0`. The
//! buffered path follows redirects manually, re-running the async security gate
//! and SSRF airlock on every hop and stripping credentials cross-origin; the
//! streaming path delegates per-hop airlocking to reqwest's redirect policy.
//! Stream-resource method bodies are shared here too, keyed by the resource
//! table `rep` so both versions' marker types index one `ActiveHttpStream`.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use wasmtime::component::Resource;

use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;

use super::options::{
    ResolvedOptions, check_scheme, same_origin, strip_credentials, verify_integrity,
};
use super::ssrf::{
    RedirectAction, SafeDnsResolver, airlock_or, classify_redirect, streaming_redirect_policy,
};
use super::{
    ErrorCode, HttpMethod, HttpRequestData, HttpResponseData, HttpStream, KeyValuePair,
    RedirectPolicy, ResponseMeta,
};

/// Map an [`HttpMethod`] WIT variant to a `reqwest::Method`.
pub(super) fn map_method(m: &HttpMethod) -> Result<reqwest::Method, ErrorCode> {
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
pub(super) fn method_name(m: &HttpMethod) -> &str {
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
    /// Per-chunk read timeout. Caller-overridable via
    /// `timeout-config.between-bytes-ms`; defaults to
    /// [`HTTP_STREAM_READ_TIMEOUT`].
    pub read_timeout: Duration,
}

const HTTP_STREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-chunk read timeout for streaming HTTP responses. Kept as a
/// named constant so per-principal timeout tuning has a single edit
/// point. Overridable per request via `timeout-config.between-bytes-ms`.
const HTTP_STREAM_READ_TIMEOUT: Duration = Duration::from_secs(120);

/// Outcome of one wire request: the response plus the wire-byte count
/// (content-length when present; otherwise filled in after buffering).
struct WireResponse {
    response: reqwest::Response,
    /// Best-effort bytes-on-wire before decompression (content-length header).
    content_length: Option<u64>,
}

impl HostState {
    /// Build a reqwest client for ONE hop. Redirects are always `Policy::none()`
    /// on the buffered path — the host follows manually so every hop re-runs
    /// the async security gate and the airlock. The streaming path passes its
    /// own redirect policy via `redirect_policy`.
    fn build_http_client(
        &self,
        opts: &ResolvedOptions,
        exempt_host: Option<Arc<str>>,
        tripped: Arc<AtomicBool>,
        redirect_policy: reqwest::redirect::Policy,
    ) -> Result<reqwest::Client, ErrorCode> {
        let mut builder = reqwest::Client::builder()
            .redirect(redirect_policy)
            .dns_resolver(Arc::new(SafeDnsResolver {
                tripped,
                exempt_host,
            }));

        if let Some(t) = opts.connect_timeout {
            builder = builder.connect_timeout(t);
        }
        if let Some(t) = opts.total_timeout {
            builder = builder.timeout(t);
        }
        // Best-effort read-timeout: prefer the explicit between-bytes gap; fall
        // back to first-byte. reqwest's `read_timeout` is an idle-gap timeout,
        // the closest single knob for both.
        if let Some(t) = opts.between_bytes_timeout.or(opts.first_byte_timeout) {
            builder = builder.read_timeout(t);
        }

        // reqwest decompression is client-level and only active when the
        // corresponding feature is compiled in. Toggle gzip/brotli/deflate/zstd
        // as a group per `auto-decompress`. When off, the raw wire bytes are
        // delivered (the host does not set Accept-Encoding either, matching the
        // "raw download" contract).
        if opts.auto_decompress {
            builder = builder.gzip(true).brotli(true).deflate(true).zstd(true);
        } else {
            builder = builder.no_gzip().no_brotli().no_deflate().no_zstd();
        }

        builder
            .build()
            .map_err(|e| ErrorCode::Unknown(format!("client: {e}")))
    }

    /// Send ONE request hop: enforce scheme, run the security gate, pre-flight
    /// egress, build a per-hop client, and send (no body read). Shared by the
    /// buffered manual-redirect loop. `exempt_host` is re-evaluated per hop, so
    /// a redirect to a different host re-runs the full airlock.
    async fn send_one_hop(
        &mut self,
        url: &str,
        method: &reqwest::Method,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        opts: &ResolvedOptions,
    ) -> Result<WireResponse, ErrorCode> {
        check_scheme(url, opts.https_only)?;

        let capsule_id = self.capsule_id.as_str().to_owned();
        let security = self.security.clone();
        let io_semaphore = self.io_semaphore.clone();
        check_http_security(&security, capsule_id, url, method.as_str(), &io_semaphore).await?;

        let exempt_host = self.egress_decision_with_consent(url)?;

        let tripped = Arc::new(AtomicBool::new(false));
        // Manual redirect following: reqwest must NOT follow on its own.
        let client = self.build_http_client(
            opts,
            exempt_host,
            tripped.clone(),
            reqwest::redirect::Policy::none(),
        )?;

        let mut request_builder = client.request(method.clone(), url).headers(headers.clone());
        if let Some(b) = body {
            request_builder = request_builder.body(b.to_vec());
        }

        let response =
            util::bounded_await(&io_semaphore, async move { request_builder.send().await })
                .await
                .map_err(|e| airlock_or(&tripped, &e))?;

        let content_length = response.content_length();
        Ok(WireResponse {
            response,
            content_length,
        })
    }

    /// The shared buffered backend behind `@1.0.0 http_request` and
    /// `@1.1.0 http_request_opts`. Follows redirects MANUALLY per `opts`
    /// (re-validating each hop), buffers the body under the response cap,
    /// verifies integrity, and returns the `@1.1.0` response with metadata.
    pub(super) async fn http_request_backend(
        &mut self,
        request: HttpRequestData,
        opts: ResolvedOptions,
    ) -> Result<HttpResponseData, ErrorCode> {
        let started = Instant::now();
        let mut method = map_method(&request.method)?;
        let mut headers = build_headers(&request.headers)?;
        let mut current_url =
            reqwest::Url::parse(&request.url).map_err(|_| ErrorCode::InvalidRequest)?;
        // The body is forwarded across redirect hops that preserve the method
        // (307/308). On 301/302/303 the method is downgraded to GET and the
        // body dropped — the RFC 7231 behaviour reqwest's default policy
        // already implemented, preserved here in the manual loop.
        let mut body = request.body.clone();
        let mut redirect_count: u32 = 0;

        loop {
            let wire = self
                .send_one_hop(
                    current_url.as_str(),
                    &method,
                    &headers,
                    body.as_deref(),
                    &opts,
                )
                .await?;
            let status = wire.response.status();

            // A 3xx WITH a Location is a redirect; anything else (or a 3xx with
            // no Location) is the final response.
            if status.is_redirection()
                && let Some(location) = wire.response.headers().get(reqwest::header::LOCATION)
            {
                match opts.redirect {
                    // Return the 3xx as-is.
                    RedirectPolicy::Manual => {
                        return self
                            .finalize_buffered(wire, &opts, started, &current_url, redirect_count)
                            .await;
                    },
                    RedirectPolicy::Error => return Err(ErrorCode::RedirectBlocked),
                    RedirectPolicy::Follow => {
                        if redirect_count as usize >= opts.max_redirects {
                            return Err(ErrorCode::TooManyRedirects);
                        }
                        let loc_str = location
                            .to_str()
                            .map_err(|_| ErrorCode::Protocol("invalid Location header".into()))?;
                        // Resolve relative → absolute against the current URL.
                        let next_url = current_url
                            .join(loc_str)
                            .map_err(|_| ErrorCode::Protocol("invalid redirect target".into()))?;
                        // Per-hop SSRF re-validation on an IP-literal target
                        // (hostnames are airlocked at resolution by the next
                        // hop's `send_one_hop`).
                        if classify_redirect(next_url.host_str(), redirect_count as usize)
                            == RedirectAction::Block
                        {
                            return Err(ErrorCode::RedirectBlocked);
                        }
                        // Strip credentials on a cross-origin hop.
                        if !same_origin(&current_url, &next_url) {
                            strip_credentials(&mut headers);
                        }
                        // RFC 7231 method downgrade: 303 always → GET; 301/302
                        // → GET except for GET/HEAD (de-facto browser behaviour
                        // reqwest's default policy implements). 307/308 preserve
                        // method + body. On a downgrade, drop the request body
                        // and its content headers.
                        let downgrade = status == reqwest::StatusCode::SEE_OTHER
                            || ((status == reqwest::StatusCode::MOVED_PERMANENTLY
                                || status == reqwest::StatusCode::FOUND)
                                && method != reqwest::Method::GET
                                && method != reqwest::Method::HEAD);
                        if downgrade {
                            method = reqwest::Method::GET;
                            body = None;
                            headers.remove(reqwest::header::CONTENT_TYPE);
                            headers.remove(reqwest::header::CONTENT_LENGTH);
                            headers.remove(reqwest::header::TRANSFER_ENCODING);
                        }
                        current_url = next_url;
                        redirect_count += 1;
                        continue;
                    },
                }
            }

            // Terminal response.
            return self
                .finalize_buffered(wire, &opts, started, &current_url, redirect_count)
                .await;
        }
    }

    /// Buffer the body of a terminal response under the caps, verify integrity,
    /// and assemble the `@1.1.0` `HttpResponseData` (with `meta`).
    async fn finalize_buffered(
        &mut self,
        wire: WireResponse,
        opts: &ResolvedOptions,
        started: Instant,
        final_url: &reqwest::Url,
        redirect_count: u32,
    ) -> Result<HttpResponseData, ErrorCode> {
        let WireResponse {
            response,
            content_length,
        } = wire;
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

        let io_semaphore = self.io_semaphore.clone();
        let max_response = opts.max_response_bytes;
        let max_decompressed = opts.max_decompressed_bytes;
        let body = util::bounded_await(&io_semaphore, async move {
            let mut response = response;
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|e| map_reqwest_err(&e))? {
                // `chunk()` yields decoded bytes when auto-decompress is on.
                // Enforce the decompressed ceiling first (bomb defence), then
                // the response cap. Both are hard limits.
                if let Some(cap) = max_decompressed
                    && bytes.len() as u64 + chunk.len() as u64 > cap
                {
                    return Err(ErrorCode::DecompressionBomb);
                }
                if bytes.len() as u64 + chunk.len() as u64 > max_response {
                    return Err(ErrorCode::BodyTooLarge);
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(bytes)
        })
        .await?;

        if let Some(integrity) = &opts.integrity {
            verify_integrity(integrity, &body)?;
        }

        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        // wire-bytes is best-effort: content-length when the server sent it,
        // else the buffered length (an undercount only when decompression
        // shrank a chunked response — acceptable for a "best-effort" field).
        let wire_bytes = content_length.unwrap_or(body.len() as u64);

        Ok(HttpResponseData {
            status,
            headers: resp_headers,
            body,
            meta: ResponseMeta {
                final_url: final_url.to_string(),
                redirect_count,
                elapsed_ms,
                wire_bytes,
            },
        })
    }

    /// Shared streaming backend behind `@1.0.0 http_stream_start` and
    /// `@1.1.0 http_stream_start_opts`. Redirects on the streaming path are
    /// handled by reqwest's airlock policy (the body cannot be buffered to
    /// re-issue, so the per-hop resolver airlock + literal block is the
    /// enforcement point — same posture as `@1.0.0`).
    pub(super) async fn http_stream_backend(
        &mut self,
        request: HttpRequestData,
        opts: ResolvedOptions,
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

        check_scheme(&request.url, opts.https_only)?;

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
        // Streaming redirect policy: `error`/`manual` refuse to follow (return
        // the first response); `follow` uses the per-hop airlock policy bounded
        // by the caller's max-redirects. An exempt endpoint never follows
        // (port-scoped allowlist must not widen).
        let redirect_policy = match opts.redirect {
            RedirectPolicy::Error | RedirectPolicy::Manual => reqwest::redirect::Policy::none(),
            RedirectPolicy::Follow if exempt_host.is_some() => reqwest::redirect::Policy::none(),
            RedirectPolicy::Follow => {
                streaming_redirect_policy(tripped.clone(), opts.max_redirects)
            },
        };

        // Connect timeout: caller override, else the streaming default.
        let mut stream_opts = opts.clone();
        if stream_opts.connect_timeout.is_none() {
            stream_opts.connect_timeout = Some(HTTP_STREAM_CONNECT_TIMEOUT);
        }
        // The streaming path uses a per-chunk read loop, not a whole-request
        // timeout — clear the DEFAULT total so a long stream isn't cut at 30s.
        // An explicit caller `total-ms` is honoured.
        if opts.total_was_default() {
            stream_opts.total_timeout = None;
        }

        let client =
            self.build_http_client(&stream_opts, exempt_host, tripped.clone(), redirect_policy)?;

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

        // `error` policy: a 3xx that wasn't followed is a blocked redirect.
        if matches!(opts.redirect, RedirectPolicy::Error)
            && response.status().is_redirection()
            && response.headers().contains_key(reqwest::header::LOCATION)
        {
            return Err(ErrorCode::RedirectBlocked);
        }

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

        let read_timeout = opts
            .between_bytes_timeout
            .unwrap_or(HTTP_STREAM_READ_TIMEOUT);

        let active = ActiveHttpStream {
            response: Arc::new(tokio::sync::Mutex::new(response)),
            creator: principal,
            status,
            headers: resp_headers,
            read_timeout,
        };
        let resource = self
            .resource_table
            .push(active)
            .map_err(|e| ErrorCode::Unknown(format!("resource table: {e}")))?;
        Ok(Resource::new_own(resource.rep()))
    }
}

// ── Stream-method bodies (shared by both versions, keyed by resource rep) ──

pub(super) fn stream_status(state: &mut HostState, rep: u32) -> u16 {
    state
        .resource_table
        .get::<ActiveHttpStream>(&Resource::new_borrow(rep))
        .map(|s| s.status)
        .unwrap_or(0)
}

pub(super) fn stream_headers(state: &mut HostState, rep: u32) -> Vec<KeyValuePair> {
    state
        .resource_table
        .get::<ActiveHttpStream>(&Resource::new_borrow(rep))
        .map(|s| s.headers.clone())
        .unwrap_or_default()
}

pub(super) async fn stream_read_chunk(
    state: &mut HostState,
    rep: u32,
) -> Result<Vec<u8>, ErrorCode> {
    let stream = state
        .resource_table
        .get::<ActiveHttpStream>(&Resource::new_borrow(rep))
        .map_err(|_| ErrorCode::Closed)?;
    let response_arc = stream.response.clone();
    let read_timeout = stream.read_timeout;
    let cancel = state.cancel_token.clone();
    let sem = state.io_semaphore.clone();
    let started = Instant::now();
    let result = util::bounded_await_cancellable(&sem, &cancel, async {
        let mut resp = response_arc.lock().await;
        tokio::time::timeout(read_timeout, resp.chunk()).await
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
    let capsule_id = state.capsule_id.as_str();
    let principal = state.effective_principal();
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

pub(super) fn stream_close(state: &mut HostState, rep: u32) -> Result<(), ErrorCode> {
    let _ = state
        .resource_table
        .delete::<ActiveHttpStream>(Resource::new_own(rep));
    Ok(())
}

pub(super) fn stream_drop(state: &mut HostState, rep: u32) {
    let _ = state
        .resource_table
        .delete::<ActiveHttpStream>(Resource::new_own(rep));
}

/// Classify a reqwest error into the typed `http::ErrorCode`.
pub(super) fn map_reqwest_err(e: &reqwest::Error) -> ErrorCode {
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
