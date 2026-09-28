//! Shared HTTP backend behind both `astrid:http@1.0.0` and `@1.1.0`. BOTH the
//! buffered and streaming paths follow redirects manually through one driver
//! (`follow_redirects` over `send_one_hop`), so every hop — initial or redirect
//! target — re-runs the full airlock: scheme check, the async `check_http_request`
//! gate, and the egress airlock, plus cross-origin credential stripping. reqwest
//! never follows redirects on either path. The only divergence is the terminal
//! action: buffer the body (buffered) or hand the unread response to a stream
//! resource (streaming). Stream-resource method bodies are shared here too,
//! keyed by the resource table `rep` so both versions' marker types index one
//! `ActiveHttpStream`.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use wasmtime::component::Resource;

use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;

use super::audit::{HttpExchange, error_text};
use super::credentials::strip_injected;
use super::options::{
    ResolvedOptions, check_scheme, same_origin, strip_credentials, verify_integrity,
};
use super::ssrf::{SafeDnsResolver, airlock_or, redirect_target_blocked};
use super::{
    ErrorCode, HttpMethod, HttpRequestData, HttpResponseData, HttpStream, KeyValuePair,
    RedirectPolicy, ResponseMeta,
};
use crate::audit_sink::HostAuditOutcome;

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

pub(super) fn build_headers(raw: &[KeyValuePair]) -> Result<HeaderMap, ErrorCode> {
    let mut headers = HeaderMap::new();
    for kv in raw {
        let h_name =
            HeaderName::from_bytes(kv.key.as_bytes()).map_err(|_| ErrorCode::InvalidRequest)?;
        // The WIT contract explicitly allows duplicate request headers (e.g.
        // multiple `Cookie` lines), so `append` — not `insert` (last-write-
        // wins) — is required. `from_bytes` (not `from_str`) accepts header
        // values carrying UTF-8 / obs-text while still rejecting control chars.
        let h_value =
            HeaderValue::from_bytes(kv.value.as_bytes()).map_err(|_| ErrorCode::InvalidRequest)?;
        headers.append(h_name, h_value);
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

/// A live HTTP streaming response pinned to the principal that opened it.
#[derive(Debug, Clone)]
pub struct ActiveHttpStream {
    pub response: Arc<tokio::sync::Mutex<reqwest::Response>>,
    pub creator: astrid_core::principal::PrincipalId,
    pub status: u16,
    pub headers: Vec<KeyValuePair>,
    /// Per-chunk read timeout. Caller-overridable via
    /// `timeout-config.between-bytes-ms`; defaults to the host
    /// [`HttpLimits::stream_read_timeout`](crate::engine::wasm::limits::HttpLimits::stream_read_timeout).
    pub read_timeout: Duration,
    /// Audit exchange of the request that opened this stream. The response
    /// hash is extended as chunks are delivered and the completion is
    /// recorded at end of body, on a read error, or when the stream is closed.
    pub(crate) audit: Arc<std::sync::Mutex<HttpExchange>>,
}

impl ActiveHttpStream {
    /// Build a quota-counting placeholder stream WITHOUT any network. The
    /// streaming concurrency quota in [`HostState::http_stream_backend`] only
    /// counts `active_http_streams` entries — it never reads the `response` — so
    /// tests can pre-populate the map to the cap and assert the next open is
    /// rejected with `Quota` immediately, instead of opening real streams (which
    /// would block on the streaming header deadline waiting for a responder).
    /// The `response` is a synthetic empty-body `200` made from an
    /// `http::Response`, never an over-the-wire one.
    #[cfg(test)]
    pub(crate) fn dummy_for_test(creator: &astrid_core::principal::PrincipalId) -> Self {
        let http_resp = http::Response::builder()
            .status(200)
            .body(reqwest::Body::from(Vec::<u8>::new()))
            .expect("build synthetic http::Response");
        Self {
            response: Arc::new(tokio::sync::Mutex::new(reqwest::Response::from(http_resp))),
            creator: creator.clone(),
            status: 200,
            headers: Vec::new(),
            read_timeout: Duration::from_secs(120),
            audit: Arc::default(),
        }
    }
}

/// The deadline for `send()` to produce response HEADERS. An explicit caller
/// `first-byte-ms` wins; else the (buffered) total deadline; else the host
/// `header_deadline_floor` — so the streaming path (total cleared, no
/// first-byte) is still bounded and a hung pre-header server can't block the
/// executor forever, while a legitimately slow-TTFT LLM stream is not cut. The
/// floor comes from the resolved [`HttpLimits`](crate::engine::wasm::limits::HttpLimits)
/// (operator-configurable; default 120s).
pub(super) fn header_deadline(opts: &ResolvedOptions, floor: Duration) -> Duration {
    opts.first_byte_timeout
        .or(opts.total_timeout)
        .unwrap_or(floor)
}

/// Outcome of one wire request: the response, the wire-byte count
/// (content-length when present; otherwise filled in after buffering), and
/// whether this hop's endpoint was operator-exempt (pre-blessed / consent-
/// granted local egress). The exempt flag drives the exempt-no-follow rule:
/// an exempt endpoint must not follow redirects, because the resolver
/// exemption is host-only and a `30x` to a different port/host would escape
/// the port-scoped allowlist.
struct WireResponse {
    response: reqwest::Response,
    /// Best-effort bytes-on-wire before decompression (content-length header).
    content_length: Option<u64>,
    /// True if the request endpoint matched the operator local-egress
    /// allowlist (or a runtime consent grant) — i.e. `egress_decision_*`
    /// returned an exempt host.
    exempt: bool,
    /// Audit exchange opened by this hop's pre-commit; the consumer of the
    /// response records its completion.
    exchange: HttpExchange,
}

impl HostState {
    /// Build a reqwest client for ONE hop. The caller always passes
    /// `Policy::none()` (both the buffered and streaming paths follow manually),
    /// so reqwest never follows a redirect on its own and every hop re-enters
    /// `send_one_hop` for a full airlock re-check. `redirect_policy` is a
    /// parameter only to keep the client builder generic.
    fn build_http_client(
        &self,
        opts: &ResolvedOptions,
        exempt_host: Option<Arc<str>>,
        tripped: Arc<AtomicBool>,
        dns_failed: Arc<AtomicBool>,
        redirect_policy: reqwest::redirect::Policy,
    ) -> Result<reqwest::Client, ErrorCode> {
        let mut builder = reqwest::Client::builder()
            .redirect(redirect_policy)
            .dns_resolver(Arc::new(SafeDnsResolver {
                tripped,
                dns_failed,
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

    /// Send ONE request hop: enforce scheme, run the async security gate,
    /// pre-flight egress, build a per-hop client, and send (no body read).
    /// Shared by the unified manual-redirect loop on BOTH the buffered and
    /// streaming paths. The egress decision is re-evaluated per hop, so a
    /// redirect to a different host re-runs the full airlock.
    ///
    /// A hop refused by the scheme check or the egress or security gate is
    /// recorded as a denied HTTP request. A hop that passes is pre-committed to the audit log —
    /// the host waits for the durable append — before it is sent; the
    /// returned [`WireResponse`] carries the open exchange.
    async fn send_one_hop(
        &mut self,
        url: &str,
        method: &reqwest::Method,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        opts: &ResolvedOptions,
        redirect_hop: u32,
    ) -> Result<WireResponse, ErrorCode> {
        if let Err(error) = check_scheme(url, opts.https_only) {
            // A refused scheme is a refused request: record it like the other
            // refusals whenever the URL parses at all.
            if let Ok(parsed) = reqwest::Url::parse(url)
                && let Some(precommit) =
                    self.http_precommit(&parsed, method, headers, body, redirect_hop, &[])
            {
                precommit.deny("scheme denied");
            }
            return Err(error);
        }

        let parsed = reqwest::Url::parse(url).map_err(|_| ErrorCode::InvalidRequest)?;
        let host = parsed.host_str().ok_or(ErrorCode::InvalidRequest)?;
        let port = parsed
            .port_or_known_default()
            .ok_or(ErrorCode::InvalidRequest)?;
        let deny = |state: &Self, reason: &str| {
            if let Some(precommit) =
                state.http_precommit(&parsed, method, headers, body, redirect_hop, &[])
            {
                precommit.deny(reason);
            }
        };
        if !self.principal_egress_allows(host, Some(port)) {
            deny(self, "principal egress denied");
            return Err(ErrorCode::CapabilityDenied);
        }

        let capsule_id = self.capsule_id.as_str().to_owned();
        let security = self.security.clone();
        let io_semaphore = self.io_semaphore.clone();
        if let Err(error) =
            check_http_security(&security, capsule_id, url, method.as_str(), &io_semaphore).await
        {
            deny(self, "security gate denied");
            return Err(error);
        }

        let exempt_host = match self.egress_decision_with_consent(url) {
            Ok(exempt_host) => exempt_host,
            Err(error) => {
                deny(self, &error_text(&error));
                return Err(error);
            },
        };
        let exempt = exempt_host.is_some();

        // Host-side credential injection: `{{secret:NAME}}` placeholders in
        // header values become the secret on the wire only. The audit
        // commitment below is computed over the placeholder form.
        let injected = match self.inject_credentials(headers) {
            Ok(injected) => injected,
            Err(error) => {
                deny(self, &format!("credential injection refused: {error:?}"));
                return Err(error.code());
            },
        };

        let tripped = Arc::new(AtomicBool::new(false));
        // Out-of-band DNS-miss flag: reqwest collapses a `dns_resolver` failure
        // into an opaque connect error, so the resolver flags a genuine
        // NXDOMAIN/no-address miss here for `airlock_or` to map to `dns-error`.
        let dns_failed = Arc::new(AtomicBool::new(false));
        // Manual redirect following on BOTH the buffered and streaming paths:
        // reqwest must NEVER follow on its own, so every hop re-enters this fn
        // and re-runs the full airlock (scheme + async gate + egress).
        let client = self.build_http_client(
            opts,
            exempt_host,
            tripped.clone(),
            dns_failed.clone(),
            reqwest::redirect::Policy::none(),
        )?;

        let mut request_builder = client
            .request(method.clone(), url)
            .headers(injected.headers);
        if let Some(b) = body {
            request_builder = request_builder.body(b.to_vec());
        }

        // Pre-commit: the request entry is durable before anything leaves
        // the host (DNS resolution included).
        let precommit = self.http_precommit(
            &parsed,
            method,
            headers,
            body,
            redirect_hop,
            &injected.names,
        );
        let mut exchange = match precommit {
            Some(precommit) => precommit.commit().await,
            None => HttpExchange::default(),
        };

        // Header (time-to-first-byte) deadline — see [`header_deadline`].
        // `send().await` resolves once the response HEADERS arrive; the body is
        // streamed afterwards. On the streaming path `total_timeout` is cleared,
        // so without this bound a server that accepts the TCP connection then
        // hangs before sending headers would block this future forever
        // (executor starvation).
        let header_deadline = header_deadline(opts, self.http_limits.header_deadline_floor);
        let sent = util::bounded_await(&io_semaphore, async move {
            match tokio::time::timeout(header_deadline, request_builder.send()).await {
                Ok(result) => result.map_err(|e| airlock_or(&tripped, &dns_failed, &e)),
                Err(_elapsed) => Err(ErrorCode::Timeout),
            }
        })
        .await;
        let response = match sent {
            Ok(response) => response,
            Err(error) => {
                exchange
                    .finish(false, HostAuditOutcome::Failed(&error_text(&error)))
                    .await;
                return Err(error);
            },
        };
        exchange.observe_response(&response);

        let content_length = response.content_length();
        Ok(WireResponse {
            response,
            content_length,
            exempt,
            exchange,
        })
    }

    /// Shared manual redirect-follow driver for BOTH the buffered and streaming
    /// backends. Sends the first hop, then follows redirects per `opts`,
    /// re-running the full airlock on every hop via [`send_one_hop`] (scheme +
    /// async `check_http_request` gate + egress airlock). reqwest never follows
    /// on either path.
    ///
    /// Returns the UNREAD terminal [`WireResponse`] plus the redirect-hop count
    /// and the final URL. The caller decides the terminal action: buffer the
    /// body (buffered) or hand the live response to a stream resource
    /// (streaming).
    ///
    /// Redirect semantics:
    /// - `Manual` → return the first 3xx as the terminal response.
    /// - `Error` → a 3xx-with-Location is `RedirectBlocked`.
    /// - `Follow` → bounded by `max_redirects` (`TooManyRedirects` on exceed);
    ///   each `Location` is resolved relative→absolute, IP-literal targets are
    ///   airlock-blocked (`RedirectBlocked`), `Authorization`/`Cookie` are
    ///   stripped cross-origin, and the method is downgraded per RFC 7231 on
    ///   301/302/303.
    /// - EXEMPT-NO-FOLLOW (both paths): if the hop that produced the 3xx was
    ///   operator-exempt, the response is returned as terminal without
    ///   following — the port-scoped allowlist must not widen via a redirect.
    ///
    /// The audit exchange of every followed or failed hop is completed here;
    /// the terminal hop's exchange travels with the returned response.
    async fn follow_redirects(
        &mut self,
        request: &HttpRequestData,
        opts: &ResolvedOptions,
    ) -> Result<(WireResponse, u32, reqwest::Url), ErrorCode> {
        let mut method = map_method(&request.method)?;
        let mut headers = build_headers(&request.headers)?;
        let mut current_url =
            reqwest::Url::parse(&request.url).map_err(|_| ErrorCode::InvalidRequest)?;
        // The body is forwarded across redirect hops that preserve the method
        // (307/308). On 301/302/303 the method is downgraded to GET and the
        // body dropped — the RFC 7231 behaviour reqwest's default policy
        // implemented, preserved here in the manual loop.
        let mut body = request.body.clone();
        let mut redirect_count: u32 = 0;

        loop {
            let mut wire = self
                .send_one_hop(
                    current_url.as_str(),
                    &method,
                    &headers,
                    body.as_deref(),
                    opts,
                    redirect_count,
                )
                .await?;
            let status = wire.response.status();

            // A 3xx WITH a Location is a redirect; anything else (or a 3xx with
            // no Location) is the terminal response.
            let Some(location) = status
                .is_redirection()
                .then(|| wire.response.headers().get(reqwest::header::LOCATION))
                .flatten()
                .cloned()
            else {
                return Ok((wire, redirect_count, current_url));
            };
            let next_url =
                match redirect_step(opts, wire.exempt, redirect_count, &current_url, &location) {
                    Ok(Some(next_url)) => next_url,
                    // Terminal 3xx (manual policy or exempt-no-follow).
                    Ok(None) => return Ok((wire, redirect_count, current_url)),
                    Err(error) => {
                        wire.exchange
                            .finish(false, HostAuditOutcome::Failed(&error_text(&error)))
                            .await;
                        return Err(error);
                    },
                };
            // The redirect body is discarded unread; this hop is complete.
            wire.exchange.finish(false, HostAuditOutcome::Allowed).await;
            // Strip credentials on a cross-origin hop, including every header
            // that would carry a host-injected secret.
            if !same_origin(&current_url, &next_url) {
                strip_credentials(&mut headers);
                strip_injected(&mut headers);
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
        }
    }

    /// The shared buffered backend behind `@1.0.0 http_request` and
    /// `@1.1.0 http_request_opts`. Follows redirects MANUALLY via
    /// [`follow_redirects`](Self::follow_redirects) (re-validating each hop
    /// through the full airlock), buffers the terminal body under the response
    /// cap, verifies integrity, and returns the `@1.1.0` response with metadata.
    pub(super) async fn http_request_backend(
        &mut self,
        request: HttpRequestData,
        opts: ResolvedOptions,
    ) -> Result<HttpResponseData, ErrorCode> {
        let started = Instant::now();
        let (wire, redirect_count, final_url) = self.follow_redirects(&request, &opts).await?;
        self.finalize_buffered(wire, &opts, started, &final_url, redirect_count)
            .await
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
            exempt: _,
            mut exchange,
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
        // The decompressed cap is a decompression-BOMB defence, so it only
        // applies when the host is actually decompressing. With
        // `auto_decompress == false`, `chunk()` yields the raw (possibly
        // compressed) wire bytes — enforcing the decompressed cap on those would
        // false-positive `DecompressionBomb` on a large compressed download.
        let max_decompressed = if opts.auto_decompress {
            opts.max_decompressed_bytes
        } else {
            None
        };
        // The loop hands back the bytes read so far even on failure, so the
        // completion commits to exactly what the host received.
        let (body, read_error) = util::bounded_await(&io_semaphore, async move {
            let mut response = response;
            let mut bytes = Vec::new();
            loop {
                let chunk = match response.chunk().await {
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => return (bytes, None),
                    Err(e) => return (bytes, Some(map_reqwest_err(&e))),
                };
                // `chunk()` yields decoded bytes when auto-decompress is on.
                // Enforce the decompressed ceiling first (bomb defence), then
                // the response cap. Both are hard limits.
                if let Some(cap) = max_decompressed
                    && bytes.len() as u64 + chunk.len() as u64 > cap
                {
                    return (bytes, Some(ErrorCode::DecompressionBomb));
                }
                if bytes.len() as u64 + chunk.len() as u64 > max_response {
                    return (bytes, Some(ErrorCode::BodyTooLarge));
                }
                bytes.extend_from_slice(&chunk);
            }
        })
        .await;
        exchange.begin_body();
        exchange.digest(&body);
        if let Some(error) = read_error {
            exchange
                .finish(false, HostAuditOutcome::Failed(&error_text(&error)))
                .await;
            return Err(error);
        }

        if let Some(integrity) = &opts.integrity
            && let Err(error) = verify_integrity(integrity, &body)
        {
            exchange
                .finish(true, HostAuditOutcome::Failed(&error_text(&error)))
                .await;
            return Err(error);
        }
        exchange.finish(true, HostAuditOutcome::Allowed).await;

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
    /// `@1.1.0 http_stream_start_opts`. Redirects are followed MANUALLY via the
    /// same [`follow_redirects`](Self::follow_redirects) driver as the buffered
    /// path, so EVERY streaming redirect hop re-runs the full airlock (scheme +
    /// async `check_http_request` gate + egress). The only divergence is the
    /// terminal action: the unread response is handed to a stream resource
    /// instead of being buffered.
    pub(super) async fn http_stream_backend(
        &mut self,
        request: HttpRequestData,
        opts: ResolvedOptions,
    ) -> Result<Resource<HttpStream>, ErrorCode> {
        let principal = self.effective_principal();
        let max_streams = self.http_limits.max_concurrent_streams;
        // Per-capsule concurrency cap (matches the `max_concurrent_streams` field
        // doc). `active_http_streams` holds this capsule's live streams, so its
        // length is the per-capsule count. A separate, SMALLER per-principal
        // limit would be needed for true per-principal isolation (one principal
        // not starving others within the capsule) — out of scope here.
        if self.active_http_streams.len() >= max_streams {
            return Err(ErrorCode::Quota);
        }

        // Streaming timeout shape: a per-chunk read loop, not a whole-request
        // deadline. Apply the streaming connect default when the caller set
        // none, and clear the DEFAULT total so a long-lived stream isn't cut at
        // 30s (an explicit caller `total-ms` is honoured). The per-chunk read
        // timeout comes from `between-bytes-ms`, else the streaming default.
        let mut stream_opts = opts.clone();
        if stream_opts.connect_timeout.is_none() {
            stream_opts.connect_timeout = Some(self.http_limits.stream_connect_timeout);
        }
        // Clear the total ONLY when it is the host default (the caller did NOT
        // explicitly set `total-ms`). An explicit caller total is honoured even
        // if it happens to equal the configured host default — keyed on
        // explicitness, not value, so a configured default can't silently clear
        // a caller's matching deadline.
        if !opts.total_explicit {
            stream_opts.total_timeout = None;
        }
        let read_timeout = opts
            .between_bytes_timeout
            .unwrap_or(self.http_limits.stream_read_timeout);

        // Manual follow with `stream_opts` so connect/total timeouts apply to
        // every hop. The terminal response is returned UNREAD.
        let (wire, _redirect_count, _final_url) =
            self.follow_redirects(&request, &stream_opts).await?;

        let response = wire.response;
        let mut exchange = wire.exchange;
        exchange.begin_body();
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

        let active = ActiveHttpStream {
            response: Arc::new(tokio::sync::Mutex::new(response)),
            creator: principal,
            status,
            headers: resp_headers,
            read_timeout,
            audit: Arc::new(std::sync::Mutex::new(exchange)),
        };
        let resource = self
            .resource_table
            .push(active.clone())
            .map_err(|e| ErrorCode::Unknown(format!("resource table: {e}")))?;
        // Mirror the stream into `active_http_streams`, keyed by the resource
        // rep, so the per-capsule concurrency quota (checked at the top of this
        // fn) actually counts live streams. Without this the cap was dead — the
        // resource table is not enumerable. The mirror shares the same
        // `Arc<Mutex<Response>>`, so `read_chunk` via the resource table stays
        // consistent; this copy is purely for counting and is removed in
        // `stream_close` / `stream_drop`.
        self.active_http_streams
            .insert(u64::from(resource.rep()), active);
        Ok(Resource::new_own(resource.rep()))
    }
}

/// Decide what to do with a 3xx that carries a `Location`: `Ok(Some(url))`
/// to follow it, `Ok(None)` to return it as the terminal response, or an
/// error that ends the request.
///
/// - `Manual` → terminal.
/// - `Error` → `RedirectBlocked`.
/// - `Follow` → terminal when the hop was operator-exempt (an exempt endpoint
///   must not redirect past its port-scoped allowlist — the resolver
///   exemption is host-only, so a 30x to a different port/host would widen
///   it); else bounded by `max_redirects` (`TooManyRedirects`), the
///   `Location` resolved relative→absolute, and an IP-literal target blocked
///   (`RedirectBlocked`; hostnames are airlocked at resolution by the next
///   hop's `send_one_hop`).
fn redirect_step(
    opts: &ResolvedOptions,
    exempt: bool,
    redirect_count: u32,
    current_url: &reqwest::Url,
    location: &HeaderValue,
) -> Result<Option<reqwest::Url>, ErrorCode> {
    match opts.redirect {
        RedirectPolicy::Manual => Ok(None),
        RedirectPolicy::Error => Err(ErrorCode::RedirectBlocked),
        RedirectPolicy::Follow => {
            if exempt {
                return Ok(None);
            }
            if redirect_count as usize >= opts.max_redirects {
                return Err(ErrorCode::TooManyRedirects);
            }
            let loc_str = location
                .to_str()
                .map_err(|_| ErrorCode::Protocol("invalid Location header".into()))?;
            let next_url = current_url
                .join(loc_str)
                .map_err(|_| ErrorCode::Protocol("invalid redirect target".into()))?;
            if redirect_target_blocked(next_url.host_str()) {
                return Err(ErrorCode::RedirectBlocked);
            }
            Ok(Some(next_url))
        },
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
    let audit = Arc::clone(&stream.audit);
    let read_timeout = stream.read_timeout;
    let cancel = state.effective_cancel_token();
    let sem = state.io_semaphore.clone();
    let started = Instant::now();
    let result = util::bounded_await_cancellable(&sem, &cancel, async {
        let mut resp = response_arc.lock().await;
        tokio::time::timeout(read_timeout, resp.chunk()).await
    })
    .await;
    // The audit exchange hashes each delivered chunk and is completed at end
    // of body or on a read error. A per-chunk timeout leaves it open: the
    // guest may read again.
    let bytes_result: Result<Vec<u8>, ErrorCode> = match result {
        None => {
            complete_stream(&audit, false, HostAuditOutcome::Failed("cancelled")).await;
            Ok(Vec::new())
        },
        Some(Err(_)) => Err(ErrorCode::Timeout),
        Some(Ok(Err(e))) => {
            let error = map_reqwest_err(&e);
            complete_stream(&audit, false, HostAuditOutcome::Failed(&error_text(&error))).await;
            Err(error)
        },
        Some(Ok(Ok(Some(bytes)))) => {
            with_exchange(&audit, |exchange| exchange.digest(&bytes));
            Ok(bytes.to_vec())
        },
        Some(Ok(Ok(None))) => {
            complete_stream(&audit, true, HostAuditOutcome::Allowed).await;
            Ok(Vec::new())
        },
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

/// Run `f` on a stream's audit exchange (skipped if the lock is poisoned).
fn with_exchange(audit: &std::sync::Mutex<HttpExchange>, f: impl FnOnce(&mut HttpExchange)) {
    if let Ok(mut exchange) = audit.lock() {
        f(&mut exchange);
    }
}

/// Complete the audit exchange of a stream the guest closed or dropped. Not
/// reading to the end is the guest's choice (for example after an SSE
/// terminator), so the completion is successful but marked incomplete.
fn close_stream_exchange(stream: &ActiveHttpStream) {
    with_exchange(&stream.audit, |exchange| {
        exchange.finish_detached(false, HostAuditOutcome::Allowed);
    });
}

/// Complete a stream's audit exchange and wait until the record is durable.
/// The lock is held only to take the record.
async fn complete_stream(
    audit: &std::sync::Mutex<HttpExchange>,
    complete: bool,
    outcome: HostAuditOutcome<'_>,
) {
    let completion = audit
        .lock()
        .ok()
        .and_then(|mut exchange| exchange.take_completion(complete, outcome));
    if let Some(completion) = completion {
        completion.commit().await;
    }
}

pub(super) fn stream_close(state: &mut HostState, rep: u32) -> Result<(), ErrorCode> {
    if let Ok(stream) = state
        .resource_table
        .delete::<ActiveHttpStream>(Resource::new_own(rep))
    {
        close_stream_exchange(&stream);
    }
    // Release the quota slot (see the mirror insert in `http_stream_backend`).
    state.active_http_streams.remove(&u64::from(rep));
    Ok(())
}

pub(super) fn stream_drop(state: &mut HostState, rep: u32) {
    if let Ok(stream) = state
        .resource_table
        .delete::<ActiveHttpStream>(Resource::new_own(rep))
    {
        close_stream_exchange(&stream);
    }
    // Release the quota slot (see the mirror insert in `http_stream_backend`).
    state.active_http_streams.remove(&u64::from(rep));
}

/// Classify a reqwest error into the typed `http::ErrorCode`.
///
/// `dns-error` is NOT recovered here — reqwest collapses a `dns_resolver`
/// failure into an opaque `is_connect()` error, so a genuine resolution miss is
/// distinguished out-of-band via the resolver's `dns_failed` flag in
/// [`airlock_or`](super::ssrf::airlock_or), which runs before this on the send
/// path.
///
// TODO(http): map TLS handshake / certificate failures to the contract's
// `tls-error` arm. reqwest collapses them into `is_connect()` (→
// `ConnectionError`). The TLS backend is `rustls`, a *transitive* dependency
// (via hyper-rustls), so there is no stable typed error to `downcast` to
// without adding rustls as a direct dependency and version-coupling to it;
// walking `source()` and matching rustls' `Display` strings / type names is
// brittle (not a stable API across rustls versions). Deferred rather than
// shipping a fragile string matcher — the reliable `dns-error` half ships now.
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
