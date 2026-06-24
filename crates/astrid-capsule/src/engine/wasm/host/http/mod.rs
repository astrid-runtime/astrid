//! `astrid:http@1.0.0` + `astrid:http@1.1.0` host implementation.
//!
//! HTTP client with SSRF protection. Both contract versions are backed by ONE
//! implementation:
//!
//! - The real backend (`backend.rs`) lives behind the `@1.1.0` trait impls. It
//!   honours the full `request-options` control surface (timeouts, redirect
//!   policy, size / decompression caps, https-only, subresource integrity) and
//!   populates `response-meta` on every buffered response.
//! - The `@1.0.0` `http_request` / `http_stream_start` are THIN SHIMS: they
//!   call the `@1.1.0` backend with options that reproduce `@1.0.0` behaviour
//!   exactly (follow redirects ≤10, host default timeouts, 10 MB body cap) and
//!   drop the `meta` field on the way back.
//!
//! SSRF discipline (`ssrf.rs`) is shared by both: DNS resolution airlocks
//! private / loopback / link-local / multicast / unspecified IPs; IP-literal
//! URLs are pre-flighted (reqwest never runs the resolver on a literal); every
//! redirect hop is re-validated through the SAME airlock and `Authorization` /
//! `Cookie` are stripped on a cross-origin hop. The host — never the capsule —
//! owns DNS resolution and the connect path.

mod backend;
mod options;
mod ssrf;

use wasmtime::component::Resource;

// Both versions generate version-suffixed modules under `bindings`; neither
// keeps a bare `http` module. The shim maps between the two record shapes.
use crate::engine::wasm::bindings::astrid::http1_0_0::host as http_v10;
use crate::engine::wasm::bindings::astrid::http1_1_0::host as http_v11;
// Re-export the `@1.1.0` generated types the submodules (`backend`, `options`,
// `tests`) reach via `super::`. The shared backend speaks `@1.1.0` throughout.
use http_v11::HttpUpload;
pub(super) use http_v11::{
    ErrorCode, HttpMethod, HttpRequestData, HttpResponseData, HttpStream, KeyValuePair,
    RedirectPolicy, RequestOptions, ResponseMeta, TimeoutConfig,
};

use crate::engine::wasm::bindings::astrid::io::streams::{InputStream, OutputStream};
use crate::engine::wasm::host_state::HostState;
use wasmtime_wasi::p2::DynPollable;

pub use backend::ActiveHttpStream;
use backend::{stream_close, stream_drop, stream_headers, stream_read_chunk, stream_status};
use options::ResolvedOptions;
pub(super) use ssrf::is_safe_ip;

// ── @1.0.0 ⇄ @1.1.0 type bridging ──────────────────────────────────────
//
// The two contract versions generate DISTINCT Rust types for `error-code`,
// `key-value-pair`, etc. The shared backend speaks `@1.1.0`; the `@1.0.0`
// trait impl converts at the boundary.

/// Map a `@1.1.0` `error-code` back to the `@1.0.0` arm set. The `@1.0.0`
/// shim runs with `v10_defaults` options (follow redirects, no https-only, no
/// SRI, no decompressed cap), so the `@1.1.0`-only arms that depend on those
/// controls cannot arise — but a redirect chain CAN exceed the cap or hit a
/// blocked hop, so those two are mapped to the closest `@1.0.0` arm. The rest
/// are mapped defensively and should be unreachable from the `@1.0.0` path.
fn v11_error_to_v10(e: ErrorCode) -> http_v10::ErrorCode {
    use http_v10::ErrorCode as V10;
    match e {
        ErrorCode::CapabilityDenied => V10::CapabilityDenied,
        ErrorCode::InvalidRequest => V10::InvalidRequest,
        ErrorCode::DnsError => V10::DnsError,
        ErrorCode::AirlockRejected => V10::AirlockRejected,
        ErrorCode::TlsError => V10::TlsError,
        ErrorCode::Timeout => V10::Timeout,
        ErrorCode::ConnectionError => V10::ConnectionError,
        ErrorCode::BodyTooLarge => V10::BodyTooLarge,
        ErrorCode::Closed => V10::Closed,
        ErrorCode::Quota => V10::Quota,
        ErrorCode::Protocol(s) => V10::Protocol(s),
        ErrorCode::Unknown(s) => V10::Unknown(s),
        // `@1.1.0`-only arms. A blocked redirect hop is an airlock refusal in
        // @1.0.0 terms; a too-long chain has no @1.0.0 arm, so surface it as a
        // protocol-level error rather than a misleading airlock rejection.
        ErrorCode::RedirectBlocked => V10::AirlockRejected,
        ErrorCode::TooManyRedirects => V10::Protocol("too many redirects".into()),
        // Unreachable from `v10_defaults` (no https-only / SRI / decompressed
        // cap is ever set on the shim path). Mapped honestly if they somehow
        // arise.
        ErrorCode::SchemeDenied => V10::InvalidRequest,
        ErrorCode::IntegrityMismatch => V10::Protocol("integrity mismatch".into()),
        ErrorCode::DecompressionBomb => V10::BodyTooLarge,
    }
}

/// Map a `@1.1.0` `key-value-pair` list to the `@1.0.0` one (identical shape).
fn v11_headers_to_v10(headers: Vec<KeyValuePair>) -> Vec<http_v10::KeyValuePair> {
    headers
        .into_iter()
        .map(|kv| http_v10::KeyValuePair {
            key: kv.key,
            value: kv.value,
        })
        .collect()
}

// ── @1.0.0 host impl (thin shims) ──────────────────────────────────────

impl http_v10::Host for HostState {
    async fn http_request(
        &mut self,
        request: http_v10::HttpRequestData,
    ) -> Result<http_v10::HttpResponseData, http_v10::ErrorCode> {
        // Delegate to the @1.1.0 backend with @1.0.0-equivalent options, then
        // drop the `meta` field the @1.0.0 record lacks and convert types.
        let v11_request = v10_request_to_v11(request);
        let resp = self
            .http_request_backend(v11_request, ResolvedOptions::v10_defaults())
            .await
            .map_err(v11_error_to_v10)?;
        Ok(http_v10::HttpResponseData {
            status: resp.status,
            headers: v11_headers_to_v10(resp.headers),
            body: resp.body,
        })
    }

    async fn http_stream_start(
        &mut self,
        request: http_v10::HttpRequestData,
    ) -> Result<Resource<http_v10::HttpStream>, http_v10::ErrorCode> {
        let v11_request = v10_request_to_v11(request);
        let res = self
            .http_stream_backend(v11_request, ResolvedOptions::v10_defaults())
            .await
            .map_err(v11_error_to_v10)?;
        // `HttpStream` is a zero-sized bindgen marker; both versions index the
        // same `ActiveHttpStream` in the resource table by rep. Re-tag the
        // @1.1.0 handle as the @1.0.0 marker type.
        Ok(Resource::new_own(res.rep()))
    }
}

/// Map a `@1.0.0` request record to the structurally-identical `@1.1.0` one.
fn v10_request_to_v11(r: http_v10::HttpRequestData) -> HttpRequestData {
    HttpRequestData {
        url: r.url,
        method: v10_method_to_v11(r.method),
        headers: r
            .headers
            .into_iter()
            .map(|kv| KeyValuePair {
                key: kv.key,
                value: kv.value,
            })
            .collect(),
        body: r.body,
    }
}

/// Map a `@1.0.0` method variant to the `@1.1.0` one (identical shapes).
fn v10_method_to_v11(m: http_v10::HttpMethod) -> HttpMethod {
    match m {
        http_v10::HttpMethod::Get => HttpMethod::Get,
        http_v10::HttpMethod::Head => HttpMethod::Head,
        http_v10::HttpMethod::Post => HttpMethod::Post,
        http_v10::HttpMethod::Put => HttpMethod::Put,
        http_v10::HttpMethod::Delete => HttpMethod::Delete,
        http_v10::HttpMethod::Connect => HttpMethod::Connect,
        http_v10::HttpMethod::Options => HttpMethod::Options,
        http_v10::HttpMethod::Trace => HttpMethod::Trace,
        http_v10::HttpMethod::Patch => HttpMethod::Patch,
        http_v10::HttpMethod::Other(s) => HttpMethod::Other(s),
    }
}

impl http_v10::HostHttpStream for HostState {
    fn status(&mut self, self_: Resource<http_v10::HttpStream>) -> u16 {
        stream_status(self, self_.rep())
    }

    fn headers(&mut self, self_: Resource<http_v10::HttpStream>) -> Vec<http_v10::KeyValuePair> {
        v11_headers_to_v10(stream_headers(self, self_.rep()))
    }

    async fn read_chunk(
        &mut self,
        self_: Resource<http_v10::HttpStream>,
    ) -> Result<Vec<u8>, http_v10::ErrorCode> {
        stream_read_chunk(self, self_.rep())
            .await
            .map_err(v11_error_to_v10)
    }

    fn close(&mut self, self_: Resource<http_v10::HttpStream>) -> Result<(), http_v10::ErrorCode> {
        stream_close(self, self_.rep()).map_err(v11_error_to_v10)
    }

    fn subscribe_readable(
        &mut self,
        _self_: Resource<http_v10::HttpStream>,
    ) -> Resource<DynPollable> {
        super::stubs::always_ready_pollable(&mut self.resource_table)
    }

    fn body_stream(&mut self, _self_: Resource<http_v10::HttpStream>) -> Resource<InputStream> {
        super::stubs::closed_input_stream(&mut self.resource_table)
    }

    fn drop(&mut self, rep: Resource<http_v10::HttpStream>) -> wasmtime::Result<()> {
        stream_drop(self, rep.rep());
        Ok(())
    }
}

// ── @1.1.0 host impl (real backend) ────────────────────────────────────

impl http_v11::Host for HostState {
    async fn http_request(
        &mut self,
        request: HttpRequestData,
    ) -> Result<HttpResponseData, ErrorCode> {
        // The bare `http-request` on @1.1.0 == `http-request-opts` with empty
        // options (the contract says an empty `request-options` reproduces
        // @1.0.0 behaviour).
        self.http_request_backend(request, ResolvedOptions::v10_defaults())
            .await
    }

    async fn http_request_opts(
        &mut self,
        request: HttpRequestData,
        options: RequestOptions,
    ) -> Result<HttpResponseData, ErrorCode> {
        self.http_request_backend(request, ResolvedOptions::from_options(options))
            .await
    }

    async fn http_stream_start(
        &mut self,
        request: HttpRequestData,
    ) -> Result<Resource<HttpStream>, ErrorCode> {
        self.http_stream_backend(request, ResolvedOptions::v10_defaults())
            .await
    }

    async fn http_stream_start_opts(
        &mut self,
        request: HttpRequestData,
        options: RequestOptions,
    ) -> Result<Resource<HttpStream>, ErrorCode> {
        self.http_stream_backend(request, ResolvedOptions::from_options(options))
            .await
    }

    fn http_upload_start(
        &mut self,
        _request: HttpRequestData,
        _options: RequestOptions,
    ) -> Result<Resource<HttpUpload>, ErrorCode> {
        // TODO(http@1.1.0): streaming request body — follow-up. The streaming
        // upload path (guest-written body sink + finish-then-send) is not yet
        // implemented; the buffered `http-request*` path covers in-memory
        // bodies. Fail honestly rather than returning a half-wired handle.
        Err(ErrorCode::Unknown(
            "streaming upload (http-upload) not yet implemented".into(),
        ))
    }
}

impl http_v11::HostHttpStream for HostState {
    fn status(&mut self, self_: Resource<HttpStream>) -> u16 {
        stream_status(self, self_.rep())
    }

    fn headers(&mut self, self_: Resource<HttpStream>) -> Vec<KeyValuePair> {
        stream_headers(self, self_.rep())
    }

    async fn read_chunk(&mut self, self_: Resource<HttpStream>) -> Result<Vec<u8>, ErrorCode> {
        stream_read_chunk(self, self_.rep()).await
    }

    fn close(&mut self, self_: Resource<HttpStream>) -> Result<(), ErrorCode> {
        stream_close(self, self_.rep())
    }

    fn subscribe_readable(&mut self, _self_: Resource<HttpStream>) -> Resource<DynPollable> {
        // Reuse the @1.0.0 stub; the real pollable adapter is a separate
        // follow-up shared by both versions.
        super::stubs::always_ready_pollable(&mut self.resource_table)
    }

    fn body_stream(&mut self, _self_: Resource<HttpStream>) -> Resource<InputStream> {
        // Reuse the @1.0.0 stub; the real stream-half adapter is a separate
        // follow-up shared by both versions.
        super::stubs::closed_input_stream(&mut self.resource_table)
    }

    fn trailers(
        &mut self,
        _self_: Resource<HttpStream>,
    ) -> Result<Option<Vec<KeyValuePair>>, ErrorCode> {
        // TODO(http@1.1.0): surface HTTP trailers — follow-up. reqwest does not
        // expose response trailers without dropping to hyper, so report "no
        // trailers" rather than blocking the version on trailer extraction.
        Ok(None)
    }

    fn drop(&mut self, rep: Resource<HttpStream>) -> wasmtime::Result<()> {
        stream_drop(self, rep.rep());
        Ok(())
    }
}

impl http_v11::HostHttpUpload for HostState {
    fn body_sink(&mut self, _self_: Resource<HttpUpload>) -> Resource<OutputStream> {
        // TODO(http@1.1.0): streaming request body — follow-up. `http_upload_start`
        // never hands out an `http-upload` handle, so these methods are
        // unreachable; the closed-on-write stub keeps the trait total.
        super::stubs::closed_output_stream(&mut self.resource_table)
    }

    fn subscribe_writable(&mut self, _self_: Resource<HttpUpload>) -> Resource<DynPollable> {
        // Unreachable (see `body_sink`); always-ready stub.
        super::stubs::always_ready_pollable(&mut self.resource_table)
    }

    async fn finish(
        &mut self,
        _self_: Resource<HttpUpload>,
    ) -> Result<Resource<HttpStream>, ErrorCode> {
        // Unreachable: no `http-upload` handle is ever created. Fail honestly.
        Err(ErrorCode::Unknown(
            "streaming upload (http-upload) not yet implemented".into(),
        ))
    }

    fn drop(&mut self, _rep: Resource<HttpUpload>) -> wasmtime::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
