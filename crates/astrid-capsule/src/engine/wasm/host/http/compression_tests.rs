//! Codec round-trips for the HTTP host auto-decompress path.
//!
//! Reqwest toggles gzip/brotli/deflate/zstd as a group from `auto_decompress`
//! (`backend.rs`). These tests serve real `zstd` and `br` frames from
//! `compression_fixtures/` (host CLI codecs; see SOURCE.txt there) and assert:
//! default decode of the exact plaintext, raw opt-out returning the frame
//! bytes, and a genuine compressed payload tripping `DecompressionBomb`.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::{
    ErrorCode, HttpMethod, HttpRequestData, HttpResponseData, RedirectPolicy, RequestOptions,
};
use crate::engine::wasm::host_state::HostState;
use crate::engine::wasm::test_fixtures::minimal_host_state;
use crate::security::AllowAllGate;

const PLAINTEXT: &[u8] = include_bytes!("compression_fixtures/payload.txt");
const ZSTD_FRAME: &[u8] = include_bytes!("compression_fixtures/payload.zst");
const BROTLI_FRAME: &[u8] = include_bytes!("compression_fixtures/payload.br");

const LINE: &[u8] = b"astrid-http-compression-fixture-v1\n";

/// Cap sits above both compressed frames (58 / 44 bytes) and below the 2240-byte
/// plaintext, so a wire-byte cap would not trip and a decoded cap must.
const BOMB_CAP: u64 = 64;

fn follow_opts(
    auto_decompress: Option<bool>,
    max_decompressed_bytes: Option<u64>,
) -> RequestOptions {
    RequestOptions {
        timeouts: None,
        redirect: Some(RedirectPolicy::Follow),
        max_redirects: None,
        max_response_bytes: Some(1024 * 1024),
        max_decompressed_bytes,
        auto_decompress,
        https_only: None,
        integrity: None,
    }
}

fn get_request(url: String) -> HttpRequestData {
    HttpRequestData {
        url,
        method: HttpMethod::Get,
        headers: Vec::new(),
        body: None,
    }
}

fn exempt_state(rt: tokio::runtime::Handle, port: u16) -> HostState {
    let mut state = minimal_host_state(rt);
    state.security = Some(Arc::new(AllowAllGate));
    state.local_egress = vec![format!("127.0.0.1:{port}")];
    state
}

/// Spawn a one-shot loopback server returning `response` verbatim then closing.
/// Bind failure, including sandbox `PermissionDenied`, fails the test.
async fn one_shot_server(response: Vec<u8>) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|error| panic!("loopback bind failed: {error}"));
    let addr = listener
        .local_addr()
        .expect("bound listener has a local address");
    let handle = tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(&response).await;
            let _ = sock.flush().await;
        }
    });
    (addr, handle)
}

fn encoded_response(encoding: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Encoding: {encoding}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

/// Run the backend to completion, then abort and reap the owned accept task.
/// Pre-connect rejects never call `accept`; awaiting without abort would hang.
async fn complete_backend(
    mut state: HostState,
    addr: std::net::SocketAddr,
    server: tokio::task::JoinHandle<()>,
    opts: RequestOptions,
) -> Result<HttpResponseData, ErrorCode> {
    let limits = state.http_limits;
    let result = state
        .http_request_backend(
            get_request(format!("http://{addr}/")),
            super::options::ResolvedOptions::from_options(opts, &limits),
        )
        .await;
    server.abort();
    let _ = server.await;
    result
}

async fn request_encoded(
    encoding: &str,
    frame: &[u8],
    opts: RequestOptions,
) -> Result<HttpResponseData, ErrorCode> {
    let (addr, server) = one_shot_server(encoded_response(encoding, frame)).await;
    let state = exempt_state(tokio::runtime::Handle::current(), addr.port());
    complete_backend(state, addr, server, opts).await
}

#[test]
fn compression_fixtures_match_documented_plaintext() {
    assert_eq!(
        PLAINTEXT,
        LINE.repeat(64),
        "payload.txt must stay 64 LF lines"
    );
    assert_eq!(PLAINTEXT.len(), 2240);
    assert!(
        ZSTD_FRAME.len() < BOMB_CAP as usize,
        "zstd frame must fit under the bomb cap so a wire-byte check would miss it"
    );
    assert!(
        BROTLI_FRAME.len() < BOMB_CAP as usize,
        "brotli frame must fit under the bomb cap so a wire-byte check would miss it"
    );
}

#[tokio::test]
async fn zstd_default_auto_decompress_yields_plaintext() {
    let resp = request_encoded("zstd", ZSTD_FRAME, follow_opts(None, None))
        .await
        .expect("default auto_decompress must decode zstd");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body.as_slice(), PLAINTEXT);
}

#[tokio::test]
async fn brotli_default_auto_decompress_yields_plaintext() {
    let resp = request_encoded("br", BROTLI_FRAME, follow_opts(None, None))
        .await
        .expect("default auto_decompress must decode brotli");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body.as_slice(), PLAINTEXT);
}

#[tokio::test]
async fn zstd_auto_decompress_off_returns_raw_frame() {
    let resp = request_encoded("zstd", ZSTD_FRAME, follow_opts(Some(false), None))
        .await
        .expect("auto_decompress=false must return the zstd frame");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body.as_slice(), ZSTD_FRAME);
}

#[tokio::test]
async fn brotli_auto_decompress_off_returns_raw_frame() {
    let resp = request_encoded("br", BROTLI_FRAME, follow_opts(Some(false), None))
        .await
        .expect("auto_decompress=false must return the brotli frame");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body.as_slice(), BROTLI_FRAME);
}

#[tokio::test]
async fn zstd_decompressed_cap_trips_decompression_bomb() {
    let err = request_encoded("zstd", ZSTD_FRAME, follow_opts(None, Some(BOMB_CAP)))
        .await
        .expect_err("decoded zstd plaintext exceeds the decompressed cap");
    assert!(
        matches!(err, ErrorCode::DecompressionBomb),
        "expected DecompressionBomb, got {err:?}"
    );
}

#[tokio::test]
async fn brotli_decompressed_cap_trips_decompression_bomb() {
    let err = request_encoded("br", BROTLI_FRAME, follow_opts(None, Some(BOMB_CAP)))
        .await
        .expect_err("decoded brotli plaintext exceeds the decompressed cap");
    assert!(
        matches!(err, ErrorCode::DecompressionBomb),
        "expected DecompressionBomb, got {err:?}"
    );
}

/// Loopback without `local_egress` is airlocked before TCP. The owned accept
/// task would hang on `server.await` unless aborted after that reject.
#[tokio::test]
async fn preconnect_airlock_aborts_idle_accept() {
    let (addr, server) = one_shot_server(encoded_response("zstd", ZSTD_FRAME)).await;
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    state.security = Some(Arc::new(AllowAllGate));

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        complete_backend(state, addr, server, follow_opts(None, None)),
    )
    .await
    .expect("airlock before connect must abort idle accept rather than hang");

    assert!(
        matches!(result, Err(ErrorCode::AirlockRejected)),
        "expected AirlockRejected before connect, got {result:?}"
    );
}
