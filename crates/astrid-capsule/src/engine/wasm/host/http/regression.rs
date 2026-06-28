//! Regression tests for review-bot findings on `astrid:http@1.1.0`.
//!
//! Each test fails WITHOUT its corresponding fix:
//! - duplicate request headers preserved + non-ASCII header values accepted
//!   (`build_headers` append/from_bytes);
//! - `max_redirects` clamped to the host ceiling (`from_options`);
//! - decompressed cap NOT applied when decompression is off (`finalize_buffered`);
//! - the 4-concurrent-stream quota actually triggers (`http_stream_backend`
//!   populates `active_http_streams`; close/drop release the slot);
//! - the header (time-to-first-byte) deadline bounds a hung pre-header server
//!   (`send_one_hop`);
//! - the egress security gate and its shared I/O permit acquisition are bounded
//!   by the request deadline, and a gate denial returns `CapabilityDenied`
//!   instead of hanging the caller;
//! - a genuine host-not-found maps to the typed `DnsError` via the resolver's
//!   `dns_failed` flag (narrowed to `ErrorKind::NotFound`), while a transient
//!   resolver error falls through (`lookup_err_is_not_found` / `flag_error`).

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::engine::wasm::limits::HttpLimits;
use crate::engine::wasm::test_fixtures::minimal_host_state;
use crate::security::{AllowAllGate, CapsuleSecurityGate};

use super::ssrf::MAX_HTTP_REDIRECTS;
use super::{ErrorCode, HttpMethod, HttpRequestData, KeyValuePair, RedirectPolicy, RequestOptions};

/// The WIT contract allows duplicate request headers (e.g. multiple `Cookie`
/// lines). `HeaderMap::insert` is last-write-wins and would drop the first;
/// `append` keeps both. Fails without the `insert`→`append` change.
#[test]
fn build_headers_preserves_duplicate_headers() {
    let raw = vec![
        KeyValuePair {
            key: "Cookie".to_string(),
            value: "a=1".to_string(),
        },
        KeyValuePair {
            key: "Cookie".to_string(),
            value: "b=2".to_string(),
        },
    ];
    let headers = super::backend::build_headers(&raw).expect("valid headers");
    let cookies: Vec<_> = headers
        .get_all(reqwest::header::COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert_eq!(
        cookies,
        vec!["a=1".to_string(), "b=2".to_string()],
        "both duplicate Cookie headers must survive (append, not insert)"
    );
}

/// HTTP header values may carry UTF-8 / obs-text. `HeaderValue::from_str`
/// rejects non-ASCII; `from_bytes` accepts it (still rejecting control chars).
/// Fails without the `from_str`→`from_bytes` change.
#[test]
fn build_headers_accepts_non_ascii_value() {
    let raw = vec![KeyValuePair {
        key: "X-Display-Name".to_string(),
        value: "Café Münchën".to_string(),
    }];
    let headers = super::backend::build_headers(&raw).expect("non-ASCII value must be accepted");
    assert_eq!(
        headers.get("X-Display-Name").unwrap().as_bytes(),
        "Café Münchën".as_bytes(),
    );
}

/// A caller-requested `max_redirects` above the host ceiling must clamp down
/// to `MAX_HTTP_REDIRECTS`, never raise it. Fails without the `.min(...)`.
#[test]
fn max_redirects_clamped_to_host_ceiling() {
    let opts = RequestOptions {
        timeouts: None,
        redirect: Some(RedirectPolicy::Follow),
        max_redirects: Some(u32::MAX),
        max_response_bytes: None,
        max_decompressed_bytes: None,
        auto_decompress: None,
        https_only: None,
        integrity: None,
    };
    let resolved = super::options::ResolvedOptions::from_options(opts, &HttpLimits::default());
    assert_eq!(
        resolved.max_redirects, MAX_HTTP_REDIRECTS,
        "caller cannot raise max_redirects above the host ceiling"
    );
}

/// Spawn a one-shot loopback server returning `response` verbatim then closing.
/// Returns `None` (skip) if the sandbox blocks the loopback bind.
async fn one_shot_server(
    response: Vec<u8>,
) -> Option<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping: sandbox blocks loopback bind: {e}");
            return None;
        },
        Err(e) => panic!("loopback bind failed: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(&response).await;
            let _ = sock.flush().await;
        }
    });
    Some((addr, handle))
}

fn exempt_state(
    rt: tokio::runtime::Handle,
    port: u16,
) -> crate::engine::wasm::host_state::HostState {
    let mut state = minimal_host_state(rt);
    state.security = Some(Arc::new(AllowAllGate));
    state.local_egress = vec![format!("127.0.0.1:{port}")];
    state
}

fn get_request(url: String) -> HttpRequestData {
    HttpRequestData {
        url,
        method: HttpMethod::Get,
        headers: Vec::new(),
        body: None,
    }
}

#[derive(Debug, Clone, Copy)]
struct NeverHttpGate;

#[async_trait]
impl CapsuleSecurityGate for NeverHttpGate {
    async fn check_http_request(
        &self,
        _capsule_id: &str,
        _method: &str,
        _url: &str,
    ) -> Result<(), String> {
        std::future::pending().await
    }

    async fn check_file_read(
        &self,
        _capsule_id: &str,
        _path: &str,
        _principal_home: Option<&std::path::Path>,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn check_file_write(
        &self,
        _capsule_id: &str,
        _path: &str,
        _principal_home: Option<&std::path::Path>,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn check_host_process(&self, _capsule_id: &str, _command: &str) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct DenyHttpGate;

#[async_trait]
impl CapsuleSecurityGate for DenyHttpGate {
    async fn check_http_request(
        &self,
        capsule_id: &str,
        method: &str,
        url: &str,
    ) -> Result<(), String> {
        Err(format!("capsule '{capsule_id}' denied: {method} {url}"))
    }

    async fn check_file_read(
        &self,
        _capsule_id: &str,
        _path: &str,
        _principal_home: Option<&std::path::Path>,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn check_file_write(
        &self,
        _capsule_id: &str,
        _path: &str,
        _principal_home: Option<&std::path::Path>,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn check_host_process(&self, _capsule_id: &str, _command: &str) -> Result<(), String> {
        Ok(())
    }
}

fn short_first_byte_options(first_byte_ms: u64) -> RequestOptions {
    RequestOptions {
        timeouts: Some(super::TimeoutConfig {
            connect_ms: None,
            first_byte_ms: Some(first_byte_ms),
            between_bytes_ms: None,
            total_ms: None,
        }),
        redirect: Some(RedirectPolicy::Follow),
        max_redirects: None,
        max_response_bytes: None,
        max_decompressed_bytes: None,
        auto_decompress: None,
        https_only: None,
        integrity: None,
    }
}

/// Reproduces astrid#1078 without live network: the egress gate never replies,
/// so old code waits forever before `send()` and never reaches the request's
/// HTTP deadlines. The fix wraps the gate itself and returns `Timeout`.
#[tokio::test]
async fn http_security_gate_stall_is_bounded_by_request_deadline() {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.security = Some(Arc::new(NeverHttpGate));

    let limits = state.http_limits;
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        state.http_request_backend(
            get_request("https://example.com/".to_string()),
            super::options::ResolvedOptions::from_options(short_first_byte_options(200), &limits),
        ),
    )
    .await
    .expect("stalled egress gate must be bounded by the request deadline");

    assert!(
        matches!(result, Err(ErrorCode::Timeout)),
        "a stalled egress gate must surface Timeout, got {result:?}"
    );
}

/// The gate is run through the shared host I/O semaphore. If all permits are
/// exhausted, old code waits forever before even calling the gate. The timeout
/// must cover permit acquisition too, not only the policy future.
#[tokio::test]
async fn http_security_gate_permit_wait_is_bounded_by_request_deadline() {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.security = Some(Arc::new(AllowAllGate));
    state.io_semaphore = Arc::new(Semaphore::new(0));

    let limits = state.http_limits;
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        state.http_request_backend(
            get_request("https://example.com/".to_string()),
            super::options::ResolvedOptions::from_options(short_first_byte_options(200), &limits),
        ),
    )
    .await
    .expect("egress gate permit wait must be bounded by the request deadline");

    assert!(
        matches!(result, Err(ErrorCode::Timeout)),
        "an exhausted gate semaphore must surface Timeout, got {result:?}"
    );
}

/// Missing manifest egress permission is a normal authorization denial. It must
/// fail closed with a typed `CapabilityDenied` error before any network attempt,
/// which gives the caller a visible failure instead of a silent tool hang.
#[tokio::test]
async fn http_security_gate_denial_surfaces_capability_denied() {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.security = Some(Arc::new(DenyHttpGate));

    let limits = state.http_limits;
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        state.http_request_backend(
            get_request("https://example.com/".to_string()),
            super::options::ResolvedOptions::from_options(short_first_byte_options(200), &limits),
        ),
    )
    .await
    .expect("egress gate denial must return promptly");

    assert!(
        matches!(result, Err(ErrorCode::CapabilityDenied)),
        "egress gate denial must surface CapabilityDenied, got {result:?}"
    );
}

/// A body larger than `max_decompressed_bytes` but under `max_response_bytes`,
/// fetched with `auto_decompress = false`, must NOT trip `DecompressionBomb` —
/// the raw wire bytes aren't decompressed, so the bomb cap doesn't apply. Fails
/// without gating the cap on `auto_decompress`.
#[tokio::test]
async fn decompressed_cap_ignored_when_decompression_off() {
    // 2 KiB body; cap decompressed at 100 (would trip if mis-applied), response
    // cap well above 2 KiB.
    let body = vec![b'x'; 2048];
    let response =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    let mut full = response;
    full.extend_from_slice(&body);

    let Some((addr, server)) = one_shot_server(full).await else {
        return;
    };
    let rt = tokio::runtime::Handle::current();
    let mut state = exempt_state(rt, addr.port());

    let opts = RequestOptions {
        timeouts: None,
        redirect: Some(RedirectPolicy::Follow),
        max_redirects: None,
        max_response_bytes: Some(1024 * 1024),
        max_decompressed_bytes: Some(100),
        auto_decompress: Some(false),
        https_only: None,
        integrity: None,
    };
    let limits = state.http_limits;
    let resp = state
        .http_request_backend(
            get_request(format!("http://{addr}/")),
            super::options::ResolvedOptions::from_options(opts, &limits),
        )
        .await
        .expect("auto_decompress=off must not trip DecompressionBomb on raw bytes");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body.len(), 2048);
    let _ = server.await;
}

/// The concurrency quota counts `active_http_streams`; the open past the cap is
/// rejected with `Quota`; `stream_close` / `stream_drop` each release a slot so
/// the next open fits again. Fails without the mirror insert/remove — the cap
/// was dead (streams lived only in the resource table, which the quota check
/// can't enumerate).
///
/// Hermetic and hang-proof: the quota gate runs BEFORE any network and reads
/// only `active_http_streams.len()`, so the map is pre-populated with synthetic
/// (no-network) streams; the at-cap open rejects immediately, and close/drop are
/// asserted to release a slot (dropping the count below the cap so the gate
/// would permit the next open). Opening real streams would block on the 120s
/// streaming header deadline waiting for a responder.
#[tokio::test]
async fn stream_quota_triggers_and_releases() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let rt = tokio::runtime::Handle::current();
        let mut state = minimal_host_state(rt);
        state.security = Some(Arc::new(AllowAllGate));
        let limits = state.http_limits;
        let cap = limits.max_concurrent_streams;
        let principal = state.effective_principal();

        // Fill the quota map to the cap with synthetic streams (no network),
        // keyed by rep so `stream_close` / `stream_drop` can remove by rep.
        let reps: Vec<u32> = (0..cap as u32).collect();
        for &rep in &reps {
            state.active_http_streams.insert(
                u64::from(rep),
                super::backend::ActiveHttpStream::dummy_for_test(&principal),
            );
        }
        assert_eq!(
            state.active_http_streams.len(),
            cap,
            "the quota map is populated to the cap"
        );

        // An open at the cap is rejected by the quota gate (it trips before any
        // network — no responder is reached).
        let err = state
            .http_stream_backend(
                get_request("http://127.0.0.1:9/".to_string()),
                super::options::ResolvedOptions::from_options(follow(), &limits),
            )
            .await
            .expect_err("an open at the cap must hit the quota");
        assert!(
            matches!(err, ErrorCode::Quota),
            "expected Quota, got {err:?}"
        );

        // `stream_close` releases a slot: the count drops below the cap, so the
        // quota gate (`len >= cap`) would now permit the next open.
        super::backend::stream_close(&mut state, reps[0]).expect("close ok");
        assert_eq!(
            state.active_http_streams.len(),
            cap - 1,
            "close must release the quota slot"
        );
        assert!(
            state.active_http_streams.len() < cap,
            "after a close the quota gate permits another open"
        );

        // Re-fill to the cap, then `stream_drop` releases a slot too.
        state.active_http_streams.insert(
            u64::from(reps[0]),
            super::backend::ActiveHttpStream::dummy_for_test(&principal),
        );
        assert_eq!(state.active_http_streams.len(), cap);
        super::backend::stream_drop(&mut state, reps[1]);
        assert_eq!(
            state.active_http_streams.len(),
            cap - 1,
            "drop must release the quota slot"
        );
    })
    .await
    .expect("stream-quota test must not hang (5s backstop)");
}

/// A NON-default operator `max_concurrent_streams` actually lowers the quota:
/// with a configured cap of 2, the 3rd concurrent stream is rejected with
/// `Quota` — where the host default (4) would allow it. Proves the stream cap
/// reads `http_limits`, not the old `MAX_ACTIVE_HTTP_STREAMS` constant.
///
/// Hermetic and hang-proof: the quota gate runs at the TOP of
/// `http_stream_backend`, BEFORE any network, and counts only
/// `active_http_streams` entries — so the cap is pre-populated with synthetic
/// (no-network) streams and a single open is asserted to reject immediately.
/// Opening real streams would block on the 120s streaming header deadline
/// waiting for a responder.
#[tokio::test]
async fn configured_max_concurrent_streams_lowers_quota() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let rt = tokio::runtime::Handle::current();
        let mut state = minimal_host_state(rt);
        state.security = Some(Arc::new(AllowAllGate));
        // Operator override: cap concurrent streams at 2 (below the default 4).
        state.http_limits.max_concurrent_streams = 2;
        let limits = state.http_limits;
        let principal = state.effective_principal();

        // Pre-fill the quota map to the configured cap (2) with synthetic
        // streams — no sockets, no network.
        for rep in 0..2u64 {
            state.active_http_streams.insert(
                rep,
                super::backend::ActiveHttpStream::dummy_for_test(&principal),
            );
        }
        assert_eq!(state.active_http_streams.len(), 2);

        // The next open is rejected by the LOWERED quota (the gate trips before
        // any network). The default cap of 4 would have allowed it here.
        let err = state
            .http_stream_backend(
                get_request("http://127.0.0.1:9/".to_string()),
                super::options::ResolvedOptions::from_options(follow(), &limits),
            )
            .await
            .expect_err("the 3rd stream must hit the configured cap of 2");
        assert!(
            matches!(err, ErrorCode::Quota),
            "expected Quota at the configured cap, got {err:?}"
        );
    })
    .await
    .expect("stream-quota test must not hang (5s backstop)");
}

/// A genuine host-not-found surfaces the typed `DnsError`, but a transient
/// resolver error (timeout / I/O) does NOT — it falls through to the generic
/// classification. reqwest collapses a
/// `dns_resolver` failure into an opaque `is_connect()` error, so the
/// `SafeDnsResolver` flags a NOT-FOUND miss out-of-band via `dns_failed`
/// (mirroring the airlock `tripped` channel) and `airlock_or` maps it to
/// `DnsError`. `dns_failed` is narrowed to `ErrorKind::NotFound` so a transient
/// failure isn't mislabeled as not-found.
///
/// The narrowing is asserted directly via `lookup_err_is_not_found` (fully
/// hermetic, platform-independent — `lookup_host`'s error kind for a `.invalid`
/// host varies by platform: macOS reports `Uncategorized`, others `NotFound`).
#[test]
fn dns_not_found_is_narrowed_to_notfound_kind() {
    use std::io::{Error, ErrorKind};

    // Only NotFound is a `dns-error` miss.
    assert!(super::ssrf::lookup_err_is_not_found(&Error::new(
        ErrorKind::NotFound,
        "host not found"
    )));
    // A transient resolver timeout / I/O error must NOT be treated as not-found
    // (it would mislabel a connection problem as DnsError).
    assert!(!super::ssrf::lookup_err_is_not_found(&Error::new(
        ErrorKind::TimedOut,
        "resolver timed out"
    )));
    assert!(!super::ssrf::lookup_err_is_not_found(&Error::other(
        "transient resolver failure"
    )));
}

/// The resolver's empty-resolved-addresses path (a host that resolves to ONLY
/// airlock-filtered-out addresses, with none unsafe — an unambiguous no-resolve)
/// sets `dns_failed`, and `flag_error` maps the flags to the typed errors with
/// the airlock taking precedence. Driven at the resolver/flag layer so it is
/// hermetic and proxy-independent.
#[test]
fn dns_failed_flag_maps_to_dns_error_with_airlock_precedence() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let tripped = AtomicBool::new(false);
    let dns_failed = AtomicBool::new(false);

    // Neither flag → fall through (None).
    assert!(super::ssrf::flag_error(&tripped, &dns_failed).is_none());

    // dns_failed alone → DnsError.
    dns_failed.store(true, Ordering::Relaxed);
    assert!(matches!(
        super::ssrf::flag_error(&tripped, &dns_failed),
        Some(ErrorCode::DnsError)
    ));

    // Airlock takes precedence when both are set.
    tripped.store(true, Ordering::Relaxed);
    assert!(
        matches!(
            super::ssrf::flag_error(&tripped, &dns_failed),
            Some(ErrorCode::AirlockRejected)
        ),
        "airlock must take precedence over a DNS miss"
    );
}

fn follow() -> RequestOptions {
    RequestOptions {
        timeouts: None,
        redirect: Some(RedirectPolicy::Follow),
        max_redirects: None,
        max_response_bytes: None,
        max_decompressed_bytes: None,
        auto_decompress: None,
        https_only: None,
        integrity: None,
    }
}

/// The header-deadline decision table. The streaming case (total cleared, no
/// first-byte / between-bytes) has no reqwest read-timeout or total-timeout, so
/// only `header_deadline`'s floor bounds `send()`. A
/// regression that drops the floor (e.g. `unwrap_or` → `None` then no timeout)
/// is caught here without waiting 120s for a live hang.
#[test]
fn header_deadline_decision_table() {
    use super::backend::header_deadline;
    use super::options::ResolvedOptions;

    let limits = HttpLimits::default();
    let floor = limits.header_deadline_floor;
    let base = ResolvedOptions::v10_defaults(&limits);

    // Explicit first-byte wins over everything.
    let mut o = base.clone();
    o.first_byte_timeout = Some(Duration::from_millis(250));
    o.total_timeout = Some(Duration::from_secs(30));
    assert_eq!(header_deadline(&o, floor), Duration::from_millis(250));

    // No first-byte, but a total (the buffered default) → bound by total.
    let mut o = base.clone();
    o.first_byte_timeout = None;
    o.total_timeout = Some(Duration::from_secs(30));
    assert_eq!(header_deadline(&o, floor), Duration::from_secs(30));

    // STREAMING shape: total cleared, no first-byte → the floor bounds it.
    // (Without the floor, `send()` on a hung pre-header server never returns.)
    let mut o = base;
    o.first_byte_timeout = None;
    o.total_timeout = None;
    assert_eq!(header_deadline(&o, floor), floor);
}

/// End-to-end: a server that accepts the TCP connection then never sends
/// response headers must NOT hang. With a short caller `first-byte-ms`, the
/// header deadline fires and returns `Timeout`. The outer 5s test timeout turns
/// a regression (infinite hang) into a loud failure rather than a CI hang.
#[tokio::test]
async fn hung_pre_header_server_times_out() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping: sandbox blocks loopback bind: {e}");
            return;
        },
        Err(e) => panic!("loopback bind failed: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    // Accept then hold the connection open WITHOUT sending any response.
    let server = tokio::spawn(async move {
        if let Ok((sock, _)) = listener.accept().await {
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(sock);
        }
    });

    let rt = tokio::runtime::Handle::current();
    let mut state = exempt_state(rt, addr.port());

    let opts = RequestOptions {
        timeouts: Some(super::TimeoutConfig {
            connect_ms: None,
            // Short first-byte deadline: must fire well before the 30s server
            // sleep / the 5s test bound.
            first_byte_ms: Some(300),
            between_bytes_ms: None,
            total_ms: None,
        }),
        redirect: Some(RedirectPolicy::Follow),
        max_redirects: None,
        max_response_bytes: None,
        max_decompressed_bytes: None,
        auto_decompress: None,
        https_only: None,
        integrity: None,
    };

    let limits = state.http_limits;
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        state.http_request_backend(
            get_request(format!("http://{addr}/")),
            super::options::ResolvedOptions::from_options(opts, &limits),
        ),
    )
    .await
    .expect("the request must not hang past the first-byte deadline");

    assert!(
        matches!(result, Err(ErrorCode::Timeout)),
        "a hung pre-header server must surface Timeout, got {result:?}"
    );
    server.abort();
}
