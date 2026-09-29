//! Tests for the HTTP exchange audit: credential redaction, request
//! commitments, pre-commit ordering and completion records.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use astrid_capabilities::AuditEntryId;
use astrid_core::PrincipalId;
use astrid_crypto::ContentHash;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::audit::{REDACTED, Redactor, RequestCommitment, canonical_headers, redacted_path};
use super::{HttpMethod, HttpRequestData, KeyValuePair};
use crate::audit_sink::{HostAuditEvent, HostAuditOutcome, HostAuditReceipt, HostAuditSink};
use crate::engine::wasm::host_state::HostState;
use crate::engine::wasm::test_fixtures::minimal_host_state;
use crate::security::{AllowAllGate, DenyAllGate};

const SECRET: &str = "sk-live-0123456789abcdef";

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

// ── Redaction and commitments ─────────────────────────────────────────────

#[test]
fn credential_headers_are_redacted_by_name() {
    let redactor = Redactor::new(std::iter::empty());
    let canonical = canonical_headers(
        &headers(&[
            ("Content-Type", "application/json"),
            ("Authorization", "Bearer abc"),
            ("X-Api-Key", "k-123"),
            ("Cookie", "session=1"),
        ]),
        &redactor,
    );
    let text = String::from_utf8(canonical).unwrap();
    assert_eq!(
        text,
        format!(
            "authorization:{REDACTED}\ncontent-type:application/json\ncookie:{REDACTED}\n\
             x-api-key:{REDACTED}\n"
        )
    );
}

#[test]
fn credential_query_values_are_redacted_by_name() {
    let url =
        reqwest::Url::parse("https://api.example.com/v1/models?key=abc&q=cats&API_KEY=x&flag")
            .unwrap();
    assert_eq!(
        redacted_path(&url),
        format!("/v1/models?key={REDACTED}&q=cats&API_KEY={REDACTED}&flag")
    );
}

#[test]
fn revealed_secret_values_are_redacted_everywhere() {
    let secrets = [SECRET];
    let redactor = Redactor::new(secrets.iter().copied());
    let body = format!(r#"{{"note":"key is {SECRET}","again":"{SECRET}"}}"#);
    let redacted = redactor.redact(body.as_bytes());
    assert!(!contains(&redacted, SECRET));
    assert_eq!(
        redacted.as_ref(),
        format!(r#"{{"note":"key is {REDACTED}","again":"{REDACTED}"}}"#).as_bytes()
    );

    let canonical = canonical_headers(
        &headers(&[("X-Custom", &format!("token {SECRET}"))]),
        &redactor,
    );
    assert!(!contains(&canonical, SECRET));

    // Content without the secret is committed unchanged, without copying.
    assert!(matches!(
        redactor.redact(b"plain"),
        std::borrow::Cow::Borrowed(_)
    ));
}

/// Short secrets and any number of distinct secrets are all redacted: a value
/// left out would reach the commitment in the clear, where a low-entropy one
/// could be recovered by hashing candidates.
#[test]
fn every_revealed_secret_is_redacted_regardless_of_length_or_count() {
    let mut revealed = super::audit::RevealedSecrets::default();
    let many: Vec<String> = (0..40).map(|i| format!("secret-{i:02}")).collect();
    for value in &many {
        revealed.note(value);
    }
    revealed.note("k9z");
    let body = format!("pin=k9z&last={}&first={}", many[39], many[0]);

    let redactor = super::audit::Redactor::new(revealed_values(&revealed));
    let redacted = redactor.redact(body.as_bytes());
    assert_eq!(
        redacted.as_ref(),
        format!("pin={REDACTED}&last={REDACTED}&first={REDACTED}").as_bytes()
    );
}

/// At each position the longest secret wins and replaced text is not
/// rescanned, so the redacted form is a deterministic function of the input.
#[test]
fn redaction_is_a_single_longest_match_pass() {
    let secrets = ["abc", "abcdef", "D]x"];
    let redactor = Redactor::new(secrets.iter().copied());
    assert_eq!(
        redactor.redact(b"xabcdefabcx").as_ref(),
        format!("x{REDACTED}{REDACTED}x").as_bytes()
    );
}

fn revealed_values(revealed: &super::audit::RevealedSecrets) -> impl Iterator<Item = &str> {
    revealed.iter()
}

/// The commitment is the plain BLAKE3 of the redacted forms, so a verifier
/// holding the request can recompute it.
#[test]
fn commitment_hashes_the_redacted_forms() {
    let secrets = [SECRET];
    let redactor = Redactor::new(secrets.iter().copied());
    let url = reqwest::Url::parse("https://api.example.com/v1/chat?token=t0k&x=1").unwrap();
    let hdrs = headers(&[("Authorization", &format!("Bearer {SECRET}"))]);
    let body = format!("prompt with {SECRET}");
    let commitment = RequestCommitment::compute(&url, &hdrs, Some(body.as_bytes()), &redactor);

    assert_eq!(
        commitment.path_hash,
        ContentHash::hash(format!("/v1/chat?token={REDACTED}&x=1").as_bytes())
    );
    assert_eq!(
        commitment.headers_hash,
        ContentHash::hash(format!("authorization:{REDACTED}\n").as_bytes())
    );
    assert_eq!(
        commitment.body_hash,
        ContentHash::hash(format!("prompt with {REDACTED}").as_bytes())
    );
    assert_eq!(commitment.body_len, body.len() as u64);
    assert_ne!(
        commitment.body_hash,
        ContentHash::hash(body.as_bytes()),
        "the secret must not be part of the committed bytes"
    );
}

// ── Recording sink ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Recorded {
    Commit {
        sequence: u64,
        method: String,
        host: String,
        body_hash: ContentHash,
        headers_hash: ContentHash,
        sent_during_commit: bool,
    },
    Denied {
        reason: String,
    },
    Response {
        sequence: Option<u64>,
        entry_id: Option<AuditEntryId>,
        status: Option<u16>,
        body_hash: Option<ContentHash>,
        body_len: u64,
        complete: bool,
        request_ids: Vec<(String, String)>,
        failed: bool,
        /// Written through the durable `commit` path, not the queue.
        durable: bool,
    },
}

fn response_record(
    response: &crate::audit_sink::HostHttpResponse<'_>,
    outcome: HostAuditOutcome<'_>,
    durable: bool,
) -> Recorded {
    Recorded::Response {
        sequence: response.request.sequence,
        entry_id: response.request.entry_id.clone(),
        status: response.status,
        body_hash: response.body_hash,
        body_len: response.body_len,
        complete: response.complete,
        request_ids: response.provider_request_ids.to_vec(),
        failed: !matches!(outcome, HostAuditOutcome::Allowed),
        durable,
    }
}

/// Test sink: numbers pre-commits, holds each pre-commit open for a while
/// and notes whether the server saw the request in the meantime.
#[derive(Default)]
struct HttpSink {
    records: Mutex<Vec<Recorded>>,
    next: AtomicU64,
    server_hit: Arc<AtomicBool>,
}

impl HttpSink {
    fn records(&self) -> Vec<Recorded> {
        self.records.lock().unwrap().clone()
    }
}

impl HostAuditSink for HttpSink {
    fn record(
        &self,
        _principal: &PrincipalId,
        event: HostAuditEvent<'_>,
        outcome: HostAuditOutcome<'_>,
    ) {
        let recorded = match (event, outcome) {
            (HostAuditEvent::HttpRequest(_), HostAuditOutcome::Denied(reason)) => {
                Recorded::Denied {
                    reason: reason.to_owned(),
                }
            },
            (HostAuditEvent::HttpResponse(response), outcome) => {
                response_record(&response, outcome, false)
            },
            _ => return,
        };
        self.records.lock().unwrap().push(recorded);
    }

    fn commit<'a>(
        &'a self,
        _principal: &'a PrincipalId,
        event: HostAuditEvent<'a>,
        outcome: HostAuditOutcome<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostAuditReceipt> + Send + 'a>> {
        if let HostAuditEvent::HttpResponse(response) = event {
            self.records
                .lock()
                .unwrap()
                .push(response_record(&response, outcome, true));
            return Box::pin(std::future::ready(HostAuditReceipt::default()));
        }
        let HostAuditEvent::HttpRequest(request) = event else {
            return Box::pin(std::future::ready(HostAuditReceipt::default()));
        };
        let sequence = self.next.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        let method = request.method.to_owned();
        let host = request.host.to_owned();
        let (body_hash, headers_hash) = (request.body_hash, request.headers_hash);
        Box::pin(async move {
            // Hold the pre-commit open: a request sent before the commit
            // resolved would reach the server during this window.
            tokio::time::sleep(Duration::from_millis(100)).await;
            self.records.lock().unwrap().push(Recorded::Commit {
                sequence,
                method,
                host,
                body_hash,
                headers_hash,
                sent_during_commit: self.server_hit.load(Ordering::SeqCst),
            });
            HostAuditReceipt {
                sequence: Some(sequence),
                entry_id: Some(AuditEntryId::new()),
            }
        })
    }
}

/// Loopback server answering one request with `response`; sets `hit` when a
/// connection is accepted. `None` if the sandbox blocks loopback binds.
async fn server(
    response: Vec<u8>,
    hit: Arc<AtomicBool>,
) -> Option<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
        Err(e) => panic!("loopback bind failed: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            hit.store(true, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(&response).await;
            let _ = sock.flush().await;
        }
    });
    Some((addr, handle))
}

fn audited_state(port: u16, sink: &Arc<HttpSink>) -> HostState {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    state.security = Some(Arc::new(AllowAllGate));
    state.local_egress = vec![format!("127.0.0.1:{port}")];
    state.audit_sink = Some(Arc::clone(sink) as Arc<dyn HostAuditSink>);
    state
}

fn post(url: String, body: &str, extra: &[(&str, &str)]) -> HttpRequestData {
    HttpRequestData {
        url,
        method: HttpMethod::Post,
        headers: extra
            .iter()
            .map(|(key, value)| KeyValuePair {
                key: (*key).to_owned(),
                value: (*value).to_owned(),
            })
            .collect(),
        body: Some(body.as_bytes().to_vec()),
    }
}

const RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nx-request-id: req_abc\r\n\r\nhello";

// ── Buffered exchange ─────────────────────────────────────────────────────

/// The pre-commit resolves before the request reaches the server; the
/// completion carries the pre-commit's sequence and entry id, the status,
/// the response body hash and the provider request id; the committed body
/// and header hashes exclude a secret the guest read and put in the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn buffered_request_is_precommitted_then_completed() {
    let sink = Arc::new(HttpSink::default());
    let Some((addr, server)) = server(RESPONSE.to_vec(), Arc::clone(&sink.server_hit)).await else {
        return;
    };
    let mut state = audited_state(addr.port(), &sink);
    state.revealed_secrets.note(SECRET);

    let body = format!(r#"{{"messages":[],"key":"{SECRET}"}}"#);
    let request = post(
        format!("http://{addr}/v1/chat"),
        &body,
        &[("Authorization", &format!("Bearer {SECRET}"))],
    );
    let limits = state.http_limits;
    let response = state
        .http_request_backend(
            request,
            super::options::ResolvedOptions::v10_defaults(&limits),
        )
        .await
        .expect("request succeeds");
    assert_eq!(response.body, b"hello");
    let _ = server.await;

    let records = sink.records();
    assert_eq!(records.len(), 2, "{records:?}");
    let Recorded::Commit {
        sequence,
        ref method,
        ref host,
        body_hash,
        headers_hash,
        sent_during_commit,
    } = records[0]
    else {
        panic!("first record must be the pre-commit: {records:?}");
    };
    assert!(!sent_during_commit, "request left before the pre-commit");
    assert_eq!((method.as_str(), host.as_str()), ("POST", "127.0.0.1"));
    assert_eq!(
        body_hash,
        ContentHash::hash(format!(r#"{{"messages":[],"key":"{REDACTED}"}}"#).as_bytes())
    );
    assert_eq!(
        headers_hash,
        ContentHash::hash(format!("authorization:{REDACTED}\n").as_bytes())
    );
    let Recorded::Response {
        sequence: response_sequence,
        ref entry_id,
        status,
        body_hash,
        body_len,
        complete,
        ref request_ids,
        failed,
        durable,
    } = records[1]
    else {
        panic!("second record must be the completion: {records:?}");
    };
    assert!(durable, "completions use the durable path");
    assert_eq!(response_sequence, Some(sequence));
    assert!(entry_id.is_some());
    assert_eq!(status, Some(200));
    assert_eq!(body_hash, Some(ContentHash::hash(b"hello")));
    assert_eq!(body_len, 5);
    assert!(complete && !failed);
    assert_eq!(
        request_ids,
        &vec![("x-request-id".to_owned(), "req_abc".to_owned())]
    );
}

// ── Streaming exchange ────────────────────────────────────────────────────

/// The stream's completion is recorded at end of body with the hash of every
/// delivered chunk.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streamed_response_is_hashed_as_it_is_read() {
    let sink = Arc::new(HttpSink::default());
    let response = b"HTTP/1.1 200 OK\r\nrequest-id: r-9\r\nContent-Length: 11\r\n\r\nhello world";
    let Some((addr, server)) = server(response.to_vec(), Arc::clone(&sink.server_hit)).await else {
        return;
    };
    let mut state = audited_state(addr.port(), &sink);
    let limits = state.http_limits;
    let stream = state
        .http_stream_backend(
            post(format!("http://{addr}/stream"), "{}", &[]),
            super::options::ResolvedOptions::v10_defaults(&limits),
        )
        .await
        .expect("stream opens");
    let mut delivered = Vec::new();
    loop {
        let chunk = super::backend::stream_read_chunk(&mut state, stream.rep())
            .await
            .expect("chunk");
        if chunk.is_empty() {
            break;
        }
        delivered.extend_from_slice(&chunk);
    }
    assert_eq!(delivered, b"hello world");
    let _ = server.await;

    let records = sink.records();
    let completion = records
        .iter()
        .find_map(|r| match r {
            Recorded::Response {
                body_hash,
                body_len,
                complete,
                request_ids,
                durable: true,
                ..
            } => Some((*body_hash, *body_len, *complete, request_ids.clone())),
            _ => None,
        })
        .expect("completion recorded at end of body");
    assert_eq!(
        completion,
        (
            Some(ContentHash::hash(b"hello world")),
            11,
            true,
            vec![("request-id".to_owned(), "r-9".to_owned())]
        )
    );

    // Closing after end of body does not record a second completion.
    super::backend::stream_drop(&mut state, stream.rep());
    let completions = sink
        .records()
        .iter()
        .filter(|r| matches!(r, Recorded::Response { .. }))
        .count();
    assert_eq!(completions, 1);
}

/// A stream the guest drops before the end records one successful but
/// incomplete completion covering the bytes delivered so far.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_dropped_early_is_completed_incomplete() {
    let sink = Arc::new(HttpSink::default());
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world";
    let Some((addr, server)) = server(response.to_vec(), Arc::clone(&sink.server_hit)).await else {
        return;
    };
    let mut state = audited_state(addr.port(), &sink);
    let limits = state.http_limits;
    let stream = state
        .http_stream_backend(
            post(format!("http://{addr}/stream"), "{}", &[]),
            super::options::ResolvedOptions::v10_defaults(&limits),
        )
        .await
        .expect("stream opens");
    super::backend::stream_drop(&mut state, stream.rep());
    let _ = server.await;

    // A drop is synchronous, so the durable append runs as a task.
    let completions = loop {
        let completions: Vec<_> = sink
            .records()
            .iter()
            .filter_map(|r| match r {
                Recorded::Response {
                    body_len,
                    complete,
                    failed,
                    durable,
                    ..
                } => Some((*body_len, *complete, *failed, *durable)),
                _ => None,
            })
            .collect();
        if !completions.is_empty() {
            break completions;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(completions, vec![(0, false, false, true)]);
}

// ── Failures and denials ──────────────────────────────────────────────────

/// A request that fails in transport after its pre-commit still gets a
/// (failed) completion without a status.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_failure_completes_the_exchange() {
    let port = {
        let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:0") else {
            return;
        };
        listener.local_addr().unwrap().port()
    };
    let sink = Arc::new(HttpSink::default());
    let mut state = audited_state(port, &sink);
    let limits = state.http_limits;
    let result = state
        .http_request_backend(
            post(format!("http://127.0.0.1:{port}/"), "{}", &[]),
            super::options::ResolvedOptions::v10_defaults(&limits),
        )
        .await;
    assert!(result.is_err());

    let records = sink.records();
    assert!(matches!(records[0], Recorded::Commit { .. }), "{records:?}");
    assert!(
        matches!(
            records[1],
            Recorded::Response {
                status: None,
                body_hash: None,
                complete: false,
                failed: true,
                durable: true,
                ..
            }
        ),
        "{records:?}"
    );
}

/// A request the security gate refuses is recorded as denied and never
/// pre-committed or sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gate_denied_request_is_recorded_as_denied() {
    let sink = Arc::new(HttpSink::default());
    let mut state = audited_state(9, &sink);
    state.security = Some(Arc::new(DenyAllGate));
    let limits = state.http_limits;
    let result = state
        .http_request_backend(
            post("https://api.example.com/v1/chat".to_owned(), "{}", &[]),
            super::options::ResolvedOptions::v10_defaults(&limits),
        )
        .await;
    assert!(matches!(result, Err(super::ErrorCode::CapabilityDenied)));
    let records = sink.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert!(
        matches!(&records[0], Recorded::Denied { reason } if reason == "security gate denied"),
        "{records:?}"
    );
}

/// A request refused by the caller's https-only option is recorded as denied
/// and never sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_only_refusal_is_recorded_as_denied() {
    let sink = Arc::new(HttpSink::default());
    let mut state = audited_state(9, &sink);
    let limits = state.http_limits;
    let mut opts = super::options::ResolvedOptions::v10_defaults(&limits);
    opts.https_only = true;
    let result = state
        .http_request_backend(
            post("http://api.example.com/v1/chat".to_owned(), "{}", &[]),
            opts,
        )
        .await;
    assert!(matches!(result, Err(super::ErrorCode::SchemeDenied)));
    let records = sink.records();
    assert!(
        matches!(records.as_slice(), [Recorded::Denied { reason }] if reason == "scheme denied"),
        "{records:?}"
    );
}
