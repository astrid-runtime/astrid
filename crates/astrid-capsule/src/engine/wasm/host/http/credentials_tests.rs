//! Tests for host-side credential injection (`{{secret:NAME}}` header
//! placeholders).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use astrid_core::PrincipalId;
use astrid_crypto::ContentHash;
use astrid_storage::secret::{SecretStore, SecretStoreError};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

use super::audit::{Redactor, canonical_headers};
use super::credentials::{InjectError, strip_injected, substitute_headers};
use super::{ErrorCode, HttpMethod, HttpRequestData, KeyValuePair};
use crate::audit_sink::{HostAuditEvent, HostAuditOutcome, HostAuditReceipt, HostAuditSink};
use crate::engine::wasm::test_fixtures::minimal_host_state;
use crate::security::AllowAllGate;

const SECRET: &str = "sk-live-inject-0123456789";

fn template(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

fn resolver(
    secrets: &[(&'static str, &'static str)],
) -> impl FnMut(&str) -> Result<Zeroizing<String>, InjectError> {
    let secrets: HashMap<&str, &str> = secrets.iter().copied().collect();
    move |name| match secrets.get(name) {
        Some(value) => Ok(Zeroizing::new((*value).to_owned())),
        None => Err(InjectError::Undeclared(name.to_owned())),
    }
}

// ── Substitution rules ────────────────────────────────────────────────────

#[test]
fn placeholders_are_replaced_and_named_once() {
    let injected = substitute_headers(
        &template(&[
            ("Authorization", "Bearer {{secret:api_key}}"),
            ("X-Pair", "{{secret:api_key}}:{{secret:org}}"),
            ("Accept", "application/json"),
        ]),
        resolver(&[("api_key", SECRET), ("org", " org-42\n")]),
    )
    .expect("injects");
    assert_eq!(
        injected.headers["authorization"].as_bytes(),
        format!("Bearer {SECRET}").as_bytes()
    );
    assert!(injected.headers["authorization"].is_sensitive());
    assert_eq!(
        injected.headers["x-pair"].as_bytes(),
        format!("{SECRET}:org-42").as_bytes()
    );
    assert_eq!(injected.headers["accept"], "application/json");
    assert_eq!(injected.names, ["api_key", "org"]);
}

#[test]
fn blank_secret_omits_the_header() {
    let injected = substitute_headers(
        &template(&[
            ("Authorization", "Bearer {{secret:api_key}}"),
            ("Accept", "*/*"),
        ]),
        resolver(&[("api_key", "  ")]),
    )
    .expect("injects");
    assert!(injected.headers.get("authorization").is_none());
    assert_eq!(injected.headers.len(), 1);
    assert!(injected.names.is_empty());
}

#[test]
fn malformed_undeclared_and_unsendable_values_are_refused() {
    for value in [
        "Bearer {{secret:api_key",
        "{{secret:}}",
        "{{secret:bad name}}",
    ] {
        assert_eq!(
            substitute_headers(
                &template(&[("Authorization", value)]),
                resolver(&[("api_key", SECRET)])
            )
            .err(),
            Some(InjectError::Malformed),
            "{value}"
        );
    }
    let undeclared = substitute_headers(
        &template(&[("Authorization", "{{secret:other}}")]),
        resolver(&[("api_key", SECRET)]),
    )
    .err();
    assert_eq!(
        undeclared,
        Some(InjectError::Undeclared("other".to_owned()))
    );
    assert!(matches!(
        undeclared.map(|e| e.code()),
        Some(ErrorCode::CapabilityDenied)
    ));
    assert_eq!(
        substitute_headers(
            &template(&[("Authorization", "{{secret:api_key}}")]),
            resolver(&[("api_key", "line\r\nX-Evil: 1")])
        )
        .err(),
        Some(InjectError::InvalidValue)
    );
}

#[test]
fn cross_origin_strip_removes_placeholder_headers_only() {
    let mut headers = template(&[("X-Api-Key", "{{secret:api_key}}"), ("X-Trace", "abc")]);
    strip_injected(&mut headers);
    assert!(headers.get("x-api-key").is_none());
    assert_eq!(headers["x-trace"], "abc");
}

// ── End to end through the HTTP host ──────────────────────────────────────

#[derive(Debug, Default)]
struct MapSecrets(Mutex<HashMap<String, String>>);

impl SecretStore for MapSecrets {
    fn set(&self, key: &str, value: &str) -> Result<(), SecretStoreError> {
        self.0.lock().unwrap().insert(key.into(), value.into());
        Ok(())
    }
    fn exists(&self, key: &str) -> Result<bool, SecretStoreError> {
        Ok(self.0.lock().unwrap().contains_key(key))
    }
    fn get(&self, key: &str) -> Result<Option<String>, SecretStoreError> {
        Ok(self.0.lock().unwrap().get(key).cloned())
    }
    fn delete(&self, key: &str) -> Result<bool, SecretStoreError> {
        Ok(self.0.lock().unwrap().remove(key).is_some())
    }
}

/// Captures the pre-commit's header commitment and injected names.
#[derive(Default)]
struct CommitSink {
    commits: Mutex<Vec<(ContentHash, Vec<String>)>>,
    denials: Mutex<Vec<String>>,
}

impl HostAuditSink for CommitSink {
    fn record(
        &self,
        _principal: &PrincipalId,
        event: HostAuditEvent<'_>,
        outcome: HostAuditOutcome<'_>,
    ) {
        if let (HostAuditEvent::HttpRequest(_), HostAuditOutcome::Denied(reason)) = (event, outcome)
        {
            self.denials.lock().unwrap().push(reason.to_owned());
        }
    }

    fn commit<'a>(
        &'a self,
        _principal: &'a PrincipalId,
        event: HostAuditEvent<'a>,
        _outcome: HostAuditOutcome<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostAuditReceipt> + Send + 'a>> {
        if let HostAuditEvent::HttpRequest(request) = event {
            self.commits
                .lock()
                .unwrap()
                .push((request.headers_hash, request.injected_secrets.to_vec()));
        }
        Box::pin(std::future::ready(HostAuditReceipt::default()))
    }
}

/// One-shot loopback server that hands back the raw request it received.
async fn capture_server() -> Option<(
    std::net::SocketAddr,
    tokio::task::JoinHandle<Vec<u8>>,
    Arc<AtomicBool>,
)> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
        Err(e) => panic!("loopback bind failed: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    let hit = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&hit);
    let handle = tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return Vec::new();
        };
        seen.store(true, Ordering::SeqCst);
        let mut buf = vec![0u8; 8192];
        let n = sock.read(&mut buf).await.unwrap_or(0);
        buf.truncate(n);
        let _ = sock
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await;
        let _ = sock.flush().await;
        buf
    });
    Some((addr, handle, hit))
}

fn request_with(url: String, headers: &[(&str, &str)]) -> HttpRequestData {
    HttpRequestData {
        url,
        method: HttpMethod::Get,
        headers: headers
            .iter()
            .map(|(key, value)| KeyValuePair {
                key: (*key).to_owned(),
                value: (*value).to_owned(),
            })
            .collect(),
        body: None,
    }
}

/// The secret reaches the wire, the guest never read it, and the audit
/// commitment is computed over the placeholder form and names the secret.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn injected_secret_reaches_the_wire_but_not_the_commitment() {
    let Some((addr, server, _hit)) = capture_server().await else {
        return;
    };
    let sink = Arc::new(CommitSink::default());
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    state.security = Some(Arc::new(AllowAllGate));
    state.local_egress = vec![format!("127.0.0.1:{}", addr.port())];
    state.audit_sink = Some(Arc::clone(&sink) as Arc<dyn HostAuditSink>);
    state.secret_env.insert("api_key".to_owned());
    let secrets = MapSecrets::default();
    secrets.set("api_key", SECRET).unwrap();
    state.secret_store = Arc::new(secrets);

    let header = ("X-Provider-Key", "{{secret:api_key}}");
    let limits = state.http_limits;
    state
        .http_request_backend(
            request_with(format!("http://{addr}/v1/models"), &[header]),
            super::options::ResolvedOptions::v10_defaults(&limits),
        )
        .await
        .expect("request succeeds");
    let wire = String::from_utf8(server.await.unwrap()).unwrap();
    assert!(
        wire.to_ascii_lowercase()
            .contains(&format!("x-provider-key: {SECRET}").to_ascii_lowercase()),
        "{wire}"
    );
    assert!(
        format!("{:?}", state.revealed_secrets).contains("0 values"),
        "the guest never received the secret"
    );

    let commits = sink.commits.lock().unwrap().clone();
    let expected = ContentHash::hash(&canonical_headers(
        &template(&[header]),
        &Redactor::new(std::iter::empty()),
    ));
    assert_eq!(commits, vec![(expected, vec!["api_key".to_owned()])]);
}

/// A placeholder naming a secret the manifest does not declare refuses the
/// request before anything is sent, and the refusal is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn undeclared_secret_is_refused_before_sending() {
    let Some((addr, server, hit)) = capture_server().await else {
        return;
    };
    let sink = Arc::new(CommitSink::default());
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    state.security = Some(Arc::new(AllowAllGate));
    state.local_egress = vec![format!("127.0.0.1:{}", addr.port())];
    state.audit_sink = Some(Arc::clone(&sink) as Arc<dyn HostAuditSink>);

    let limits = state.http_limits;
    let result = state
        .http_request_backend(
            request_with(
                format!("http://{addr}/"),
                &[("Authorization", "Bearer {{secret:api_key}}")],
            ),
            super::options::ResolvedOptions::v10_defaults(&limits),
        )
        .await;
    assert!(matches!(result, Err(ErrorCode::CapabilityDenied)));
    server.abort();
    assert!(!hit.load(Ordering::SeqCst), "nothing may be sent");
    assert!(sink.commits.lock().unwrap().is_empty());
    let denials = sink.denials.lock().unwrap().clone();
    assert_eq!(denials.len(), 1);
    assert!(denials[0].contains("Undeclared"), "{denials:?}");
}
