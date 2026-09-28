//! Kernel mapping of HTTP exchange records: durable pre-commits, the
//! per-principal request sequence, and completions linked to their request.

use std::sync::Arc;

use astrid_audit::{AuditAction, AuditLog, AuditOutcome, AuthorizationProof};
use astrid_capsule::{
    HostAuditActor, HostAuditEvent, HostAuditOutcome, HostAuditReceipt, HostAuditSink,
    HostHttpRequest, HostHttpResponse,
};
use astrid_config::types::AuditConfig;
use astrid_core::{PrincipalId, SessionId};
use astrid_crypto::{ContentHash, KeyPair};

use super::{HostAuditPolicy, KernelAuditSink};

fn sink(log: &Arc<AuditLog>, session: &SessionId) -> KernelAuditSink {
    KernelAuditSink::with_policy(
        Arc::clone(log),
        session.clone(),
        HostAuditPolicy::from(&AuditConfig {
            host_coalesce_ms: 10,
            ..AuditConfig::default()
        }),
    )
}

fn request(host: &str) -> HostHttpRequest<'_> {
    HostHttpRequest {
        method: "POST",
        host,
        port: 443,
        path_hash: ContentHash::hash(b"/v1/chat"),
        headers_hash: ContentHash::hash(b"authorization:[REDACTED]\n"),
        body_hash: ContentHash::hash(b"{}"),
        body_len: 2,
        redirect_hop: 0,
        injected_secrets: &[],
    }
}

/// `commit` returns only after the entry is in the log, numbers requests per
/// principal from 1, and stamps the capsule identity of the handle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn precommit_is_durable_on_return_and_numbered_per_principal() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0b01));
    let kernel_sink = sink(&log, &session);
    let fetcher = kernel_sink
        .attributed(HostAuditActor {
            capsule_id: "llm".to_owned(),
            wasm_hash: Some(ContentHash::hash(b"llm")),
        })
        .expect("attributed");
    let alice = PrincipalId::new("alice").expect("principal");
    let bob = PrincipalId::new("bob").expect("principal");

    let first = fetcher
        .commit(
            &alice,
            HostAuditEvent::HttpRequest(request("api.example.com")),
        )
        .await;
    let second = fetcher
        .commit(
            &alice,
            HostAuditEvent::HttpRequest(request("api.example.com")),
        )
        .await;
    let other = kernel_sink
        .commit(
            &bob,
            HostAuditEvent::HttpRequest(request("api.example.com")),
        )
        .await;
    assert_eq!(
        (first.sequence, second.sequence, other.sequence),
        (Some(1), Some(2), Some(1))
    );

    // Durable on return: readable without waiting for the queued writer.
    let entry = log
        .get(first.entry_id.as_ref().expect("appended"))
        .await
        .expect("read")
        .expect("present");
    assert_eq!(entry.principal.as_ref(), Some(&alice));
    let AuditAction::HttpRequest {
        sequence,
        ref method,
        ref host,
        port,
        body_len,
        ref actor,
        ..
    } = entry.action
    else {
        panic!("unexpected action {:?}", entry.action);
    };
    assert_eq!(
        (sequence, method.as_str(), host.as_str(), port, body_len),
        (1, "POST", "api.example.com", 443, 2)
    );
    assert_eq!(actor.as_ref().map(|a| a.capsule_id.as_str()), Some("llm"));
    assert!(matches!(entry.outcome, AuditOutcome::Success { .. }));
    kernel_sink.shutdown();
}

/// A denied request takes the next number too, and a completion carries the
/// request's number and entry id plus bounded provider request ids.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denial_takes_a_number_and_completion_links_to_its_request() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0b02));
    let kernel_sink = sink(&log, &session);
    let alice = PrincipalId::new("alice").expect("principal");

    let receipt: HostAuditReceipt = kernel_sink
        .commit(
            &alice,
            HostAuditEvent::HttpRequest(request("api.example.com")),
        )
        .await;
    kernel_sink.record(
        &alice,
        HostAuditEvent::HttpRequest(request("blocked.example.com")),
        HostAuditOutcome::Denied("security gate denied"),
    );
    let ids: Vec<(String, String)> = (0..12)
        .map(|i| (format!("x-request-id-{i}"), "v".repeat(500)))
        .collect();
    kernel_sink.record(
        &alice,
        HostAuditEvent::HttpResponse(HostHttpResponse {
            request: &receipt,
            status: Some(200),
            body_hash: Some(ContentHash::hash(b"hello")),
            body_len: 5,
            complete: true,
            provider_request_ids: &ids,
        }),
        HostAuditOutcome::Allowed,
    );
    kernel_sink.shutdown();

    let entries = log.get_session_entries(&session).await.expect("entries");
    let denied = entries
        .iter()
        .find_map(|e| match (&e.action, &e.authorization) {
            (
                AuditAction::HttpRequest { sequence, host, .. },
                AuthorizationProof::Denied { .. },
            ) if host == "blocked.example.com" => Some(*sequence),
            _ => None,
        })
        .expect("denied request recorded");
    assert_eq!(denied, 2);

    let completion = entries
        .iter()
        .find_map(|e| match &e.action {
            AuditAction::HttpResponse {
                sequence,
                request_entry_id,
                status,
                body_hash,
                provider_request_ids,
                ..
            } => Some((
                *sequence,
                request_entry_id.clone(),
                *status,
                *body_hash,
                provider_request_ids.clone(),
            )),
            _ => None,
        })
        .expect("completion recorded");
    assert_eq!(completion.0, 1);
    assert_eq!(completion.1, receipt.entry_id);
    assert_eq!(completion.2, Some(200));
    assert_eq!(completion.3, Some(ContentHash::hash(b"hello")));
    assert_eq!(completion.4.len(), 8, "provider ids are capped");
    assert!(completion.4.iter().all(|id| id.value.len() <= 128));
    assert!(log.verify_chain(&session).await.expect("verify").valid);
}
