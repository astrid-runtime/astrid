//! Kernel mapping of tool-call and approval records.

use std::sync::Arc;

use astrid_audit::{ApprovalScope, AuditAction, AuditLog, AuditOutcome, AuthorizationProof};
use astrid_capsule::{
    HostApprovalDecision, HostApprovalScope, HostAuditEvent, HostAuditOutcome, HostAuditSink,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tool_call_maps_to_capsule_tool_call() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0c01));
    let kernel_sink = sink(&log, &session);
    let alice = PrincipalId::new("alice").expect("principal");
    kernel_sink.record(
        &alice,
        HostAuditEvent::ToolCall {
            capsule_id: "search-tool",
            tool: "search",
            call_id: Some("call-1"),
            args_hash: ContentHash::hash(b"{\"q\":1}"),
            result_hash: Some(ContentHash::hash(b"3 results")),
        },
        HostAuditOutcome::Allowed,
    );
    kernel_sink.shutdown();

    let entries = log.get_session_entries(&session).await.expect("entries");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    let AuditAction::CapsuleToolCall {
        capsule_id,
        tool,
        args_hash,
        call_id,
        result_hash,
        ..
    } = &entry.action
    else {
        panic!("unexpected action {:?}", entry.action);
    };
    assert_eq!(
        (capsule_id.as_str(), tool.as_str()),
        ("search-tool", "search")
    );
    assert_eq!(*args_hash, ContentHash::hash(b"{\"q\":1}"));
    assert_eq!(call_id.as_deref(), Some("call-1"));
    assert_eq!(*result_hash, Some(ContentHash::hash(b"3 results")));
    assert!(matches!(
        &entry.authorization,
        AuthorizationProof::System { reason } if reason == "kernel-dispatched tool invocation"
    ));
    assert!(matches!(entry.outcome, AuditOutcome::Success { .. }));
}

/// The committed prompt and the queued decisions are linked by request id and
/// by the prompt's entry id; a denial carries how it was reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_request_and_decisions_are_linked() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0c02));
    let kernel_sink = sink(&log, &session);
    let alice = PrincipalId::new("alice").expect("principal");

    let receipt = kernel_sink
        .commit(
            &alice,
            HostAuditEvent::ApprovalRequested {
                request_id: "req-1",
                action: "git push",
                resource: "git push origin main",
            },
            HostAuditOutcome::Allowed,
        )
        .await;
    let decision = |scope, via| {
        HostAuditEvent::ApprovalDecided(HostApprovalDecision {
            request_id: Some("req-1"),
            request: Some(&receipt),
            action: "git push",
            resource: "git push origin main",
            scope,
            via,
        })
    };
    kernel_sink.record(
        &alice,
        decision(Some(HostApprovalScope::Session), "user"),
        HostAuditOutcome::Allowed,
    );
    kernel_sink.record(
        &alice,
        decision(None, "timeout"),
        HostAuditOutcome::Denied("no response before the timeout"),
    );
    kernel_sink.shutdown();

    let request_entry = log
        .get(receipt.entry_id.as_ref().expect("committed"))
        .await
        .expect("read")
        .expect("present");
    assert!(matches!(
        &request_entry.action,
        AuditAction::ApprovalRequested { request_id: Some(id), action_type, .. }
            if id == "req-1" && action_type == "git push"
    ));

    let entries = log.get_session_entries(&session).await.expect("entries");
    let granted = entries
        .iter()
        .find_map(|e| match &e.action {
            AuditAction::ApprovalGranted {
                scope,
                request_id,
                request_entry_id,
                via,
                ..
            } => Some((
                *scope,
                request_id.clone(),
                request_entry_id.clone(),
                via.clone(),
            )),
            _ => None,
        })
        .expect("grant recorded");
    assert_eq!(
        granted,
        (
            ApprovalScope::Session,
            Some("req-1".to_owned()),
            receipt.entry_id.clone(),
            Some("user".to_owned())
        )
    );
    let denied = entries
        .iter()
        .find(|e| matches!(e.action, AuditAction::ApprovalDenied { .. }))
        .expect("denial recorded");
    assert!(matches!(
        &denied.action,
        AuditAction::ApprovalDenied { reason: Some(reason), request_entry_id, .. }
            if reason == "timeout" && *request_entry_id == receipt.entry_id
    ));
    assert!(matches!(
        denied.authorization,
        AuthorizationProof::Denied { .. }
    ));
    assert!(log.verify_chain(&session).await.expect("verify").valid);
}
