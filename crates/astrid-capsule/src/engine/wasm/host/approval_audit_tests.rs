//! Audit records of command approvals: the prompt is committed before it is
//! published and every check records one decision linked to its prompt.

use std::sync::{Arc, Mutex};

use astrid_capabilities::AuditEntryId;
use astrid_core::PrincipalId;

use super::tests::{answer_action_request, approval_request, persistent_test_state};
use super::*;
use crate::audit_sink::{
    HostApprovalScope, HostAuditEvent, HostAuditOutcome, HostAuditReceipt, HostAuditSink,
};

#[derive(Debug, Clone, PartialEq)]
struct Decision {
    request_id: Option<String>,
    request_entry_id: Option<AuditEntryId>,
    scope: Option<HostApprovalScope>,
    via: String,
    denied: bool,
}

/// Records approval prompts (committed) and decisions (queued).
#[derive(Default)]
struct ApprovalSink {
    requests: Mutex<Vec<(String, AuditEntryId)>>,
    decisions: Mutex<Vec<Decision>>,
}

impl HostAuditSink for ApprovalSink {
    fn record(
        &self,
        _principal: &PrincipalId,
        event: HostAuditEvent<'_>,
        outcome: HostAuditOutcome<'_>,
    ) {
        if let HostAuditEvent::ApprovalDecided(decision) = event {
            self.decisions.lock().unwrap().push(Decision {
                request_id: decision.request_id.map(str::to_owned),
                request_entry_id: decision.request.and_then(|r| r.entry_id.clone()),
                scope: decision.scope,
                via: decision.via.to_owned(),
                denied: matches!(outcome, HostAuditOutcome::Denied(_)),
            });
        }
    }

    fn commit<'a>(
        &'a self,
        _principal: &'a PrincipalId,
        event: HostAuditEvent<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostAuditReceipt> + Send + 'a>> {
        let receipt = match event {
            HostAuditEvent::ApprovalRequested { request_id, .. } => {
                let entry_id = AuditEntryId::new();
                self.requests
                    .lock()
                    .unwrap()
                    .push((request_id.to_owned(), entry_id.clone()));
                HostAuditReceipt {
                    sequence: None,
                    entry_id: Some(entry_id),
                }
            },
            _ => HostAuditReceipt::default(),
        };
        Box::pin(std::future::ready(receipt))
    }
}

fn audited(state: &mut HostState) -> Arc<ApprovalSink> {
    let sink = Arc::new(ApprovalSink::default());
    state.audit_sink = Some(Arc::clone(&sink) as Arc<dyn HostAuditSink>);
    sink
}

/// Each user answer records one decision that names the prompt it answers
/// and the prompt's entry id, with the granted scope.
#[tokio::test]
async fn user_decisions_are_linked_to_their_prompt() {
    for (reply, scope) in [
        ("approve", Some(HostApprovalScope::Once)),
        ("approve_session", Some(HostApprovalScope::Session)),
        ("approve_always", Some(HostApprovalScope::Always)),
        ("deny", None),
    ] {
        let home = tempfile::tempdir().unwrap();
        let mut state = persistent_test_state(home.path());
        let sink = audited(&mut state);
        answer_action_request(state, reply).await.unwrap();

        let requests = sink.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 1, "{reply}: one committed prompt");
        let (request_id, entry_id) = requests[0].clone();
        assert_eq!(
            sink.decisions.lock().unwrap().clone(),
            vec![Decision {
                request_id: Some(request_id),
                request_entry_id: Some(entry_id),
                scope,
                via: "user".to_owned(),
                denied: scope.is_none(),
            }],
            "{reply}"
        );
    }
}

/// The prompt a user sees was committed first: its id is the committed one.
#[tokio::test]
async fn prompt_is_committed_before_it_is_published() {
    let home = tempfile::tempdir().unwrap();
    let mut state = persistent_test_state(home.path());
    let sink = audited(&mut state);
    let owner = super::tests::install_request_owner(&mut state);
    let bus = state.event_bus.clone();
    let mut prompts = bus.subscribe_topic(Topic::approval_request().as_str());
    let task = tokio::task::spawn_blocking(move || {
        approval::Host::request_approval(
            &mut state,
            approval_request("git push", "git push origin main"),
        )
    });
    let event = prompts.recv().await.expect("prompt published");
    let AstridEvent::Ipc { message, .. } = &*event else {
        panic!("unexpected event");
    };
    let IpcPayload::ApprovalRequired { request_id, .. } = &message.payload else {
        panic!("unexpected payload");
    };
    // By the time the prompt is observable, its record is already committed.
    let committed = sink.requests.lock().unwrap().clone();
    assert_eq!(committed.len(), 1);
    assert_eq!(&committed[0].0, request_id);

    super::tests::publish_approval_reply(
        &bus,
        request_id,
        message.principal.as_deref(),
        Some(owner),
        "approve",
    );
    task.await.unwrap().unwrap();
}

/// A check refused before any prompt records a denial without a request.
#[tokio::test]
async fn missing_request_owner_is_a_recorded_denial() {
    let home = tempfile::tempdir().unwrap();
    let mut state = persistent_test_state(home.path());
    let sink = audited(&mut state);
    let response = tokio::task::spawn_blocking(move || {
        approval::Host::request_approval(
            &mut state,
            approval_request("git push", "git push origin main"),
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.decision, ApprovalDecision::Denied);
    assert!(sink.requests.lock().unwrap().is_empty());
    let decisions = sink.decisions.lock().unwrap().clone();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].via, "no_request_owner");
    assert!(decisions[0].denied && decisions[0].request_id.is_none());
}

/// A remembered `approve_always` answers later checks without a prompt; the
/// decision says so.
#[tokio::test]
async fn remembered_consent_is_recorded_as_such() {
    let home = tempfile::tempdir().unwrap();
    answer_action_request(persistent_test_state(home.path()), "approve_always")
        .await
        .unwrap();

    let mut state = persistent_test_state(home.path());
    let sink = audited(&mut state);
    let response = tokio::task::spawn_blocking(move || {
        approval::Host::request_approval(
            &mut state,
            approval_request("git push", "git push origin main"),
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.decision, ApprovalDecision::Allowance);
    assert!(sink.requests.lock().unwrap().is_empty());
    let decisions = sink.decisions.lock().unwrap().clone();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].scope, Some(HostApprovalScope::Always));
    assert_eq!(decisions[0].via, "remembered_consent");
}
