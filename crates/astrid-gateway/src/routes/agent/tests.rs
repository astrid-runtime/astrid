use std::sync::Arc;
use std::time::Duration;

use astrid_core::kernel_api::MissingImport;
use astrid_events::ipc::IpcPayload as BusIpcPayload;
use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
use astrid_events::{AstridEvent, EventMetadata};
use futures::StreamExt;
use uuid::Uuid;

use super::*;

/// The fail-fast `error` payload must name exactly which piece of the
/// loop is missing, so the client gets an actionable signal instead of a
/// 5-minute silent wait.
#[test]
fn unready_payload_names_missing_pieces() {
    let report = AgentLoopReadiness {
        ready: false,
        prompt_subscribers: vec![],
        response_publishers: vec!["loop".to_string()],
        unsatisfied_required_imports: vec![MissingImport {
            capsule: "loop".to_string(),
            namespace: "astrid".to_string(),
            interface: "llm".to_string(),
            requirement: "^1.0".to_string(),
        }],
        loaded_capsules: vec!["loop".to_string()],
    };
    let payload = unready_payload(&report);
    assert_eq!(payload["error"], "agent loop not ready");
    assert_eq!(payload["missing"]["prompt_subscriber"], true);
    assert_eq!(payload["missing"]["response_publisher"], false);
    let imports = payload["missing"]["unsatisfied_imports"]
        .as_array()
        .expect("unsatisfied_imports is an array");
    assert_eq!(imports.len(), 1);
    assert_eq!(imports[0], "astrid:llm (^1.0)");
}

/// A ready report still serializes. `unready_payload` is only called on the
/// not-ready path, but it must not panic on a ready one.
#[test]
fn unready_payload_ready_report_reports_no_missing() {
    let report = AgentLoopReadiness {
        ready: true,
        prompt_subscribers: vec!["loop".to_string()],
        response_publishers: vec!["loop".to_string()],
        unsatisfied_required_imports: vec![],
        loaded_capsules: vec!["loop".to_string()],
    };
    let payload = unready_payload(&report);
    assert_eq!(payload["missing"]["prompt_subscriber"], false);
    assert_eq!(payload["missing"]["response_publisher"], false);
    assert!(
        payload["missing"]["unsatisfied_imports"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

/// `publish_elicit_response` must publish an `ElicitResponse` onto the
/// per-request reply topic carrying the `request_id`, the value/values, and
/// the caller's principal.
#[tokio::test]
async fn elicit_response_publishes_stamped_reply_on_topic() {
    let bus = astrid_events::EventBus::with_capacity(64);
    let request_id = Uuid::new_v4();
    let topic = Topic::elicit_response(request_id);
    let mut rx = bus.subscribe_topic(topic.as_str());

    publish_elicit_response(
        &bus,
        "agent-alice",
        ElicitResponseRequest {
            request_id,
            value: Some("hello".to_string()),
            values: None,
        },
    );

    let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("reply observed within timeout")
        .expect("bus open");
    let AstridEvent::Ipc { message, .. } = &*event else {
        panic!("expected an IPC event");
    };
    assert_eq!(
        message.principal.as_deref(),
        Some("agent-alice"),
        "reply must carry the caller's verified principal"
    );
    match &message.payload {
        BusIpcPayload::ElicitResponse {
            request_id: got_id,
            value,
            values,
        } => {
            assert_eq!(*got_id, request_id, "request_id must round-trip");
            assert_eq!(value.as_deref(), Some("hello"));
            assert!(values.is_none());
        },
        other => panic!("expected ElicitResponse, got {other:?}"),
    }
}

/// A cancellation (both `value` and `values` `None`) round-trips as the
/// host's cancel sentinel; the endpoint must be able to express it.
#[tokio::test]
async fn elicit_response_cancellation_round_trips() {
    let bus = astrid_events::EventBus::with_capacity(64);
    let request_id = Uuid::new_v4();
    let mut rx = bus.subscribe_topic(Topic::elicit_response(request_id).as_str());

    publish_elicit_response(
        &bus,
        "agent-alice",
        ElicitResponseRequest {
            request_id,
            value: None,
            values: None,
        },
    );

    let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("reply observed")
        .expect("bus open");
    let AstridEvent::Ipc { message, .. } = &*event else {
        panic!("expected IPC event");
    };
    match &message.payload {
        BusIpcPayload::ElicitResponse { value, values, .. } => {
            assert!(
                value.is_none() && values.is_none(),
                "cancellation = both None (host cancel sentinel)"
            );
        },
        other => panic!("expected ElicitResponse, got {other:?}"),
    }
}

/// REGRESSION: `value` and `values` are mutually exclusive. A body carrying
/// both must be rejected before it reaches the bus.
#[test]
fn elicit_response_rejects_both_value_and_values() {
    let request_id = Uuid::new_v4();
    let both = ElicitResponseRequest {
        request_id,
        value: Some("scalar".to_string()),
        values: Some(vec!["array".to_string()]),
    };
    assert!(both.validate().is_err(), "both set must be rejected");

    assert!(
        ElicitResponseRequest {
            request_id,
            value: Some("v".into()),
            values: None
        }
        .validate()
        .is_ok(),
        "scalar answer is valid"
    );
    assert!(
        ElicitResponseRequest {
            request_id,
            value: None,
            values: Some(vec!["a".into()])
        }
        .validate()
        .is_ok(),
        "array answer is valid"
    );
    assert!(
        ElicitResponseRequest {
            request_id,
            value: None,
            values: None
        }
        .validate()
        .is_ok(),
        "cancel sentinel (both None) is valid"
    );
}

#[tokio::test]
async fn approval_response_publishes_stamped_reply_on_topic() {
    let bus = astrid_events::EventBus::with_capacity(64);
    let request_id = Uuid::new_v4().to_string();
    let mut rx = bus.subscribe_topic(Topic::approval_response(&request_id).as_str());

    publish_approval_response(
        &bus,
        "agent-alice",
        ApprovalResponseRequest {
            request_id: request_id.clone(),
            decision: "approve_session".to_string(),
            reason: Some("ok for this run".to_string()),
        },
    );

    let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("reply observed")
        .expect("bus open");
    let AstridEvent::Ipc { message, .. } = &*event else {
        panic!("expected IPC event");
    };
    assert_eq!(message.principal.as_deref(), Some("agent-alice"));
    match &message.payload {
        BusIpcPayload::ApprovalResponse {
            request_id: got_id,
            decision,
            reason,
        } => {
            assert_eq!(got_id, &request_id);
            assert_eq!(decision, "approve_session");
            assert_eq!(reason.as_deref(), Some("ok for this run"));
        },
        other => panic!("expected ApprovalResponse, got {other:?}"),
    }
}

#[test]
fn approval_response_rejects_unsupported_decisions() {
    let valid = ApprovalResponseRequest {
        request_id: "req-1".to_string(),
        decision: "deny".to_string(),
        reason: None,
    };
    assert!(valid.validate().is_ok());

    let empty_id = ApprovalResponseRequest {
        request_id: String::new(),
        decision: "approve".to_string(),
        reason: None,
    };
    assert!(empty_id.validate().is_err());

    let invalid_decision = ApprovalResponseRequest {
        request_id: "req-1".to_string(),
        decision: "maybe".to_string(),
        reason: None,
    };
    assert!(invalid_decision.validate().is_err());
}

#[test]
fn control_request_stream_filters_to_caller_principal() {
    let own_request = Arc::new(AstridEvent::Ipc {
        metadata: EventMetadata::default(),
        message: IpcMessage::new(
            Topic::approval_request(),
            IpcPayload::ApprovalRequired {
                request_id: "req-1".to_string(),
                action: "run".to_string(),
                resource: "command".to_string(),
                reason: "needs consent".to_string(),
            },
            Uuid::nil(),
        )
        .with_principal("agent-alice"),
    });
    let peer_request = Arc::new(AstridEvent::Ipc {
        metadata: EventMetadata::default(),
        message: IpcMessage::new(
            Topic::approval_request(),
            IpcPayload::ApprovalRequired {
                request_id: "req-2".to_string(),
                action: "run".to_string(),
                resource: "other command".to_string(),
                reason: "needs consent".to_string(),
            },
            Uuid::nil(),
        )
        .with_principal("agent-bob"),
    });
    let response_event = Arc::new(AstridEvent::Ipc {
        metadata: EventMetadata::default(),
        message: IpcMessage::new(
            Topic::approval_response("req-1"),
            IpcPayload::ApprovalResponse {
                request_id: "req-1".to_string(),
                decision: "approve".to_string(),
                reason: None,
            },
            Uuid::nil(),
        )
        .with_principal("agent-alice"),
    });
    let grant_request = Arc::new(AstridEvent::Ipc {
        metadata: EventMetadata::default(),
        message: IpcMessage::new(
            Topic::approval_request(),
            IpcPayload::GrantRequired {
                request_id: "grant-1".to_string(),
                principal: "agent-alice".to_string(),
                capsule_id: "astrid-capsule-extra".to_string(),
            },
            Uuid::nil(),
        )
        .with_principal("agent-alice"),
    });
    let forged_grant_request = Arc::new(AstridEvent::Ipc {
        metadata: EventMetadata::default(),
        message: IpcMessage::new(
            Topic::approval_request(),
            IpcPayload::GrantRequired {
                request_id: "grant-2".to_string(),
                principal: "agent-alice".to_string(),
                capsule_id: "astrid-capsule-extra".to_string(),
            },
            Uuid::new_v4(),
        )
        .with_principal("agent-alice"),
    });
    let mismatched_grant_request = Arc::new(AstridEvent::Ipc {
        metadata: EventMetadata::default(),
        message: IpcMessage::new(
            Topic::approval_request(),
            IpcPayload::GrantRequired {
                request_id: "grant-3".to_string(),
                principal: "agent-bob".to_string(),
                capsule_id: "astrid-capsule-extra".to_string(),
            },
            Uuid::nil(),
        )
        .with_principal("agent-alice"),
    });

    assert!(forward_control_request(&own_request, "agent-alice", "approval").is_some());
    assert!(forward_control_request(&peer_request, "agent-alice", "approval").is_none());
    assert!(forward_control_request(&response_event, "agent-alice", "approval").is_none());
    assert!(forward_control_request(&grant_request, "agent-alice", "approval").is_some());
    assert!(forward_control_request(&forged_grant_request, "agent-alice", "approval").is_none());
    assert!(
        forward_control_request(&mismatched_grant_request, "agent-alice", "approval").is_none()
    );
}

/// The fail-fast stream emits exactly one `error` event and then closes.
#[tokio::test]
async fn unready_stream_emits_single_event_then_closes() {
    let report = AgentLoopReadiness {
        ready: false,
        prompt_subscribers: vec![],
        response_publishers: vec![],
        unsatisfied_required_imports: vec![],
        loaded_capsules: vec![],
    };
    let mut stream = unready_event_stream(&report);
    let _first = stream.next().await.expect("one event").expect("infallible");
    assert!(
        stream.next().await.is_none(),
        "fail-fast stream must close after one event, not wait the timeout"
    );
}
