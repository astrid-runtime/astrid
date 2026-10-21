use astrid_events::EventMetadata;
use astrid_types::Topic;
use astrid_types::ipc::{IpcMessage, IpcPayload};

use super::*;

#[test]
fn terminal_failure_is_delivered_only_to_its_captured_owner() {
    let owner = RequestOwnerId::generate();
    let foreign = RequestOwnerId::generate();
    let request = IpcMessage::new(
        Topic::from_raw("astrid.v1.request.example"),
        IpcPayload::RawJson(serde_json::json!({"req_id":"1234567890abcdef1234567890abcdef"})),
        uuid::Uuid::nil(),
    )
    .with_principal("alice")
    .with_request_owner(owner)
    .with_origin(astrid_types::ipc::MessageOrigin::LocalSocket);
    let reply = astrid_types::ipc::request_failure::RequestFailureBinding::capture(&request)
        .unwrap()
        .message("deadline exceeded");
    assert!(request_owner_allows(&reply, owner));
    assert!(!request_owner_allows(&reply, foreign));
}

#[test]
fn unanswered_human_requests_have_a_bounded_lifetime_on_the_connection() {
    let queue = EgressQueue::new();
    let owner = RequestOwnerId::generate();
    for index in 0..=CLIENT_EGRESS_CAPACITY {
        queue.enqueue(
            Arc::new(AstridEvent::Ipc {
                metadata: EventMetadata::new("test"),
                message: IpcMessage::new(
                    Topic::approval_request(),
                    IpcPayload::GrantRequired {
                        request_id: index.to_string(),
                        request_owner: owner.to_string(),
                        principal: "alice".to_owned(),
                        capsule_id: "test".to_owned(),
                    },
                    uuid::Uuid::nil(),
                )
                .with_principal("alice")
                .with_request_owner(owner),
            }),
            1,
        );
        if index < CLIENT_EGRESS_CAPACITY {
            assert!(queue.try_recv().is_ok());
        }
    }
    assert_eq!(queue.try_recv().err(), Some(TryRecvError::Lagged));
    let state = queue.state.lock().expect("state");
    assert!(state.human_replies.is_empty());
    assert_eq!(state.human_reply_bytes, 0);
}

fn event() -> Arc<AstridEvent> {
    Arc::new(AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: IpcMessage::new(
            Topic::from_raw("astrid.v1.response.test"),
            IpcPayload::RawJson(serde_json::json!({"ok": true})),
            uuid::Uuid::nil(),
        )
        .with_principal("alice"),
    })
}

#[tokio::test]
async fn byte_budget_fail_closes_and_releases_retained_events() {
    let queue = EgressQueue::new();
    queue.enqueue(event(), CLIENT_EGRESS_BYTE_BUDGET);
    queue.enqueue(event(), 1);

    assert!(matches!(queue.recv().await, Err(RecvError::Lagged)));
    let state = queue
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(state.events.is_empty());
    assert_eq!(state.bytes, 0);
}

#[tokio::test]
async fn request_owned_event_reaches_only_the_originating_connection() {
    let bus = Arc::new(EventBus::new());
    let registry = Registry::install(&bus);
    let owner = RequestOwnerId::generate();
    let other_owner = RequestOwnerId::generate();
    let mut origin = registry.subscribe("alice".to_owned(), None, owner);
    let mut peer = registry.subscribe("alice".to_owned(), None, other_owner);

    bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: IpcMessage::new(
            Topic::from_raw("astrid.v1.approval"),
            IpcPayload::ApprovalRequired {
                request_id: "request-1".to_owned(),
                request_owner: owner.to_string(),
                action: "run".to_owned(),
                resource: "command".to_owned(),
                reason: "test".to_owned(),
            },
            uuid::Uuid::nil(),
        )
        .with_principal("alice")
        .with_request_owner(owner),
    });

    let delivered = tokio::time::timeout(std::time::Duration::from_secs(1), origin.recv())
        .await
        .expect("originating connection receives its approval")
        .expect("egress remains open");
    let message = event_message(&delivered).expect("approval IPC");
    assert_eq!(message.request_owner, Some(owner));
    assert!(matches!(peer.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn ownerless_approval_reaches_no_native_connection() {
    let bus = Arc::new(EventBus::new());
    let registry = Registry::install(&bus);
    let owner = RequestOwnerId::generate();
    let mut client = registry.subscribe("alice".to_owned(), None, owner);

    bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: IpcMessage::new(
            Topic::from_raw("astrid.v1.approval"),
            IpcPayload::ApprovalRequired {
                request_id: "request-1".to_owned(),
                request_owner: owner.to_string(),
                action: "run".to_owned(),
                resource: "command".to_owned(),
                reason: "test".to_owned(),
            },
            uuid::Uuid::nil(),
        )
        .with_principal("alice"),
    });

    assert!(matches!(client.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn forged_or_internally_inconsistent_approval_reaches_no_native_connection() {
    let bus = Arc::new(EventBus::new());
    let registry = Registry::install(&bus);
    let owner = RequestOwnerId::generate();
    let mut client = registry.subscribe("alice".to_owned(), None, owner);

    for (source_id, payload_owner) in [
        (uuid::Uuid::new_v4(), owner.to_string()),
        (uuid::Uuid::nil(), RequestOwnerId::generate().to_string()),
    ] {
        bus.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test"),
            message: IpcMessage::new(
                Topic::from_raw("astrid.v1.approval"),
                IpcPayload::ApprovalRequired {
                    request_id: "request-1".to_owned(),
                    request_owner: payload_owner,
                    action: "run".to_owned(),
                    resource: "command".to_owned(),
                    reason: "test".to_owned(),
                },
                source_id,
            )
            .with_principal("alice")
            .with_request_owner(owner),
        });
    }

    assert!(matches!(client.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn malformed_typed_approval_reaches_no_native_connection() {
    let bus = Arc::new(EventBus::new());
    let registry = Registry::install(&bus);
    let owner = RequestOwnerId::generate();
    let mut client = registry.subscribe("alice".to_owned(), None, owner);

    bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: IpcMessage::new(
            Topic::approval_request(),
            IpcPayload::Custom {
                data: serde_json::json!({
                    "type": "approval_required",
                    "request_id": "request-1",
                    "action": "run",
                    "resource": "command",
                    "reason": "missing payload owner"
                }),
            },
            uuid::Uuid::nil(),
        )
        .with_principal("alice")
        .with_request_owner(owner),
    });

    assert!(matches!(client.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn one_turn_per_principal_session_until_terminal_publication() {
    let bus = Arc::new(EventBus::new());
    let registry = Registry::install(&bus);
    let mut first = registry.subscribe("alice".to_owned(), None, RequestOwnerId::generate());
    let mut second = registry.subscribe("alice".to_owned(), None, RequestOwnerId::generate());

    assert!(first.begin_turn("session-1"));
    assert!(!second.begin_turn("session-1"));
    assert!(second.begin_turn("session-2"));

    bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: IpcMessage::new(
            Topic::from_raw("agent.v1.response"),
            IpcPayload::AgentResponse {
                text: "done".to_owned(),
                is_final: true,
                session_id: "session-1".to_owned(),
            },
            uuid::Uuid::nil(),
        )
        .with_principal("alice")
        .with_request_owner(first.turn_owner().expect("first turn owner")),
    });

    assert_eq!(first.session(), None);
    assert!(!second.begin_turn("session-1"));
    assert!(first.try_recv().is_ok(), "owner receives its terminal");

    bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: IpcMessage::new(
            Topic::from_raw("agent.v1.response"),
            IpcPayload::AgentResponse {
                text: "done".to_owned(),
                is_final: true,
                session_id: "session-2".to_owned(),
            },
            uuid::Uuid::nil(),
        )
        .with_principal("alice")
        .with_request_owner(second.turn_owner().expect("second turn owner")),
    });
    assert_eq!(second.session(), None);
    assert!(
        second.try_recv().is_ok(),
        "second owner receives its terminal"
    );
    assert!(second.begin_turn("session-1"));

    bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: IpcMessage::new(
            Topic::from_raw("agent.v1.stream.delta"),
            IpcPayload::RawJson(serde_json::json!({
                "session_id": "session-1",
                "delta": "new"
            })),
            uuid::Uuid::nil(),
        )
        .with_principal("alice")
        .with_request_owner(second.turn_owner().expect("new turn owner")),
    });
    assert!(matches!(first.try_recv(), Err(TryRecvError::Empty)));
    assert!(
        second.try_recv().is_ok(),
        "only the new owner receives deltas"
    );
}

#[test]
fn dropping_turn_owner_releases_only_its_admission() {
    let bus = Arc::new(EventBus::new());
    let registry = Registry::install(&bus);
    let first = registry.subscribe("alice".to_owned(), None, RequestOwnerId::generate());
    let second = registry.subscribe("alice".to_owned(), None, RequestOwnerId::generate());

    assert!(first.begin_turn("session-1"));
    drop(first);
    assert!(second.begin_turn("session-1"));
}
