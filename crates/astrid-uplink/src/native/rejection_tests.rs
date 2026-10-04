//! Refused requests terminate on their own socket, never through bus fan-out.

use super::*;
use astrid_core::PrincipalId;
use astrid_types::ipc::RequestOwnerId;
use std::time::Duration;
use uuid::Uuid;

fn prompt(session: &str) -> IpcMessage {
    IpcMessage::new(
        Topic::from_raw(routing::CHAT_REQUEST_TOPIC),
        IpcPayload::UserInput {
            text: "private prompt must not be echoed".to_owned(),
            session_id: session.to_owned(),
            context: None,
        },
        Uuid::new_v4(),
    )
    .with_principal("forged")
    .with_request_owner(RequestOwnerId::generate())
}

fn identity() -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        principal: PrincipalId::new("alice").expect("principal"),
        device_key_id: None,
        request_owner: RequestOwnerId::generate(),
    }
}

#[tokio::test]
async fn busy_prompt_returns_terminal_error_without_releasing_existing_turn() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = identity();
    let mut receiver = registry.subscribe("alice".to_owned(), None, identity.request_owner);
    process_inbound(&bus, &identity, "alice", &receiver, prompt("original"))
        .expect("first prompt admitted");
    let mut bus_responses = bus.subscribe_topic("agent.v1.response");
    let (server, peer) = LocalStream::pair().expect("socket pair");
    let (_reader, mut writer) = local_transport::split(server);
    let mut peer = FramedReader::new(peer);
    route_connection_message(
        &mut writer,
        &bus,
        &identity,
        &receiver,
        None,
        prompt("retry"),
    )
    .await
    .expect("write refusal");
    let reply = tokio::time::timeout(Duration::from_secs(1), peer.read_message())
        .await
        .expect("refused prompt must not hang")
        .expect("valid response frame")
        .expect("response present");
    assert_eq!(reply.topic.as_str(), "agent.v1.response");
    assert_eq!(reply.principal.as_deref(), Some("alice"));
    assert_eq!(reply.request_owner, Some(identity.request_owner));
    let IpcPayload::AgentResponse {
        text,
        is_final,
        session_id,
    } = reply.payload
    else {
        panic!("CLI-readable terminal response required");
    };
    assert!(is_final);
    assert_eq!(session_id, "retry");
    assert!(text.contains("already has an active turn"));
    assert!(!text.contains("private prompt"));
    assert_eq!(receiver.session().as_deref(), Some("original"));
    assert!(
        bus_responses.try_recv().is_none(),
        "refusal is socket-private"
    );
    assert!(matches!(
        receiver.try_recv(),
        Err(egress::TryRecvError::Empty)
    ));
    bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: IpcMessage::new(
            Topic::from_raw("agent.v1.response"),
            IpcPayload::AgentResponse {
                text: "original completed".to_owned(),
                is_final: true,
                session_id: "original".to_owned(),
            },
            Uuid::new_v4(),
        )
        .with_principal("alice")
        .with_request_owner(identity.request_owner),
    });
    assert!(
        receiver.try_recv().is_ok(),
        "original response still delivered"
    );
    process_inbound(&bus, &identity, "alice", &receiver, prompt("retry"))
        .expect("next prompt admitted after original completes");
}

#[tokio::test]
async fn malformed_chat_and_foreign_cancel_return_terminal_reasons() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = identity();
    let receiver = registry.subscribe("alice".to_owned(), None, identity.request_owner);
    process_inbound(&bus, &identity, "alice", &receiver, prompt("original"))
        .expect("original turn");
    let missing_session = IpcMessage::new(
        Topic::from_raw(routing::CHAT_REQUEST_TOPIC),
        IpcPayload::RawJson(serde_json::json!({"text": "secret"})),
        Uuid::new_v4(),
    );
    let mut foreign_cancel = prompt("foreign-session");
    if let IpcPayload::UserInput { context, .. } = &mut foreign_cancel.payload {
        *context = Some(serde_json::json!({"action": "cancel_turn"}));
    }
    for (request, expected_session, expected_reason) in [
        (missing_session, "default", "missing a session ID"),
        (
            foreign_cancel,
            "foreign-session",
            "cancellation does not match",
        ),
    ] {
        let (server, peer) = LocalStream::pair().expect("socket pair");
        let (_reader, mut writer) = local_transport::split(server);
        route_connection_message(&mut writer, &bus, &identity, &receiver, None, request)
            .await
            .expect("write refusal");
        let mut peer = FramedReader::new(peer);
        let reply = tokio::time::timeout(Duration::from_secs(1), peer.read_message())
            .await
            .expect("refusal timeout")
            .expect("frame")
            .expect("response");
        let IpcPayload::AgentResponse {
            text,
            is_final,
            session_id,
        } = reply.payload
        else {
            panic!("terminal chat response required");
        };
        assert!(is_final);
        assert_eq!(session_id, expected_session);
        assert!(text.contains(expected_reason));
        assert!(!text.contains("secret"));
        assert_eq!(receiver.session().as_deref(), Some("original"));
    }
}

#[tokio::test]
async fn forbidden_non_chat_request_receives_reason_and_disconnects() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = identity();
    let receiver = registry.subscribe("alice".to_owned(), None, identity.request_owner);
    let request = IpcMessage::new(
        Topic::from_raw("internal.v1.forbidden"),
        IpcPayload::RawJson(serde_json::json!({"secret": "must not be echoed"})),
        Uuid::new_v4(),
    );
    let (server, peer) = LocalStream::pair().expect("socket pair");
    let (reader, mut writer) = local_transport::split(server);
    let error = route_connection_message(&mut writer, &bus, &identity, &receiver, None, request)
        .await
        .expect_err("non-chat refusal closes connection");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    drop(writer);
    drop(reader);
    let mut peer = FramedReader::new(peer);
    let reply = tokio::time::timeout(Duration::from_secs(1), peer.read_message())
        .await
        .expect("disconnect timeout")
        .expect("frame")
        .expect("response");
    assert_eq!(
        reply.payload,
        IpcPayload::Disconnect {
            reason: Some("topic is not allowed from local clients".to_owned()),
        }
    );
    assert!(peer.read_message().await.expect("EOF").is_none());
}

#[tokio::test]
async fn another_connection_receives_busy_error_but_cannot_finish_owner_turn() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let owner_identity = identity();
    let other_identity = identity();
    let owner = registry.subscribe("alice".to_owned(), None, owner_identity.request_owner);
    let other = registry.subscribe("alice".to_owned(), None, other_identity.request_owner);
    process_inbound(
        &bus,
        &owner_identity,
        "alice",
        &owner,
        prompt("same-session"),
    )
    .expect("owner admitted");
    let (server, peer) = LocalStream::pair().expect("socket pair");
    let (_reader, mut writer) = local_transport::split(server);
    route_connection_message(
        &mut writer,
        &bus,
        &other_identity,
        &other,
        None,
        prompt("same-session"),
    )
    .await
    .expect("write private refusal");
    let mut peer = FramedReader::new(peer);
    let reply = tokio::time::timeout(Duration::from_secs(1), peer.read_message())
        .await
        .expect("busy response timeout")
        .expect("response frame")
        .expect("response");
    assert_eq!(reply.request_owner, Some(other_identity.request_owner));
    assert_eq!(owner.session().as_deref(), Some("same-session"));
    assert_eq!(other.session(), None);
    assert!(
        !other.begin_turn("same-session"),
        "owner retains turn admission"
    );
}
