use std::time::Duration;

use astrid_core::{PrincipalId, SessionId};
use uuid::Uuid;

use super::*;
use crate::socket_client::{SocketClient, perform_handshake_in_home};

fn egress_event(principal: &str, payload_bytes: usize) -> AstridEvent {
    AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: IpcMessage::new(
            Topic::from_raw("astrid.v1.response.test"),
            IpcPayload::RawJson(serde_json::Value::String("x".repeat(payload_bytes))),
            Uuid::nil(),
        )
        .with_principal(principal),
    }
}

#[test]
fn general_connection_limit_does_not_consume_the_admin_reserve() {
    let established = Arc::new(tokio::sync::Semaphore::new(1));
    let reserved = Arc::new(tokio::sync::Semaphore::new(1));

    let _general = Arc::clone(&established)
        .try_acquire_owned()
        .expect("general connection permit");
    assert!(Arc::clone(&established).try_acquire_owned().is_err());
    assert_eq!(reserved.available_permits(), 1);
}

#[test]
fn reserved_lane_accepts_real_status_and_shutdown_requests() {
    let request = |topic: &str, request: KernelRequest| {
        IpcMessage::new(
            Topic::from_raw(topic),
            IpcPayload::RawJson(serde_json::to_value(request).expect("serialize request")),
            Uuid::nil(),
        )
    };

    let status = reserved_response_for(&request(
        "astrid.v1.request.status.correlation1",
        KernelRequest::GetStatus,
    ))
    .expect("status uses reserved lane");
    assert_eq!(status.topic, "astrid.v1.response.status.correlation1");

    let shutdown = reserved_response_for(&request(
        "astrid.v1.request.shutdown.correlation2",
        KernelRequest::Shutdown { reason: None },
    ))
    .expect("shutdown uses reserved lane");
    assert_eq!(shutdown.topic, "astrid.v1.response.shutdown.correlation2");

    assert!(
        reserved_response_for(&request(
            "astrid.v1.request.status.correlation3",
            KernelRequest::Shutdown { reason: None },
        ))
        .is_none(),
        "topic and payload operation must agree"
    );
    assert!(
        reserved_response_for(&request(
            "astrid.v1.request.list_capsules.correlation4",
            KernelRequest::ListCapsules,
        ))
        .is_none(),
        "the reserve is limited to liveness and shutdown operations"
    );
    assert!(
        reserved_response_for(&IpcMessage::new(
            Topic::from_raw("astrid.v1.admin.status.correlation5"),
            IpcPayload::RawJson(serde_json::json!({"request_id": "correlation5"})),
            Uuid::nil(),
        ))
        .is_none(),
        "legacy admin operations cannot consume the liveness reserve"
    );
}

#[test]
fn kernel_reserved_completion_uses_private_response_topic() {
    let request = IpcMessage::new(
        Topic::from_raw("astrid.v1.request.status.correlation1"),
        IpcPayload::RawJson(
            serde_json::to_value(KernelRequest::GetStatus).expect("serialize request"),
        ),
        Uuid::nil(),
    );
    let expected = reserved_response_for(&request).expect("reserved response target");
    let response = |topic: &str| AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: IpcMessage::new(
            Topic::from_raw(topic),
            IpcPayload::RawJson(serde_json::json!({"status": "Success", "data": {}})),
            Uuid::nil(),
        ),
    };

    assert!(!reserved_response_matches(
        &response("astrid.v1.response.status.other"),
        &expected
    ));
    assert!(reserved_response_matches(
        &response("astrid.v1.response.status.correlation1"),
        &expected
    ));

    let working = AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: IpcMessage::new(
            Topic::from_raw("astrid.v1.response.status.correlation1"),
            IpcPayload::RawJson(
                serde_json::to_value(KernelResponse::Working).expect("serialize keepalive"),
            ),
            Uuid::nil(),
        ),
    };
    assert!(
        !reserved_response_matches(&working, &expected),
        "Working keepalive is not terminal"
    );
}

#[test]
fn cancel_turn_is_forwarded_only_by_the_active_connection() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let owner = registry.subscribe("alice".to_owned(), None);
    let other = registry.subscribe("alice".to_owned(), None);
    let identity = AuthenticatedIdentity {
        principal: PrincipalId::new("alice").expect("valid principal"),
        device_key_id: None,
    };
    let mut inbound = bus.subscribe_topic(routing::CHAT_REQUEST_TOPIC);
    let prompt = |context| {
        IpcMessage::new(
            Topic::from_raw(routing::CHAT_REQUEST_TOPIC),
            IpcPayload::UserInput {
                text: String::new(),
                session_id: "session-1".to_owned(),
                context,
            },
            Uuid::nil(),
        )
    };

    process_inbound(&bus, &identity, "alice", &owner, prompt(None)).expect("start turn");
    process_inbound(
        &bus,
        &identity,
        "alice",
        &owner,
        prompt(Some(serde_json::json!({"action": "cancel_turn"}))),
    )
    .expect("owner cancellation is forwarded");
    assert!(
        process_inbound(
            &bus,
            &identity,
            "alice",
            &other,
            prompt(Some(serde_json::json!({"action": "cancel_turn"}))),
        )
        .is_err(),
        "another connection cannot cancel the owner's turn"
    );
    assert!(inbound.try_recv().is_some(), "initial prompt published");
    assert!(inbound.try_recv().is_some(), "cancellation published");
    assert!(
        inbound.try_recv().is_none(),
        "foreign cancellation rejected"
    );
}

#[tokio::test]
async fn egress_registry_preserves_full_payloads_and_isolates_principals() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let mut alice_rx = registry.subscribe("alice".to_owned(), None);
    let mut bob_rx = registry.subscribe("bob".to_owned(), None);

    // Publishing both events without yielding makes this a deterministic
    // regression for the former shared 1 MiB routed budget: Bob's event
    // evicted Alice's before the hub could drain it. Per-connection queues
    // retain both full frames without exposing one principal's event to
    // the other principal's receiver.
    bus.publish(egress_event("alice", 600 * 1024));
    bus.publish(egress_event("bob", 600 * 1024));

    for (expected, receiver) in [("alice", &mut alice_rx), ("bob", &mut bob_rx)] {
        let item = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("egress timeout")
            .expect("egress channel closed");
        let AstridEvent::Ipc { message, .. } = &*item else {
            panic!("expected IPC event");
        };
        assert_eq!(message.principal.as_deref(), Some(expected));
    }

    // The old routed queue also rejected a valid maximum-size payload
    // because its topic bytes pushed accounting beyond the 1 MiB budget.
    bus.publish(egress_event("alice", MAX_PAYLOAD_BYTES - 2));
    let item = tokio::time::timeout(Duration::from_secs(2), alice_rx.recv())
        .await
        .expect("maximum-size egress timeout")
        .expect("egress channel closed");
    assert!(matches!(&*item, AstridEvent::Ipc { .. }));
    assert!(matches!(
        bob_rx.try_recv(),
        Err(egress::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn unrelated_bus_burst_cannot_lag_client_egress() {
    let bus = Arc::new(EventBus::with_capacity(1));
    let registry = egress::Registry::install(&bus);
    let mut egress_rx = registry.subscribe("alice".to_owned(), None);

    for _ in 0..2048 {
        let mut event = egress_event("alice", 1);
        let AstridEvent::Ipc { message, .. } = &mut event else {
            unreachable!("helper always creates IPC events");
        };
        message.topic = Topic::from_raw("internal.v1.audit.noise");
        bus.publish(event);
    }
    bus.publish(egress_event("alice", 1));

    let item = tokio::time::timeout(Duration::from_secs(2), egress_rx.recv())
        .await
        .expect("egress timeout")
        .expect("egress channel closed");
    assert!(matches!(&*item, AstridEvent::Ipc { .. }));
}

#[tokio::test]
async fn one_principal_burst_cannot_lag_another_principal() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let mut bob_rx = registry.subscribe("bob".to_owned(), None);

    for _ in 0..=CLIENT_EGRESS_CAPACITY {
        bus.publish(egress_event("alice", 1));
    }
    bus.publish(egress_event("bob", 1));

    let item = tokio::time::timeout(Duration::from_secs(2), bob_rx.recv())
        .await
        .expect("Bob egress timeout")
        .expect("Bob egress queue lagged on Alice traffic");
    let AstridEvent::Ipc { message, .. } = &*item else {
        panic!("expected IPC event");
    };
    assert_eq!(message.principal.as_deref(), Some("bob"));
}

#[tokio::test]
async fn token_only_peer_is_anonymous_and_can_round_trip() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(temp.path().join("home"));
    home.ensure().expect("create Astrid home");
    let token = Arc::new(SessionToken::generate());
    token
        .write_to_file(&home.token_path())
        .expect("write session token");
    let listener = Arc::new(tokio::sync::Mutex::new(
        local_transport::bind(&home.socket_path()).expect("bind local listener"),
    ));
    let bus = Arc::new(EventBus::new());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = NativeUplink {
        listener,
        session_token: token,
        home: home.clone(),
        event_bus: Arc::clone(&bus),
        shutdown: shutdown_rx,
    }
    .spawn();

    let requested = PrincipalId::new("default").expect("valid principal");
    let mut stream = local_transport::connect(&home.socket_path())
        .await
        .expect("connect");
    assert!(
        !perform_handshake_in_home(&mut stream, &requested, &home)
            .await
            .expect("token-only handshake")
    );
    let mut client =
        SocketClient::from_stream_for_test(stream, SessionId::from_uuid(Uuid::new_v4()), requested);
    // astrid-emit uses this legacy hook family through SocketClient. The
    // native transport must preserve it while hook bridges migrate callers
    // onto the canonical hook.v1 surface.
    let request_topic = "sage.v1.hook.before_tool_call";
    let mut inbound = bus.subscribe_topic(request_topic);
    let mut request = IpcMessage::new(
        Topic::from_raw(request_topic),
        IpcPayload::RawJson(serde_json::json!({"method": "get_status"})),
        Uuid::new_v4(),
    )
    .with_principal("forged")
    .with_device_key_id("forged-device")
    .with_origin(MessageOrigin::RemoteGateway);
    request.seq = u64::MAX;
    client.send_message(request).await.expect("send request");

    let event = tokio::time::timeout(Duration::from_secs(2), inbound.recv())
        .await
        .expect("request timeout")
        .expect("request event");
    let AstridEvent::Ipc { message, .. } = &*event else {
        panic!("expected IPC event");
    };
    assert_eq!(message.principal.as_deref(), Some("anonymous"));
    assert_eq!(message.device_key_id, None);
    assert_eq!(message.origin, MessageOrigin::System);
    assert_eq!(message.source_id, Uuid::nil());
    assert_eq!(message.signature, None);
    assert_ne!(message.seq, u64::MAX, "bus must assign sequence");

    let response_topic = "astrid.v1.response.status.test";
    let response = IpcMessage::new(
        Topic::from_raw(response_topic),
        IpcPayload::RawJson(serde_json::json!({"ok": true})),
        Uuid::nil(),
    )
    .with_principal("anonymous");
    bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: response,
    });
    // The kernel publishes its shutdown acknowledgement immediately
    // before signaling daemon shutdown. Model that exact ordering and
    // require the buffered terminal frame to survive connection teardown.
    shutdown_tx.send(true).expect("request shutdown");
    let response = tokio::time::timeout(Duration::from_secs(2), client.read_raw_frame())
        .await
        .expect("response timeout")
        .expect("read response")
        .expect("response frame");
    let response: serde_json::Value =
        serde_json::from_slice(&response).expect("JSON response frame");
    assert_eq!(response["topic"], response_topic);
    assert_eq!(response["payload"], serde_json::json!({"ok": true}));
    assert_eq!(response["principal"], "anonymous");

    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("server shutdown timeout")
        .expect("server task");
}

#[tokio::test]
async fn stalled_handshake_does_not_block_later_clients() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(temp.path().join("home"));
    home.ensure().expect("create Astrid home");
    let token = Arc::new(SessionToken::generate());
    token
        .write_to_file(&home.token_path())
        .expect("write session token");
    let listener = Arc::new(tokio::sync::Mutex::new(
        local_transport::bind(&home.socket_path()).expect("bind local listener"),
    ));
    let bus = Arc::new(EventBus::new());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = NativeUplink {
        listener,
        session_token: token,
        home: home.clone(),
        event_bus: bus,
        shutdown: shutdown_rx,
    }
    .spawn();

    let stalled = local_transport::connect(&home.socket_path())
        .await
        .expect("connect stalled peer");
    let requested = PrincipalId::new("default").expect("valid principal");
    let mut healthy = local_transport::connect(&home.socket_path())
        .await
        .expect("connect healthy peer");
    let authenticated = tokio::time::timeout(
        Duration::from_secs(2),
        perform_handshake_in_home(&mut healthy, &requested, &home),
    )
    .await
    .expect("healthy handshake was blocked")
    .expect("healthy handshake failed");
    assert!(!authenticated);

    drop(stalled);
    drop(healthy);
    shutdown_tx.send(true).expect("request shutdown");

    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("server shutdown timeout")
        .expect("server task");
}

#[tokio::test]
async fn established_connections_release_handshake_capacity() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(temp.path().join("home"));
    home.ensure().expect("create Astrid home");
    let token = Arc::new(SessionToken::generate());
    token
        .write_to_file(&home.token_path())
        .expect("write session token");
    let listener = Arc::new(tokio::sync::Mutex::new(
        local_transport::bind(&home.socket_path()).expect("bind local listener"),
    ));
    let bus = Arc::new(EventBus::new());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = NativeUplink {
        listener,
        session_token: token,
        home: home.clone(),
        event_bus: bus,
        shutdown: shutdown_rx,
    }
    .spawn();

    let requested = PrincipalId::new("default").expect("valid principal");
    let mut established = Vec::new();
    for _ in 0..=MAX_PENDING_HANDSHAKES {
        let mut stream = local_transport::connect(&home.socket_path())
            .await
            .expect("connect peer");
        tokio::time::timeout(
            Duration::from_secs(2),
            perform_handshake_in_home(&mut stream, &requested, &home),
        )
        .await
        .expect("established connection consumed handshake capacity")
        .expect("handshake failed");
        established.push(stream);
    }

    drop(established);
    shutdown_tx.send(true).expect("request shutdown");
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("server shutdown timeout")
        .expect("server task");
}
