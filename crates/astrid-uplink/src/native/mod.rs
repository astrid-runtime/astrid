//! Astrid's built-in local socket server.
//!
//! This is the baseline control-plane transport. Distributions may add
//! frontends, but daemon boot and the `astrid` CLI do not depend on one.

mod egress;
mod handshake;
mod routing;

use std::collections::HashMap;
use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::local_transport::{self, LocalListener, LocalStream, LocalWriteHalf};
use astrid_core::session_token::SessionToken;
use astrid_events::{AstridEvent, EventBus, EventMetadata};
use astrid_types::Topic;
use astrid_types::ipc::{IpcMessage, IpcPayload, MessageOrigin};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use handshake::AuthenticatedIdentity;

const MAX_PENDING_HANDSHAKES: usize = 8;
const MAX_FRAME_BYTES: usize = 50 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
const CLIENT_EGRESS_CAPACITY: usize = 1024;
const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const EVENT_SOURCE: &str = "native_local_uplink";

/// Handles required by the Astrid-owned local uplink server.
pub struct NativeUplink {
    /// Kernel-bound listener. Only this server should accept from it.
    pub listener: Arc<tokio::sync::Mutex<LocalListener>>,
    /// Session token generated for this daemon boot.
    pub session_token: Arc<SessionToken>,
    /// Runtime home used to resolve registered principal keys.
    pub home: AstridHome,
    /// Kernel event bus.
    pub event_bus: Arc<EventBus>,
    /// Daemon shutdown signal.
    pub shutdown: tokio::sync::watch::Receiver<bool>,
}

impl NativeUplink {
    /// Spawn the accept loop. The returned task exits when daemon shutdown is
    /// requested or the listener becomes unusable.
    #[must_use]
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(self.run())
    }

    async fn run(mut self) {
        let handshake_permits = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_HANDSHAKES));
        let mut connections = tokio::task::JoinSet::new();
        let egress_registry = egress::Registry::install(&self.event_bus);
        let (connection_shutdown_tx, connection_shutdown_rx) = tokio::sync::watch::channel(false);
        loop {
            let permit = tokio::select! {
                changed = self.shutdown.changed() => {
                    if changed.is_err() || *self.shutdown.borrow() {
                        break;
                    }
                    continue;
                },
                permit = Arc::clone(&handshake_permits).acquire_owned() => match permit {
                    Ok(permit) => permit,
                    Err(_) => break,
                },
            };
            let accepted = tokio::select! {
                changed = self.shutdown.changed() => {
                    drop(permit);
                    if changed.is_err() || *self.shutdown.borrow() {
                        break;
                    }
                    continue;
                },
                result = async {
                    let listener = self.listener.lock().await;
                    local_transport::accept(&listener).await
                } => result,
            };
            let stream = match accepted {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::warn!(%error, "native local uplink accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                },
            };
            let event_bus = Arc::clone(&self.event_bus);
            let mut shutdown = connection_shutdown_rx.clone();
            let session_token = Arc::clone(&self.session_token);
            let home = self.home.clone();
            let egress_registry = Arc::clone(&egress_registry);
            connections.spawn(async move {
                let handshake_permit = permit;
                let mut stream = stream;
                let identity = tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return;
                        }
                        return;
                    },
                    result = handshake::authenticate(&mut stream, &session_token, &home) => {
                        match result {
                            Ok(identity) => identity,
                            Err(reason) => {
                                tracing::warn!(
                                    security_event = true,
                                    %reason,
                                    "rejected local uplink connection"
                                );
                                return;
                            },
                        }
                    },
                };
                // Stalled, unauthenticated peers are bounded, but an
                // authenticated long-lived MCP connection must not consume
                // capacity needed by later status/stop clients.
                drop(handshake_permit);
                let egress = egress_registry.subscribe(
                    identity.principal.to_string(),
                    identity.device_key_id.clone(),
                );
                serve_connection(stream, identity, event_bus, egress, shutdown).await;
            });
            while let Some(result) = connections.try_join_next() {
                if let Err(error) = result {
                    tracing::warn!(%error, "native local uplink connection task failed");
                }
            }
        }
        let _ = connection_shutdown_tx.send(true);
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                tracing::warn!(%error, "native local uplink connection task failed");
            }
        }
    }
}

fn event_topic(event: &AstridEvent) -> Option<&str> {
    let AstridEvent::Ipc { message, .. } = event else {
        return None;
    };
    Some(message.topic.as_str())
}

async fn serve_connection(
    stream: LocalStream,
    identity: AuthenticatedIdentity,
    event_bus: Arc<EventBus>,
    mut receiver: egress::Subscription,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let principal = identity.principal.to_string();
    publish_lifecycle(&event_bus, Topic::client_connect(), &principal, None);
    tracing::info!(%principal, authenticated = identity.is_principal_verified(), "local client connected");

    let (reader, mut writer) = local_transport::split(stream);
    let mut reader = FramedReader::new(reader);
    let mut stream_accumulators = HashMap::new();

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    // A management shutdown response is published before the
                    // kernel flips this watch channel. Both become ready in
                    // the same scheduler turn, so drain already-buffered
                    // outbound frames before closing the transport. Without
                    // this, `select!` can observe shutdown first and discard
                    // the acknowledgement the CLI is waiting for.
                    let session = receiver.session();
                    drain_outbound_on_shutdown(
                        &mut writer,
                        &mut receiver,
                        &principal,
                        identity.device_key_id.as_deref(),
                        session.as_deref(),
                        &mut stream_accumulators,
                    ).await;
                    break;
                }
            },
            inbound = reader.read_message() => match inbound {
                Ok(Some(message)) => {
                    if let Err(reason) = validate_ingress(&message) {
                        tracing::warn!(security_event = true, %principal, %reason, "dropped local uplink message");
                        continue;
                    }
                    if message.topic.as_str() == routing::CHAT_REQUEST_TOPIC {
                        let session = routing::payload_session_id(&message.payload).map(str::to_owned);
                        routing::begin_turn(&message.payload, &mut stream_accumulators);
                        receiver.set_session(session);
                    }
                    // Rebuild the envelope so every provenance field is
                    // host-derived. The client controls only the allowlisted
                    // topic and payload — never principal, device, origin,
                    // source, signature, timestamp, or sequence.
                    let mut trusted = IpcMessage::new(
                        message.topic,
                        message.payload,
                        uuid::Uuid::nil(),
                    )
                    .with_principal(&principal);
                    trusted.device_key_id.clone_from(&identity.device_key_id);
                    trusted.origin = if identity.is_principal_verified() {
                        MessageOrigin::LocalSocket
                    } else {
                        MessageOrigin::System
                    };
                    event_bus.publish(AstridEvent::Ipc {
                        metadata: EventMetadata::new(EVENT_SOURCE),
                        message: trusted,
                    });
                },
                Ok(None) => break,
                Err(error) => {
                    tracing::warn!(%principal, %error, "local uplink read failed");
                    break;
                },
            },
            outbound = receiver.recv() => {
                let event = match outbound {
                    Ok(event) => event,
                    Err(egress::RecvError::Lagged) => {
                        tracing::error!(
                            security_event = true,
                            %principal,
                            "closing lagged local uplink connection"
                        );
                        break;
                    },
                };
                if let Err(error) = forward_outbound(
                    &mut writer,
                    &event,
                    &principal,
                    identity.device_key_id.as_deref(),
                    receiver.session().as_deref(),
                    &mut stream_accumulators,
                ).await {
                    tracing::warn!(%principal, %error, "local uplink write failed");
                    break;
                }
            },
        }
    }

    publish_lifecycle(
        &event_bus,
        Topic::client_disconnect(),
        &principal,
        Some("socket closed"),
    );
    tracing::info!(%principal, "local client disconnected");
}

async fn drain_outbound_on_shutdown(
    writer: &mut LocalWriteHalf,
    receiver: &mut egress::Subscription,
    principal: &str,
    device_key_id: Option<&str>,
    session: Option<&str>,
    stream_accumulators: &mut HashMap<String, Option<String>>,
) {
    loop {
        let event = match receiver.try_recv() {
            Ok(event) => event,
            Err(egress::TryRecvError::Empty) => break,
            Err(egress::TryRecvError::Lagged) => {
                tracing::error!(
                    security_event = true,
                    %principal,
                    "closing lagged local uplink connection"
                );
                break;
            },
        };
        if let Err(error) = forward_outbound(
            writer,
            &event,
            principal,
            device_key_id,
            session,
            stream_accumulators,
        )
        .await
        {
            tracing::warn!(
                %principal,
                %error,
                "local uplink write failed during shutdown drain"
            );
            break;
        }
    }
}

async fn forward_outbound(
    writer: &mut LocalWriteHalf,
    event: &AstridEvent,
    principal: &str,
    device_key_id: Option<&str>,
    session: Option<&str>,
    stream_accumulators: &mut HashMap<String, Option<String>>,
) -> std::io::Result<()> {
    let AstridEvent::Ipc { message, .. } = event else {
        return Ok(());
    };
    if !routing::should_deliver(message, principal, device_key_id, session) {
        return Ok(());
    }
    let mut message = message.clone();
    routing::reconcile_stream(&mut message, stream_accumulators);
    write_message(writer, &message).await
}

fn validate_ingress(message: &IpcMessage) -> Result<(), &'static str> {
    let topic = message.topic.as_str();
    if topic.len() > 256
        || topic.split('.').count() > 8
        || topic.is_empty()
        || topic.split('.').any(str::is_empty)
    {
        return Err("invalid topic shape");
    }
    if !routing::ingress_allowed(topic) {
        return Err("topic is not allowed from local clients");
    }
    let payload_len = serde_json::to_vec(&message.payload)
        .map_err(|_| "payload is not serializable")?
        .len();
    if payload_len > MAX_PAYLOAD_BYTES {
        return Err("payload exceeds IPC limit");
    }
    Ok(())
}

struct FramedReader<R> {
    reader: R,
    buffered: Vec<u8>,
}

impl<R: tokio::io::AsyncRead + Unpin> FramedReader<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            buffered: Vec::new(),
        }
    }

    /// Read one length-prefixed message while retaining partial frame state.
    ///
    /// `AsyncReadExt::read` is cancellation-safe, and all bytes returned by a
    /// completed read are appended before the next await. Recreating this
    /// future after another `select!` branch wins therefore cannot discard a
    /// partially received prefix or body.
    async fn read_message(&mut self) -> std::io::Result<Option<IpcMessage>> {
        loop {
            if self.buffered.len() >= 4 {
                let len = u32::from_be_bytes(
                    self.buffered[..4]
                        .try_into()
                        .expect("four-byte frame prefix"),
                ) as usize;
                if len > MAX_FRAME_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("IPC frame too large: {len} bytes"),
                    ));
                }
                let frame_len = 4_usize.checked_add(len).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "IPC frame overflow")
                })?;
                if self.buffered.len() >= frame_len {
                    let message =
                        serde_json::from_slice(&self.buffered[4..frame_len]).map_err(|error| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("invalid IPC message: {error}"),
                            )
                        })?;
                    self.buffered.drain(..frame_len);
                    return Ok(Some(message));
                }
            }

            let mut chunk = [0_u8; 8192];
            let read = self.reader.read(&mut chunk).await?;
            if read == 0 {
                if self.buffered.is_empty() {
                    return Ok(None);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "local IPC stream ended within a frame",
                ));
            }
            self.buffered.extend_from_slice(&chunk[..read]);
        }
    }
}

async fn write_message(writer: &mut LocalWriteHalf, message: &IpcMessage) -> std::io::Result<()> {
    let payload_bytes = message
        .payload
        .to_guest_bytes()
        .map_err(|error| std::io::Error::other(format!("serialize IPC payload: {error}")))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|error| std::io::Error::other(format!("decode IPC payload: {error}")))?;
    let mut frame = serde_json::json!({
        "topic": message.topic,
        "payload": payload,
        "source_id": message.source_id,
    });
    if let Some(principal) = &message.principal {
        frame
            .as_object_mut()
            .expect("wire frame is an object")
            .insert(
                "principal".to_owned(),
                serde_json::Value::String(principal.clone()),
            );
    }
    let bytes = serde_json::to_vec(&frame)
        .map_err(|error| std::io::Error::other(format!("serialize IPC message: {error}")))?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| std::io::Error::other("IPC message exceeds 4 GiB"))?;
    tokio::time::timeout(WRITE_TIMEOUT, async {
        writer.write_all(&len.to_be_bytes()).await?;
        writer.write_all(&bytes).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "IPC write timed out"))?
}

fn publish_lifecycle(event_bus: &EventBus, topic: Topic, principal: &str, reason: Option<&str>) {
    let payload = match reason {
        Some(reason) => IpcPayload::Disconnect {
            reason: Some(reason.to_owned()),
        },
        None => IpcPayload::Connect,
    };
    let message = IpcMessage::new(topic, payload, uuid::Uuid::nil()).with_principal(principal);
    event_bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new(EVENT_SOURCE),
        message,
    });
}

#[cfg(all(test, unix))]
mod tests {
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

    #[tokio::test]
    async fn framed_reader_retains_partial_body_when_read_is_cancelled() {
        let (mut writer, reader) = tokio::io::duplex(4096);
        let expected = IpcMessage::new(
            Topic::from_raw("astrid.v1.admin.status.test"),
            IpcPayload::RawJson(serde_json::json!({"request": "status"})),
            Uuid::new_v4(),
        );
        let body = serde_json::to_vec(&expected).expect("serialize frame");
        let split = body.len() / 2;
        writer
            .write_all(&(body.len() as u32).to_be_bytes())
            .await
            .expect("write prefix");
        writer
            .write_all(&body[..split])
            .await
            .expect("write partial body");

        let mut reader = FramedReader::new(reader);
        tokio::time::timeout(Duration::from_millis(20), reader.read_message())
            .await
            .expect_err("partial frame should remain pending");

        writer
            .write_all(&body[split..])
            .await
            .expect("write body remainder");
        let actual = tokio::time::timeout(Duration::from_secs(2), reader.read_message())
            .await
            .expect("completed frame timeout")
            .expect("read completed frame")
            .expect("frame present");
        assert_eq!(actual.topic, expected.topic);
        assert_eq!(actual.payload, expected.payload);
        assert_eq!(actual.source_id, expected.source_id);
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
        let mut client = SocketClient::from_stream_for_test(
            stream,
            SessionId::from_uuid(Uuid::new_v4()),
            requested,
        );
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
}
