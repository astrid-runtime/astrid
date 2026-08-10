//! Astrid's built-in local socket server.
//!
//! This is the baseline control-plane transport. Distributions may add
//! frontends, but daemon boot and the `astrid` CLI do not depend on one.

mod egress;
mod framing;
mod handshake;
mod routing;
#[cfg(all(test, unix))]
mod tests;

use std::collections::HashMap;
use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::{KernelRequest, KernelResponse};
use astrid_core::local_transport::{self, LocalListener, LocalStream, LocalWriteHalf};
use astrid_core::session_token::SessionToken;
use astrid_events::{AstridEvent, EventBus, EventMetadata};
use astrid_types::Topic;
use astrid_types::ipc::{IpcMessage, IpcPayload, MessageOrigin};
use tokio::io::AsyncWriteExt;

use framing::FramedReader;
use handshake::AuthenticatedIdentity;

const MAX_PENDING_HANDSHAKES: usize = 8;
const MAX_ESTABLISHED_CONNECTIONS: usize = 128;
const RESERVED_ADMIN_CONNECTIONS: usize = 8;
const RESERVED_ADMIN_ADMISSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
const RESERVED_ADMIN_LIFETIME: std::time::Duration = std::time::Duration::from_mins(1);
// A valid payload is at most 1 MiB. Allow another MiB for the JSON envelope,
// topic, and provenance fields without permitting a small set of peers to
// force 50 MiB allocations with ignored metadata.
const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
const CLIENT_EGRESS_CAPACITY: usize = 1024;
const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const EVENT_SOURCE: &str = "native_local_uplink";

struct ReservedResponse {
    topic: String,
}

struct ConnectionAdmission {
    _permit: tokio::sync::OwnedSemaphorePermit,
    initial_message: Option<IpcMessage>,
    reserved_response: Option<ReservedResponse>,
}

struct ConnectionRuntime {
    session_token: Arc<SessionToken>,
    home: AstridHome,
    event_bus: Arc<EventBus>,
    egress_registry: Arc<egress::Registry>,
    established_permits: Arc<tokio::sync::Semaphore>,
    reserved_admin_permits: Arc<tokio::sync::Semaphore>,
    shutdown: tokio::sync::watch::Receiver<bool>,
}

impl ConnectionRuntime {
    async fn handle(
        self: Arc<Self>,
        mut stream: LocalStream,
        handshake_permit: tokio::sync::OwnedSemaphorePermit,
    ) {
        let mut shutdown = self.shutdown.clone();
        let identity = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
                return;
            },
            result = handshake::authenticate(&mut stream, &self.session_token, &self.home) => {
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
        let admission =
            if let Ok(permit) = Arc::clone(&self.established_permits).try_acquire_owned() {
                ConnectionAdmission {
                    _permit: permit,
                    initial_message: None,
                    reserved_response: None,
                }
            } else {
                let Some(admission) = self.admit_reserved_admin(&mut stream).await else {
                    return;
                };
                admission
            };
        drop(handshake_permit);
        let egress = self.egress_registry.subscribe(
            identity.principal.to_string(),
            identity.device_key_id.clone(),
        );
        serve_connection(
            stream,
            identity,
            Arc::clone(&self.event_bus),
            egress,
            shutdown,
            admission,
        )
        .await;
    }

    async fn admit_reserved_admin(&self, stream: &mut LocalStream) -> Option<ConnectionAdmission> {
        let mut reader = FramedReader::new(stream);
        let message =
            match tokio::time::timeout(RESERVED_ADMIN_ADMISSION_TIMEOUT, reader.read_message())
                .await
            {
                Ok(Ok(Some(message))) => message,
                Ok(Ok(None)) => return None,
                Ok(Err(error)) => {
                    tracing::warn!(%error, "reserved admin admission read failed");
                    return None;
                },
                Err(_) => {
                    tracing::warn!("reserved admin admission timed out");
                    return None;
                },
            };
        if let Err(reason) = validate_ingress(&message) {
            tracing::warn!(security_event = true, %reason, "reserved admin admission rejected");
            return None;
        }
        let Some(reserved_response) = reserved_response_for(&message) else {
            tracing::warn!("non-admin request rejected from reserved connection lane");
            return None;
        };
        let Ok(permit) = Arc::clone(&self.reserved_admin_permits).try_acquire_owned() else {
            tracing::warn!("reserved admin connection limit exhausted");
            return None;
        };
        Some(ConnectionAdmission {
            _permit: permit,
            initial_message: Some(message),
            reserved_response: Some(reserved_response),
        })
    }
}

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
        let established_permits =
            Arc::new(tokio::sync::Semaphore::new(MAX_ESTABLISHED_CONNECTIONS));
        let reserved_admin_permits =
            Arc::new(tokio::sync::Semaphore::new(RESERVED_ADMIN_CONNECTIONS));
        let egress_registry = egress::Registry::install(&self.event_bus);
        let (connection_shutdown_tx, connection_shutdown_rx) = tokio::sync::watch::channel(false);
        let runtime = Arc::new(ConnectionRuntime {
            session_token: Arc::clone(&self.session_token),
            home: self.home.clone(),
            event_bus: Arc::clone(&self.event_bus),
            egress_registry,
            established_permits,
            reserved_admin_permits,
            shutdown: connection_shutdown_rx,
        });
        let mut connections = tokio::task::JoinSet::new();
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
            connections.spawn(Arc::clone(&runtime).handle(stream, permit));
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

fn publish_trusted_ingress(
    event_bus: &EventBus,
    identity: &AuthenticatedIdentity,
    principal: &str,
    message: IpcMessage,
) {
    // Rebuild the envelope so every provenance field is host-derived. The
    // client controls only the allowlisted topic and payload.
    let mut trusted = IpcMessage::new(message.topic, message.payload, uuid::Uuid::nil())
        .with_principal(principal);
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
}

fn reserved_response_for(message: &IpcMessage) -> Option<ReservedResponse> {
    let (operation, correlation) = message
        .topic
        .as_str()
        .strip_prefix("astrid.v1.request.")?
        .split_once('.')?;
    if correlation.is_empty() || correlation.contains('.') {
        return None;
    }
    let IpcPayload::RawJson(value) = &message.payload else {
        return None;
    };
    let request: KernelRequest = serde_json::from_value(value.clone()).ok()?;
    let matches_operation = matches!(
        (operation, request),
        ("status", KernelRequest::GetStatus) | ("shutdown", KernelRequest::Shutdown { .. })
    );
    matches_operation.then(|| ReservedResponse {
        topic: format!("astrid.v1.response.{operation}.{correlation}"),
    })
}

fn reserved_response_matches(event: &AstridEvent, expected: &ReservedResponse) -> bool {
    let AstridEvent::Ipc { message, .. } = event else {
        return false;
    };
    if message.topic.as_str() != expected.topic {
        return false;
    }
    let IpcPayload::RawJson(value) = &message.payload else {
        return true;
    };
    !matches!(
        serde_json::from_value::<KernelResponse>(value.clone()),
        Ok(KernelResponse::Working)
    )
}

fn process_inbound(
    event_bus: &EventBus,
    identity: &AuthenticatedIdentity,
    principal: &str,
    receiver: &egress::Subscription,
    message: IpcMessage,
) -> Result<(), &'static str> {
    validate_ingress(&message)?;
    if message.topic.as_str() == routing::CHAT_REQUEST_TOPIC {
        let session = routing::payload_session_id(&message.payload)
            .ok_or("chat request is missing a session ID")?;
        if routing::is_cancel_turn(&message.payload) {
            if receiver.session().as_deref() != Some(session) {
                return Err("cancellation does not match this connection's active session");
            }
        } else if !receiver.begin_turn(session) {
            return Err("this principal or connection already has an active turn");
        }
    }
    publish_trusted_ingress(event_bus, identity, principal, message);
    Ok(())
}

async fn serve_connection(
    stream: LocalStream,
    identity: AuthenticatedIdentity,
    event_bus: Arc<EventBus>,
    mut receiver: egress::Subscription,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    mut admission: ConnectionAdmission,
) {
    let principal = identity.principal.to_string();
    let (reader, mut writer) = local_transport::split(stream);
    let mut reader = FramedReader::new(reader);
    let mut stream_accumulators = HashMap::new();
    let reserved_admin = admission.reserved_response.is_some();
    let reserved_deadline = tokio::time::Instant::now()
        .checked_add(RESERVED_ADMIN_LIFETIME)
        .unwrap_or_else(tokio::time::Instant::now);
    if let Some(message) = admission.initial_message.take()
        && let Err(reason) = process_inbound(&event_bus, &identity, &principal, &receiver, message)
    {
        tracing::warn!(security_event = true, %principal, %reason);
        return;
    }
    publish_lifecycle(&event_bus, Topic::client_connect(), &principal, None);
    tracing::info!(%principal, authenticated = identity.is_principal_verified(), "local client connected");

    loop {
        tokio::select! {
            () = tokio::time::sleep_until(reserved_deadline), if reserved_admin => {
                tracing::warn!(%principal, "reserved admin connection exceeded its lifetime");
                break;
            },
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
                    if reserved_admin {
                        tracing::warn!(%principal, "reserved admin connection attempted multiple requests");
                        break;
                    }
                    if let Err(reason) = process_inbound(
                        &event_bus,
                        &identity,
                        &principal,
                        &receiver,
                        message,
                    ) {
                        tracing::warn!(security_event = true, %principal, %reason, "dropped local uplink message");
                    }
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
                if admission
                    .reserved_response
                    .as_ref()
                    .is_some_and(|expected| reserved_response_matches(&event, expected))
                {
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
