//! In-process kernel-request client for co-located gateway routes.
//!
//! The socket-backed [`astrid_uplink::KernelClient`] is the right transport for
//! external uplinks that can authenticate their own principal key. The HTTP
//! gateway is different: it already verified a bearer token and has a live
//! `EventBus` handle from the daemon, but it must not hold every agent's
//! private key. Sending a bearer-authenticated request back through the socket
//! path can therefore fall back to an unauthenticated `anonymous` caller.
//!
//! This client mirrors `KernelClient`'s topic and payload shape while publishing
//! directly onto the shared bus. The caller principal and optional device key id
//! are stamped from the verified HTTP context, matching the admin bus client.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use astrid_core::PrincipalId;
use astrid_core::kernel_api::{KernelRequest, KernelResponse};
use astrid_events::ipc::{IpcMessage, IpcPayload, MessageOrigin, Topic};
use astrid_events::{AstridEvent, EventBus, EventMetadata};
use astrid_uplink::kernel_client::{KernelClientError, TimeoutKind, topic_suffix};
use serde_json::Value;
use tokio::time::Instant;
use uuid::Uuid;

/// Inactivity (max-silence-between-frames) timeout — matches the socket client's
/// `DEFAULT_TIMEOUT`. NOT a total deadline: the kernel emits a
/// [`KernelResponse::Working`] keepalive every 5s while a slow handler (chiefly
/// `InstallCapsule`) is in flight, and each such frame resets this window, so a
/// legitimately slow install no longer trips a 15s total deadline. Sized at ~3x
/// the 5s keepalive interval to tolerate a couple of missed pings.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Absolute backstop on the total wait for one request — matches the socket
/// client's `MAX_TOTAL`. Bounds a kernel that keeps pinging forever; exceeding
/// it returns a timeout error (mapped to 504) just like an inactivity timeout.
const MAX_TOTAL: Duration = Duration::from_mins(10);

/// Bus-direct kernel-request client.
pub struct BusKernelClient {
    bus: Arc<EventBus>,
    caller: PrincipalId,
    device_key_id: Option<String>,
    expected_source_id: Uuid,
    timeout: Duration,
}

impl BusKernelClient {
    /// Build a client bound to `caller`.
    #[must_use]
    pub fn new(bus: Arc<EventBus>, caller: PrincipalId, expected_source_id: Uuid) -> Self {
        Self {
            bus,
            caller,
            device_key_id: None,
            expected_source_id,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Bind the device `key_id` this caller's bearer was scoped to, if any.
    #[must_use]
    pub fn with_device_key_id(mut self, device_key_id: Option<String>) -> Self {
        self.device_key_id = device_key_id;
        self
    }

    /// Override the response timeout (used in tests).
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send a kernel request and await the matching terminal response,
    /// tolerating any number of intervening [`KernelResponse::Working`]
    /// keepalive frames.
    ///
    /// The wait is an **inactivity** loop: [`self.timeout`](Self::with_timeout)
    /// bounds the silence *between* frames on the response topic, not the whole
    /// request. A `Working` keepalive resets that window (its arrival is
    /// activity, so the deadline is recomputed from "now") and is swallowed —
    /// it never reaches an HTTP client — so a slow-but-live handler (an
    /// `InstallCapsule` running its `#[install]` hook under load) does not trip
    /// a total-deadline timeout. An overall [`MAX_TOTAL`] ceiling bounds a
    /// kernel that keeps pinging forever.
    ///
    /// # Errors
    /// Returns [`KernelClientError`]: `Timeout` on the inactivity window or the
    /// overall [`MAX_TOTAL`] ceiling (the route layer maps this to 504),
    /// `BusClosed` if the event bus shuts down first, `Build` on a serialise
    /// failure, and `Deserialize` on an undecodable frame — all 500.
    pub async fn request(
        &self,
        req: KernelRequest,
    ) -> std::result::Result<KernelResponse, KernelClientError> {
        let (msg, want_response) =
            build_request_message(&self.caller, self.device_key_id.as_deref(), &req)
                .map_err(|source| KernelClientError::Build { source })?;
        let topic = want_response.as_str().to_string();

        let mut receiver = self.bus.subscribe_topic(want_response.as_str());
        self.bus.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("astrid-gateway::bus_kernel"),
            message: msg,
        });

        let started = Instant::now();
        // Inactivity deadline: recomputed from "now" on every activity (any
        // frame on the response topic, including a `Working` keepalive).
        let mut inactivity_deadline = Instant::now()
            .checked_add(self.timeout)
            .unwrap_or_else(Instant::now);

        loop {
            // Cap each wait to min(inactivity remaining, ceiling remaining) so
            // the overall ceiling can't be overshot by up to a full inactivity
            // window even while the kernel keeps pinging.
            let ceiling_left = MAX_TOTAL.saturating_sub(started.elapsed());
            let inactivity_left = inactivity_deadline.saturating_duration_since(Instant::now());
            let remaining = ceiling_left.min(inactivity_left);
            if remaining.is_zero() {
                // Whichever budget is exhausted classifies the timeout; the
                // ceiling wins ties (a wedged-but-pinging kernel).
                let kind = if ceiling_left <= inactivity_left {
                    TimeoutKind::Ceiling
                } else {
                    TimeoutKind::Inactivity
                };
                return Err(KernelClientError::Timeout {
                    topic: topic.clone(),
                    kind,
                });
            }
            // Whether the ceiling is the binding constraint on this wait — used to
            // classify a read timeout as Ceiling vs Inactivity.
            let capped_by_ceiling = ceiling_left < inactivity_left;

            let event = match tokio::time::timeout(remaining, receiver.recv()).await {
                Ok(Some(ev)) => ev,
                Ok(None) => {
                    return Err(KernelClientError::BusClosed {
                        topic: topic.clone(),
                    });
                },
                Err(_) => {
                    return Err(KernelClientError::Timeout {
                        topic: topic.clone(),
                        kind: if capped_by_ceiling {
                            TimeoutKind::Ceiling
                        } else {
                            TimeoutKind::Inactivity
                        },
                    });
                },
            };

            let AstridEvent::Ipc { message, .. } = &*event else {
                continue;
            };
            if message.topic != want_response {
                continue;
            }
            if message.source_id != self.expected_source_id {
                continue;
            }
            if let Some(resp) = extract_kernel_response(&message.payload) {
                match resp {
                    // Keepalive: the handler is still alive. Reset the inactivity
                    // window from now and keep waiting. Swallowed — never
                    // surfaces to the HTTP client. A stray late `Working` racing
                    // out after the terminal is harmless (this arm just loops).
                    KernelResponse::Working => {
                        inactivity_deadline = Instant::now()
                            .checked_add(self.timeout)
                            .unwrap_or_else(Instant::now);
                    },
                    other => return Ok(other),
                }
            }
        }
    }
}

fn build_request_message(
    caller: &PrincipalId,
    device_key_id: Option<&str>,
    req: &KernelRequest,
) -> Result<(IpcMessage, Topic)> {
    let correlation = Uuid::new_v4().simple().to_string();
    let suffix = format!("{}.{correlation}", topic_suffix(req));
    let request_topic = Topic::kernel_request(&suffix);
    let want_response = Topic::kernel_response(&suffix);
    let payload = serde_json::to_value(req).context("serialise KernelRequest")?;

    let mut msg = IpcMessage::new(request_topic, IpcPayload::RawJson(payload), Uuid::nil())
        .with_principal(caller.to_string())
        .with_origin(MessageOrigin::RemoteGateway);
    if let Some(kid) = device_key_id {
        msg = msg.with_device_key_id(kid);
    }
    Ok((msg, want_response))
}

fn extract_kernel_response(payload: &IpcPayload) -> Option<KernelResponse> {
    let value: Value = match payload {
        IpcPayload::RawJson(v) => v.clone(),
        other => serde_json::to_value(other).ok()?,
    };
    let value = if value
        .as_object()
        .is_some_and(|m| m.contains_key("type") && m.contains_key("value"))
    {
        value.get("value").cloned().unwrap_or(value)
    } else {
        value
    };
    serde_json::from_value::<KernelResponse>(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_ignores_wrong_source_kernel_response() {
        let bus = Arc::new(EventBus::new());
        let expected_source = Uuid::from_u128(0x1111);
        let caller = PrincipalId::new("alice").expect("valid principal");
        let client = BusKernelClient::new(Arc::clone(&bus), caller, expected_source)
            .with_timeout(Duration::from_millis(150));

        let mut request_rx = bus.subscribe_topic_as("astrid.v1.request.status.*", "test");
        let bus_bg = Arc::clone(&bus);
        let (saw_request_tx, saw_request_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let event = request_rx.recv().await.expect("request published");
            let _ = saw_request_tx.send(());
            let AstridEvent::Ipc { message, .. } = &*event else {
                panic!("expected IPC request");
            };
            let response_topic = Topic::kernel_response(
                message
                    .topic
                    .as_str()
                    .strip_prefix("astrid.v1.request.")
                    .expect("kernel request topic suffix"),
            );
            let payload = serde_json::to_value(KernelResponse::Success(serde_json::json!({
                "forged": true,
            })))
            .expect("response serializes");
            let forged = IpcMessage::new(
                response_topic,
                IpcPayload::RawJson(payload),
                Uuid::from_u128(0x2222),
            );
            bus_bg.publish(AstridEvent::Ipc {
                metadata: EventMetadata::new("test::forged-kernel"),
                message: forged,
            });
        });

        let err = client
            .request(KernelRequest::GetStatus)
            .await
            .expect_err("wrong-source kernel response must be ignored");
        assert!(
            matches!(err, KernelClientError::Timeout { .. }),
            "a wrong-source response must be ignored and time out: {err:?}"
        );
        tokio::time::timeout(Duration::from_millis(250), saw_request_rx)
            .await
            .expect("wrong-source regression must observe the real request topic")
            .expect("request observer task dropped");
    }

    #[test]
    fn request_message_stamps_gateway_origin_principal_and_device_key() {
        let caller = PrincipalId::new("regular-user").unwrap();
        let (msg, want_response) =
            build_request_message(&caller, Some("abcdef0123456789"), &KernelRequest::GetStatus)
                .expect("build request");

        assert!(msg.topic.as_str().starts_with("astrid.v1.request.status."));
        assert!(
            want_response
                .as_str()
                .starts_with("astrid.v1.response.status.")
        );
        assert_eq!(msg.principal.as_deref(), Some("regular-user"));
        assert_eq!(msg.device_key_id.as_deref(), Some("abcdef0123456789"));
        assert_eq!(msg.origin, MessageOrigin::RemoteGateway);
    }

    #[test]
    fn request_message_omits_device_key_for_full_authority_bearer() {
        let caller = PrincipalId::new("regular-user").unwrap();
        let (msg, _) =
            build_request_message(&caller, None, &KernelRequest::GetStatus).expect("build request");

        assert_eq!(msg.principal.as_deref(), Some("regular-user"));
        assert!(msg.device_key_id.is_none());
        assert_eq!(msg.origin, MessageOrigin::RemoteGateway);
    }

    #[test]
    fn extracts_raw_json_kernel_response() {
        let payload = IpcPayload::RawJson(
            serde_json::to_value(KernelResponse::Error("denied".to_string())).unwrap(),
        );

        assert!(matches!(
            extract_kernel_response(&payload),
            Some(KernelResponse::Error(msg)) if msg == "denied"
        ));
    }

    /// A slow kernel that emits `Working` keepalives before the real answer must
    /// have those keepalives SWALLOWED — `request()` returns only the terminal
    /// `Success`, never `Working`. This is the gateway-side proof that a
    /// keepalive never surfaces to the HTTP layer.
    #[tokio::test]
    async fn working_keepalives_are_swallowed_and_terminal_returned() {
        let bus = Arc::new(EventBus::new());
        let source = Uuid::from_u128(0x1234);
        let caller = PrincipalId::new("alice").expect("valid principal");
        let client = BusKernelClient::new(Arc::clone(&bus), caller, source)
            .with_timeout(Duration::from_secs(2));

        // Subscribe to the request topic BEFORE the client publishes, so the
        // faux-kernel task cannot miss the request frame (the client subscribes
        // to its own response topic before publishing, so responses are safe).
        let mut req_rx = bus.subscribe_topic_as("astrid.v1.request.status.*", "test-kernel");
        let bus_bg = Arc::clone(&bus);
        let server = tokio::spawn(async move {
            let event = req_rx.recv().await.expect("request published");
            let AstridEvent::Ipc { message, .. } = &*event else {
                panic!("expected IPC request");
            };
            let response_topic = Topic::kernel_response(
                message
                    .topic
                    .as_str()
                    .strip_prefix("astrid.v1.request.")
                    .expect("kernel request topic suffix"),
            );
            let publish = |resp: &KernelResponse| {
                let payload = serde_json::to_value(resp).expect("serialize response");
                let msg =
                    IpcMessage::new(response_topic.clone(), IpcPayload::RawJson(payload), source);
                bus_bg.publish(AstridEvent::Ipc {
                    metadata: EventMetadata::new("test::slow-kernel"),
                    message: msg,
                });
            };
            // Three keepalives, then the real answer.
            for _ in 0..3 {
                publish(&KernelResponse::Working);
            }
            publish(&KernelResponse::Success(
                serde_json::json!({ "installed": true }),
            ));
        });

        let resp = client
            .request(KernelRequest::GetStatus)
            .await
            .expect("terminal response after keepalives");
        assert!(
            matches!(resp, KernelResponse::Success(v) if v == serde_json::json!({ "installed": true })),
            "only the terminal Success may surface; Working keepalives are swallowed",
        );
        server.await.expect("server task");
    }

    /// A silent kernel (no frame at all) trips the inactivity timeout, and the
    /// returned error is a typed `KernelClientError::Timeout` so the route layer
    /// maps it to 504 rather than 500.
    #[tokio::test]
    async fn inactivity_timeout_is_typed_for_504_mapping() {
        let bus = Arc::new(EventBus::new());
        let caller = PrincipalId::new("alice").expect("valid principal");
        let client = BusKernelClient::new(Arc::clone(&bus), caller, Uuid::from_u128(1))
            .with_timeout(Duration::from_millis(80));

        let err = client
            .request(KernelRequest::GetStatus)
            .await
            .expect_err("silent kernel must time out");
        assert!(
            matches!(
                err,
                KernelClientError::Timeout {
                    kind: TimeoutKind::Inactivity,
                    ..
                }
            ),
            "a bus-kernel inactivity timeout must be a typed inactivity Timeout: {err:?}"
        );
        assert!(err.is_timeout(), "and is_timeout() must agree");
    }
}
