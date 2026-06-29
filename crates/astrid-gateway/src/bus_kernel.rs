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

use anyhow::{Context, Result, anyhow};
use astrid_core::PrincipalId;
use astrid_core::kernel_api::{KernelRequest, KernelResponse};
use astrid_events::ipc::{IpcMessage, IpcPayload, MessageOrigin, Topic};
use astrid_events::{AstridEvent, EventBus, EventMetadata};
use astrid_uplink::kernel_client::topic_suffix;
use serde_json::Value;
use uuid::Uuid;

/// Match the socket client's default so route timeouts stay consistent.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

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

    /// Send a kernel request and await the matching response.
    ///
    /// # Errors
    /// Returns an error on serialisation failure, timeout, event-bus shutdown,
    /// or a response payload that cannot be decoded as [`KernelResponse`].
    pub async fn request(&self, req: KernelRequest) -> Result<KernelResponse> {
        let (msg, want_response) =
            build_request_message(&self.caller, self.device_key_id.as_deref(), &req)
                .context("build bus kernel request")?;

        let mut receiver = self.bus.subscribe_topic(want_response.as_str());
        self.bus.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("astrid-gateway::bus_kernel"),
            message: msg,
        });

        let deadline = tokio::time::Instant::now()
            .checked_add(self.timeout)
            .unwrap_or_else(tokio::time::Instant::now);

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!(
                    "bus kernel request timed out after {:?} waiting for {want_response}",
                    self.timeout
                ));
            }

            let event = match tokio::time::timeout(remaining, receiver.recv()).await {
                Ok(Some(ev)) => ev,
                Ok(None) => {
                    return Err(anyhow!(
                        "event bus closed before response on {want_response}"
                    ));
                },
                Err(_) => {
                    return Err(anyhow!(
                        "bus kernel request timed out after {:?} waiting for {want_response}",
                        self.timeout
                    ));
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
                return Ok(resp);
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

        let mut request_rx = bus.subscribe_topic_as("astrid.v1.kernel.request.status.*", "test");
        let bus_bg = Arc::clone(&bus);
        tokio::spawn(async move {
            let event = request_rx.recv().await.expect("request published");
            let AstridEvent::Ipc { message, .. } = &*event else {
                panic!("expected IPC request");
            };
            let response_topic = Topic::kernel_response(
                message
                    .topic
                    .as_str()
                    .strip_prefix("astrid.v1.kernel.request.")
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
            err.to_string().contains("timed out"),
            "unexpected error: {err:#}"
        );
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
}
