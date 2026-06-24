//! In-process admin client that talks to the kernel via the
//! shared `EventBus` instead of going over the Unix socket and
//! through the `astrid-capsule-cli` proxy capsule.
//!
//! The socket path (the `astrid_uplink::AdminClient` family) was
//! built for **external** uplinks — the CLI, future remote
//! dashboards talking to a different daemon. The HTTP gateway is
//! co-located with the daemon: it gets `Arc<EventBus>` injected at
//! boot and shares the same in-process bus the kernel reads from.
//! Routing admin requests through the socket means three extra
//! hops (gateway → socket → proxy → bus) and bottlenecks on the
//! proxy's accept loop / `MAX_ACTIVE_STREAMS = 8` budget. For a
//! deployment hosting thousands of agents that's a hard wall at
//! ~19 admin RPS per daemon.
//!
//! This client publishes the admin request straight onto the
//! kernel's bus and subscribes to the response topic in-process —
//! same envelope shape as `AdminClient`, but with no proxy in the
//! middle. The kernel's admin dispatcher does not distinguish
//! between bus-direct and proxy-relayed requests: both arrive as
//! `IpcMessage`s with the same topic/payload/principal shape.
//!
//! ## Correlation
//!
//! Each request carries a fresh UUID `request_id` in the payload.
//! The kernel's response handler echoes it back. We subscribe to
//! the response topic **before** publishing (avoids a race where a
//! fast response lands before the subscription is open) and filter
//! incoming responses by `request_id` so concurrent in-flight
//! calls don't pick up each other's responses.
//!
//! ## Trust
//!
//! Identical to `AdminClient`. The gateway has already
//! cryptographically verified the inbound bearer and resolved
//! `caller: PrincipalId`. We stamp that on the outgoing message;
//! the kernel's `resolve_caller` reads the IPC envelope's
//! `principal` field for cap-gating.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use astrid_core::PrincipalId;
use astrid_core::kernel_api::{
    AdminKernelRequest, AdminKernelResponse, AdminRequestKind, AdminResponseBody,
};
use astrid_events::ipc::{IpcMessage, IpcPayload};
use astrid_events::{AstridEvent, EventBus, EventMetadata};
use astrid_uplink::{request_topic, response_topic};
use serde_json::Value;
use uuid::Uuid;

/// Match the socket client's default so timeouts behave the same
/// from the operator's perspective.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Bus-direct admin client.
pub struct BusAdminClient {
    bus: Arc<EventBus>,
    caller: PrincipalId,
    /// The device `key_id` the inbound bearer was scoped to, if any. Stamped
    /// onto every outbound admin request so the kernel cap-gate can apply this
    /// device's scope as an attenuation floor on `caller`'s authority. `None`
    /// for a legacy full-authority bearer or a bootstrap (`default`) caller.
    device_key_id: Option<String>,
    timeout: Duration,
}

impl BusAdminClient {
    /// Build a client bound to `caller`. Cloning `Arc<EventBus>` is
    /// cheap — every gateway request can mint one.
    ///
    /// The client is unscoped (no device key); use
    /// [`with_device_key_id`](Self::with_device_key_id) for a request that must
    /// carry a scoped caller's device id to the kernel cap-gate.
    #[must_use]
    pub fn new(bus: Arc<EventBus>, caller: PrincipalId) -> Self {
        Self {
            bus,
            caller,
            device_key_id: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Bind the device `key_id` this caller's bearer was scoped to, so the
    /// kernel cap-gate attenuates the request to that device's scope. `None`
    /// leaves the request unattenuated (full principal authority).
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

    /// Send an admin request and await the matching response.
    ///
    /// # Errors
    /// Returns an error on serialisation failure, timeout, or a
    /// response shape the dispatcher refuses to deserialise.
    pub async fn request(&self, kind: AdminRequestKind) -> Result<AdminResponseBody> {
        let request_id = Uuid::new_v4().to_string();
        let want_response = response_topic(&kind);
        let topic = request_topic(&kind);

        // Subscribe FIRST. A fast kernel handler can publish the
        // response on the same tokio task that processes the
        // request — subscribing afterwards would miss it.
        let mut receiver = self.bus.subscribe_topic(want_response.as_str());

        let req = AdminKernelRequest::with_request_id(request_id.clone(), kind);
        let payload = serde_json::to_value(&req).context("serialize AdminKernelRequest")?;
        let mut msg = IpcMessage::new(topic, IpcPayload::RawJson(payload), Uuid::nil())
            .with_principal(self.caller.to_string())
            // Host-stamp the gateway transport origin so no message published by
            // a gateway route inherits the `System` default; an admin op from
            // a remote bearer is `RemoteGateway`, never a local operator.
            .with_origin(astrid_events::ipc::MessageOrigin::RemoteGateway);
        // Carry the caller's device scope to the kernel cap-gate. A scoped
        // bearer's key_id rides on every admin op so a paired device cannot
        // exceed its scope (e.g. a use-only device's PairDeviceIssue is denied
        // even though its principal holds `self:auth:pair`).
        if let Some(key_id) = &self.device_key_id {
            msg = msg.with_device_key_id(key_id.clone());
        }
        self.bus.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("astrid-gateway::bus_admin"),
            message: msg,
        });

        let deadline = tokio::time::Instant::now()
            .checked_add(self.timeout)
            .unwrap_or_else(tokio::time::Instant::now);

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!(
                    "bus admin request timed out after {:?} waiting for {want_response}",
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
                        "bus admin request timed out after {:?} waiting for {want_response}",
                        self.timeout
                    ));
                },
            };

            let AstridEvent::Ipc { message, .. } = &*event else {
                continue;
            };
            // The kernel's `publish_response` wraps the
            // `AdminKernelResponse` in `IpcPayload::RawJson`, with
            // an explicit `request_id` for correlation.
            let value: Value = match &message.payload {
                IpcPayload::RawJson(v) => v.clone(),
                other => match serde_json::to_value(other) {
                    Ok(v) => v,
                    Err(_) => continue,
                },
            };
            if let Some(req_id) = value.get("request_id").and_then(Value::as_str) {
                if req_id != request_id {
                    continue;
                }
            } else {
                // No request_id on the envelope — older shape or
                // foreign payload. Skip rather than mis-assign.
                continue;
            }

            let resp: AdminKernelResponse = match serde_json::from_value(value) {
                Ok(r) => r,
                Err(_) => continue,
            };
            return Ok(resp.body);
        }
    }
}
