//! Non-lossy client connection lifecycle accounting.

use std::sync::Arc;

use astrid_events::ipc::IpcPayload;
use tracing::{debug, warn};

use super::caller::resolve_connection_principal;

/// Whether a `client.v1.*` message opens or closes a connection.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ConnectionSignal {
    Opened,
    /// Carries the disconnect reason when present — the typed
    /// `IpcPayload::Disconnect { reason }`, or a `"reason"` string in a JSON
    /// payload — so the tracker can preserve it in the diagnostic log.
    Closed {
        reason: Option<String>,
    },
}

/// Classifies a `client.v1.*` message as a connection open/close.
///
/// Recognises **both** the typed [`IpcPayload::Connect`]/[`IpcPayload::Disconnect`]
/// that native producers emit, **and** the `client.v1.connect` /
/// `client.v1.disconnect` topics carrying any payload. Uplink capsules can only
/// reach the bus through the JSON-only SDK publish surface (no typed-payload
/// publish exists), so the topic is the only signal they can produce — without
/// the topic arm, the per-principal connection counter is never populated and
/// the idle monitor / `astrid who` see zero connections regardless of reality.
///
/// Typed payloads take precedence over the topic, so a mismatched topic can
/// never suppress a real connection event.
pub(super) fn connection_signal(topic: &str, payload: &IpcPayload) -> Option<ConnectionSignal> {
    match payload {
        IpcPayload::Disconnect { reason } => Some(ConnectionSignal::Closed {
            reason: reason.clone(),
        }),
        IpcPayload::Connect => Some(ConnectionSignal::Opened),
        // Uplink capsules can only publish JSON; the topic is the signal, and
        // the reason (if any) rides along under the `"reason"` key.
        IpcPayload::RawJson(val) if topic == "client.v1.disconnect" => {
            let reason = val.get("reason").and_then(|r| r.as_str().map(String::from));
            Some(ConnectionSignal::Closed { reason })
        },
        _ if topic == "client.v1.disconnect" => Some(ConnectionSignal::Closed { reason: None }),
        _ if topic == "client.v1.connect" => Some(ConnectionSignal::Opened),
        _ => None,
    }
}

/// Register non-lossy client connection lifecycle accounting.
///
/// Connection leases control ephemeral process lifetime, so they cannot ride
/// the bounded broadcast receiver used for ordinary event consumers. This
/// synchronous observer performs only atomic bookkeeping and captures a weak
/// kernel reference to avoid an `EventBus` → `Kernel` → `EventBus` cycle.
pub(super) fn register_connection_tracker(kernel: &Arc<crate::Kernel>) {
    let weak_kernel = Arc::downgrade(kernel);
    kernel
        .event_bus
        .observe_permanently("connection_tracker", move |event| {
            let astrid_events::AstridEvent::Ipc { message, .. } = event else {
                return;
            };
            let Some(signal) = connection_signal(&message.topic, &message.payload) else {
                return;
            };
            // Lifecycle messages without a principal belong to the explicit
            // no-authority identity. A malformed principal is not a lifecycle
            // identity at all, so ignore it rather than crediting the bootstrap
            // `default` principal with a connection it never authenticated.
            let principal = match resolve_connection_principal(message) {
                Ok(principal) => principal,
                Err(error) => {
                    warn!(
                        security_event = true,
                        topic = %message.topic,
                        reason = error.reason(),
                        "Ignored connection lifecycle event with malformed principal"
                    );
                    return;
                },
            };
            let Some(kernel) = weak_kernel.upgrade() else {
                return;
            };
            match signal {
                ConnectionSignal::Closed { reason } => {
                    kernel.connection_closed(&principal);
                    debug!(%principal, topic = %message.topic, ?reason, "Client disconnected");
                },
                ConnectionSignal::Opened => {
                    kernel.connection_opened(&principal);
                    debug!(%principal, topic = %message.topic, "New client connection accepted");
                },
            }
        });
}
