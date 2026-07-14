//! `GET /api/events` — Server-Sent Events stream of audit entries.
//!
//! Subscribes to the kernel's `astrid.v1.audit.entry` topic on the
//! in-process event bus and streams matching entries to the
//! authenticated caller. Filtering happens at the consumer end:
//!
//! * Caller with `audit:read_all` → firehose, every entry the
//!   kernel records.
//! * Anyone else → only entries whose `principal` field matches the
//!   caller's own principal (i.e. "what did I do").
//!
//! No `last-event-id` resume support today — the audit log on disk
//! is the canonical history; SSE is a live feed. A dashboard that
//! wants backfill should query the persistent log via a separate
//! route (deferred).

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use astrid_core::PrincipalId;
use astrid_events::AstridEvent;
use astrid_events::ipc::IpcPayload;
use axum::extract::State;
use axum::http::Request;
use axum::response::Sse;
use axum::response::sse::{Event, KeepAlive};
use futures::Stream;
use futures::StreamExt;

use crate::error::{GatewayError, GatewayResult};
use crate::routes::principals::caller_from;
use crate::state::GatewayState;

pub const AUDIT_TOPIC: &str = "astrid.v1.audit.entry";
/// Capability that lifts the per-principal filter and lets the
/// caller see every audit entry. Operators (admin group `*`) hold
/// it; regular agents do not. Shared with the
/// `GET /api/sys/audit` route in [`super::audit`].
pub(super) const AUDIT_FIREHOSE_CAP: &str = "audit:read_all";

type CapabilityEvaluator = dyn Fn(&PrincipalId, Option<&str>, &str) -> bool + Send + Sync + 'static;

#[derive(Clone)]
pub(crate) struct CapabilityProbe(Arc<CapabilityEvaluator>);

impl CapabilityProbe {
    pub(crate) fn new(
        evaluator: impl Fn(&PrincipalId, Option<&str>, &str) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self(Arc::new(evaluator))
    }

    pub(crate) fn deny_all() -> Self {
        Self::new(|_, _, _| false)
    }

    fn allows(
        &self,
        principal: &PrincipalId,
        device_key_id: Option<&str>,
        capability: &str,
    ) -> bool {
        (self.0)(principal, device_key_id, capability)
    }
}

/// `GET /api/events` — opens a long-lived Server-Sent Events
/// stream. The connection stays open until the client disconnects
/// or the daemon shuts down.
#[utoipa::path(
    get,
    path = "/api/events",
    tag = "audit",
    responses(
        (status = 200, description = "Server-Sent Events stream of audit entries. Each event is one of: `event: ready` (initial handshake) or `event: audit` (audit entry, JSON payload). Holders of `audit:read_all` see the firehose; others see only entries whose `principal` matches their own. 15s `event: keep-alive` heartbeat.", content_type = "text/event-stream"),
        (status = 401, description = "Missing / invalid bearer."),
        (status = 500, description = "Gateway not wired to a live event bus."),
    )
)]
pub async fn get_events(
    State(state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    let caller = caller_from(&req)?.clone();
    let capability_probe = req
        .extensions()
        .get::<CapabilityProbe>()
        .cloned()
        .unwrap_or_else(CapabilityProbe::deny_all);

    // Without a bus handle (the standalone GatewayState ctor used
    // by route-level tests), report an honest 502 instead of
    // hanging — a dashboard would otherwise wait forever on a
    // stream that can never produce.
    let Some(bus) = state.event_bus.clone() else {
        return Err(GatewayError::Internal(anyhow::anyhow!(
            "gateway is not wired to a live event bus; audit stream unavailable"
        )));
    };

    // The kernel-owned probe applies the caller's live device scope.
    let initial_firehose = caller_holds(
        &capability_probe,
        &caller.principal,
        caller.device_key_id.as_deref(),
        AUDIT_FIREHOSE_CAP,
    );

    // Routed subscription so the audit firehose gets the same
    // per-(topic, principal) DRR fairness the rest of the gateway
    // SSE streams now use (#813 Layer 4). The principal-firehose
    // filter at the post-receive layer is unchanged — it's a
    // capability gate, not a routing concern.
    let receiver = bus.subscribe_topic_routed(
        state.gateway_route_uuid,
        AUDIT_TOPIC,
        "gateway",
        "gateway::audit_sse",
    );
    let stream = audit_event_stream(
        receiver,
        capability_probe,
        caller.principal,
        caller.device_key_id,
        initial_firehose,
    );

    // Heartbeat every 15s — keeps NAT/proxy state alive and lets
    // clients distinguish "idle stream" from "daemon crashed".
    Ok(Sse::new(stream.boxed()).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

fn audit_event_stream(
    mut receiver: astrid_events::RoutedEventReceiver,
    capability_probe: CapabilityProbe,
    caller_principal: PrincipalId,
    device_key_id: Option<String>,
    initial_firehose: bool,
) -> impl Stream<Item = Result<Event, Infallible>> {
    async_stream::stream! {
        // Initial handshake event so clients can confirm the
        // stream opened without waiting on the first audit entry.
        yield Ok::<Event, Infallible>(
            Event::default()
                .event("ready")
                .data(serde_json::json!({
                    "principal": caller_principal.to_string(),
                    "firehose": initial_firehose,
                }).to_string())
        );

        while let Some(event) = receiver.recv(None).await {
            let AstridEvent::Ipc { message, .. } = &*event else {
                continue;
            };
            let IpcPayload::RawJson(val) = &message.payload else {
                continue;
            };
            // Re-evaluate long-lived streams so policy changes and device
            // revocation narrow the feed without waiting for reconnect.
            let firehose = caller_holds(
                &capability_probe,
                &caller_principal,
                device_key_id.as_deref(),
                AUDIT_FIREHOSE_CAP,
            );
            if !firehose {
                let entry_principal = val.get("principal").and_then(serde_json::Value::as_str);
                if entry_principal != Some(caller_principal.as_str()) {
                    continue;
                }
            }
            let Ok(payload) = serde_json::to_string(val) else { continue };
            yield Ok(Event::default().event("audit").data(payload));
        }
    }
}

/// The deny-all default keeps callers on the per-principal view.
pub(super) fn caller_holds(
    capability_probe: &CapabilityProbe,
    principal: &PrincipalId,
    device_key_id: Option<&str>,
    capability: &str,
) -> bool {
    capability_probe.allows(principal, device_key_id, capability)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicBool, Ordering};

    use astrid_events::ipc::{IpcMessage, Topic};
    use astrid_events::{AstridEvent, EventBus, EventMetadata};

    fn audit_event(principal: &str) -> AstridEvent {
        let message = IpcMessage::new(
            Topic::from_raw(AUDIT_TOPIC),
            IpcPayload::RawJson(serde_json::json!({ "principal": principal })),
            uuid::Uuid::nil(),
        )
        .with_principal(principal.to_owned());
        AstridEvent::Ipc {
            metadata: EventMetadata::new("audit_stream_test"),
            message,
        }
    }

    #[tokio::test]
    async fn live_stream_loses_firehose_and_keeps_own_visibility() {
        let bus = EventBus::new();
        let receiver = bus.subscribe_topic_routed(
            uuid::Uuid::new_v4(),
            AUDIT_TOPIC,
            "gateway-test",
            "audit_stream_test",
        );
        let firehose = Arc::new(AtomicBool::new(true));
        let firehose_for_probe = Arc::clone(&firehose);
        let probe = CapabilityProbe::new(move |principal, device_key_id, capability| {
            principal.as_str() == "alice"
                && device_key_id == Some("0123456789abcdef")
                && capability == AUDIT_FIREHOSE_CAP
                && firehose_for_probe.load(Ordering::SeqCst)
        });
        let principal = PrincipalId::new("alice").expect("principal");
        let mut stream = Box::pin(audit_event_stream(
            receiver,
            probe,
            principal,
            Some("0123456789abcdef".to_owned()),
            true,
        ));

        assert!(stream.next().await.is_some());
        let _ = bus.publish(audit_event("bob"));
        assert!(
            tokio::time::timeout(Duration::from_secs(1), stream.next())
                .await
                .expect("firehose event")
                .is_some()
        );

        firehose.store(false, Ordering::SeqCst);
        let _ = bus.publish(audit_event("bob"));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), stream.next())
                .await
                .is_err()
        );

        let _ = bus.publish(audit_event("alice"));
        assert!(
            tokio::time::timeout(Duration::from_secs(1), stream.next())
                .await
                .expect("own event")
                .is_some()
        );
    }
}
