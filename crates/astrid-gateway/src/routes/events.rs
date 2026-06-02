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

    // Without a bus handle (the standalone GatewayState ctor used
    // by route-level tests), report an honest 502 instead of
    // hanging — a dashboard would otherwise wait forever on a
    // stream that can never produce.
    let Some(bus) = state.event_bus.clone() else {
        return Err(GatewayError::Internal(anyhow::anyhow!(
            "gateway is not wired to a live event bus; audit stream unavailable"
        )));
    };

    // Resolve whether the caller gets the firehose or the
    // per-principal filtered view. The caller's capability set is
    // expressed in their bearer — we don't have it directly, so
    // ask the kernel via AgentList and look for the caller's row.
    // AgentList is cap-gated by self:agent:list for agents and by
    // `*` for admins, so the call always succeeds for any valid
    // bearer. The kernel filters by scope server-side.
    //
    // Use the bus-direct admin client (not the socket-based one) —
    // SSE handshakes happen once per dashboard tab open, and the
    // socket-dial latency would otherwise dominate first-byte
    // time for the audit stream.
    let firehose = caller_holds(&state, &caller.principal, AUDIT_FIREHOSE_CAP).await;

    // Routed subscription so the audit firehose gets the same
    // per-(topic, principal) DRR fairness the rest of the gateway
    // SSE streams now use (#813 Layer 4). The principal-firehose
    // filter at the post-receive layer is unchanged — it's a
    // capability gate, not a routing concern.
    let mut receiver = bus.subscribe_topic_routed(
        state.gateway_route_uuid,
        AUDIT_TOPIC,
        "gateway",
        "gateway::audit_sse",
    );
    let caller_principal = caller.principal;

    let stream = async_stream::stream! {
        // Initial handshake event so clients can confirm the
        // stream opened without waiting on the first audit entry.
        yield Ok::<Event, Infallible>(
            Event::default()
                .event("ready")
                .data(serde_json::json!({
                    "principal": caller_principal.to_string(),
                    "firehose": firehose,
                }).to_string())
        );

        while let Some(event) = receiver.recv(None).await {
            let AstridEvent::Ipc { message, .. } = &*event else {
                continue;
            };
            let IpcPayload::RawJson(val) = &message.payload else {
                continue;
            };
            // Per-principal filter for non-firehose subscribers.
            // The kernel-side broadcast embeds `principal` (the
            // acting caller); if that's not present or doesn't
            // match, skip silently.
            if !firehose {
                let entry_principal = val.get("principal").and_then(serde_json::Value::as_str);
                if entry_principal != Some(caller_principal.as_str()) {
                    continue;
                }
            }
            let Ok(payload) = serde_json::to_string(val) else { continue };
            yield Ok(Event::default().event("audit").data(payload));
        }
    };

    // Heartbeat every 15s — keeps NAT/proxy state alive and lets
    // clients distinguish "idle stream" from "daemon crashed".
    Ok(Sse::new(stream.boxed()).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

/// Best-effort capability check via the kernel's `AgentList`. Returns
/// `false` on any failure (parse error, bus unavailable) so the
/// caller falls back to the safer per-principal filter rather than
/// accidentally widening to the firehose.
pub(super) async fn caller_holds(
    state: &GatewayState,
    principal: &PrincipalId,
    capability: &str,
) -> bool {
    use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody};
    let Ok(client) = state.admin_client(principal.clone()) else {
        return false;
    };
    let Ok(resp) = client.request(AdminRequestKind::AgentList).await else {
        return false;
    };
    let AdminResponseBody::AgentList(list) = resp else {
        return false;
    };
    // Approximate: caller holds the cap if their direct grants
    // include it or if they're in the admin group. Group-level
    // inheritance resolution proper lives kernel-side; the gateway
    // doesn't have a public API for it, so we recognise the
    // bootstrap shape (admin → universal grant) and explicit
    // direct grants.
    list.into_iter()
        .find(|s| &s.principal == principal)
        .is_some_and(|s| {
            s.groups.iter().any(|g| g == "admin")
                || s.grants.iter().any(|g| g == capability || g == "*")
        })
}
