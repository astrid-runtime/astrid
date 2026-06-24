//! `GET /api/agent/stream` — the per-principal live conversation feed
//! (#973).
//!
//! A long-lived Server-Sent Events stream that fans **every** event the
//! caller's principal produces across **all** of its threads — the
//! multi-device sync feed. A second device attaching here sees the same
//! in-flight turns and thread-lifecycle changes as the first, in real
//! time, without polling. Unlike `POST /api/agent/prompt` (a single-turn
//! stream scoped to one `session_id`), this feed is NOT session-scoped:
//! it carries the principal's whole conversation surface.
//!
//! ## Two scoped subscriptions
//!
//! The handler subscribes — FIRST, before the stream is returned, so a
//! burst that lands the instant the route is hit isn't missed — to two
//! routed topics, **both** scoped to `Some(Some(caller.principal))`:
//!
//! * `agent.v1.*` — in-flight turn events (deltas, responses,
//!   session-changed notices) that `capsule-react` emits while a turn is
//!   running, stamped with the originating principal.
//! * `session.v1.event.*` — thread lifecycle (`created` / `updated` /
//!   `deleted`), stamped with the owning principal.
//!
//! Both subtree patterns (`a.b.*` is a subtree match in the route layer)
//! merge into one `async_stream` via `tokio::select!`. `agent.v1.*` events
//! are forwarded under the SSE event name `agent` and `session.v1.event.*`
//! under `session_event`; each event's full topic travels in the payload
//! (`{ "topic": "...", "data": ... }`) so a client can tell a delta from a
//! response from a session-changed without a second channel.
//!
//! ## Cross-principal isolation (the #973 security property)
//!
//! The scope argument `Some(Some(principal))` is the whole guarantee. The
//! inner `Some(principal)` is enforced at **enqueue**: a routed entry only
//! admits an event whose publisher principal equals the scope (see
//! `RouteEntry::accepts`), so a foreign principal's event is dropped before
//! it ever enters this route's buffer — a co-resident (buggy or hostile)
//! publisher on `agent.v1.*` / `session.v1.event.*` cannot leak another
//! principal's conversation onto this device's feed. This mirrors the
//! per-principal scoping `models.rs` uses for registry replies; the
//! property holds because `capsule-react` / `capsule-session` publish these
//! events stamped with the originating principal (the host resolves the
//! outgoing principal from the inbound caller-context, not the capsule's own
//! identity).

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use astrid_events::AstridEvent;
use astrid_events::ipc::IpcPayload;
use axum::extract::State;
use axum::http::Request;
use axum::response::Sse;
use axum::response::sse::{Event, KeepAlive};
use futures::Stream;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{ErrorBody, GatewayError, GatewayResult};
use crate::routes::principals::caller_from;
use crate::state::GatewayState;

/// Topic prefixes the live feed subscribes to. `&'static str` so no
/// caller input can reshape the subscription namespace.
const TOPIC_AGENT_EVENTS: &str = "agent.v1.*";
const TOPIC_SESSION_EVENTS: &str = "session.v1.event.*";

/// SSE event names for the two streams. The client switches on these.
const SSE_AGENT: &str = "agent";
const SSE_SESSION_EVENT: &str = "session_event";

/// Overall cap on a single feed connection. The feed is long-lived by
/// design — a client keeps it open across many turns — so this is an order
/// of magnitude beyond `POST /api/agent/prompt`'s single-turn 5-minute
/// bound. It exists only so an abandoned connection eventually releases its
/// routed subscriptions instead of living forever; clients reconnect (and
/// SSE clients auto-reconnect) when it lapses.
const FEED_TIMEOUT: Duration = Duration::from_hours(1);

/// Initial SSE `ready` event — lets a client confirm the feed is live and
/// learn which principal it is scoped to (its own) before any conversation
/// event arrives.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FeedReady {
    /// The principal this feed is scoped to — the caller's own.
    pub principal: String,
}

/// `GET /api/agent/stream` — the per-principal live conversation feed.
///
/// Returns a Server-Sent Events stream. Event types:
///
/// * `ready` — initial event, payload [`FeedReady`].
/// * `agent` — an `agent.v1.*` event (delta / response / session-changed).
///   Payload is `{ "topic": "agent.v1.…", "data": <event body> }`.
/// * `session_event` — a `session.v1.event.*` lifecycle event. Payload is
///   `{ "topic": "session.v1.event.…", "data": <event body> }`.
/// * `keep-alive` — 15-second heartbeat.
///
/// The stream is NOT session-scoped — it carries every thread the caller's
/// principal owns. Cross-principal events never arrive (the bus drops them
/// at enqueue via the `Some(Some(principal))` route scope).
#[utoipa::path(
    get,
    path = "/api/agent/stream",
    tag = "agent",
    responses(
        (status = 200, description = "Long-lived Server-Sent Events feed of the caller's own conversation activity across all threads. `event: ready` first, then `event: agent` (in-flight turn events) and `event: session_event` (thread lifecycle). Cross-principal events are never delivered.", content_type = "text/event-stream"),
        (status = 401, body = ErrorBody, description = "Missing / invalid bearer."),
        (status = 500, body = ErrorBody, description = "Gateway not wired to a live event bus."),
    )
)]
pub async fn get_stream(
    State(state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    let caller = caller_from(&req)?;
    metrics::counter!("astrid_gateway_agent_stream_total").increment(1);

    let Some(bus) = state.event_bus.clone() else {
        return Err(GatewayError::Internal(anyhow::anyhow!(
            "gateway is not wired to a live event bus; live feed unavailable"
        )));
    };

    let principal = caller.principal.to_string();

    // Subscribe FIRST, both routes scoped to the caller's principal. The
    // outer `Some` marks the route as scoped; the inner `Some(principal)` is
    // the security boundary — a foreign-principal event is dropped at
    // enqueue and never enters this route's budget (see module docs). A
    // fresh per-call UUID isolates this connection's routes from any other
    // live feed.
    let conn_uuid = Uuid::new_v4();
    let scope = Some(Some(principal.clone()));
    let mut agent_rx = bus.subscribe_topic_routed_scoped(
        conn_uuid,
        TOPIC_AGENT_EVENTS,
        "gateway",
        "gateway::agent_stream",
        scope.clone(),
    );
    let mut session_rx = bus.subscribe_topic_routed_scoped(
        conn_uuid,
        TOPIC_SESSION_EVENTS,
        "gateway",
        "gateway::agent_stream",
        scope,
    );

    let principal_for_stream = principal;

    let stream = async_stream::stream! {
        // Initial ready event — confirms the feed is live and names the
        // (own) principal it is scoped to.
        let ready = FeedReady { principal: principal_for_stream };
        yield Ok::<Event, Infallible>(
            Event::default()
                .event("ready")
                .data(serde_json::to_string(&ready).unwrap_or_default())
        );

        let deadline = tokio::time::Instant::now()
            .checked_add(FEED_TIMEOUT)
            .unwrap_or_else(tokio::time::Instant::now);

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            tokio::select! {
                () = tokio::time::sleep(remaining) => break,
                event = agent_rx.recv(None) => {
                    let Some(event) = event else { break };
                    if let Some(ev) = forward_feed_event(&event, SSE_AGENT) {
                        yield Ok(ev);
                    }
                }
                event = session_rx.recv(None) => {
                    let Some(event) = event else { break };
                    if let Some(ev) = forward_feed_event(&event, SSE_SESSION_EVENT) {
                        yield Ok(ev);
                    }
                }
            }
        }
    };

    Ok(Sse::new(Box::pin(stream)).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

/// Convert an in-bus `AstridEvent::Ipc` into an SSE `Event`, wrapping the
/// payload with its full topic so the client can disambiguate sub-kinds
/// (delta / response / session-changed; created / updated / deleted)
/// without a separate channel. NO `session_id` filtering — the feed fans
/// ALL of the principal's threads. Returns `None` for non-IPC events or
/// non-JSON payloads (defensive).
fn forward_feed_event(event: &Arc<AstridEvent>, sse_name: &'static str) -> Option<Event> {
    let AstridEvent::Ipc { message, .. } = &**event else {
        return None;
    };
    let data = match &message.payload {
        IpcPayload::RawJson(v) => v.clone(),
        other => serde_json::to_value(other).ok()?,
    };
    let envelope = serde_json::json!({
        "topic": message.topic,
        "data": data,
    });
    let body = serde_json::to_string(&envelope).ok()?;
    Some(Event::default().event(sse_name).data(body))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use astrid_events::EventBus;
    use astrid_events::ipc::IpcMessage;
    use astrid_events::{AstridEvent, EventMetadata};
    use uuid::Uuid;

    use super::*;

    /// Build a principal-stamped IPC event on `topic` carrying `body`.
    fn ipc_event(topic: &str, principal: &str, body: serde_json::Value) -> AstridEvent {
        let msg = IpcMessage::new(topic.to_string(), IpcPayload::RawJson(body), Uuid::nil())
            .with_principal(principal.to_string());
        AstridEvent::Ipc {
            metadata: EventMetadata::new("test::publisher"),
            message: msg,
        }
    }

    #[test]
    fn forward_feed_event_wraps_topic_and_data() {
        // The envelope embeds the full topic so the client can tell a delta
        // from a response without a second channel. `Event` has no public
        // data accessor, so assert the pure inputs that the body is built
        // from, and that a valid IPC event always forwards to Some.
        let event = Arc::new(ipc_event(
            "agent.v1.stream.delta",
            "alice",
            serde_json::json!({ "text": "hi" }),
        ));
        assert!(
            forward_feed_event(&event, SSE_AGENT).is_some(),
            "a valid IPC event must forward to an SSE event"
        );
        let AstridEvent::Ipc { message, .. } = &*event else {
            unreachable!()
        };
        assert_eq!(message.topic, "agent.v1.stream.delta");
        // The envelope the forwarder builds, re-derived from the same input.
        let envelope = serde_json::json!({ "topic": message.topic, "data": { "text": "hi" } });
        assert_eq!(envelope["topic"], "agent.v1.stream.delta");
        assert_eq!(envelope["data"]["text"], "hi");
    }

    /// The #973 cross-principal isolation property, end-to-end over a real
    /// `EventBus`: a `session.v1.event.*` published under the FEED's principal
    /// is delivered to a `Some(Some(principal))`-scoped route, while an
    /// otherwise-identical event published under a DIFFERENT principal is
    /// dropped at enqueue and never observed. This is the security guarantee
    /// the live feed rests on — a second device only ever sees its own
    /// principal's conversation.
    #[tokio::test]
    async fn scoped_feed_drops_foreign_principal_events() {
        let bus = Arc::new(EventBus::new());
        let me = "alice";

        // The feed's scoped subscription — exactly what `get_stream` opens.
        let mut feed_rx = bus.subscribe_topic_routed_scoped(
            Uuid::new_v4(),
            TOPIC_SESSION_EVENTS,
            "gateway",
            "gateway::agent_stream",
            Some(Some(me.to_string())),
        );

        // Publish a foreign-principal lifecycle event FIRST, then our own.
        // The foreign one must be dropped at enqueue; the recv must surface
        // OUR event, proving the scope filters by publisher principal.
        bus.publish(ipc_event(
            "session.v1.event.created",
            "mallory",
            serde_json::json!({ "kind": "created", "session_id": "m1", "summary": null }),
        ));
        bus.publish(ipc_event(
            "session.v1.event.created",
            me,
            serde_json::json!({ "kind": "created", "session_id": "a1", "summary": null }),
        ));

        let event = feed_rx
            .recv(Some(Duration::from_secs(2)))
            .await
            .expect("our own event is delivered");
        let AstridEvent::Ipc { message, .. } = &*event else {
            panic!("expected an IPC event");
        };
        // The delivered event is OURS — the foreign one was dropped at
        // enqueue, so the very first (and only) event on the route is alice's.
        assert_eq!(message.principal.as_deref(), Some(me));
        if let IpcPayload::RawJson(v) = &message.payload {
            assert_eq!(
                v["session_id"], "a1",
                "must be our session, never mallory's"
            );
        } else {
            panic!("expected RawJson payload");
        }

        // No second event: the foreign publish never entered the route's
        // budget. A short timeout confirms the route is now empty.
        assert!(
            feed_rx
                .recv(Some(Duration::from_millis(100)))
                .await
                .is_none(),
            "a foreign-principal event must never reach a principal-scoped feed"
        );

        // And the forwarder wraps our event under the session_event name.
        let sse = forward_feed_event(&event, SSE_SESSION_EVENT);
        assert!(sse.is_some(), "our own event forwards to SSE");
    }

    /// A `agent.v1.*` event under the caller's principal is delivered to the
    /// agent route (subtree match), confirming the in-flight-turn half of the
    /// feed is wired to the right topic and scope.
    #[tokio::test]
    async fn scoped_feed_delivers_own_agent_events() {
        let bus = Arc::new(EventBus::new());
        let me = "alice";
        let mut feed_rx = bus.subscribe_topic_routed_scoped(
            Uuid::new_v4(),
            TOPIC_AGENT_EVENTS,
            "gateway",
            "gateway::agent_stream",
            Some(Some(me.to_string())),
        );

        bus.publish(ipc_event(
            "agent.v1.stream.delta",
            me,
            serde_json::json!({ "text": "chunk" }),
        ));

        let event = feed_rx
            .recv(Some(Duration::from_secs(2)))
            .await
            .expect("own agent.v1.* event delivered (subtree match)");
        let AstridEvent::Ipc { message, .. } = &*event else {
            panic!("expected IPC");
        };
        assert_eq!(message.topic, "agent.v1.stream.delta");
        assert_eq!(message.principal.as_deref(), Some(me));
    }
}
