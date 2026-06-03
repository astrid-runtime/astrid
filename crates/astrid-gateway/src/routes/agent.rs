//! `POST /api/agent/prompt` — invoke the agent and stream the response.
//!
//! Submits a user prompt to the runtime and returns a Server-Sent
//! Events stream of the agent's incremental + final output. The
//! gateway publishes directly onto the in-process kernel event bus
//! (the same bus the SSE handler subscribes from) — no socket
//! round-trip via the CLI proxy. That dodges any proxy back-pressure
//! and gives the dashboard the lowest-latency path to the agent.
//!
//! ## Topic wiring
//!
//! * Outbound (published): `user.v1.prompt` with `IpcPayload::UserInput
//!   { text, session_id, context }`. Subscribed by
//!   `astrid-capsule-react`, which fans out through the session +
//!   identity + LLM router capsules and produces:
//! * Inbound (subscribed):
//!   * `agent.v1.stream.delta` — incremental token chunks while the
//!     LLM is generating.
//!   * `agent.v1.response` — final, complete reply (also fires once
//!     for non-streaming providers).
//!   * `agent.v1.session_changed` — session metadata updates the
//!     dashboard may want to render.
//!   * `astrid.v1.elicit.*` — agent requests for follow-up user
//!     input. Dashboard rendering is out of scope here; we forward
//!     the events so a client that knows the elicit contract can
//!     respond out-of-band (the elicit response goes back through
//!     `POST /api/agent/elicit-response` once that ships).
//!
//! ## Filtering
//!
//! Each SSE subscription opens a routed receiver via
//! [`astrid_events::EventBus::subscribe_topic_routed`]; per-(topic,
//! principal) DRR fairness and publish-side byte-budget eviction are
//! enforced by the bus's routing demux. The `session_id` post-receive
//! filter handles cross-session de-multiplexing within a principal's
//! stream — session is a payload concern, not a routing concern.
//!
//! ## Termination
//!
//! The stream terminates when:
//! * The client disconnects (axum drops the stream).
//! * An `agent.v1.response` event arrives — we emit it and close.
//! * A 5 minute upper bound elapses (sentinel — the dashboard can
//!   re-POST to continue).

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use astrid_events::AstridEvent;
use astrid_events::ipc::{IpcMessage, IpcPayload};
use astrid_types::ipc::IpcPayload as TypesIpcPayload;
use axum::extract::State;
use axum::http::Request;
use axum::response::Sse;
use axum::response::sse::{Event, KeepAlive};
use futures::Stream;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{ErrorBody, GatewayError, GatewayResult};
use crate::routes::principals::caller_from;
use crate::state::GatewayState;

/// Default per-prompt stream timeout. Long enough to cover most
/// model latencies + tool loops, short enough that an orphaned
/// stream doesn't tie up state forever.
const STREAM_TIMEOUT: Duration = Duration::from_mins(5);

/// Inbound body for `POST /api/agent/prompt`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct PromptRequest {
    /// User prompt text. Routed through the kernel exactly the same
    /// way the CLI's `astrid` chat prompt is.
    pub text: String,
    /// Conversation continuity. Multiple prompts with the same
    /// `session_id` share the same agent history. Optional — if
    /// omitted the gateway mints a fresh UUID and echoes it in the
    /// initial `ready` SSE event.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Extra structured context the receiver may understand
    /// (matches `IpcPayload::UserInput.context`). Opaque to the
    /// gateway.
    #[serde(default)]
    pub context: Option<serde_json::Value>,
}

/// Initial SSE event sent immediately after a successful prompt
/// dispatch. Lets the client correlate later events without parsing
/// payload bodies.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PromptReady {
    /// Session id the prompt was published with (the one the client
    /// sent, or a freshly minted UUID).
    pub session_id: String,
    /// Principal the prompt was attributed to — useful for
    /// dashboards displaying multi-agent conversations.
    pub principal: String,
}

/// `POST /api/agent/prompt` — submit a prompt, stream the response.
///
/// Returns a Server-Sent Events stream. Event types:
///
/// * `ready` — initial event, payload = [`PromptReady`].
/// * `delta` — incremental token chunk (one per LLM-emitted chunk).
///   Payload mirrors `agent.v1.stream.delta`'s body.
/// * `response` — final response. Payload mirrors `agent.v1.response`.
///   The stream **closes** after this event lands.
/// * `session_changed` — session metadata mutation
///   (`agent.v1.session_changed`).
/// * `elicit` — the agent is asking the user for follow-up input.
///   Forwarded verbatim from `astrid.v1.elicit.*`.
/// * `keep-alive` — 15-second heartbeat so reverse proxies don't
///   half-close the connection on idle.
///
/// On error the response is a normal JSON `ErrorBody` (not SSE),
/// status 401/403/500.
#[utoipa::path(
    post,
    path = "/api/agent/prompt",
    tag = "agent",
    request_body = PromptRequest,
    responses(
        (status = 200, description = "Server-Sent Events stream of agent output. `event: ready` first, then `event: delta` chunks and/or `event: response` for the final reply. Stream closes on `response` or client disconnect.", content_type = "text/event-stream"),
        (status = 401, body = ErrorBody, description = "Missing / invalid bearer."),
        (status = 500, body = ErrorBody, description = "Gateway not wired to a live event bus."),
    )
)]
pub async fn post_prompt(
    State(state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    let caller = caller_from(&req)?.clone();

    let Some(bus) = state.event_bus.clone() else {
        return Err(GatewayError::Internal(anyhow::anyhow!(
            "gateway is not wired to a live event bus; agent invocation unavailable"
        )));
    };

    let body: PromptRequest = crate::routes::principals::read_json_body(req).await?;
    let session_id = body
        .session_id
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // Subscribe FIRST, then publish. Reverse order would race a fast
    // model response — the first delta could land before subscribe
    // returns and we'd miss it. Routed subscription so each SSE
    // stream gets its own per-(topic, principal) DRR queue inside
    // the bus, replacing the broadcast-channel back-pressure that
    // collapsed the 100-principal fan-in (#813 Layer 4).
    // Per-connection routing identity. Sharing one
    // `state.gateway_route_uuid` across every concurrent SSE connection
    // made them all drain a single routed queue, so concurrent prompts
    // *competed* for `agent.v1.response`: each event was consumed by
    // whichever connection recv'd first and dropped (wrong session) if
    // that wasn't its target, collapsing concurrent response delivery to
    // ~1 per batch regardless of N (astrid#813 layer 4). A fresh rep per
    // connection gives each its own routed queue, so every connection
    // sees every response and forwards its own (filtered by session_id).
    let conn_route_uuid = Uuid::new_v4();
    let subscribe = |topic: &'static str| {
        bus.subscribe_topic_routed(conn_route_uuid, topic, "gateway", "gateway::agent_sse")
    };
    let mut response_rx = subscribe("agent.v1.response");
    let mut delta_rx = subscribe("agent.v1.stream.delta");
    let mut session_rx = subscribe("agent.v1.session_changed");
    let mut elicit_rx = subscribe("astrid.v1.elicit");

    let payload = TypesIpcPayload::UserInput {
        text: body.text,
        session_id: session_id.clone(),
        context: body.context,
    };
    let msg = IpcMessage::new("user.v1.prompt", payload, Uuid::nil())
        .with_principal(caller.principal.to_string());
    bus.publish(AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("gateway::agent.prompt"),
        message: msg,
    });

    let principal_str = caller.principal.to_string();
    let session_id_for_stream = session_id.clone();

    let stream = async_stream::stream! {
        // Initial ready event — gives clients the session_id back
        // without having to peek into the first payload.
        let ready = PromptReady {
            session_id: session_id_for_stream.clone(),
            principal: principal_str,
        };
        yield Ok::<Event, Infallible>(
            Event::default()
                .event("ready")
                .data(serde_json::to_string(&ready).unwrap_or_default())
        );

        let deadline = tokio::time::Instant::now()
            .checked_add(STREAM_TIMEOUT)
            .unwrap_or_else(tokio::time::Instant::now);

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            tokio::select! {
                // Bias toward `response` so the final reply ends the
                // stream promptly even if delta events are still
                // buffered.
                biased;
                () = tokio::time::sleep(remaining) => break,
                event = response_rx.recv(None) => {
                    let Some(event) = event else { break };
                    if let Some(ev) = forward_event(&event, &session_id_for_stream, "response") {
                        yield Ok(ev);
                        // `agent.v1.response` is terminal — but only for
                        // OUR session. Close once we've forwarded our own
                        // response; a different session's response (now
                        // visible because each connection fans in every
                        // response) must NOT close this stream, or the
                        // connection that consumed someone else's reply
                        // would close empty and the real target would
                        // never be served.
                        break;
                    }
                }
                event = delta_rx.recv(None) => {
                    let Some(event) = event else { break };
                    if let Some(ev) = forward_event(&event, &session_id_for_stream, "delta") {
                        yield Ok(ev);
                    }
                }
                event = session_rx.recv(None) => {
                    let Some(event) = event else { break };
                    if let Some(ev) = forward_event(&event, &session_id_for_stream, "session_changed") {
                        yield Ok(ev);
                    }
                }
                event = elicit_rx.recv(None) => {
                    let Some(event) = event else { break };
                    // Elicit events don't carry session_id in the
                    // same shape — forward unconditionally and let
                    // the client filter. Replying out-of-band is on
                    // the caller (a future POST /api/agent/elicit-response
                    // is the planned path).
                    if let Some(ev) = forward_event(&event, "", "elicit") {
                        yield Ok(ev);
                    }
                }
            }
        }
    };

    Ok(Sse::new(stream.boxed()).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

/// Convert an in-bus `AstridEvent::Ipc` into an SSE `Event`, filtering by
/// `session_id` when the payload carries one. Returns `None` for events
/// that don't match this session (silent drop — the bus is shared
/// across every prompt in flight) or events with non-JSON payloads
/// (defensive).
fn forward_event(
    event: &Arc<AstridEvent>,
    session_filter: &str,
    sse_name: &'static str,
) -> Option<Event> {
    let AstridEvent::Ipc { message, .. } = &**event else {
        return None;
    };
    let value = match &message.payload {
        IpcPayload::RawJson(v) => v.clone(),
        _ => serde_json::to_value(&message.payload).ok()?,
    };
    // Session filter. The dashboard's prompt-handler reads only its
    // own session's events; everyone else's chunks are dropped here.
    if !session_filter.is_empty()
        && let Some(payload_session) = value.get("session_id").and_then(|v| v.as_str())
        && payload_session != session_filter
    {
        return None;
    }
    let body = serde_json::to_string(&value).ok()?;
    Some(Event::default().event(sse_name).data(body))
}
