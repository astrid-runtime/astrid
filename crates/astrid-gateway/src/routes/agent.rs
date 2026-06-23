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

use astrid_core::kernel_api::AgentLoopReadiness;
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

    // Fail fast on an unconfigured agent loop. A daemon whose loaded capsule
    // set has no prompt subscriber / response publisher (or an unsatisfied
    // required import) would otherwise emit `ready`, wait out the 5-minute
    // timeout, and close empty — the client gets no signal. So when the loop
    // is definitively NOT ready, return a single `error` SSE event and close
    // immediately.
    //
    // Readiness is read from the in-process probe the daemon wired in: it
    // reflects live daemon health and needs no per-principal capability, so the
    // fail-fast fires for EVERY authenticated prompt caller (single- and
    // multi-tenant alike), not only `capsule:list` holders. Fail OPEN: when no
    // probe is wired (standalone test build) we proceed exactly as before,
    // never blocking a legitimately-configured prompt.
    if let Some(probe) = &state.readiness_probe {
        let report = probe.probe().await;
        if !report.ready {
            return Ok(unready_stream(&report));
        }
    }

    // Subscribe FIRST, then publish. Reverse order would race a fast
    // model response — the first delta could land before subscribe
    // returns and we'd miss it. Routed subscription so each SSE
    // stream gets its own per-(topic, principal) DRR queue inside
    // the bus, replacing the broadcast-channel back-pressure that
    // collapsed the 100-principal fan-in (#813 Layer 4).
    //
    // Per-connection routing isolation is provided by the bus, not by
    // this UUID: `subscribe_topic_routed` stamps every subscribe call
    // with a fresh `subscription_rep` (monotonic allocator), so the
    // resulting `RouteKey` is distinct per call even when the
    // `capsule_uuid` argument is shared. Each connection therefore drains
    // its own routed queue and sees every response (forwarding only its
    // own, filtered by session_id) regardless of what UUID is passed
    // here. A per-connection `Uuid::new_v4()` only relabels this
    // connection's routes; the audit-firehose route (`events.rs`) shares
    // the single `state.gateway_route_uuid` and is just as isolated.
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

    Ok(sse_with_keepalive(stream.boxed()))
}

/// Wrap a boxed SSE stream with the standard 15s keep-alive heartbeat.
/// Both the happy path and the fail-fast path go through here so they
/// return the same concrete `Sse` type (the handler's `impl Stream`).
fn sse_with_keepalive(
    stream: futures::stream::BoxStream<'static, Result<Event, Infallible>>,
) -> Sse<futures::stream::BoxStream<'static, Result<Event, Infallible>>> {
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

/// Build a one-shot SSE stream that emits a single `error` event naming what
/// the agent loop is missing, then closes — instead of `ready` + a 5-minute
/// wait against a loop that can never reply.
fn unready_stream(
    report: &AgentLoopReadiness,
) -> Sse<futures::stream::BoxStream<'static, Result<Event, Infallible>>> {
    sse_with_keepalive(unready_event_stream(report))
}

/// The raw one-shot stream behind [`unready_stream`]: a single `error` event,
/// then end-of-stream. Split out (un-wrapped from `Sse`) so a test can drive
/// it directly — `axum::response::Sse` exposes no stream accessor.
fn unready_event_stream(
    report: &AgentLoopReadiness,
) -> futures::stream::BoxStream<'static, Result<Event, Infallible>> {
    let event = Event::default()
        .event("error")
        .data(serde_json::to_string(&unready_payload(report)).unwrap_or_default());
    futures::stream::once(async move { Ok::<Event, Infallible>(event) }).boxed()
}

/// The JSON body of the single `error` SSE event emitted when the agent loop
/// is not ready — names which piece(s) of the loop are missing. Split out as a
/// pure function so the fail-fast content is unit-testable without a live bus.
fn unready_payload(report: &AgentLoopReadiness) -> serde_json::Value {
    serde_json::json!({
        "error": "agent loop not ready",
        "missing": {
            "prompt_subscriber": report.prompt_subscribers.is_empty(),
            "response_publisher": report.response_publishers.is_empty(),
            "unsatisfied_imports": report
                .unsatisfied_required_imports
                .iter()
                .map(|m| format!("{}:{} ({})", m.namespace, m.interface, m.requirement))
                .collect::<Vec<_>>(),
        }
    })
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

#[cfg(test)]
mod tests {
    use astrid_core::kernel_api::MissingImport;

    use super::*;

    /// The fail-fast `error` payload must name exactly which piece of the
    /// loop is missing — a not-ready report with no prompt subscriber and an
    /// unsatisfied import must say so, so the client gets an actionable
    /// signal instead of a 5-minute silent wait.
    #[test]
    fn unready_payload_names_missing_pieces() {
        let report = AgentLoopReadiness {
            ready: false,
            prompt_subscribers: vec![],
            response_publishers: vec!["loop".to_string()],
            unsatisfied_required_imports: vec![MissingImport {
                capsule: "loop".to_string(),
                namespace: "astrid".to_string(),
                interface: "llm".to_string(),
                requirement: "^1.0".to_string(),
            }],
            loaded_capsules: vec!["loop".to_string()],
        };
        let payload = unready_payload(&report);
        assert_eq!(payload["error"], "agent loop not ready");
        assert_eq!(payload["missing"]["prompt_subscriber"], true);
        assert_eq!(payload["missing"]["response_publisher"], false);
        let imports = payload["missing"]["unsatisfied_imports"]
            .as_array()
            .expect("unsatisfied_imports is an array");
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0], "astrid:llm (^1.0)");
    }

    /// A ready report still serializes (defensive — `unready_payload` is only
    /// called on the not-ready path, but it must not panic on a ready one).
    #[test]
    fn unready_payload_ready_report_reports_no_missing() {
        let report = AgentLoopReadiness {
            ready: true,
            prompt_subscribers: vec!["loop".to_string()],
            response_publishers: vec!["loop".to_string()],
            unsatisfied_required_imports: vec![],
            loaded_capsules: vec!["loop".to_string()],
        };
        let payload = unready_payload(&report);
        assert_eq!(payload["missing"]["prompt_subscriber"], false);
        assert_eq!(payload["missing"]["response_publisher"], false);
        assert!(
            payload["missing"]["unsatisfied_imports"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    /// The fail-fast stream emits exactly one `error` event and then closes —
    /// it does NOT wait out the 5-minute timeout against a loop that can never
    /// reply. Drive the inner stream and assert single-event termination.
    #[tokio::test]
    async fn unready_stream_emits_single_event_then_closes() {
        let report = AgentLoopReadiness {
            ready: false,
            prompt_subscribers: vec![],
            response_publishers: vec![],
            unsatisfied_required_imports: vec![],
            loaded_capsules: vec![],
        };
        let mut stream = unready_event_stream(&report);
        // Exactly one event, then end-of-stream — the load-bearing property:
        // the fail-fast path closes immediately rather than waiting out the
        // 5-minute timeout against a loop that can never reply.
        let _first = stream.next().await.expect("one event").expect("infallible");
        assert!(
            stream.next().await.is_none(),
            "fail-fast stream must close after one event, not wait the timeout"
        );
    }
}
