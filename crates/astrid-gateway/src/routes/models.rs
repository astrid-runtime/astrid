//! `/api/models*` — list and bind the caller's active LLM model.
//!
//! Three principal-scoped routes that wrap the registry capsule's
//! existing IPC contract:
//!
//! * `GET  /api/models`         — list the caller's available provider-entries.
//! * `GET  /api/models/active`  — the caller's bound model (or JSON `null`).
//! * `PUT  /api/models/active`  — bind by `{ "id": "<capsule>:<model>" }`.
//!
//! The gateway is a thin transport: it publishes the registry request IPC
//! stamped with the caller's principal, awaits the registry's reply on a
//! **principal-scoped** routed subscription, and surfaces the registry's
//! own success/error verbatim. It does **not** resolve ids, enumerate
//! models, or persist selection — that is the registry capsule's job.
//!
//! ## Per-principal isolation (the core security property)
//!
//! Registry state (the provider list + active-model id) is principal-scoped
//! KV; the kernel scopes it by the invocation principal. The gateway
//! preserves that end-to-end:
//!
//! 1. The principal is the **verified** [`CallerContext::principal`] from
//!    the signed bearer — never a body/query field.
//! 2. The request IPC is **stamped** with that principal
//!    ([`IpcMessage::with_principal`]), which routes it into the caller's
//!    registry KV scope and is the value the reply is matched against.
//! 3. The reply is awaited on a route scoped to `Some(Some(principal))`
//!    ([`EventBus::subscribe_topic_routed_scoped`]); a foreign-principal
//!    reply is dropped at enqueue, so a buggy or malicious co-resident
//!    publisher cannot leak another principal's binding into this stream.
//!    This is sound because the registry's reply genuinely carries the
//!    requester's principal (the host resolves the outgoing principal from
//!    the inbound caller-context, not the registry's own identity).

use std::sync::Arc;
use std::time::Duration;

use astrid_events::AstridEvent;
use astrid_events::ipc::{IpcMessage, IpcPayload};
use axum::Json;
use axum::extract::State;
use axum::http::Request;
use serde::Deserialize;
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::CallerContext;
use crate::error::{ErrorBody, GatewayError, GatewayResult};
use crate::routes::principals::caller_from;
use crate::state::GatewayState;

/// Wall-clock budget for the registry to answer a model request. Matches
/// the 10s budget the CLI uses for the equivalent daemon read
/// (`capsule_verb.rs`); long enough for a cold capsule, short enough that
/// an unresponsive registry doesn't tie a request up indefinitely.
const REGISTRY_TIMEOUT: Duration = Duration::from_secs(10);

/// Registry request/response topic pairs. Kept as `&'static str` so the
/// `id` a client supplies can never reshape the topic namespace (no
/// `format!`-into-topic interpolation reaches the bus).
const GET_PROVIDERS_REQUEST: &str = "registry.v1.get_providers";
const GET_PROVIDERS_RESPONSE: &str = "registry.v1.response.get_providers";
const GET_ACTIVE_REQUEST: &str = "registry.v1.get_active_model";
const GET_ACTIVE_RESPONSE: &str = "registry.v1.response.get_active_model";
const SET_ACTIVE_REQUEST: &str = "registry.v1.set_active_model";
const SET_ACTIVE_RESPONSE: &str = "registry.v1.response.set_active_model";

/// Body for `PUT /api/models/active`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SetActiveModelRequest {
    /// Canonical model id to bind, `<capsule>:<model>`. Forwarded to the
    /// registry as an opaque string — the gateway does not resolve, parse,
    /// or interpret it; the registry owns id resolution and ambiguity
    /// errors.
    #[schema(example = "openai:gpt-4o")]
    pub id: String,
}

/// Publish `request_topic` (stamped with the caller's principal) and await
/// the single reply on `response_topic`, scoped to the caller so no other
/// principal's registry reply can be observed. Mirrors the subscribe-first
/// / publish-second ordering and timeout discipline of `agent.rs`.
async fn registry_round_trip(
    state: &GatewayState,
    caller: &CallerContext,
    request_topic: &'static str,
    response_topic: &'static str,
    payload: serde_json::Value,
) -> GatewayResult<serde_json::Value> {
    let Some(bus) = state.event_bus.clone() else {
        return Err(GatewayError::Internal(anyhow::anyhow!(
            "gateway is not wired to a live event bus; model registry unavailable"
        )));
    };

    let principal = caller.principal.to_string();

    // Subscribe FIRST, then publish. Reverse order would race a fast
    // registry reply — the reply could land before subscribe returns and
    // we'd miss it. The route is scoped to `Some(Some(principal))`: the
    // outer `Some` marks the route as scoped, the inner `Some(principal)`
    // is the security boundary — a reply stamped with any other principal
    // is dropped at enqueue and never enters this route's budget. A fresh
    // per-call UUID isolates this connection's route from any concurrent
    // model request.
    let mut reply_rx = bus.subscribe_topic_routed_scoped(
        Uuid::new_v4(),
        response_topic,
        "gateway",
        "gateway::models",
        Some(Some(principal.clone())),
    );

    // Stamp the request with the caller's principal: it both routes the
    // request into the caller's registry KV scope and is the value the
    // reply is matched against on the scoped subscription above.
    let msg = IpcMessage::new(request_topic, IpcPayload::RawJson(payload), Uuid::nil())
        .with_principal(principal);
    bus.publish(AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("gateway::models"),
        message: msg,
    });

    // Await the single reply. `recv(Some(..))` returns `None` on timeout.
    // The wait budget defaults to the production `REGISTRY_TIMEOUT`; a test
    // may shorten it via `GatewayState::registry_timeout` so a negative
    // (no-reply) assertion doesn't block for the full 10s.
    let timeout = state.registry_timeout.unwrap_or(REGISTRY_TIMEOUT);
    let Some(event) = reply_rx.recv(Some(timeout)).await else {
        return Err(GatewayError::Internal(anyhow::anyhow!(
            "registry did not respond"
        )));
    };
    let AstridEvent::Ipc { message, .. } = &*event else {
        return Err(GatewayError::Internal(anyhow::anyhow!(
            "registry reply was not an IPC message"
        )));
    };
    // Extract the reply payload exactly as agent.rs does: a `RawJson`
    // body is the bare inner value; any other payload shape is serialized
    // structurally.
    let value = match &message.payload {
        IpcPayload::RawJson(v) => v.clone(),
        other => serde_json::to_value(other)
            .map_err(|e| GatewayError::Internal(anyhow::anyhow!("registry reply not JSON: {e}")))?,
    };
    Ok(value)
}

/// `GET /api/models` — list the caller's available provider-entries.
#[utoipa::path(
    get,
    path = "/api/models",
    tag = "models",
    responses(
        (status = 200, description = "JSON array of provider-entries the registry published on `registry.v1.response.get_providers`, passed through unchanged.", content_type = "application/json"),
        (status = 401, body = ErrorBody, description = "Missing / invalid bearer."),
        (status = 500, body = ErrorBody, description = "Gateway not wired to a live event bus, or the registry did not respond."),
    )
)]
pub async fn list_models(
    State(state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let caller = caller_from(&req)?.clone();
    let reply = registry_round_trip(
        &state,
        &caller,
        GET_PROVIDERS_REQUEST,
        GET_PROVIDERS_RESPONSE,
        json!({}),
    )
    .await?;
    // Pass the array through unchanged; the gateway does not reshape it.
    Ok(Json(reply))
}

/// `GET /api/models/active` — the caller's bound model, or JSON `null`.
#[utoipa::path(
    get,
    path = "/api/models/active",
    tag = "models",
    responses(
        (status = 200, description = "The bound provider-entry, or JSON `null` when nothing is bound (not an error).", content_type = "application/json"),
        (status = 401, body = ErrorBody, description = "Missing / invalid bearer."),
        (status = 500, body = ErrorBody, description = "Gateway not wired to a live event bus, or the registry did not respond."),
    )
)]
pub async fn get_active_model(
    State(state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let caller = caller_from(&req)?.clone();
    let reply = registry_round_trip(
        &state,
        &caller,
        GET_ACTIVE_REQUEST,
        GET_ACTIVE_RESPONSE,
        json!({}),
    )
    .await?;
    // `null` means "no model bound" — a valid 200 response, not an error.
    Ok(Json(reply))
}

/// `PUT /api/models/active` — bind by `{ "id": "<capsule>:<model>" }`.
#[utoipa::path(
    put,
    path = "/api/models/active",
    tag = "models",
    request_body = SetActiveModelRequest,
    responses(
        (status = 200, description = "The persisted active provider-entry the registry bound (canonical `<capsule>:<model>` id).", content_type = "application/json"),
        (status = 400, body = ErrorBody, description = "Empty `id`, or the registry rejected the id (unknown / ambiguous) — its message is surfaced verbatim."),
        (status = 401, body = ErrorBody, description = "Missing / invalid bearer."),
        (status = 500, body = ErrorBody, description = "Gateway not wired to a live event bus, or the registry did not respond."),
    )
)]
pub async fn set_active_model(
    State(state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let caller = caller_from(&req)?.clone();
    let body: SetActiveModelRequest = crate::routes::principals::read_json_body(req).await?;

    // Reject an empty / whitespace id BEFORE contacting the bus — no point
    // routing a request the registry can only reject, and it keeps a
    // trivially-bad input off the event bus entirely.
    if body.id.trim().is_empty() {
        return Err(GatewayError::BadRequest("id must not be empty".to_string()));
    }

    let reply = registry_round_trip(
        &state,
        &caller,
        SET_ACTIVE_REQUEST,
        SET_ACTIVE_RESPONSE,
        // The registry reads `model_id` (also accepted under `data`); the
        // gateway forwards the raw `id` untouched and never interprets it.
        json!({ "model_id": body.id }),
    )
    .await?;

    // Success: `{ "status": "ok", "active_model": <entry> }` → return the
    // persisted entry so the caller sees the canonical id the registry
    // bound. Error: `{ "error": "<msg>" }` → 400 with the registry's
    // message surfaced verbatim (the gateway does not reinterpret
    // resolution / ambiguity errors).
    if let Some(error) = reply.get("error").and_then(serde_json::Value::as_str) {
        return Err(GatewayError::BadRequest(error.to_string()));
    }
    if let Some(active) = reply.get("active_model") {
        return Ok(Json(active.clone()));
    }
    // Neither `error` nor `active_model` — a malformed reply shape the
    // registry contract says cannot happen; surface as 500 rather than
    // pretend success.
    Err(GatewayError::Internal(anyhow::anyhow!(
        "registry set_active_model reply missing both 'active_model' and 'error'"
    )))
}
