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
//! 1. The principal is the **verified**
//!    [`CallerContext::principal`](crate::auth::CallerContext::principal)
//!    from the signed bearer — never a body/query field.
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
//! 4. The reply must also be stamped with the registry capsule's deterministic
//!    source id. Principal scope is not enough: another capsule running as the
//!    same principal must not be able to satisfy the gateway's registry awaiter.

use std::sync::Arc;
use std::time::Duration;

use astrid_events::AstridEvent;
use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
use axum::Extension;
use axum::Json;
use axum::extract::State;
use axum::http::Request;
use serde::Deserialize;
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{ErrorBody, GatewayError, GatewayResult};
use crate::routes::WorkspaceContext;
use crate::routes::principals::caller_from;
use crate::state::GatewayState;
use astrid_core::PrincipalId;

/// Wall-clock budget for the registry to answer a model request. Matches
/// the 10s budget the CLI uses for the equivalent daemon read
/// (`capsule_verb.rs`); long enough for a cold capsule, short enough that
/// an unresponsive registry doesn't tie a request up indefinitely.
const REGISTRY_TIMEOUT: Duration = Duration::from_secs(10);
const CAPSULE_PROBE_INTERVAL: Duration = Duration::from_millis(100);
const SCOPED_SERVICE_PROBE_SENTINEL: &str = "\0astrid.scoped-service\0";
const REGISTRY_INTERFACE_REQUIREMENT: &str = "^1.0";

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

/// Decide whether a registry reply satisfies a correlation filter.
///
/// The set-model path stamps each request with a fresh per-request
/// `corr_id` and threads it here as `expected`. The rule (the gateway side
/// of the shared correlation contract) is deliberately permissive on the
/// "no id" case so it cannot break older paths:
///
/// * `expected == None` — GET paths, which are not correlated. Every reply
///   that passed the trusted-source check is accepted; concurrent
///   same-principal reads are idempotent and benign.
/// * `expected == Some(ours)` — a SET reply is accepted iff it carries our
///   `corr_id` **or** carries no `corr_id` field at all. A reply whose
///   `corr_id` is *present and different* is some other concurrent
///   same-principal SET's reply and is SKIPPED. A `corr_id` that is present
///   but **not a string** is anomalous — it can never equal our id, so it is
///   treated as a non-match and SKIPPED rather than accepted; accepting it
///   would let a malformed or forged reply satisfy the correlation filter and
///   be surfaced as the matching SET response. Accepting the no-`corr_id`
///   case keeps a not-yet-updated registry (and any GET reply that races
///   onto the same scoped route) working.
///
/// This is the pure core of the race fix: two concurrent same-principal SET
/// requests no longer consume each other's reply body. It is kept free of
/// IO so the decision can be unit-tested directly. The bounded recv deadline
/// in [`registry_round_trip`] bounds the skip path, so skipping an anomalous
/// reply degrades to a timeout (500) — the correct fail-safe — rather than
/// surfacing the wrong body.
fn reply_satisfies_corr_id(reply: &serde_json::Value, expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        // Uncorrelated (GET) path: accept any reply.
        return true;
    };
    match reply.get("corr_id") {
        // No `corr_id` field on the reply → accept (older registry / GET
        // reply that hasn't started echoing the id).
        None => true,
        // Present as a string → accept only an exact match; a foreign id is
        // skipped.
        Some(serde_json::Value::String(found)) => found == expected,
        // Present but NOT a string → anomalous; it cannot be our id, so it is
        // a non-match and is skipped (fail-safe to a timeout, not accept).
        Some(_) => false,
    }
}

/// Outcome of classifying a `set_active_model` registry reply.
///
/// Pure core of the SET response mapping, lifted out of the async handler so
/// the shape decision — including the explicit-`null` edge — is unit-testable
/// without a live bus.
enum SetActiveOutcome {
    /// Registry persisted an entry; the inner value is the canonical
    /// provider-entry to return as a 200 body.
    Bound(serde_json::Value),
    /// Registry rejected the id; the string is its verbatim message (→ 400).
    Rejected(String),
    /// Reply carried neither a non-null `active_model` nor an `error` — a
    /// shape the registry contract says cannot happen (→ 500).
    Malformed,
}

fn registry_reply_payload_json(payload: &IpcPayload) -> GatewayResult<serde_json::Value> {
    let bytes = payload
        .to_guest_bytes()
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("registry reply not JSON: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("registry reply not JSON: {e}")))
}

/// Classify a `set_active_model` registry reply into the response the handler
/// returns.
///
/// An `error` string maps to [`SetActiveOutcome::Rejected`]. A **non-null**
/// `active_model` maps to [`SetActiveOutcome::Bound`]. An explicit JSON `null`
/// for `active_model` is treated as ABSENT — a successful bind always carries
/// the canonical entry, so a `null` is a malformed reply, not a `200 null`.
/// This mirrors typed deserialization where `active_model: null` → `None`.
/// Anything else is [`SetActiveOutcome::Malformed`].
fn classify_set_active_reply(reply: &serde_json::Value) -> SetActiveOutcome {
    if let Some(error) = reply.get("error").and_then(serde_json::Value::as_str) {
        return SetActiveOutcome::Rejected(error.to_string());
    }
    if let Some(active) = reply.get("active_model").filter(|v| !v.is_null()) {
        return SetActiveOutcome::Bound(active.clone());
    }
    SetActiveOutcome::Malformed
}

/// Publish `request_topic` (stamped with the caller's principal) and await
/// the matching reply on `response_topic`, scoped to the caller so no other
/// principal's registry reply can be observed. Mirrors the subscribe-first
/// / publish-second ordering and timeout discipline of `agent.rs`.
///
/// `corr_id` is the set-path correlation filter (see
/// [`reply_satisfies_corr_id`]). When `Some`, the reply-draining loop SKIPS
/// any reply whose `corr_id` is present and differs from ours — that reply
/// belongs to another concurrent same-principal SET — and keeps receiving
/// (within the same overall timeout budget) until a matching / un-correlated
/// reply arrives or the budget is spent. When `None` (the GET paths) the
/// first trusted-source reply on the scoped route is taken.
async fn registry_round_trip(
    state: &GatewayState,
    principal_id: &PrincipalId,
    _workspace: &WorkspaceContext,
    request_topic: &'static str,
    response_topic: &'static str,
    payload: serde_json::Value,
    corr_id: Option<&str>,
) -> GatewayResult<serde_json::Value> {
    let Some(bus) = state.event_bus.clone() else {
        return Err(GatewayError::Internal(anyhow::anyhow!(
            "gateway is not wired to a live event bus; model registry unavailable"
        )));
    };

    let principal = principal_id.to_string();
    ensure_registry_request_subscribed(state, principal_id, request_topic).await?;
    let expected_source_ids = provider_source_ids(state, principal_id, request_topic).await?;

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
    // reply is matched against on the scoped subscription above. The source
    // id is a fresh per-request UUID — never `Uuid::nil()`, which is the
    // reserved `SYSTEM_SESSION_UUID` and would mis-attribute this
    // client-originated request as the system session. Reply correlation is
    // unaffected: replies are matched by the principal-scoped routed
    // subscription, not by this source id.
    let msg = IpcMessage::new(
        Topic::from_raw(request_topic),
        IpcPayload::RawJson(payload),
        Uuid::new_v4(),
    )
    .with_principal(principal)
    // Host-stamp the gateway transport origin (a remote API caller), so no
    // gateway-published message inherits the `System` default.
    .with_origin(astrid_events::ipc::MessageOrigin::RemoteGateway);
    bus.publish(AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("gateway::models"),
        message: msg,
    });

    // Await the matching reply. `recv(Some(..))` returns `None` on timeout.
    // The wait budget defaults to the production `REGISTRY_TIMEOUT`; a test
    // may shorten it via `GatewayState::registry_timeout` so a negative
    // (no-reply) assertion doesn't block for the full 10s.
    //
    // The loop drains replies on the scoped route, skipping any that carry a
    // foreign `corr_id` (another concurrent same-principal SET's reply). The
    // budget is an absolute DEADLINE, not a per-iteration timeout: each
    // `recv` is bounded by the time REMAINING, so a stream of skipped foreign
    // replies can never extend the total wait past the original budget.
    let timeout = state.registry_timeout.unwrap_or(REGISTRY_TIMEOUT);
    // `checked_add` over the bare `+` so an absurd timeout can't panic on
    // overflow; saturating to `now` (a zero remaining budget) on overflow is
    // a harmless immediate timeout that the production budget never hits.
    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(tokio::time::Instant::now);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        // No budget left (deadline already elapsed, or zero remaining): break
        // to the timeout path rather than calling `recv(Some(ZERO))`, whose
        // behaviour with a zero duration is implementation-defined. The
        // absolute deadline above keeps total wait bounded regardless.
        if remaining.is_zero() {
            return Err(GatewayError::Internal(anyhow::anyhow!(
                "registry did not respond"
            )));
        }
        let Some(event) = reply_rx.recv(Some(remaining)).await else {
            return Err(GatewayError::Internal(anyhow::anyhow!(
                "registry did not respond"
            )));
        };
        let AstridEvent::Ipc { message, .. } = &*event else {
            return Err(GatewayError::Internal(anyhow::anyhow!(
                "registry reply was not an IPC message"
            )));
        };
        if !expected_source_ids.contains(&message.source_id) {
            continue;
        }
        // Extract the guest-facing payload. Capsule `publish_json` arrives as
        // `Custom { data }` when the JSON has no known IPC `type`; using the
        // guest bytes unwraps that data instead of exposing the internal tagged
        // wrapper to the HTTP API.
        let value = registry_reply_payload_json(&message.payload)?;
        // Skip a reply that belongs to a different concurrent same-principal
        // SET (foreign `corr_id`); keep waiting within the remaining budget.
        if reply_satisfies_corr_id(&value, corr_id) {
            return Ok(value);
        }
    }
}

async fn ensure_registry_request_subscribed(
    state: &GatewayState,
    principal: &PrincipalId,
    request_topic: &str,
) -> GatewayResult<()> {
    let Some(probe) = &state.topic_probe else {
        return Err(GatewayError::Kernel(
            "gateway has no live capsule provider probe".into(),
        ));
    };
    let key = scoped_topic_probe_key(principal, request_topic);
    if probe.is_subscribed(&key).await || probe.ensure_subscribed(&key).await {
        return Ok(());
    }

    let timeout = state.registry_timeout.unwrap_or(REGISTRY_TIMEOUT);
    let started = tokio::time::Instant::now();
    loop {
        if probe.is_subscribed(&key).await {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(GatewayError::Internal(anyhow::anyhow!(
                "no loaded capsule handles the registry request for caller"
            )));
        }
        tokio::time::sleep(CAPSULE_PROBE_INTERVAL).await;
    }
}

async fn provider_source_ids(
    state: &GatewayState,
    principal: &PrincipalId,
    request_topic: &str,
) -> GatewayResult<Vec<Uuid>> {
    let probe = state.topic_probe.as_ref().ok_or_else(|| {
        GatewayError::Internal(anyhow::anyhow!(
            "gateway has no live capsule provider probe"
        ))
    })?;
    let key = scoped_topic_probe_key(principal, request_topic);
    if !probe.is_subscribed(&key).await && !probe.ensure_subscribed(&key).await {
        return Err(GatewayError::Internal(anyhow::anyhow!(
            "no loaded capsule handles the registry request for caller"
        )));
    }
    let source_ids = probe.subscriber_source_ids(&key).await;
    if source_ids.is_empty() {
        return Err(GatewayError::Internal(anyhow::anyhow!(
            "no unique compatible loaded capsule handles the registry request for caller"
        )));
    }
    Ok(source_ids)
}

fn scoped_topic_probe_key(principal: &PrincipalId, topic: &str) -> String {
    format!(
        "{SCOPED_SERVICE_PROBE_SENTINEL}{principal}\0astrid\0registry\0{REGISTRY_INTERFACE_REQUIREMENT}\0{topic}"
    )
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
    list_models_inner(state, &WorkspaceContext::default(), req).await
}

pub(crate) async fn list_models_with_layout(
    State(state): State<Arc<GatewayState>>,
    Extension(workspace): Extension<WorkspaceContext>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    list_models_inner(state, &workspace, req).await
}

async fn list_models_inner(
    state: Arc<GatewayState>,
    workspace: &WorkspaceContext,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let caller = caller_from(&req)?;
    let reply = registry_round_trip(
        &state,
        &caller.principal,
        workspace,
        GET_PROVIDERS_REQUEST,
        GET_PROVIDERS_RESPONSE,
        json!({}),
        // GET is uncorrelated: concurrent same-principal reads are idempotent.
        None,
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
    get_active_model_inner(state, &WorkspaceContext::default(), req).await
}

pub(crate) async fn get_active_model_with_layout(
    State(state): State<Arc<GatewayState>>,
    Extension(workspace): Extension<WorkspaceContext>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    get_active_model_inner(state, &workspace, req).await
}

async fn get_active_model_inner(
    state: Arc<GatewayState>,
    workspace: &WorkspaceContext,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let caller = caller_from(&req)?;
    let reply = registry_round_trip(
        &state,
        &caller.principal,
        workspace,
        GET_ACTIVE_REQUEST,
        GET_ACTIVE_RESPONSE,
        json!({}),
        // GET is uncorrelated: concurrent same-principal reads are idempotent.
        None,
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
    set_active_model_inner(state, &WorkspaceContext::default(), req).await
}

pub(crate) async fn set_active_model_with_layout(
    State(state): State<Arc<GatewayState>>,
    Extension(workspace): Extension<WorkspaceContext>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    set_active_model_inner(state, &workspace, req).await
}

async fn set_active_model_inner(
    state: Arc<GatewayState>,
    workspace: &WorkspaceContext,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    // Clone only the principal id, not the whole `CallerContext`: the
    // round-trip needs nothing else, and `read_json_body` below consumes
    // `req` (which `caller_from` borrows), so the value we carry past it must
    // be owned.
    let principal = caller_from(&req)?.principal.clone();
    let body: SetActiveModelRequest = crate::routes::principals::read_json_body(req).await?;

    // Reject an empty / whitespace id BEFORE contacting the bus — no point
    // routing a request the registry can only reject, and it keeps a
    // trivially-bad input off the event bus entirely.
    if body.id.trim().is_empty() {
        return Err(GatewayError::BadRequest("id must not be empty".to_string()));
    }

    // A fresh per-request correlation id. The set path can be raced by two
    // concurrent same-principal SETs whose replies land on the same
    // principal-scoped route; without correlation each could consume the
    // other's reply BODY (the registry CAS already keeps the persisted state
    // correct, but the wrong reply could be surfaced to the caller). The
    // `corr_id` travels in the request PAYLOAD; the registry echoes it
    // verbatim, and the round-trip skips any reply carrying a different one.
    let corr_id = Uuid::new_v4().to_string();

    let reply = registry_round_trip(
        &state,
        &principal,
        workspace,
        SET_ACTIVE_REQUEST,
        SET_ACTIVE_RESPONSE,
        // The registry reads `model_id` (also accepted under `data`); the
        // gateway forwards the raw `id` untouched and never interprets it.
        // `corr_id` is echoed verbatim by the registry for reply correlation.
        json!({ "model_id": body.id, "corr_id": corr_id }),
        Some(corr_id.as_str()),
    )
    .await?;

    // Success: `{ "status": "ok", "active_model": <entry> }` → return the
    // persisted entry so the caller sees the canonical id the registry
    // bound. Error: `{ "error": "<msg>" }` → 400 with the registry's
    // message surfaced verbatim (the gateway does not reinterpret
    // resolution / ambiguity errors). An explicit `null` active_model is a
    // malformed reply, not a success — see `classify_set_active_reply`.
    match classify_set_active_reply(&reply) {
        SetActiveOutcome::Bound(active) => Ok(Json(active)),
        SetActiveOutcome::Rejected(message) => Err(GatewayError::BadRequest(message)),
        SetActiveOutcome::Malformed => Err(GatewayError::Internal(anyhow::anyhow!(
            "registry set_active_model reply carried neither an 'error' nor a \
             non-null 'active_model' (an explicit-null 'active_model' is treated \
             as absent)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GET_ACTIVE_REQUEST, GET_ACTIVE_RESPONSE, SetActiveOutcome, classify_set_active_reply,
        registry_reply_payload_json, registry_round_trip, reply_satisfies_corr_id,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::error::GatewayError;
    use crate::routes::WorkspaceContext;
    use crate::state::{GatewayState, SigningMaterial};
    use astrid_core::PrincipalId;
    use astrid_core::kernel_api::CapsuleTopicProbe;
    use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
    use astrid_events::{AstridEvent, EventBus, EventMetadata};
    use serde_json::json;
    use tokio::sync::Mutex;
    use uuid::Uuid;

    fn test_provider_source_id() -> Uuid {
        Uuid::from_u128(0x9141b6d2_61a8_4bf4_93cc_d0468375c492)
    }

    #[test]
    fn set_reply_with_entry_binds() {
        // A non-null `active_model` is a successful bind: the canonical entry
        // is returned verbatim as the 200 body.
        let entry = json!({ "id": "openai:gpt-4o" });
        match classify_set_active_reply(&json!({ "status": "ok", "active_model": entry })) {
            SetActiveOutcome::Bound(active) => {
                assert_eq!(active, json!({ "id": "openai:gpt-4o" }));
            },
            _ => panic!("a non-null active_model must classify as Bound"),
        }
    }

    #[test]
    fn set_reply_with_explicit_null_active_model_is_malformed() {
        // Regression: an explicit JSON `null` for `active_model` must NOT be
        // surfaced as a `200 null` success. A genuine bind always carries the
        // canonical entry, so a null is a malformed reply (→ 500), matching
        // the typed view where `active_model: null` deserializes to `None`.
        assert!(
            matches!(
                classify_set_active_reply(&json!({ "status": "ok", "active_model": null })),
                SetActiveOutcome::Malformed
            ),
            "explicit null active_model must classify as Malformed, not Bound(null)"
        );
    }

    #[test]
    fn set_reply_with_error_is_rejected() {
        // An `error` string maps to a 400 with the registry message verbatim.
        match classify_set_active_reply(&json!({ "error": "unknown model 'foo'" })) {
            SetActiveOutcome::Rejected(msg) => assert_eq!(msg, "unknown model 'foo'"),
            _ => panic!("an error string must classify as Rejected"),
        }
    }

    #[test]
    fn set_reply_missing_both_fields_is_malformed() {
        // Neither `error` nor `active_model` → malformed (→ 500).
        assert!(matches!(
            classify_set_active_reply(&json!({ "status": "ok" })),
            SetActiveOutcome::Malformed
        ));
    }

    #[test]
    fn registry_reply_payload_unwraps_custom_guest_json() {
        let payload = IpcPayload::Custom {
            data: json!({
                "status": "ok",
                "active_model": { "id": "openai-compat:fake-slow" },
                "corr_id": "abc",
            }),
        };

        let decoded = registry_reply_payload_json(&payload).expect("custom payload decodes");
        assert_eq!(
            decoded,
            json!({
                "status": "ok",
                "active_model": { "id": "openai-compat:fake-slow" },
                "corr_id": "abc",
            })
        );
        assert!(matches!(
            classify_set_active_reply(&decoded),
            SetActiveOutcome::Bound(_)
        ));
    }

    fn model_test_state(bus: Arc<EventBus>) -> GatewayState {
        GatewayState {
            config: crate::config::GatewayConfig::default(),
            signing: SigningMaterial::fresh(),
            event_bus: Some(bus),
            distribution: Arc::new(crate::routes::distribution::DistributionInfo::single_tenant()),
            onboarding: Arc::new(crate::routes::distribution::OnboardingFields::default()),
            redeem_limiter: Mutex::default(),
            metrics_handle: crate::metrics::install_recorder().expect("recorder"),
            revoked_at: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            revoked_key_ids: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            audit_log: None,
            session_id: None,
            gateway_route_uuid: Uuid::new_v4(),
            readiness_probe: None,
            topic_probe: Some(CapsuleTopicProbe::new_with_ensure_and_sources(
                |_topic| Box::pin(async { true }),
                |_topic| Box::pin(async { true }),
                |_topic| Box::pin(async { vec![test_provider_source_id()] }),
            )),
            registry_timeout: Some(std::time::Duration::from_millis(150)),
        }
    }

    #[tokio::test]
    async fn registry_round_trip_ignores_wrong_capsule_source_reply() {
        let bus = Arc::new(EventBus::new());
        let state = model_test_state(Arc::clone(&bus));
        let principal = PrincipalId::new("alice").expect("valid principal");

        let bus_bg = Arc::clone(&bus);
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            let msg = IpcMessage::new(
                Topic::from_raw(GET_ACTIVE_RESPONSE),
                IpcPayload::RawJson(json!({
                    "active_model": { "id": "openai-compat:forged" }
                })),
                Uuid::from_u128(0x6ad9013c_23e4_4c0b_8cad_a7303e241ef0),
            )
            .with_principal("alice".to_string());
            bus_bg.publish(AstridEvent::Ipc {
                metadata: EventMetadata::new("test::forged-registry"),
                message: msg,
            });
        });

        let err = registry_round_trip(
            &state,
            &principal,
            &WorkspaceContext::default(),
            GET_ACTIVE_REQUEST,
            GET_ACTIVE_RESPONSE,
            json!({}),
            None,
        )
        .await
        .expect_err("wrong-source registry reply must be ignored");
        assert!(matches!(err, GatewayError::Internal(_)));
    }

    #[tokio::test]
    async fn registry_round_trip_warms_caller_registry_before_publish() {
        let bus = Arc::new(EventBus::new());
        let mut state = model_test_state(Arc::clone(&bus));
        let principal = PrincipalId::new("alice").expect("valid principal");
        let warmed = Arc::new(AtomicBool::new(false));

        let warmed_probe = Arc::clone(&warmed);
        state.topic_probe = Some(CapsuleTopicProbe::new_with_ensure_and_sources(
            |_topic| Box::pin(async { false }),
            move |topic| {
                assert!(topic.contains("alice"));
                assert!(topic.contains(GET_ACTIVE_REQUEST));
                warmed_probe.store(true, Ordering::SeqCst);
                Box::pin(async { true })
            },
            |_topic| Box::pin(async { vec![test_provider_source_id()] }),
        ));

        let mut req_rx = bus.subscribe_topic(GET_ACTIVE_REQUEST.to_string());
        let bus_bg = Arc::clone(&bus);
        let warmed_bg = Arc::clone(&warmed);
        let responder = tokio::spawn(async move {
            let event = req_rx.recv().await.expect("request arrives");
            assert!(
                warmed_bg.load(Ordering::SeqCst),
                "registry request was published before caller-scoped warm-up"
            );
            if let AstridEvent::Ipc { message, .. } = &*event {
                assert_eq!(message.principal.as_deref(), Some("alice"));
            } else {
                panic!("expected an IPC request event");
            }
            let msg = IpcMessage::new(
                Topic::from_raw(GET_ACTIVE_RESPONSE),
                IpcPayload::RawJson(json!({
                    "active_model": { "id": "openai-compat:fake-slow" }
                })),
                test_provider_source_id(),
            )
            .with_principal("alice".to_string());
            bus_bg.publish(AstridEvent::Ipc {
                metadata: EventMetadata::new("test::registry"),
                message: msg,
            });
        });

        let reply = registry_round_trip(
            &state,
            &principal,
            &WorkspaceContext::default(),
            GET_ACTIVE_REQUEST,
            GET_ACTIVE_RESPONSE,
            json!({}),
            None,
        )
        .await
        .expect("warmed registry reply arrives");
        responder.await.expect("responder task completes");

        assert_eq!(
            reply,
            json!({ "active_model": { "id": "openai-compat:fake-slow" } })
        );
    }

    #[test]
    fn uncorrelated_get_accepts_any_reply() {
        // GET paths thread `None`: every reply is accepted regardless of
        // whether it carries a `corr_id`.
        assert!(reply_satisfies_corr_id(&json!({}), None));
        assert!(reply_satisfies_corr_id(&json!(null), None));
        assert!(reply_satisfies_corr_id(
            &json!({ "corr_id": "anything" }),
            None
        ));
    }

    #[test]
    fn set_accepts_matching_corr_id() {
        // A SET reply carrying our exact `corr_id` is accepted.
        assert!(reply_satisfies_corr_id(
            &json!({ "status": "ok", "corr_id": "abc" }),
            Some("abc")
        ));
        assert!(reply_satisfies_corr_id(
            &json!({ "error": "nope", "corr_id": "abc" }),
            Some("abc")
        ));
    }

    #[test]
    fn set_skips_foreign_corr_id() {
        // A reply whose `corr_id` is PRESENT and differs belongs to another
        // concurrent same-principal SET — it must be skipped (false).
        assert!(!reply_satisfies_corr_id(
            &json!({ "status": "ok", "corr_id": "other" }),
            Some("abc")
        ));
        assert!(!reply_satisfies_corr_id(
            &json!({ "error": "nope", "corr_id": "other" }),
            Some("abc")
        ));
    }

    #[test]
    fn set_accepts_reply_without_corr_id() {
        // Back-compat: a reply with NO `corr_id` field (older registry that
        // hasn't started echoing it, or a GET reply racing onto the route) is
        // accepted even when a `corr_id` was expected.
        assert!(reply_satisfies_corr_id(
            &json!({ "status": "ok", "active_model": { "id": "openai:gpt-4o" } }),
            Some("abc")
        ));
        assert!(reply_satisfies_corr_id(&json!(null), Some("abc")));
    }

    #[test]
    fn non_string_corr_id_is_skipped() {
        // Security regression: a `corr_id` that is PRESENT but not a string is
        // anomalous — it can never equal our id, so it must be a non-match and
        // SKIPPED, not accepted. Accepting it would let a malformed or forged
        // reply satisfy the correlation filter and be surfaced as the matching
        // SET response; the bounded recv deadline turns the skip into a
        // timeout (500), the correct fail-safe. Several non-string JSON shapes
        // are covered so the rule is "present-non-string ⇒ skip", not a single
        // type quirk.
        assert!(
            !reply_satisfies_corr_id(&json!({ "corr_id": 42 }), Some("abc")),
            "a numeric corr_id must be skipped (non-match), not accepted"
        );
        assert!(
            !reply_satisfies_corr_id(&json!({ "corr_id": true }), Some("abc")),
            "a boolean corr_id must be skipped (non-match), not accepted"
        );
        assert!(
            !reply_satisfies_corr_id(&json!({ "corr_id": ["abc"] }), Some("abc")),
            "an array corr_id must be skipped (non-match), not accepted"
        );
        assert!(
            !reply_satisfies_corr_id(&json!({ "corr_id": { "v": "abc" } }), Some("abc")),
            "an object corr_id must be skipped (non-match), not accepted"
        );
        // An explicit JSON `null` is a present field too — and not a string —
        // so it is likewise a non-match and skipped.
        assert!(
            !reply_satisfies_corr_id(&json!({ "corr_id": null }), Some("abc")),
            "an explicit-null corr_id must be skipped (non-match), not accepted"
        );
    }
}
