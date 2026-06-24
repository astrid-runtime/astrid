//! `GET /api/agent/sessions` + `GET /api/agent/sessions/{id}/messages` —
//! expose a principal's conversation threads over HTTP.
//!
//! Both routes proxy to the `capsule-session` capsule over the
//! in-process event bus, mirroring the request/reply-over-bus shape
//! `bus_admin.rs` uses for kernel admin ops but targeting capsule
//! topics instead. The gateway:
//!
//! 1. Generates a fresh `correlation_id` (UUID v4).
//! 2. Subscribes to a **per-correlation scoped** response topic
//!    (`session.v1.response.<verb>.<correlation_id>`) FIRST — before
//!    publishing — so a fast capsule reply can't land before the
//!    subscription is open.
//! 3. Publishes the request, principal-stamped, on the verb's request
//!    topic.
//! 4. Awaits one reply on the scoped topic (verifying `correlation_id`
//!    defensively), with a 15s timeout.
//!
//! ## Trust boundary
//!
//! The principal stamp is the *only* authority. The kernel scopes
//! capsule-session's KV reads to the stamped principal's namespace, so
//! a caller only ever sees their own threads. We stamp
//! `caller.principal` (and `caller.device_key_id` when the bearer is
//! device-scoped, exactly as `bus_admin.rs` does) on every outbound
//! request. The path `{id}` and every query param are payload data —
//! they NEVER substitute for the principal and NEVER reach a topic
//! segment (the response topic is keyed on the gateway-generated
//! `correlation_id`, not on caller input), so a malicious `id` cannot
//! cross into another principal's namespace or hijack another request's
//! reply.

use std::sync::Arc;
use std::time::Duration;

use astrid_core::PrincipalId;
use astrid_events::ipc::{IpcMessage, IpcPayload};
use astrid_events::{AstridEvent, EventBus, EventMetadata};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::Request;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{ErrorBody, GatewayError, GatewayResult};
use crate::routes::principals::caller_from;
use crate::state::GatewayState;

/// Default page size for the session-list endpoint when the caller
/// omits `limit` (or passes `0`). Bounds the response body for casual
/// scraping while still covering a typical user's recent threads.
const DEFAULT_LIMIT: u32 = 50;

/// Hard upper bound on `limit`. A dashboard wanting more should
/// paginate; the cap stops a malicious bearer from requesting an
/// enormous page and forcing the capsule to materialise it.
const MAX_LIMIT: u32 = 200;

/// Maximum accepted length of a session id in the transcript path.
/// Session ids the capsule mints are short (a UUID or `"default"`);
/// 256 is a generous ceiling that still rejects an abusive id outright.
const MAX_SESSION_ID_LEN: usize = 256;

/// Reply timeout for a capsule request/reply round-trip. Matches
/// `bus_admin.rs`'s default so the operator sees consistent behaviour
/// across bus-proxied endpoints.
const CAPSULE_TIMEOUT: Duration = Duration::from_secs(15);

/// Request topic the gateway publishes a session-list request on. Its
/// presence in a loaded capsule's interceptor events is also the
/// capability probe for [`ensure_list_supported`] — a session capsule
/// that implements the 1.1 `list` verb subscribes to exactly this topic;
/// a 1.0 (transcript-only) capsule does not.
const TOPIC_LIST_REQUEST: &str = "session.v1.request.list";

/// Response-topic prefix for a session-list reply. The full topic is
/// `"{TOPIC_LIST_RESPONSE_PREFIX}.{correlation_id}"`.
const TOPIC_LIST_RESPONSE_PREFIX: &str = "session.v1.response.list";

/// Request topic the gateway publishes a transcript request on. Reuses
/// the capsule's existing `get_messages` verb — no new capsule contract.
const TOPIC_MESSAGES_REQUEST: &str = "session.v1.request.get_messages";

/// Response-topic prefix for a transcript reply. The full topic is
/// `"{TOPIC_MESSAGES_RESPONSE_PREFIX}.{correlation_id}"`.
const TOPIC_MESSAGES_RESPONSE_PREFIX: &str = "session.v1.response.get_messages";

/// Query parameters for `GET /api/agent/sessions`. Both optional —
/// the default is "the most recent [`DEFAULT_LIMIT`] threads".
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct SessionListQuery {
    /// Page size, default [`DEFAULT_LIMIT`], capped at [`MAX_LIMIT`].
    /// `0` is treated as "unset" and falls back to the default.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Opaque cursor returned by a previous page. Passed through to the
    /// capsule verbatim — the gateway treats it as opaque so the
    /// capsule can change its pagination scheme without breaking
    /// dashboards.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// One conversation thread's metadata, as rendered for the JSON wire.
/// Mirrors the frozen `session.v1.response.list` element shape exactly.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SessionSummary {
    /// Thread identifier. `"default"` for the implicit unnamed thread;
    /// otherwise the session id the agent loop minted.
    pub session_id: String,
    /// Number of messages in the thread.
    pub message_count: u32,
    /// Unix epoch (seconds) the thread was created, or `null` when the
    /// capsule has no creation timestamp recorded for it.
    pub created_at: Option<i64>,
    /// Unix epoch (seconds) of the most recent message, or `null`.
    pub updated_at: Option<i64>,
    /// Parent thread id when this thread was forked from another, else
    /// `null`.
    pub parent_session_id: Option<String>,
    /// First user message, truncated by the capsule for a list preview,
    /// or `null` when the thread has no user message yet.
    pub preview: Option<String>,
}

/// Response shape for `GET /api/agent/sessions`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SessionListResponse {
    /// Page of threads, ordered by session key (stable, not by recency).
    /// Each summary carries `updated_at`, so a client that wants a
    /// most-recent-first view sorts the page by that field — the server
    /// does not globally recency-sort, because that can't be done with
    /// scalable cursor pagination.
    pub sessions: Vec<SessionSummary>,
    /// Opaque cursor for the next page, or `null` on the last page.
    pub next_cursor: Option<String>,
}

/// Response shape for `GET /api/agent/sessions/{id}/messages`.
///
/// `messages` is passed through as opaque JSON (`serde_json::Value`):
/// the transcript message type is owned by `capsule-session` /
/// `astrid-types` LLM message shapes and is not re-modelled here. The
/// gateway is a dumb proxy for the thread body — re-deriving the full
/// message schema would couple the gateway to the capsule's internal
/// representation for zero benefit (the client renders it, not the
/// gateway). We surface it verbatim.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TranscriptResponse {
    /// The thread id the transcript belongs to (echoes the path param).
    pub session_id: String,
    /// The thread's messages, in order, as opaque JSON values.
    #[schema(value_type = Vec<Object>)]
    pub messages: Vec<Value>,
}

/// `GET /api/agent/sessions` — list the caller's conversation threads.
///
/// Paginated, principal-scoped: the kernel scopes the capsule's KV
/// reads to the stamped principal, so a caller only ever sees their own
/// threads. There is no admin "see everyone" mode — this surface is
/// deliberately self-only.
#[utoipa::path(
    get,
    path = "/api/agent/sessions",
    tag = "agent",
    params(
        ("limit" = Option<u32>, Query, description = "Page size; default 50, max 200. `0`/absent → default."),
        ("cursor" = Option<String>, Query, description = "Opaque cursor from a previous page."),
    ),
    responses(
        (status = 200, body = SessionListResponse, description = "Page of the caller's own conversation threads, ordered by session key; each carries `updated_at` for client-side recency sorting."),
        (status = 400, body = ErrorBody, description = "Bad query params (e.g. limit > 200)."),
        (status = 401, body = ErrorBody, description = "Missing / invalid bearer."),
        (status = 500, body = ErrorBody, description = "Gateway not wired to a live event bus."),
        (status = 501, body = ErrorBody, description = "No loaded session capsule implements the 1.1 `list` verb (transcript still works)."),
        (status = 502, body = ErrorBody, description = "Session capsule did not reply within the timeout, or returned an unexpected shape."),
    )
)]
pub async fn list_sessions(
    State(state): State<Arc<GatewayState>>,
    Query(query): Query<SessionListQuery>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<SessionListResponse>> {
    let caller = caller_from(&req)?;
    metrics::counter!("astrid_gateway_agent_sessions_list_total").increment(1);

    let bus = require_bus(&state)?;
    let limit = resolve_limit(query.limit)?;
    // Support a mixed 1.0/1.1 fleet: a pre-1.1 session capsule has no
    // `list` handler, so probe the loaded capsule set first and answer
    // with an honest 501 rather than hanging to the bus timeout on a verb
    // nobody handles. The transcript route needs no such gate — its verb
    // exists in 1.0.
    ensure_list_supported(&state).await?;
    let correlation_id = Uuid::new_v4().to_string();
    let payload = build_list_payload(&correlation_id, query.cursor.as_deref(), limit);
    let response_topic = format!("{TOPIC_LIST_RESPONSE_PREFIX}.{correlation_id}");

    let value = request_capsule(
        &bus,
        TOPIC_LIST_REQUEST,
        &response_topic,
        payload,
        &correlation_id,
        &caller.principal,
        caller.device_key_id.as_deref(),
        CAPSULE_TIMEOUT,
    )
    .await?;

    let parsed = parse_list_response(value)?;
    Ok(Json(parsed))
}

/// `GET /api/agent/sessions/{id}/messages` — fetch one thread's full
/// transcript.
///
/// A non-existent thread returns an **empty** `messages` list, not a
/// 404: the capsule cannot distinguish "never existed" from "exists but
/// empty", and returning empty avoids leaking whether a given thread id
/// belongs to another principal (existence-oracle defence). The
/// principal stamp still scopes the read, so this never returns another
/// caller's thread.
#[utoipa::path(
    get,
    path = "/api/agent/sessions/{id}/messages",
    tag = "agent",
    params(
        ("id" = String, Path, description = "Thread id. Non-empty, ≤256 chars, no ASCII control characters."),
    ),
    responses(
        (status = 200, body = TranscriptResponse, description = "The thread's messages in order; empty list for an unknown/empty thread."),
        (status = 400, body = ErrorBody, description = "Invalid `id` (empty, too long, or control characters)."),
        (status = 401, body = ErrorBody, description = "Missing / invalid bearer."),
        (status = 500, body = ErrorBody, description = "Gateway not wired to a live event bus."),
        (status = 502, body = ErrorBody, description = "Session capsule did not reply within the timeout, or returned an unexpected shape."),
    )
)]
pub async fn get_session_messages(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<TranscriptResponse>> {
    let caller = caller_from(&req)?;
    metrics::counter!("astrid_gateway_agent_sessions_transcript_total").increment(1);

    validate_session_id(&id)?;
    let bus = require_bus(&state)?;
    let correlation_id = Uuid::new_v4().to_string();
    let payload = build_messages_payload(&id, &correlation_id);
    let response_topic = format!("{TOPIC_MESSAGES_RESPONSE_PREFIX}.{correlation_id}");

    let value = request_capsule(
        &bus,
        TOPIC_MESSAGES_REQUEST,
        &response_topic,
        payload,
        &correlation_id,
        &caller.principal,
        caller.device_key_id.as_deref(),
        CAPSULE_TIMEOUT,
    )
    .await?;

    let messages = parse_messages_response(&value)?;
    Ok(Json(TranscriptResponse {
        session_id: id,
        messages,
    }))
}

/// Pull the live event bus out of state, or fail with a 500 the same
/// way `agent.rs` does when the gateway isn't co-located with a daemon.
fn require_bus(state: &GatewayState) -> GatewayResult<Arc<EventBus>> {
    state.event_bus.clone().ok_or_else(|| {
        GatewayError::Internal(anyhow::anyhow!(
            "gateway is not wired to a live event bus; session threads unavailable"
        ))
    })
}

/// Gate the list route on the session `list` capability being present in
/// the loaded capsule set, so a mixed 1.0/1.1 fleet behaves honestly: a
/// pre-1.1 session capsule (which has no `list` handler) yields an
/// immediate `NotImplemented` (501) instead of waiting out the bus
/// timeout on a verb nobody handles.
///
/// Uses the in-process [`CapsuleTopicProbe`] — a cap-free read of the live
/// registry, the same approach `POST /api/agent/prompt` takes for its
/// fail-fast. Capsule serviceability is global daemon health, not
/// per-principal authorization, so this must NOT route through the
/// capability-gated `GetCapsuleMetadata` (which would 403 an ordinary
/// caller and leak the capsule inventory). When the probe is absent (a
/// standalone gateway with no kernel), the gate is skipped and the bus
/// round-trip governs the outcome.
async fn ensure_list_supported(state: &GatewayState) -> GatewayResult<()> {
    if let Some(probe) = &state.topic_probe
        && !probe.is_subscribed(TOPIC_LIST_REQUEST).await
    {
        return Err(GatewayError::NotImplemented(
            "session listing requires a session capsule that implements the 1.1 \
             `list` verb; none is loaded"
                .into(),
        ));
    }
    Ok(())
}

/// Resolve the effective page size: reject anything over [`MAX_LIMIT`]
/// with a `BadRequest`; treat `0` / absent as [`DEFAULT_LIMIT`].
fn resolve_limit(limit: Option<u32>) -> GatewayResult<u32> {
    match limit {
        Some(l) if l > MAX_LIMIT => Err(GatewayError::BadRequest(format!(
            "limit {l} exceeds the cap of {MAX_LIMIT}"
        ))),
        Some(0) | None => Ok(DEFAULT_LIMIT),
        Some(l) => Ok(l),
    }
}

/// Validate a session id taken from the request path. The id only ever
/// becomes request *payload* data — never a topic segment — so the
/// rules are about keeping the payload sane, not about topic-injection
/// (the response topic is keyed on the gateway's own `correlation_id`).
/// Dots are allowed.
fn validate_session_id(id: &str) -> GatewayResult<()> {
    if id.is_empty() {
        return Err(GatewayError::BadRequest(
            "session id must not be empty".into(),
        ));
    }
    if id.len() > MAX_SESSION_ID_LEN {
        return Err(GatewayError::BadRequest(format!(
            "session id exceeds the maximum length of {MAX_SESSION_ID_LEN}"
        )));
    }
    if id.chars().any(|c| c.is_ascii_control()) {
        return Err(GatewayError::BadRequest(
            "session id must not contain control characters".into(),
        ));
    }
    Ok(())
}

/// Build the `session.v1.request.list` request payload to the frozen
/// contract. `cursor` and `limit` are both nullable.
fn build_list_payload(correlation_id: &str, cursor: Option<&str>, limit: u32) -> Value {
    serde_json::json!({
        "correlation_id": correlation_id,
        "cursor": cursor,
        "limit": limit,
    })
}

/// Build the `session.v1.request.get_messages` request payload. Reuses
/// the existing capsule verb — `session_id` + `correlation_id` only.
fn build_messages_payload(session_id: &str, correlation_id: &str) -> Value {
    serde_json::json!({
        "session_id": session_id,
        "correlation_id": correlation_id,
    })
}

/// Deserialize a `session.v1.response.list` body into the typed
/// response. A shape the capsule never agreed to is a `Kernel`-class
/// upstream error (the capsule replied with garbage), not a client
/// fault.
fn parse_list_response(value: Value) -> GatewayResult<SessionListResponse> {
    serde_json::from_value(value).map_err(|e| {
        GatewayError::Kernel(format!(
            "session capsule returned an unexpected list shape: {e}"
        ))
    })
}

/// Extract the `messages` array from a `session.v1.response.get_messages`
/// body. A missing `messages` field is treated as an empty transcript
/// (the capsule's "unknown/empty thread" signal); a present-but-non-array
/// `messages` is an upstream-shape error.
fn parse_messages_response(value: &Value) -> GatewayResult<Vec<Value>> {
    match value.get("messages") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => Ok(items.clone()),
        Some(_) => Err(GatewayError::Kernel(
            "session capsule returned a non-array `messages` field".into(),
        )),
    }
}

/// Reusable capsule request/reply-over-bus primitive.
///
/// Subscribes to `response_topic` FIRST (a per-correlation scoped topic,
/// so no request-id filtering at the subscription layer is needed),
/// publishes the principal-stamped request on `request_topic`, and
/// awaits exactly one reply — defensively verifying the reply's
/// `correlation_id` matches before returning it. Maps a timeout to a
/// `502`-class (upstream) error and a closed bus to a `500`-class error.
///
/// `device_key_id` is stamped when present, exactly as `bus_admin.rs`
/// does, so a device-scoped bearer carries its attenuation floor to the
/// kernel cap-gate on the way to the capsule.
#[allow(clippy::too_many_arguments)]
async fn request_capsule(
    bus: &EventBus,
    request_topic: &str,
    response_topic: &str,
    payload: Value,
    correlation_id: &str,
    principal: &PrincipalId,
    device_key_id: Option<&str>,
    timeout: Duration,
) -> GatewayResult<Value> {
    // Subscribe FIRST. A fast capsule can publish the reply on the same
    // task that processed the request — subscribing afterwards races it.
    let mut receiver = bus.subscribe_topic(response_topic.to_string());

    let mut msg = IpcMessage::new(
        request_topic.to_string(),
        IpcPayload::RawJson(payload),
        Uuid::nil(),
    )
    .with_principal(principal.to_string());
    if let Some(key_id) = device_key_id {
        msg = msg.with_device_key_id(key_id.to_string());
    }
    bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new("astrid-gateway::sessions"),
        message: msg,
    });

    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(tokio::time::Instant::now);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(capsule_timeout(response_topic));
        }
        let event = match tokio::time::timeout(remaining, receiver.recv()).await {
            Ok(Some(ev)) => ev,
            Ok(None) => {
                return Err(GatewayError::Internal(anyhow::anyhow!(
                    "event bus closed before a session capsule reply on {response_topic}"
                )));
            },
            Err(_) => return Err(capsule_timeout(response_topic)),
        };

        let AstridEvent::Ipc { message, .. } = &*event else {
            continue;
        };
        let value: Value = match &message.payload {
            IpcPayload::RawJson(v) => v.clone(),
            other => match serde_json::to_value(other) {
                Ok(v) => v,
                Err(_) => continue,
            },
        };
        // Defensive correlation check. The scoped topic already isolates
        // this request's reply, but a capsule bug (or a foreign publisher
        // on the same topic) must not slip a mismatched body through. A
        // mismatch falls through to the next loop iteration (keep waiting).
        if value.get("correlation_id").and_then(Value::as_str) == Some(correlation_id) {
            return Ok(value);
        }
    }
}

/// Build the timeout error. A slow/absent session capsule should be
/// distinguishable from a gateway fault, so we surface it as an
/// **upstream** error rather than a blanket `500`. `GatewayError` has no
/// dedicated `504 Gateway Timeout` variant; the closest honest fit is
/// `Kernel`, which maps to `502 Bad Gateway` (an upstream that didn't
/// answer). The message names the timeout explicitly.
fn capsule_timeout(response_topic: &str) -> GatewayError {
    GatewayError::Kernel(format!(
        "session capsule did not reply within {}s on {response_topic}",
        CAPSULE_TIMEOUT.as_secs()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_limit_defaults_and_caps() {
        // Absent → default.
        assert_eq!(resolve_limit(None).unwrap(), DEFAULT_LIMIT);
        // Zero is "unset" → default (mirrors the audit endpoint).
        assert_eq!(resolve_limit(Some(0)).unwrap(), DEFAULT_LIMIT);
        // A sane value passes through unchanged.
        assert_eq!(resolve_limit(Some(25)).unwrap(), 25);
        // Exactly at the cap is allowed.
        assert_eq!(resolve_limit(Some(MAX_LIMIT)).unwrap(), MAX_LIMIT);
        // Over the cap is rejected as a client error.
        let err = resolve_limit(Some(MAX_LIMIT + 1)).unwrap_err();
        assert!(
            matches!(err, GatewayError::BadRequest(_)),
            "over-cap must be BadRequest"
        );
    }

    #[test]
    fn validate_session_id_accepts_normal_ids() {
        // A UUID, the implicit default thread, and a dotted id all pass —
        // dots are explicitly allowed (the id never becomes a topic segment).
        validate_session_id("default").expect("default is valid");
        validate_session_id("550e8400-e29b-41d4-a716-446655440000").expect("uuid is valid");
        validate_session_id("a.b.c").expect("dotted id is valid");
    }

    #[test]
    fn validate_session_id_rejects_abuse() {
        // Empty.
        assert!(matches!(
            validate_session_id("").unwrap_err(),
            GatewayError::BadRequest(_)
        ));
        // Too long.
        let too_long = "x".repeat(MAX_SESSION_ID_LEN + 1);
        assert!(matches!(
            validate_session_id(&too_long).unwrap_err(),
            GatewayError::BadRequest(_)
        ));
        // Exactly at the limit is fine.
        let at_limit = "x".repeat(MAX_SESSION_ID_LEN);
        validate_session_id(&at_limit).expect("max-length id is valid");
        // Control characters (newline, NUL, tab).
        for bad in ["a\nb", "a\0b", "a\tb"] {
            assert!(
                matches!(
                    validate_session_id(bad).unwrap_err(),
                    GatewayError::BadRequest(_)
                ),
                "control-char id {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn build_list_payload_matches_frozen_contract() {
        // With both cursor and limit present.
        let p = build_list_payload("corr-1", Some("opaque-cursor"), 50);
        assert_eq!(p["correlation_id"], "corr-1");
        assert_eq!(p["cursor"], "opaque-cursor");
        assert_eq!(p["limit"], 50);
        // Absent cursor serializes as JSON null, not omitted — the frozen
        // contract is `"cursor": <string> | null`.
        let p = build_list_payload("corr-2", None, 10);
        assert_eq!(p["cursor"], Value::Null);
        assert!(
            p.get("cursor").is_some(),
            "cursor key must be present as null"
        );
        assert_eq!(p["limit"], 10);
    }

    #[test]
    fn build_messages_payload_reuses_existing_verb() {
        let p = build_messages_payload("sess-7", "corr-9");
        assert_eq!(p["session_id"], "sess-7");
        assert_eq!(p["correlation_id"], "corr-9");
        // No extra fields leak into the existing capsule verb's payload.
        let obj = p.as_object().expect("payload is an object");
        assert_eq!(
            obj.len(),
            2,
            "get_messages payload must carry only session_id + correlation_id"
        );
    }

    #[test]
    fn parse_list_response_round_trips_frozen_shape() {
        // A sample body matching the frozen `session.v1.response.list`
        // contract, including a fully-populated and a mostly-null element.
        let body = serde_json::json!({
            "correlation_id": "corr-1",
            "sessions": [
                {
                    "session_id": "default",
                    "message_count": 12,
                    "created_at": 1_719_000_000_i64,
                    "updated_at": 1_719_000_100_i64,
                    "parent_session_id": "old-id",
                    "preview": "first user message, truncated"
                },
                {
                    "session_id": "fresh",
                    "message_count": 0,
                    "created_at": null,
                    "updated_at": null,
                    "parent_session_id": null,
                    "preview": null
                }
            ],
            "next_cursor": "page-2"
        });
        let parsed = parse_list_response(body).expect("frozen list shape must deserialize");
        assert_eq!(parsed.sessions.len(), 2);
        assert_eq!(parsed.next_cursor.as_deref(), Some("page-2"));

        let first = &parsed.sessions[0];
        assert_eq!(first.session_id, "default");
        assert_eq!(first.message_count, 12);
        assert_eq!(first.created_at, Some(1_719_000_000));
        assert_eq!(first.updated_at, Some(1_719_000_100));
        assert_eq!(first.parent_session_id.as_deref(), Some("old-id"));
        assert_eq!(
            first.preview.as_deref(),
            Some("first user message, truncated")
        );

        let second = &parsed.sessions[1];
        assert_eq!(second.session_id, "fresh");
        assert_eq!(second.message_count, 0);
        assert!(second.created_at.is_none());
        assert!(second.preview.is_none());
    }

    #[test]
    fn parse_list_response_null_next_cursor_is_last_page() {
        let body = serde_json::json!({
            "correlation_id": "corr-1",
            "sessions": [],
            "next_cursor": null
        });
        let parsed = parse_list_response(body).expect("empty page must deserialize");
        assert!(parsed.sessions.is_empty());
        assert!(parsed.next_cursor.is_none());
    }

    #[test]
    fn parse_list_response_rejects_garbage() {
        // A body the capsule never agreed to (sessions is a string) is an
        // upstream-shape error, surfaced as Kernel-class (502), not a 500.
        let body = serde_json::json!({ "sessions": "not-an-array" });
        let err = parse_list_response(body).unwrap_err();
        assert!(
            matches!(err, GatewayError::Kernel(_)),
            "bad upstream shape → Kernel"
        );
    }

    #[test]
    fn parse_messages_response_passes_through_array() {
        let body = serde_json::json!({
            "correlation_id": "corr-1",
            "messages": [
                { "role": "user", "content": "hi" },
                { "role": "assistant", "content": "hello" }
            ]
        });
        let messages = parse_messages_response(&body).expect("messages must extract");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "user");
        assert_eq!(messages[1]["content"], "hello");
    }

    #[test]
    fn parse_messages_response_missing_field_is_empty_not_error() {
        // The capsule cannot distinguish "never existed" from "empty"; a
        // reply with no `messages` field maps to an empty transcript so we
        // never 404 / leak thread existence.
        let body = serde_json::json!({ "correlation_id": "corr-1" });
        let messages = parse_messages_response(&body).expect("missing messages → empty");
        assert!(messages.is_empty());
        // Explicit null is treated the same way.
        let body = serde_json::json!({ "correlation_id": "corr-1", "messages": null });
        assert!(parse_messages_response(&body).unwrap().is_empty());
    }

    #[test]
    fn parse_messages_response_rejects_non_array() {
        let body = serde_json::json!({ "messages": "nope" });
        let err = parse_messages_response(&body).unwrap_err();
        assert!(
            matches!(err, GatewayError::Kernel(_)),
            "non-array messages → Kernel"
        );
    }

    /// Live round-trip over a real `EventBus`: publish a canned reply on
    /// the scoped response topic and assert the helper returns it. Proves
    /// the subscribe-first/publish/await loop and the correlation check
    /// against the actual bus wiring, not a mock.
    #[tokio::test]
    async fn request_capsule_round_trips_scoped_reply() {
        let bus = Arc::new(EventBus::new());
        let principal = PrincipalId::new("alice").expect("valid principal");
        let correlation_id = "corr-rt-1";
        let response_topic = format!("{TOPIC_LIST_RESPONSE_PREFIX}.{correlation_id}");

        // Subscribe the stand-in capsule to the REQUEST topic HERE, before
        // anything publishes — broadcast channels don't replay history to a
        // late subscriber, so subscribing inside the spawned task would race
        // `request_capsule`'s publish and the request could be missed. The
        // capsule task then awaits on the already-live receiver and echoes a
        // frozen-shape reply on the scoped RESPONSE topic.
        let mut req_rx = bus.subscribe_topic(TOPIC_LIST_REQUEST.to_string());
        let bus_capsule = Arc::clone(&bus);
        let resp_topic = response_topic.clone();
        let cid = correlation_id.to_string();
        let capsule = tokio::spawn(async move {
            let event = req_rx.recv().await.expect("request arrives");
            // The stand-in capsule sees the request principal-stamped.
            if let AstridEvent::Ipc { message, .. } = &*event {
                assert_eq!(message.principal.as_deref(), Some("alice"));
            } else {
                panic!("expected an IPC request event");
            }
            let reply = serde_json::json!({
                "correlation_id": cid,
                "sessions": [],
                "next_cursor": null
            });
            let msg = IpcMessage::new(resp_topic.clone(), IpcPayload::RawJson(reply), Uuid::nil());
            bus_capsule.publish(AstridEvent::Ipc {
                metadata: EventMetadata::new("test::capsule"),
                message: msg,
            });
        });

        let payload = build_list_payload(correlation_id, None, DEFAULT_LIMIT);
        let value = request_capsule(
            &bus,
            TOPIC_LIST_REQUEST,
            &response_topic,
            payload,
            correlation_id,
            &principal,
            None,
            CAPSULE_TIMEOUT,
        )
        .await
        .expect("helper returns the scoped reply");

        capsule.await.expect("stand-in capsule task joins");
        let parsed = parse_list_response(value).expect("reply deserializes");
        assert!(parsed.sessions.is_empty());
        assert!(parsed.next_cursor.is_none());
    }

    /// A reply whose `correlation_id` does NOT match is skipped; the
    /// helper keeps waiting and ultimately times out rather than
    /// returning a foreign body. Proves the defensive correlation check.
    #[tokio::test]
    async fn request_capsule_ignores_mismatched_correlation() {
        let bus = Arc::new(EventBus::new());
        let principal = PrincipalId::new("alice").expect("valid principal");
        let correlation_id = "corr-want";
        let response_topic = format!("{TOPIC_LIST_RESPONSE_PREFIX}.{correlation_id}");

        // Publish a mismatched reply on the same scoped topic before the
        // helper's short timeout elapses.
        let bus_bg = Arc::clone(&bus);
        let resp_topic = response_topic.clone();
        tokio::spawn(async move {
            // Let the helper subscribe first.
            tokio::task::yield_now().await;
            let reply = serde_json::json!({
                "correlation_id": "corr-other",
                "sessions": [],
                "next_cursor": null
            });
            let msg = IpcMessage::new(resp_topic, IpcPayload::RawJson(reply), Uuid::nil());
            bus_bg.publish(AstridEvent::Ipc {
                metadata: EventMetadata::new("test::foreign"),
                message: msg,
            });
        });

        let payload = build_list_payload(correlation_id, None, DEFAULT_LIMIT);
        let err = request_capsule(
            &bus,
            TOPIC_LIST_REQUEST,
            &response_topic,
            payload,
            correlation_id,
            &principal,
            None,
            // Short timeout — we expect the mismatched reply to be skipped
            // and the call to time out rather than return a foreign body.
            Duration::from_millis(150),
        )
        .await
        .expect_err("mismatched correlation must not satisfy the request");
        assert!(
            matches!(err, GatewayError::Kernel(_)),
            "timeout after skipping a foreign reply maps to Kernel-class"
        );
    }
}
