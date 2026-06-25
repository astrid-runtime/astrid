//! `GET /api/agent/sessions` (+ `/{id}`, `/{id}/messages`),
//! `PATCH`/`DELETE /api/agent/sessions/{id}`, and
//! `GET /api/agent/sessions/search` — expose and manage a principal's
//! conversation threads over HTTP.
//!
//! Every route proxies to the `capsule-session` capsule over the
//! in-process event bus, mirroring the request/reply-over-bus shape
//! `bus_admin.rs` uses for kernel admin ops but targeting capsule
//! topics instead. The gateway:
//!
//! 1. Generates a fresh `correlation_id` (UUID v4).
//! 2. Subscribes to a **per-correlation, principal-scoped** response topic
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
use astrid_events::ipc::{IpcMessage, IpcPayload, MessageOrigin, Topic};
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
/// capability probe for [`ensure_session_mgmt_supported`] — a session capsule
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

/// Request topic for one thread's metadata. 1.1 verb (its presence in a
/// loaded capsule is implied by [`ensure_session_mgmt_supported`]'s `list` probe —
/// a 1.1 session capsule that handles `list` also handles `get_meta`).
const TOPIC_GET_META_REQUEST: &str = "session.v1.request.get_meta";
/// Response-topic prefix for a `get_meta` reply.
const TOPIC_GET_META_RESPONSE_PREFIX: &str = "session.v1.response.get_meta";

/// Request topic for a metadata update (`title`/`archived`/`meta` PATCH).
const TOPIC_UPDATE_REQUEST: &str = "session.v1.request.update";
/// Response-topic prefix for an `update` reply.
const TOPIC_UPDATE_RESPONSE_PREFIX: &str = "session.v1.response.update";

/// Request topic for a thread delete.
const TOPIC_DELETE_REQUEST: &str = "session.v1.request.delete";
/// Response-topic prefix for a `delete` reply.
const TOPIC_DELETE_RESPONSE_PREFIX: &str = "session.v1.response.delete";

/// Request topic for a full-text thread search.
const TOPIC_SEARCH_REQUEST: &str = "session.v1.request.search";
/// Response-topic prefix for a `search` reply.
const TOPIC_SEARCH_RESPONSE_PREFIX: &str = "session.v1.response.search";

/// Default page size for `search` when the caller omits `limit`.
const DEFAULT_SEARCH_LIMIT: u32 = 20;
/// Hard upper bound on the `search` page size.
const MAX_SEARCH_LIMIT: u32 = 100;

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
    /// Include archived threads in the page. Absent/`false` returns only
    /// active threads; the capsule applies the filter.
    #[serde(default)]
    pub include_archived: Option<bool>,
}

/// One conversation thread's metadata, as rendered for the JSON wire.
/// Mirrors the frozen `session.v1.response.list` element shape exactly.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SessionSummary {
    /// Thread identifier. `"default"` for the implicit unnamed thread;
    /// otherwise the session id the agent loop minted.
    pub session_id: String,
    /// Human-set thread title, or `null` when unset (the client renders a
    /// preview-derived label in that case).
    #[serde(default)]
    pub title: Option<String>,
    /// First user message, truncated by the capsule for a list preview,
    /// or `null` when the thread has no user message yet.
    #[serde(default)]
    pub preview: Option<String>,
    /// Most recent message, truncated for a list preview, or `null`.
    #[serde(default)]
    pub last_message_preview: Option<String>,
    /// Number of messages in the thread.
    pub message_count: u32,
    /// Unix epoch (seconds) the thread was created, or `null` when the
    /// capsule has no creation timestamp recorded for it.
    #[serde(default)]
    pub created_at: Option<i64>,
    /// Unix epoch (seconds) of the most recent message, or `null`.
    #[serde(default)]
    pub updated_at: Option<i64>,
    /// Whether the thread is archived (hidden from the default list).
    #[serde(default)]
    pub archived: bool,
    /// Parent thread id when this thread was forked from another, else
    /// `null`.
    #[serde(default)]
    pub parent_session_id: Option<String>,
    /// Opaque capsule-owned metadata, serialized as a JSON **string** (the
    /// gateway never parses it — it is round-tripped verbatim).
    #[serde(default)]
    pub meta: Option<String>,
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
    /// Total thread count for the principal when the capsule can compute it
    /// cheaply, else `null` (e.g. the namespace is too large to count in one
    /// pass). A client uses it for a count badge; absence is not an error.
    #[serde(default)]
    pub total: Option<u32>,
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

/// Body for `PATCH /api/agent/sessions/{id}`. Every field is optional;
/// **only the keys actually present in the request body are forwarded**
/// to the capsule, so the capsule's PATCH-by-presence semantics hold:
/// an absent key leaves that field unchanged, a present key sets it, and
/// an empty string clears it. We capture the raw body as
/// [`serde_json::Value`] (not this struct) for the present-key detection;
/// this typed view exists only to document the shape in `OpenAPI`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct SessionUpdateRequest {
    /// New title. Present-and-`""` clears it; absent leaves it unchanged.
    #[serde(default)]
    pub title: Option<String>,
    /// New archived flag.
    #[serde(default)]
    pub archived: Option<bool>,
    /// New opaque metadata (a JSON string the gateway never parses).
    /// Present-and-`""` clears it; absent leaves it unchanged.
    #[serde(default)]
    pub meta: Option<String>,
}

/// Response shape for `DELETE /api/agent/sessions/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeleteResponse {
    /// `true` when the caller's own thread existed and was removed;
    /// `false` when there was nothing to delete. Not a 404 — the read is
    /// principal-scoped, so reporting whether the caller's *own* thread
    /// existed leaks nothing about anyone else.
    pub deleted: bool,
}

/// Query parameters for `GET /api/agent/sessions/search`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct SearchQuery {
    /// Full-text query. Required — an empty/whitespace `q` is a 400.
    pub q: String,
    /// Page size, default [`DEFAULT_SEARCH_LIMIT`], capped at
    /// [`MAX_SEARCH_LIMIT`]. `0`/absent → default.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Opaque cursor from a previous search page.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Whether archived threads are included in the results.
    #[serde(default)]
    pub include_archived: Option<bool>,
}

/// One search hit, mirroring the frozen `session.v1.response.search`
/// element shape.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SearchResult {
    /// The matching thread's id.
    pub session_id: String,
    /// The thread's title, or `null`.
    #[serde(default)]
    pub title: Option<String>,
    /// A snippet around the match, or `null`.
    #[serde(default)]
    pub snippet: Option<String>,
    /// Number of matches within the thread.
    pub match_count: u32,
    /// Unix epoch (seconds) of the thread's most recent message, or `null`.
    #[serde(default)]
    pub updated_at: Option<i64>,
}

/// Response shape for `GET /api/agent/sessions/search`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SearchResponse {
    /// The page of hits.
    pub results: Vec<SearchResult>,
    /// Opaque cursor for the next page, or `null` on the last page.
    #[serde(default)]
    pub next_cursor: Option<String>,
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
        ("include_archived" = Option<bool>, Query, description = "Include archived threads; default false."),
    ),
    responses(
        (status = 200, body = SessionListResponse, description = "Page of the caller's own conversation threads, ordered by session key; each carries `updated_at` for client-side recency sorting. `total` is the principal's thread count when cheaply known."),
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
    ensure_session_mgmt_supported(&state).await?;
    let correlation_id = Uuid::new_v4().to_string();
    let payload = build_list_payload(
        &correlation_id,
        query.cursor.as_deref(),
        limit,
        query.include_archived.unwrap_or(false),
    );
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

/// `GET /api/agent/sessions/{id}` — one thread's metadata.
///
/// Principal-scoped via the stamp. A thread that the caller's principal
/// does not own (or that does not exist) yields a **404**: the capsule
/// replies with a `null` `session`, and a null is mapped to `NotFound`.
/// This does NOT leak cross-principal existence — the kernel scopes the
/// capsule's read to the caller, so "null" means "not in *your* namespace",
/// never "exists for someone else".
#[utoipa::path(
    get,
    path = "/api/agent/sessions/{id}",
    tag = "agent",
    params(
        ("id" = String, Path, description = "Thread id. Non-empty, ≤256 chars, no ASCII control characters."),
    ),
    responses(
        (status = 200, body = SessionSummary, description = "The thread's metadata."),
        (status = 400, body = ErrorBody, description = "Invalid `id`."),
        (status = 401, body = ErrorBody, description = "Missing / invalid bearer."),
        (status = 404, body = ErrorBody, description = "No such thread in the caller's namespace."),
        (status = 500, body = ErrorBody, description = "Gateway not wired to a live event bus."),
        (status = 501, body = ErrorBody, description = "No loaded session capsule implements the 1.1 `get_meta` verb."),
        (status = 502, body = ErrorBody, description = "Session capsule did not reply within the timeout, or returned an unexpected shape."),
    )
)]
pub async fn get_session(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<SessionSummary>> {
    let caller = caller_from(&req)?;
    metrics::counter!("astrid_gateway_agent_sessions_get_meta_total").increment(1);

    validate_session_id(&id)?;
    // `get_meta` is a 1.1 verb, so gate it like update/delete/search: a
    // pre-1.1 capsule answers an honest 501 rather than hanging to the bus
    // timeout. (The transcript route needs no gate — `get_messages` is 1.0.)
    ensure_session_mgmt_supported(&state).await?;
    let bus = require_bus(&state)?;
    let correlation_id = Uuid::new_v4().to_string();
    let payload = serde_json::json!({
        "correlation_id": correlation_id,
        "session_id": id,
    });
    let response_topic = format!("{TOPIC_GET_META_RESPONSE_PREFIX}.{correlation_id}");

    let value = request_capsule(
        &bus,
        TOPIC_GET_META_REQUEST,
        &response_topic,
        payload,
        &correlation_id,
        &caller.principal,
        caller.device_key_id.as_deref(),
        CAPSULE_TIMEOUT,
    )
    .await?;

    let summary = parse_session_field(&value)?.ok_or(GatewayError::NotFound)?;
    Ok(Json(summary))
}

/// `PATCH /api/agent/sessions/{id}` — update a thread's metadata.
///
/// PATCH-by-presence: only the keys the client actually sent are
/// forwarded to the capsule, so an absent key leaves the field unchanged,
/// a present key sets it, and `""` clears it (the capsule owns that
/// semantics; the gateway only decides *which keys to forward*). Gated on
/// a 1.1 session capsule via [`ensure_session_mgmt_supported`]. A `null` `session`
/// in the reply (thread not in the caller's namespace) is a **404**.
#[utoipa::path(
    patch,
    path = "/api/agent/sessions/{id}",
    tag = "agent",
    request_body = SessionUpdateRequest,
    params(
        ("id" = String, Path, description = "Thread id. Non-empty, ≤256 chars, no ASCII control characters."),
    ),
    responses(
        (status = 200, body = SessionSummary, description = "The updated thread metadata."),
        (status = 400, body = ErrorBody, description = "Invalid `id` or malformed body."),
        (status = 401, body = ErrorBody, description = "Missing / invalid bearer."),
        (status = 404, body = ErrorBody, description = "No such thread in the caller's namespace."),
        (status = 500, body = ErrorBody, description = "Gateway not wired to a live event bus."),
        (status = 501, body = ErrorBody, description = "No loaded session capsule implements the 1.1 verbs."),
        (status = 502, body = ErrorBody, description = "Session capsule did not reply within the timeout, or returned an unexpected shape."),
    )
)]
pub async fn update_session(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<SessionSummary>> {
    // Clone the principal/device floor before `read_json_body` consumes
    // `req` (which `caller_from` borrows), exactly as `models.rs` does.
    let caller = caller_from(&req)?;
    let principal = caller.principal.clone();
    let device_key_id = caller.device_key_id.clone();
    metrics::counter!("astrid_gateway_agent_sessions_update_total").increment(1);

    validate_session_id(&id)?;
    ensure_session_mgmt_supported(&state).await?;
    let bus = require_bus(&state)?;

    // Read the body as a raw JSON object so we can forward ONLY the keys
    // the client actually sent. A typed struct would round-trip absent
    // fields as `null`, collapsing "unchanged" into "clear".
    let body: Value = crate::routes::principals::read_json_body(req).await?;
    let correlation_id = Uuid::new_v4().to_string();
    let payload = build_update_payload(&correlation_id, &id, &body)?;
    let response_topic = format!("{TOPIC_UPDATE_RESPONSE_PREFIX}.{correlation_id}");

    let value = request_capsule(
        &bus,
        TOPIC_UPDATE_REQUEST,
        &response_topic,
        payload,
        &correlation_id,
        &principal,
        device_key_id.as_deref(),
        CAPSULE_TIMEOUT,
    )
    .await?;

    let summary = parse_session_field(&value)?.ok_or(GatewayError::NotFound)?;
    Ok(Json(summary))
}

/// `DELETE /api/agent/sessions/{id}` — delete a thread.
///
/// Returns `{ "deleted": bool }`. Deliberately does NOT 404 on
/// `deleted:false`: the delete is principal-scoped, so reporting whether
/// the caller's *own* thread existed is safe and is the more useful
/// idempotent signal for a client. Gated on a 1.1 session capsule.
#[utoipa::path(
    delete,
    path = "/api/agent/sessions/{id}",
    tag = "agent",
    params(
        ("id" = String, Path, description = "Thread id. Non-empty, ≤256 chars, no ASCII control characters."),
    ),
    responses(
        (status = 200, body = DeleteResponse, description = "`deleted` is `true` when the caller's thread existed and was removed."),
        (status = 400, body = ErrorBody, description = "Invalid `id`."),
        (status = 401, body = ErrorBody, description = "Missing / invalid bearer."),
        (status = 500, body = ErrorBody, description = "Gateway not wired to a live event bus."),
        (status = 501, body = ErrorBody, description = "No loaded session capsule implements the 1.1 verbs."),
        (status = 502, body = ErrorBody, description = "Session capsule did not reply within the timeout, or returned an unexpected shape."),
    )
)]
pub async fn delete_session(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<DeleteResponse>> {
    let caller = caller_from(&req)?;
    metrics::counter!("astrid_gateway_agent_sessions_delete_total").increment(1);

    validate_session_id(&id)?;
    ensure_session_mgmt_supported(&state).await?;
    let bus = require_bus(&state)?;
    let correlation_id = Uuid::new_v4().to_string();
    let payload = serde_json::json!({
        "correlation_id": correlation_id,
        "session_id": id,
    });
    let response_topic = format!("{TOPIC_DELETE_RESPONSE_PREFIX}.{correlation_id}");

    let value = request_capsule(
        &bus,
        TOPIC_DELETE_REQUEST,
        &response_topic,
        payload,
        &correlation_id,
        &caller.principal,
        caller.device_key_id.as_deref(),
        CAPSULE_TIMEOUT,
    )
    .await?;

    Ok(Json(DeleteResponse {
        deleted: parse_deleted_field(&value),
    }))
}

/// `GET /api/agent/sessions/search` — full-text search the caller's threads.
///
/// Principal-scoped via the stamp. Gated on a 1.1 session capsule.
#[utoipa::path(
    get,
    path = "/api/agent/sessions/search",
    tag = "agent",
    params(
        ("q" = String, Query, description = "Full-text query (required, non-empty)."),
        ("limit" = Option<u32>, Query, description = "Page size; default 20, max 100."),
        ("cursor" = Option<String>, Query, description = "Opaque cursor from a previous page."),
        ("include_archived" = Option<bool>, Query, description = "Include archived threads; default false."),
    ),
    responses(
        (status = 200, body = SearchResponse, description = "A page of search hits."),
        (status = 400, body = ErrorBody, description = "Empty `q` or `limit` > 100."),
        (status = 401, body = ErrorBody, description = "Missing / invalid bearer."),
        (status = 500, body = ErrorBody, description = "Gateway not wired to a live event bus."),
        (status = 501, body = ErrorBody, description = "No loaded session capsule implements the 1.1 verbs."),
        (status = 502, body = ErrorBody, description = "Session capsule did not reply within the timeout, or returned an unexpected shape."),
    )
)]
pub async fn search_sessions(
    State(state): State<Arc<GatewayState>>,
    Query(query): Query<SearchQuery>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<SearchResponse>> {
    let caller = caller_from(&req)?;
    metrics::counter!("astrid_gateway_agent_sessions_search_total").increment(1);

    let q = validate_search_query(&query.q)?;
    let limit = resolve_search_limit(query.limit)?;
    ensure_session_mgmt_supported(&state).await?;
    let bus = require_bus(&state)?;
    let correlation_id = Uuid::new_v4().to_string();
    let payload = build_search_payload(
        &correlation_id,
        q,
        limit,
        query.cursor.as_deref(),
        query.include_archived.unwrap_or(false),
    );
    let response_topic = format!("{TOPIC_SEARCH_RESPONSE_PREFIX}.{correlation_id}");

    let value = request_capsule(
        &bus,
        TOPIC_SEARCH_REQUEST,
        &response_topic,
        payload,
        &correlation_id,
        &caller.principal,
        caller.device_key_id.as_deref(),
        CAPSULE_TIMEOUT,
    )
    .await?;

    let parsed = parse_search_response(value)?;
    Ok(Json(parsed))
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
/// pre-1.1 session capsule yields an immediate `NotImplemented` (501) on the
/// 1.1 thread-management routes (`list` / `get_meta` / `update` / `delete` /
/// `search`) instead of waiting out the bus timeout on a verb nobody handles.
/// It probes the `list` verb specifically as a proxy — the whole 1.1 verb set
/// ships in one capsule, so a `list` handler implies all of them.
///
/// Uses the in-process [`CapsuleTopicProbe`] — a cap-free read of the live
/// registry, the same approach `POST /api/agent/prompt` takes for its
/// fail-fast. Capsule serviceability is global daemon health, not
/// per-principal authorization, so this must NOT route through the
/// capability-gated `GetCapsuleMetadata` (which would 403 an ordinary
/// caller and leak the capsule inventory). When the probe is absent (a
/// standalone gateway with no kernel), the gate is skipped and the bus
/// round-trip governs the outcome.
async fn ensure_session_mgmt_supported(state: &GatewayState) -> GatewayResult<()> {
    if let Some(probe) = &state.topic_probe
        && !probe.is_subscribed(TOPIC_LIST_REQUEST).await
    {
        return Err(GatewayError::NotImplemented(
            "no loaded session capsule implements the 1.1 conversation-management \
             verbs (list / get_meta / update / delete / search)"
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
fn build_list_payload(
    correlation_id: &str,
    cursor: Option<&str>,
    limit: u32,
    include_archived: bool,
) -> Value {
    serde_json::json!({
        "correlation_id": correlation_id,
        "cursor": cursor,
        "limit": limit,
        "include_archived": include_archived,
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

/// Validate + normalise a `search` query string. An empty/whitespace
/// query is a client error; otherwise the trimmed query is returned.
fn validate_search_query(q: &str) -> GatewayResult<&str> {
    let trimmed = q.trim();
    if trimmed.is_empty() {
        return Err(GatewayError::BadRequest(
            "search query `q` must not be empty".into(),
        ));
    }
    Ok(trimmed)
}

/// Resolve the effective search page size: reject over [`MAX_SEARCH_LIMIT`];
/// treat `0`/absent as [`DEFAULT_SEARCH_LIMIT`].
fn resolve_search_limit(limit: Option<u32>) -> GatewayResult<u32> {
    match limit {
        Some(l) if l > MAX_SEARCH_LIMIT => Err(GatewayError::BadRequest(format!(
            "limit {l} exceeds the search cap of {MAX_SEARCH_LIMIT}"
        ))),
        Some(0) | None => Ok(DEFAULT_SEARCH_LIMIT),
        Some(l) => Ok(l),
    }
}

/// Build the `session.v1.request.update` payload, forwarding ONLY the keys
/// the client actually sent so the capsule's PATCH-by-presence works.
///
/// The raw body MUST be a JSON object (a non-object body is a 400). We
/// walk the three recognised keys (`title`, `archived`, `meta`) and copy
/// each into the outbound payload **iff it is present in the body** —
/// preserving an explicit `""` (clear) and an explicit `null` distinct
/// from absence. Unknown keys are ignored (the gateway forwards a clean,
/// minimal patch, never the client's whole object — so a client can't
/// smuggle e.g. `session_id` or another principal's field into the
/// capsule's update). `correlation_id` and `session_id` are always set by
/// the gateway, never taken from the body.
fn build_update_payload(
    correlation_id: &str,
    session_id: &str,
    body: &Value,
) -> GatewayResult<Value> {
    let obj = body
        .as_object()
        .ok_or_else(|| GatewayError::BadRequest("update body must be a JSON object".into()))?;
    let mut out = serde_json::Map::new();
    out.insert(
        "correlation_id".into(),
        Value::String(correlation_id.into()),
    );
    out.insert("session_id".into(), Value::String(session_id.into()));
    for key in ["title", "archived", "meta"] {
        if let Some(v) = obj.get(key) {
            out.insert(key.into(), v.clone());
        }
    }
    Ok(Value::Object(out))
}

/// Build the `session.v1.request.search` payload to the frozen contract.
fn build_search_payload(
    correlation_id: &str,
    query: &str,
    limit: u32,
    cursor: Option<&str>,
    include_archived: bool,
) -> Value {
    serde_json::json!({
        "correlation_id": correlation_id,
        "query": query,
        "limit": limit,
        "cursor": cursor,
        "include_archived": include_archived,
    })
}

/// Extract and type-check the `session` field from a `get_meta` / `update`
/// reply. The frozen contract is `{ correlation_id, session: SUMMARY|null }`:
///
/// * `null` (or absent) → `Ok(None)` — the handler maps this to a 404.
/// * a present object → deserialize into [`SessionSummary`]; a shape the
///   capsule never agreed to is a `Kernel`-class upstream error.
fn parse_session_field(value: &Value) -> GatewayResult<Option<SessionSummary>> {
    match value.get("session") {
        None | Some(Value::Null) => Ok(None),
        Some(session) => serde_json::from_value(session.clone())
            .map(Some)
            .map_err(|e| {
                GatewayError::Kernel(format!(
                    "session capsule returned an unexpected session shape: {e}"
                ))
            }),
    }
}

/// Extract the `deleted` boolean from a `delete` reply. A missing /
/// non-boolean field is treated as `false` — the delete is principal-scoped
/// and idempotent, so the worst case is reporting "nothing deleted", which
/// is exactly the no-op outcome and never a security leak.
fn parse_deleted_field(value: &Value) -> bool {
    value
        .get("deleted")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Deserialize a `session.v1.response.search` body into the typed response.
fn parse_search_response(value: Value) -> GatewayResult<SearchResponse> {
    serde_json::from_value(value).map_err(|e| {
        GatewayError::Kernel(format!(
            "session capsule returned an unexpected search shape: {e}"
        ))
    })
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
    // Scope the reply route to the caller principal so a foreign principal's
    // response on the same topic never enters this receiver's queue.
    let principal = principal.to_string();
    let mut receiver = bus.subscribe_topic_routed_scoped(
        Uuid::new_v4(),
        response_topic,
        "gateway",
        "gateway::sessions",
        Some(Some(principal.clone())),
    );

    let mut msg = IpcMessage::new(
        Topic::from_raw(request_topic),
        IpcPayload::RawJson(payload),
        Uuid::new_v4(),
    )
    .with_principal(principal)
    .with_origin(MessageOrigin::RemoteGateway);
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
            return Err(capsule_timeout(response_topic, timeout));
        }
        let event = receiver
            .recv(Some(remaining))
            .await
            .ok_or_else(|| capsule_timeout(response_topic, timeout))?;

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
fn capsule_timeout(response_topic: &str, timeout: Duration) -> GatewayError {
    GatewayError::Kernel(format!(
        "session capsule did not reply within {}s on {response_topic}",
        timeout.as_secs()
    ))
}

#[cfg(test)]
#[path = "sessions_tests.rs"]
mod tests;
