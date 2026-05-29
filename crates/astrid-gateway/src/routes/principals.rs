//! `/api/sys/principals` + `/api/sys/capabilities`.
//!
//! Full CRUD over the agent principal table. Reads
//! [`AdminRequestKind::AgentList`]; mutations map 1:1 to the
//! corresponding `Agent*` variants. The kernel's existing
//! capability gates apply — admins (with `*` or `agent:*`) can
//! manage everyone; principals with `self:agent:list` can read
//! their own row only. Group / quota / cap routes live in their
//! own modules.

use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody, AgentSummary};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::CallerContext;
use crate::error::{ErrorBody, GatewayError, GatewayResult};
use crate::state::GatewayState;

/// `OpenAPI` schema mirror of [`astrid_core::kernel_api::AgentSummary`].
///
/// `AgentSummary` lives in `astrid-core`, which deliberately doesn't
/// depend on utoipa (see `openapi.rs`). This struct is never
/// constructed — it exists only so the `value_type` on
/// [`PrincipalListResponse::principals`] resolves to a typed schema
/// instead of an opaque JSON value. Keep it field-for-field with the
/// serialized shape of `AgentSummary`.
#[derive(ToSchema)]
pub struct AgentSummaryView {
    /// Principal identifier (e.g. `"agent-alice"`).
    pub principal: String,
    /// Whether the principal is currently enabled (master switch).
    pub enabled: bool,
    /// Group memberships as written to `profile.toml`.
    pub groups: Vec<String>,
    /// Direct capability grants beyond group inheritance.
    pub grants: Vec<String>,
    /// Explicit revokes (highest-precedence deny).
    pub revokes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PrincipalListResponse {
    #[schema(value_type = Vec<AgentSummaryView>)]
    pub principals: Vec<AgentSummary>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreatePrincipalRequest {
    /// The principal id (validated server-side as a `PrincipalId`).
    pub name: String,
    /// Initial group memberships; empty defaults kernel-side to
    /// `["agent"]`.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Capability grants applied beyond group inheritance. Subject
    /// to the same `unsafe_admin` rail that `astrid caps grant`
    /// enforces — `*` patterns require a separate `unsafe_admin`
    /// flag (not on create, mint via `POST /api/sys/principals/{id}/caps`
    /// with `unsafe_admin = true`).
    #[serde(default)]
    pub grants: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ModifyPrincipalRequest {
    /// Groups to add. Idempotent — already-present groups are no-ops.
    #[serde(default)]
    pub add_groups: Vec<String>,
    /// Groups to remove. Idempotent — absent groups are no-ops.
    #[serde(default)]
    pub remove_groups: Vec<String>,
}

/// `GET /api/sys/principals` — list every agent principal visible
/// to the caller. Operators with `agent:list` see everyone; an
/// `agent` group member with `self:agent:list` sees only themselves
/// (the kernel filters server-side).
#[utoipa::path(
    get,
    path = "/api/sys/principals",
    tag = "principals",
    responses(
        (status = 200, body = PrincipalListResponse, description = "Visible agent principals — kernel filters by authority scope."),
        (status = 401, body = ErrorBody, description = "Missing / invalid bearer."),
        (status = 403, body = ErrorBody, description = "Caller lacks `agent:list` / `self:agent:list`."),
    )
)]
pub async fn list_principals(
    State(state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<PrincipalListResponse>> {
    let caller = caller_from(&req)?;
    let client = state.admin_client(caller.principal.clone())?;
    let resp = client
        .request(AdminRequestKind::AgentList)
        .await
        .map_err(daemon_internal)?;
    match resp {
        AdminResponseBody::AgentList(list) => Ok(Json(PrincipalListResponse { principals: list })),
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(unexpected(other)),
    }
}

/// `GET /api/sys/principals/{id}` — single-principal detail.
/// Implemented client-side by filtering the `AgentList` response —
/// the kernel doesn't yet expose a per-principal read, but the
/// `AgentList` result is already filtered by the caller's authority
/// scope server-side, so passing through is correct.
#[utoipa::path(
    get,
    path = "/api/sys/principals/{id}",
    tag = "principals",
    params(("id" = String, Path, description = "Target principal id")),
    responses(
        (status = 200, description = "Agent summary — `AgentSummary` JSON shape.", content_type = "application/json"),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
        (status = 404, body = ErrorBody, description = "Principal not visible to caller or does not exist."),
    )
)]
pub async fn get_principal(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<AgentSummary>> {
    let target = PrincipalId::new(&id)
        .map_err(|e| GatewayError::BadRequest(format!("invalid principal id: {e}")))?;
    let caller = caller_from(&req)?;
    let client = state.admin_client(caller.principal.clone())?;
    let resp = client
        .request(AdminRequestKind::AgentList)
        .await
        .map_err(daemon_internal)?;
    match resp {
        AdminResponseBody::AgentList(list) => list
            .into_iter()
            .find(|s| s.principal == target)
            .map(Json)
            .ok_or(GatewayError::NotFound),
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(unexpected(other)),
    }
}

/// `POST /api/sys/principals` — provision a new agent. Maps to
/// [`AdminRequestKind::AgentCreate`].
#[utoipa::path(
    post,
    path = "/api/sys/principals",
    tag = "principals",
    request_body = CreatePrincipalRequest,
    responses(
        (status = 200, description = "Agent created; response carries the kernel's confirmation payload.", content_type = "application/json"),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `agent:create`."),
    )
)]
pub async fn create_principal(
    State(state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let caller = caller_from(&req)?.clone();
    let body: CreatePrincipalRequest = read_json_body(req).await?;
    let client = state.admin_client(caller.principal)?;
    let resp = client
        .request(AdminRequestKind::AgentCreate {
            name: body.name,
            groups: body.groups,
            grants: body.grants,
        })
        .await
        .map_err(daemon_internal)?;
    match resp {
        AdminResponseBody::Success(v) => Ok(Json(v)),
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(unexpected(other)),
    }
}

/// `DELETE /api/sys/principals/{id}`.
#[utoipa::path(
    delete,
    path = "/api/sys/principals/{id}",
    tag = "principals",
    params(("id" = String, Path, description = "Target principal id")),
    responses(
        (status = 204, description = "Principal deleted."),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `agent:delete`."),
        (status = 404, body = ErrorBody),
    )
)]
pub async fn delete_principal(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<StatusCode> {
    let principal = PrincipalId::new(&id)
        .map_err(|e| GatewayError::BadRequest(format!("invalid principal id: {e}")))?;
    let caller = caller_from(&req)?.clone();
    let client = state.admin_client(caller.principal)?;
    let resp = client
        .request(AdminRequestKind::AgentDelete { principal })
        .await
        .map_err(daemon_internal)?;
    match resp {
        AdminResponseBody::Success(_) => Ok(StatusCode::NO_CONTENT),
        AdminResponseBody::Error(msg) if msg.contains("does not exist") => {
            Err(GatewayError::NotFound)
        },
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(unexpected(other)),
    }
}

/// `POST /api/sys/principals/{id}/enable`.
#[utoipa::path(
    post,
    path = "/api/sys/principals/{id}/enable",
    tag = "principals",
    params(("id" = String, Path)),
    responses(
        (status = 200, description = "Enable confirmed.", content_type = "application/json"),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `agent:enable`."),
    )
)]
pub async fn enable_principal(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    set_enabled(state, id, true, req).await
}

/// `POST /api/sys/principals/{id}/disable`.
#[utoipa::path(
    post,
    path = "/api/sys/principals/{id}/disable",
    tag = "principals",
    params(("id" = String, Path)),
    responses(
        (status = 200, description = "Disable confirmed.", content_type = "application/json"),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `agent:disable`."),
    )
)]
pub async fn disable_principal(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    set_enabled(state, id, false, req).await
}

async fn set_enabled(
    state: Arc<GatewayState>,
    id: String,
    enabled: bool,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let principal = PrincipalId::new(&id)
        .map_err(|e| GatewayError::BadRequest(format!("invalid principal id: {e}")))?;
    let caller = caller_from(&req)?.clone();
    let client = state.admin_client(caller.principal)?;
    let kind = if enabled {
        AdminRequestKind::AgentEnable { principal }
    } else {
        AdminRequestKind::AgentDisable { principal }
    };
    let resp = client.request(kind).await.map_err(daemon_internal)?;
    match resp {
        AdminResponseBody::Success(v) => Ok(Json(v)),
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(unexpected(other)),
    }
}

/// `PATCH /api/sys/principals/{id}` — update group memberships.
#[utoipa::path(
    patch,
    path = "/api/sys/principals/{id}",
    tag = "principals",
    params(("id" = String, Path)),
    request_body = ModifyPrincipalRequest,
    responses(
        (status = 200, description = "Group memberships updated.", content_type = "application/json"),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `agent:modify`."),
    )
)]
pub async fn modify_principal(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let principal = PrincipalId::new(&id)
        .map_err(|e| GatewayError::BadRequest(format!("invalid principal id: {e}")))?;
    let caller = caller_from(&req)?.clone();
    let body: ModifyPrincipalRequest = read_json_body(req).await?;
    let client = state.admin_client(caller.principal)?;
    let resp = client
        .request(AdminRequestKind::AgentModify {
            principal,
            add_groups: body.add_groups,
            remove_groups: body.remove_groups,
        })
        .await
        .map_err(daemon_internal)?;
    match resp {
        AdminResponseBody::Success(v) => Ok(Json(v)),
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(unexpected(other)),
    }
}

// ── /api/sys/capabilities ────────────────────────────────────────

/// Structured response for `GET /api/sys/capabilities`. Sourced
/// from `astrid_core::capability_grammar::CAPABILITY_CATALOG` — the
/// single canonical declaration. Dashboards bucket by `category`,
/// render `label` on the toggle, surface `description` as the
/// tooltip, dim or hide `self`-scoped entries depending on UX, and
/// require confirmation prompts on `extreme` / `elevated` danger.
///
/// Response shape (verbatim from the catalog):
///
/// ```json
/// {
///   "capabilities": [
///     {
///       "id": "agent:create",
///       "label": "Create agents",
///       "description": "Provision a new agent principal. …",
///       "category": "agent",
///       "scope": "global",
///       "danger": "normal"
///     },
///     …
///   ],
///   "categories": ["agent", "caps", "quota", "group", "invite", "capsule", "system", "approval"]
/// }
/// ```
///
/// `categories` is the stable ordering dashboards should use for
/// section rendering (matches the catalog's natural grouping).
/// `OpenAPI` schema mirror of
/// [`astrid_core::capability_grammar::CapabilityInfo`]. Never
/// constructed; resolves the `value_type` on
/// [`CapabilityCatalogResponse::capabilities`] to a typed schema.
/// The `category`/`scope`/`danger` enums serialize as lowercase
/// (`snake_case`) strings — modelled as `String` here rather than
/// re-deriving the kernel enums across the no-utoipa boundary.
#[derive(ToSchema)]
pub struct CapabilityInfoView {
    /// Capability identifier as it appears in policy (e.g.
    /// `"system:shutdown"`). Stable wire format.
    pub id: String,
    /// Short human-readable label for the dashboard toggle.
    pub label: String,
    /// One-sentence operator-facing description (tooltip / hint).
    pub description: String,
    /// Family bucket for UI grouping: one of `agent`, `approval`,
    /// `caps`, `capsule`, `group`, `invite`, `quota`, `system`.
    pub category: String,
    /// Authority scope: `global` or the self-scoped variant.
    pub scope: String,
    /// Risk tier for confirmation prompts: one of `safe`, `normal`,
    /// `elevated`, `extreme`.
    pub danger: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CapabilityCatalogResponse {
    /// Per-capability metadata — see `astrid_core::capability_grammar`.
    #[schema(value_type = Vec<CapabilityInfoView>)]
    pub capabilities: &'static [astrid_core::capability_grammar::CapabilityInfo],
    /// Stable render order. Dashboards group toggles into these
    /// sections in the listed sequence.
    #[schema(value_type = Vec<String>, example = json!(["agent", "caps", "quota", "group", "invite", "capsule", "system", "approval"]))]
    pub categories: &'static [&'static str],
}

/// Canonical category render order. Mirrors the catalog's natural
/// grouping; dashboards consume this for stable section ordering.
const CATEGORY_RENDER_ORDER: &[&str] = &[
    "agent", "caps", "quota", "group", "invite", "capsule", "system", "approval",
];

#[utoipa::path(
    get,
    path = "/api/sys/capabilities",
    tag = "principals",
    responses(
        (status = 200, body = CapabilityCatalogResponse, description = "Static capability catalog — what dashboards render as the permissions panel."),
        (status = 401, body = ErrorBody),
    )
)]
pub async fn list_capabilities(
    _req: Request<axum::body::Body>,
) -> GatewayResult<Json<CapabilityCatalogResponse>> {
    Ok(Json(CapabilityCatalogResponse {
        capabilities: astrid_core::capability_grammar::CAPABILITY_CATALOG,
        categories: CATEGORY_RENDER_ORDER,
    }))
}

// ── Helpers ──────────────────────────────────────────────────────

pub(crate) fn caller_from(req: &Request<axum::body::Body>) -> GatewayResult<&CallerContext> {
    req.extensions()
        .get::<CallerContext>()
        .ok_or(GatewayError::Unauthorized)
}

// Both helpers consume their argument logically (wrap and discard);
// clippy::needless_pass_by_value fires because they only `Display` /
// `Debug` the value. Taking by value keeps `map_err(daemon_internal)`
// usable as a one-line closure replacement throughout the routes —
// the by-reference shape would force every call site to write
// `map_err(|e| daemon_internal(&e))`.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn daemon_internal(e: anyhow::Error) -> GatewayError {
    GatewayError::Internal(anyhow::anyhow!("daemon request: {e}"))
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn unexpected(other: AdminResponseBody) -> GatewayError {
    GatewayError::Internal(anyhow::anyhow!(
        "unexpected admin response shape: {other:?}"
    ))
}

/// Read the request body as JSON, capping at 64 `KiB` to bound any
/// pathological inbound on the otherwise-unauthenticated edge.
pub(crate) async fn read_json_body<T: serde::de::DeserializeOwned>(
    req: Request<axum::body::Body>,
) -> GatewayResult<T> {
    let bytes = axum::body::to_bytes(req.into_body(), 64 * 1024)
        .await
        .map_err(|e| GatewayError::BadRequest(format!("body read: {e}")))?;
    Ok(serde_json::from_slice(&bytes)?)
}
