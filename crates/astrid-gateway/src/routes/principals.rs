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
    /// Capsule grants to add. Idempotent — already-granted capsules are
    /// no-ops. Grants the principal access to invoke the named capsule's
    /// user-invocable tool surface (kernel-gated at dispatch, #992).
    #[serde(default)]
    pub add_capsules: Vec<String>,
    /// Capsule grants to remove. Idempotent — absent grants are no-ops.
    #[serde(default)]
    pub remove_capsules: Vec<String>,
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
    let client = state.admin_client_for(caller)?;
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
    let client = state.admin_client_for(caller)?;
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
    let client = state.admin_client_for(&caller)?;
    let resp = client
        .request(AdminRequestKind::AgentCreate {
            name: body.name,
            groups: body.groups,
            grants: body.grants,
            // Non-inheriting by default — the API does not expose the
            // opt-in inheritance source yet. Exposing an API-level
            // `inherit_from` / `clone_from` is a follow-up.
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
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
    let caller = caller_from(&req)?;
    let client = state.admin_client_for(caller)?;
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
    let caller = caller_from(&req)?;
    let client = state.admin_client_for(caller)?;
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
    let client = state.admin_client_for(&caller)?;
    let resp = client
        .request(AdminRequestKind::AgentModify {
            principal,
            add_groups: body.add_groups,
            remove_groups: body.remove_groups,
            add_capsules: body.add_capsules,
            remove_capsules: body.remove_capsules,
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

// ── Device management ────────────────────────────────────────────

/// `OpenAPI` schema mirror of [`astrid_core::kernel_api::DeviceKeyInfo`].
///
/// Like [`AgentSummaryView`], this is never constructed — it exists so the
/// `value_type` on [`DeviceListResponse::devices`] resolves to a typed schema
/// instead of opaque JSON. Keep it field-for-field with the serialized shape
/// of `DeviceKeyInfo`. The raw pubkey is deliberately absent — only the
/// fingerprint-level `key_id` is ever surfaced.
#[derive(ToSchema)]
pub struct DeviceKeyInfoView {
    /// Deterministic per-device fingerprint handle.
    pub key_id: String,
    /// Operator/user-facing label captured at pairing time, if any.
    pub label: Option<String>,
    /// Capability attenuation scope the device authenticates under. Serialized
    /// as the `DeviceScope` shape: `{ "type": "full" }` or
    /// `{ "type": "scoped", "allow": [...], "deny": [...] }`.
    #[schema(value_type = Object)]
    pub scope: serde_json::Value,
    /// Unix epoch seconds when the device was paired (`0` for migrated
    /// legacy keys).
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DeviceListResponse {
    /// Paired devices on the principal, as fingerprint-level summaries.
    #[schema(value_type = Vec<DeviceKeyInfoView>)]
    pub devices: Vec<astrid_core::kernel_api::DeviceKeyInfo>,
}

/// `GET /api/sys/principals/{id}/devices` — list a principal's paired
/// devices. Maps to [`AdminRequestKind::PairDeviceList`]; the kernel's
/// self-vs-global authority scope applies (a principal lists its own devices
/// with `self:auth:pair`; managing another's needs the global `auth:pair`).
#[utoipa::path(
    get,
    path = "/api/sys/principals/{id}/devices",
    tag = "principals",
    params(("id" = String, Path, description = "Target principal id")),
    responses(
        (status = 200, body = DeviceListResponse, description = "Paired devices (key_id + scope + label + created_at; never the raw pubkey)."),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `self:auth:pair` / `auth:pair`."),
        (status = 404, body = ErrorBody, description = "Principal does not exist."),
    )
)]
pub async fn list_principal_devices(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<DeviceListResponse>> {
    let principal = PrincipalId::new(&id)
        .map_err(|e| GatewayError::BadRequest(format!("invalid principal id: {e}")))?;
    let caller = caller_from(&req)?;
    let client = state.admin_client_for(caller)?;
    let resp = client
        .request(AdminRequestKind::PairDeviceList { principal })
        .await
        .map_err(daemon_internal)?;
    match resp {
        AdminResponseBody::PairDeviceListed(devices) => Ok(Json(DeviceListResponse { devices })),
        AdminResponseBody::Error(msg) if msg.contains("does not exist") => {
            Err(GatewayError::NotFound)
        },
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(unexpected(other)),
    }
}

/// `DELETE /api/sys/principals/{id}/devices/{key_id}` — revoke one paired
/// device. Maps to [`AdminRequestKind::PairDeviceRevoke`]. A revoked device
/// fails closed at the kernel cap-gate immediately (its key is gone from
/// `public_keys`) and the gateway evicts any live bearer scoped to its
/// `key_id` via the revoked-key-id watcher.
#[utoipa::path(
    delete,
    path = "/api/sys/principals/{id}/devices/{key_id}",
    tag = "principals",
    params(
        ("id" = String, Path, description = "Target principal id"),
        ("key_id" = String, Path, description = "Device key_id to revoke"),
    ),
    responses(
        (status = 204, description = "Device revoked."),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `self:auth:pair` / `auth:pair`."),
        (status = 404, body = ErrorBody, description = "No device with that key_id (or principal does not exist)."),
    )
)]
pub async fn delete_principal_device(
    State(state): State<Arc<GatewayState>>,
    Path((id, key_id)): Path<(String, String)>,
    req: Request<axum::body::Body>,
) -> GatewayResult<StatusCode> {
    let principal = PrincipalId::new(&id)
        .map_err(|e| GatewayError::BadRequest(format!("invalid principal id: {e}")))?;
    let caller = caller_from(&req)?;
    let client = state.admin_client_for(caller)?;
    let resp = client
        .request(AdminRequestKind::PairDeviceRevoke { principal, key_id })
        .await
        .map_err(daemon_internal)?;
    match resp {
        AdminResponseBody::PairDeviceRevoked { .. } => Ok(StatusCode::NO_CONTENT),
        // The kernel returns a bad-input error for an unknown key_id or a
        // missing principal — both surface to the client as 404.
        AdminResponseBody::Error(msg)
            if msg.contains("no paired device") || msg.contains("does not exist") =>
        {
            Err(GatewayError::NotFound)
        },
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(unexpected(other)),
    }
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
// The admin-client request path still surfaces `anyhow::Error` (it is not part
// of this change's typed-error migration — a follow-up); every failure here maps
// to 500. The bus-direct kernel-request path uses the typed
// [`daemon_kernel_error`](crate::routes::daemon_kernel_error) instead, which can
// distinguish a 504 timeout.
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
