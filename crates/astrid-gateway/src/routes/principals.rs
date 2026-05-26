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
use astrid_uplink::AdminClient;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use serde::{Deserialize, Serialize};

use crate::auth::CallerContext;
use crate::error::{GatewayError, GatewayResult};
use crate::state::GatewayState;

#[derive(Debug, Clone, Serialize)]
pub struct PrincipalListResponse {
    pub principals: Vec<AgentSummary>,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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
pub async fn list_principals(
    State(_state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<PrincipalListResponse>> {
    let caller = caller_from(&req)?;
    let mut client = AdminClient::connect(caller.principal.clone())
        .await
        .map_err(daemon_internal)?;
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
pub async fn get_principal(
    State(_state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<AgentSummary>> {
    let target = PrincipalId::new(&id)
        .map_err(|e| GatewayError::BadRequest(format!("invalid principal id: {e}")))?;
    let caller = caller_from(&req)?;
    let mut client = AdminClient::connect(caller.principal.clone())
        .await
        .map_err(daemon_internal)?;
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
pub async fn create_principal(
    State(_state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let caller = caller_from(&req)?.clone();
    let body: CreatePrincipalRequest = read_json_body(req).await?;
    let mut client = AdminClient::connect(caller.principal)
        .await
        .map_err(daemon_internal)?;
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
pub async fn delete_principal(
    State(_state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<StatusCode> {
    let principal = PrincipalId::new(&id)
        .map_err(|e| GatewayError::BadRequest(format!("invalid principal id: {e}")))?;
    let caller = caller_from(&req)?.clone();
    let mut client = AdminClient::connect(caller.principal)
        .await
        .map_err(daemon_internal)?;
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
pub async fn enable_principal(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    set_enabled(state, id, true, req).await
}

/// `POST /api/sys/principals/{id}/disable`.
pub async fn disable_principal(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    set_enabled(state, id, false, req).await
}

async fn set_enabled(
    _state: Arc<GatewayState>,
    id: String,
    enabled: bool,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let principal = PrincipalId::new(&id)
        .map_err(|e| GatewayError::BadRequest(format!("invalid principal id: {e}")))?;
    let caller = caller_from(&req)?.clone();
    let mut client = AdminClient::connect(caller.principal)
        .await
        .map_err(daemon_internal)?;
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
pub async fn modify_principal(
    State(_state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let principal = PrincipalId::new(&id)
        .map_err(|e| GatewayError::BadRequest(format!("invalid principal id: {e}")))?;
    let caller = caller_from(&req)?.clone();
    let body: ModifyPrincipalRequest = read_json_body(req).await?;
    let mut client = AdminClient::connect(caller.principal)
        .await
        .map_err(daemon_internal)?;
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

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityCatalog {
    /// Every capability identifier the kernel currently recognises.
    /// Sourced from `astrid_core::capability_grammar::KNOWN_CAPABILITIES`
    /// — the single canonical declaration shared with the kernel's
    /// `required_capability` tables. Avoids duplication / drift.
    pub capabilities: &'static [&'static str],
}

pub async fn list_capabilities(
    _req: Request<axum::body::Body>,
) -> GatewayResult<Json<CapabilityCatalog>> {
    Ok(Json(CapabilityCatalog {
        capabilities: astrid_core::capability_grammar::KNOWN_CAPABILITIES,
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
