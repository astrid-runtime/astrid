//! `/api/sys/principals/{id}/quotas` — per-principal resource ceilings.
//!
//! Reflects [`astrid_core::profile::Quotas`] over HTTP. Gated by
//! `quota:get` / `quota:set` (operator) or `self:quota:get` /
//! `self:quota:set` when the target principal == caller (kernel
//! enforces the scope). Admins set these to bound a user's RAM /
//! CPU-time / IPC budget before handing over the bearer.

use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody};
use astrid_core::profile::Quotas;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::Request;
use serde::Deserialize;
use utoipa::ToSchema;

use crate::error::{ErrorBody, GatewayError, GatewayResult};
use crate::routes::principals::{caller_from, daemon_internal, read_json_body, unexpected};
use crate::state::GatewayState;

/// `OpenAPI` schema mirror for the [`QuotaRequest`] body — the write
/// shape of [`astrid_core::profile::Quotas`]. Never constructed;
/// resolves the `value_type` on [`QuotaRequest::quotas`] to a typed
/// schema.
///
/// Every field is `Option` because each carries a server-side default:
/// on a `set` request any field may be omitted and keeps its default,
/// so none must be marked required. Field names + inner types track
/// `Quotas` exactly. (The `get` response always serializes every field
/// populated, but that endpoint isn't typed with a body schema, so a
/// single write-shaped mirror is sufficient here.)
#[derive(ToSchema)]
pub struct QuotasView {
    /// Maximum resident memory in bytes (> 0).
    pub max_memory_bytes: Option<u64>,
    /// Maximum wall-clock time for a single invocation, in seconds.
    pub max_timeout_secs: Option<u64>,
    /// Maximum IPC throughput in bytes/sec (> 0).
    pub max_ipc_throughput_bytes: Option<u64>,
    /// Maximum concurrent background processes.
    pub max_background_processes: Option<u32>,
    /// Maximum persistent storage in bytes (> 0).
    pub max_storage_bytes: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct QuotaRequest {
    /// Resource ceilings (`Quotas` from `astrid_core::profile`). All
    /// fields optional — omitted ones fall back to server defaults.
    #[schema(value_type = QuotasView)]
    pub quotas: Quotas,
}

#[utoipa::path(
    get,
    path = "/api/sys/principals/{id}/quotas",
    tag = "quotas",
    params(("id" = String, Path, description = "Target principal id")),
    responses(
        (status = 200, description = "`Quotas` JSON shape.", content_type = "application/json"),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `quota:get` / `self:quota:get`."),
        (status = 404, body = ErrorBody),
    )
)]
pub async fn get_quotas(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<Quotas>> {
    let principal = PrincipalId::new(&id)
        .map_err(|e| GatewayError::BadRequest(format!("invalid principal id: {e}")))?;
    let caller = caller_from(&req)?.clone();
    let client = state.admin_client(caller.principal)?;
    let resp = client
        .request(AdminRequestKind::QuotaGet { principal })
        .await
        .map_err(daemon_internal)?;
    match resp {
        AdminResponseBody::Quotas(q) => Ok(Json(q)),
        AdminResponseBody::Error(msg) if msg.contains("does not exist") => {
            Err(GatewayError::NotFound)
        },
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(unexpected(other)),
    }
}

#[utoipa::path(
    put,
    path = "/api/sys/principals/{id}/quotas",
    tag = "quotas",
    params(("id" = String, Path, description = "Target principal id")),
    request_body = QuotaRequest,
    responses(
        (status = 200, description = "Quotas updated.", content_type = "application/json"),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `quota:set` / `self:quota:set`."),
        (status = 404, body = ErrorBody),
    )
)]
pub async fn set_quotas(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let principal = PrincipalId::new(&id)
        .map_err(|e| GatewayError::BadRequest(format!("invalid principal id: {e}")))?;
    let caller = caller_from(&req)?.clone();
    let body: QuotaRequest = read_json_body(req).await?;
    let client = state.admin_client(caller.principal)?;
    let resp = client
        .request(AdminRequestKind::QuotaSet {
            principal,
            quotas: body.quotas,
        })
        .await
        .map_err(daemon_internal)?;
    match resp {
        AdminResponseBody::Success(v) => Ok(Json(v)),
        AdminResponseBody::Error(msg) if msg.contains("does not exist") => {
            Err(GatewayError::NotFound)
        },
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(unexpected(other)),
    }
}
