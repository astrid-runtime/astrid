//! `/api/sys/principals/{id}/quotas` — per-principal resource ceilings,
//! and `/api/sys/principals/{id}/usage` — those ceilings paired with live
//! consumption.
//!
//! Reflects [`astrid_core::profile::Quotas`] / [`ResourceUsage`] over HTTP.
//! Gated by `quota:get` / `quota:set` (operator) or `self:quota:get` /
//! `self:quota:set` when the target principal == caller (kernel enforces the
//! scope). Admins set these to bound a user's RAM / CPU-time / IPC budget
//! before handing over the bearer; the usage read reports consumption against
//! them.

use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody, ResourceUsage};
use astrid_core::profile::Quotas;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::Request;
use serde::{Deserialize, Serialize};
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
    /// Maximum CPU rate in wasmtime fuel units per second (> 0).
    pub max_cpu_fuel_per_sec: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct QuotaRequest {
    /// Resource ceilings (`Quotas` from `astrid_core::profile`). All
    /// fields optional — omitted ones fall back to server defaults.
    #[schema(value_type = QuotasView)]
    pub quotas: Quotas,
}

/// `OpenAPI` schema + serialized response for the `usage` read — mirrors
/// [`astrid_core::kernel_api::ResourceUsage`] field-for-field. Core's
/// `ResourceUsage` deliberately carries no `ToSchema`; the gateway owns its
/// view types. `principal` renders as the principal string (its `PrincipalId`
/// serialization) so generated clients see a plain id.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ResourceUsageView {
    /// Principal this usage report describes.
    pub principal: String,
    /// Cumulative interceptor CPU burned across all capsules, in wasmtime fuel
    /// units (exact deterministic instruction count, monotonic for the process
    /// lifetime).
    pub cpu_fuel_consumed_total: u64,
    /// Configured CPU rate ceiling (`max_cpu_fuel_per_sec`), always `> 0`
    /// (validation rejects `0` — there is no "unlimited" sentinel; unbounded CPU
    /// is a capability, surfaced by `exempt`).
    pub cpu_fuel_per_sec_limit: u64,
    /// Whether the principal is exempt from resource budgets. When `true` the
    /// limit fields are advisory, never enforced.
    pub exempt: bool,
    /// Per-capsule-instance memory ceiling (`max_memory_bytes`). A per-Store
    /// cap, not a cross-capsule total.
    pub memory_bytes_limit_per_instance: u64,
    /// Current cross-capsule resident memory total, or `null` while a
    /// per-principal aggregate RAM budget is unimplemented.
    pub memory_bytes_current_total: Option<u64>,
}

impl From<ResourceUsage> for ResourceUsageView {
    fn from(u: ResourceUsage) -> Self {
        Self {
            principal: u.principal.as_str().to_owned(),
            cpu_fuel_consumed_total: u.cpu_fuel_consumed_total,
            cpu_fuel_per_sec_limit: u.cpu_fuel_per_sec_limit,
            exempt: u.exempt,
            memory_bytes_limit_per_instance: u.memory_bytes_limit_per_instance,
            memory_bytes_current_total: u.memory_bytes_current_total,
        }
    }
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
    get,
    path = "/api/sys/principals/{id}/usage",
    tag = "quotas",
    params(("id" = String, Path, description = "Target principal id")),
    responses(
        (
            status = 200,
            body = ResourceUsageView,
            description = "Per-principal resource usage vs configured budget.",
        ),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `quota:get` / `self:quota:get`."),
        (status = 404, body = ErrorBody),
    )
)]
pub async fn get_usage(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<ResourceUsageView>> {
    let principal = PrincipalId::new(&id)
        .map_err(|e| GatewayError::BadRequest(format!("invalid principal id: {e}")))?;
    let caller = caller_from(&req)?.clone();
    let client = state.admin_client(caller.principal)?;
    let resp = client
        .request(AdminRequestKind::UsageGet { principal })
        .await
        .map_err(daemon_internal)?;
    match resp {
        AdminResponseBody::Usage(u) => Ok(Json(ResourceUsageView::from(u))),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_usage() -> ResourceUsage {
        // Six distinct sentinels so a field transposition can't hide — the
        // three `u64`s especially would otherwise type-check when swapped.
        ResourceUsage {
            principal: PrincipalId::new("alice").unwrap(),
            cpu_fuel_consumed_total: 11,
            cpu_fuel_per_sec_limit: 22,
            exempt: true,
            memory_bytes_limit_per_instance: 33,
            memory_bytes_current_total: Some(44),
        }
    }

    #[test]
    fn view_maps_each_usage_field_to_its_own_slot() {
        let v = ResourceUsageView::from(sample_usage());
        assert_eq!(v.principal, "alice");
        assert_eq!(v.cpu_fuel_consumed_total, 11);
        assert_eq!(v.cpu_fuel_per_sec_limit, 22);
        assert!(v.exempt);
        assert_eq!(v.memory_bytes_limit_per_instance, 33);
        assert_eq!(v.memory_bytes_current_total, Some(44));
    }

    #[test]
    fn view_serializes_with_the_wire_shape_clients_consume() {
        // Pins the JSON contract independently of the OpenAPI schema (the two
        // derivations can drift): plain `principal` string, `None` → `null`.
        let mut u = sample_usage();
        u.exempt = false;
        u.memory_bytes_current_total = None;
        let json = serde_json::to_value(ResourceUsageView::from(u)).unwrap();
        assert_eq!(json["principal"], "alice");
        assert_eq!(json["cpu_fuel_consumed_total"], 11);
        assert_eq!(json["cpu_fuel_per_sec_limit"], 22);
        assert_eq!(json["exempt"], false);
        assert_eq!(json["memory_bytes_limit_per_instance"], 33);
        assert_eq!(json["memory_bytes_current_total"], serde_json::Value::Null);
    }
}
