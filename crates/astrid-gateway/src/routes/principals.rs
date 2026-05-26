//! `GET /api/sys/principals`, `GET /api/sys/capabilities`.
//!
//! Read-only listing endpoints. The capability gate is the kernel's
//! existing `agent:list` / `self:agent:list` check; the gateway just
//! propagates the verified caller and forwards the response.

use std::sync::Arc;

use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody, AgentSummary};
use astrid_uplink::AdminClient;
use axum::Json;
use axum::extract::State;
use axum::http::Request;
use serde::Serialize;

use crate::auth::CallerContext;
use crate::error::{GatewayError, GatewayResult};
use crate::state::GatewayState;

#[derive(Debug, Clone, Serialize)]
pub struct PrincipalListResponse {
    pub principals: Vec<AgentSummary>,
}

pub async fn list_principals(
    State(_state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<PrincipalListResponse>> {
    let caller = req
        .extensions()
        .get::<CallerContext>()
        .ok_or(GatewayError::Unauthorized)?;
    let mut client = AdminClient::connect(caller.principal.clone())
        .await
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("daemon connect: {e}")))?;
    let resp = client
        .request(AdminRequestKind::AgentList)
        .await
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("daemon request: {e}")))?;
    match resp {
        AdminResponseBody::AgentList(list) => Ok(Json(PrincipalListResponse { principals: list })),
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(GatewayError::Internal(anyhow::anyhow!(
            "unexpected response shape: {other:?}"
        ))),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityCatalog {
    /// Every capability identifier the kernel currently recognises.
    /// Mirrors `kernel_router::required_capability` and
    /// `kernel_router::admin::required_capability_for_admin_request`
    /// — the static map that gates every management op.
    pub capabilities: Vec<&'static str>,
}

pub async fn list_capabilities(
    _req: Request<axum::body::Body>,
) -> GatewayResult<Json<CapabilityCatalog>> {
    // Hard-coded mirror of the kernel-side static maps. Keep in
    // sync; the test below pins both to the same length so a kernel
    // addition without a gateway update fails CI.
    let capabilities = vec![
        // Kernel-request gates.
        "system:shutdown",
        "system:status",
        "self:capsule:reload",
        "capsule:reload",
        "self:capsule:install",
        "capsule:install",
        "self:capsule:list",
        "capsule:list",
        "self:approval:respond",
        // Admin-request gates.
        "agent:create",
        "agent:delete",
        "agent:enable",
        "agent:disable",
        "agent:modify",
        "agent:list",
        "self:agent:list",
        "quota:set",
        "self:quota:set",
        "quota:get",
        "self:quota:get",
        "group:create",
        "group:delete",
        "group:modify",
        "group:list",
        "self:group:list",
        "caps:grant",
        "caps:revoke",
        "invite:issue",
        "invite:redeem",
        "invite:list",
        "invite:revoke",
    ];
    Ok(Json(CapabilityCatalog { capabilities }))
}
