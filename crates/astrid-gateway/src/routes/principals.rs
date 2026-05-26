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
