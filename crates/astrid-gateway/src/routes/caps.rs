//! `/api/sys/principals/{id}/caps` — capability grant / revoke.
//!
//! Grants and revokes append to the principal's
//! `profile.toml` `grants` / `revokes` vectors. Both are gated by
//! the kernel's existing `caps:grant` / `caps:revoke` capabilities.
//! The `unsafe_admin` rail mirrors the CLI: granting a `*` pattern
//! requires `unsafe_admin: true` on the request body or the kernel
//! rejects.

use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody};
use astrid_uplink::AdminClient;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use serde::Deserialize;

use crate::error::{GatewayError, GatewayResult};
use crate::routes::principals::{caller_from, daemon_internal, read_json_body, unexpected};
use crate::state::GatewayState;

#[derive(Debug, Clone, Deserialize)]
pub struct GrantRequest {
    /// Colon-delimited capability patterns to append.
    pub capabilities: Vec<String>,
    /// Required when `capabilities` contains the universal `*`
    /// pattern. Acknowledges the operator is intentionally minting
    /// a wildcard grant. Mirrors `astrid caps grant --unsafe-admin`.
    #[serde(default)]
    pub unsafe_admin: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RevokeRequest {
    /// Capability patterns to add to the principal's `revokes` vec.
    /// Safe to call on caps the principal does not currently hold
    /// (pre-emptive revoke).
    pub capabilities: Vec<String>,
}

pub async fn grant_caps(
    State(_state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let principal = PrincipalId::new(&id)
        .map_err(|e| GatewayError::BadRequest(format!("invalid principal id: {e}")))?;
    let caller = caller_from(&req)?.clone();
    let body: GrantRequest = read_json_body(req).await?;
    let mut client = AdminClient::connect(caller.principal)
        .await
        .map_err(daemon_internal)?;
    let resp = client
        .request(AdminRequestKind::CapsGrant {
            principal,
            capabilities: body.capabilities,
            unsafe_admin: body.unsafe_admin,
        })
        .await
        .map_err(daemon_internal)?;
    match resp {
        AdminResponseBody::Success(v) => Ok(Json(v)),
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(unexpected(other)),
    }
}

pub async fn revoke_caps(
    State(_state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<StatusCode> {
    let principal = PrincipalId::new(&id)
        .map_err(|e| GatewayError::BadRequest(format!("invalid principal id: {e}")))?;
    let caller = caller_from(&req)?.clone();
    let body: RevokeRequest = read_json_body(req).await?;
    let mut client = AdminClient::connect(caller.principal)
        .await
        .map_err(daemon_internal)?;
    let resp = client
        .request(AdminRequestKind::CapsRevoke {
            principal,
            capabilities: body.capabilities,
        })
        .await
        .map_err(daemon_internal)?;
    match resp {
        AdminResponseBody::Success(_) => Ok(StatusCode::NO_CONTENT),
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(unexpected(other)),
    }
}
