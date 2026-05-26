//! `POST /api/sys/invites`, `GET /api/sys/invites`,
//! `DELETE /api/sys/invites/{fingerprint}`.
//!
//! Operator-only invite management. The kernel gates these on
//! `invite:issue` / `invite:list` / `invite:revoke` — the gateway
//! propagates the verified caller and the kernel does the rest.

use std::sync::Arc;

use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody, InviteIssued, InviteSummary};
use astrid_uplink::AdminClient;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use serde::{Deserialize, Serialize};

use crate::auth::CallerContext;
use crate::error::{GatewayError, GatewayResult};
use crate::state::GatewayState;

#[derive(Debug, Clone, Deserialize)]
pub struct IssueRequest {
    pub group: String,
    #[serde(default)]
    pub expires_secs: Option<u64>,
    pub max_uses: u32,
    #[serde(default)]
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssueResponse {
    pub invite: InviteIssued,
}

pub async fn issue_invite(
    State(_state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<IssueResponse>> {
    // axum's `Json<T>` and `State<...>` can't co-exist with a manual
    // `Request<Body>` extractor in the same handler order — so we
    // pull the caller from extensions, deserialise the body
    // ourselves from the request, and forward.
    let caller = req
        .extensions()
        .get::<CallerContext>()
        .cloned()
        .ok_or(GatewayError::Unauthorized)?;
    let bytes = axum::body::to_bytes(req.into_body(), 64 * 1024)
        .await
        .map_err(|e| GatewayError::BadRequest(format!("body read: {e}")))?;
    let body: IssueRequest = serde_json::from_slice(&bytes)?;

    let mut client = AdminClient::connect(caller.principal)
        .await
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("daemon connect: {e}")))?;
    let resp = client
        .request(AdminRequestKind::InviteIssue {
            group: body.group,
            expires_secs: body.expires_secs,
            max_uses: body.max_uses,
            metadata: body.metadata,
        })
        .await
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("daemon request: {e}")))?;
    match resp {
        AdminResponseBody::Invite(invite) => Ok(Json(IssueResponse { invite })),
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(GatewayError::Internal(anyhow::anyhow!(
            "unexpected response shape: {other:?}"
        ))),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ListResponse {
    pub invites: Vec<InviteSummary>,
}

pub async fn list_invites(
    State(_state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<ListResponse>> {
    let caller = req
        .extensions()
        .get::<CallerContext>()
        .cloned()
        .ok_or(GatewayError::Unauthorized)?;
    let mut client = AdminClient::connect(caller.principal)
        .await
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("daemon connect: {e}")))?;
    let resp = client
        .request(AdminRequestKind::InviteList)
        .await
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("daemon request: {e}")))?;
    match resp {
        AdminResponseBody::InviteList(invites) => Ok(Json(ListResponse { invites })),
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(GatewayError::Internal(anyhow::anyhow!(
            "unexpected response shape: {other:?}"
        ))),
    }
}

pub async fn revoke_invite(
    State(_state): State<Arc<GatewayState>>,
    Path(fingerprint): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<StatusCode> {
    let caller = req
        .extensions()
        .get::<CallerContext>()
        .cloned()
        .ok_or(GatewayError::Unauthorized)?;
    let mut client = AdminClient::connect(caller.principal)
        .await
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("daemon connect: {e}")))?;
    let resp = client
        .request(AdminRequestKind::InviteRevoke { token: fingerprint })
        .await
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("daemon request: {e}")))?;
    match resp {
        AdminResponseBody::Success(_) => Ok(StatusCode::NO_CONTENT),
        AdminResponseBody::Error(msg) if msg.contains("no invite matches") => {
            Err(GatewayError::NotFound)
        },
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(GatewayError::Internal(anyhow::anyhow!(
            "unexpected response shape: {other:?}"
        ))),
    }
}
