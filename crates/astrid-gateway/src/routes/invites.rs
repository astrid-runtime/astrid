//! `POST /api/sys/invites`, `GET /api/sys/invites`,
//! `DELETE /api/sys/invites/{fingerprint}`.
//!
//! Operator-only invite management. The kernel gates these on
//! `invite:issue` / `invite:list` / `invite:revoke` — the gateway
//! propagates the verified caller and the kernel does the rest.

use std::sync::Arc;

use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody, InviteIssued, InviteSummary};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::CallerContext;
use crate::error::{ErrorBody, GatewayError, GatewayResult};
use crate::state::GatewayState;

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct IssueRequest {
    pub group: String,
    #[serde(default)]
    pub expires_secs: Option<u64>,
    pub max_uses: u32,
    #[serde(default)]
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IssueResponse {
    /// `InviteIssued` shape: `{ token, group, remaining_uses, expires_at_epoch?, fingerprint, metadata? }`.
    #[schema(value_type = serde_json::Value)]
    pub invite: InviteIssued,
}

#[utoipa::path(
    post,
    path = "/api/sys/invites",
    tag = "invites",
    request_body = IssueRequest,
    responses(
        (status = 200, body = IssueResponse, description = "Invite minted; opaque token returned once — store it securely."),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `invite:issue`."),
    )
)]
pub async fn issue_invite(
    State(state): State<Arc<GatewayState>>,
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

    let client = state.admin_client(caller.principal)?;
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

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ListResponse {
    /// `InviteSummary` shape: `{ fingerprint, group, remaining_uses, expires_at_epoch?, metadata? }`.
    #[schema(value_type = Vec<serde_json::Value>)]
    pub invites: Vec<InviteSummary>,
}

#[utoipa::path(
    get,
    path = "/api/sys/invites",
    tag = "invites",
    responses(
        (status = 200, body = ListResponse, description = "Outstanding invites — fingerprints only, not raw tokens."),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `invite:list`."),
    )
)]
pub async fn list_invites(
    State(state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<ListResponse>> {
    let caller = req
        .extensions()
        .get::<CallerContext>()
        .cloned()
        .ok_or(GatewayError::Unauthorized)?;
    let client = state.admin_client(caller.principal)?;
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

#[utoipa::path(
    delete,
    path = "/api/sys/invites/{fingerprint}",
    tag = "invites",
    params(("fingerprint" = String, Path, description = "SHA-256 fingerprint from a prior `IssueResponse` / list entry")),
    responses(
        (status = 204, description = "Invite revoked."),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `invite:revoke`."),
        (status = 404, body = ErrorBody, description = "No invite matches the fingerprint."),
    )
)]
pub async fn revoke_invite(
    State(state): State<Arc<GatewayState>>,
    Path(fingerprint): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<StatusCode> {
    let caller = req
        .extensions()
        .get::<CallerContext>()
        .cloned()
        .ok_or(GatewayError::Unauthorized)?;
    let client = state.admin_client(caller.principal)?;
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
