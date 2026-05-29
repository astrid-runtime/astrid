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

/// `OpenAPI` schema mirror of [`astrid_core::kernel_api::InviteIssued`].
/// Never constructed; resolves the `value_type` on
/// [`IssueResponse::invite`] to a typed schema. Keep it
/// field-for-field with the serialized shape of `InviteIssued`.
#[derive(ToSchema)]
pub struct InviteIssuedView {
    /// Opaque token (URL-safe base64). Returned once — store securely.
    pub token: String,
    /// Group the redeemer will join on success.
    pub group: String,
    /// Remaining redemptions before the token is invalidated.
    pub remaining_uses: u32,
    /// Unix-epoch expiry. Absent when issued with no expiry.
    pub expires_at_epoch: Option<u64>,
    /// Operator-supplied label.
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IssueResponse {
    #[schema(value_type = InviteIssuedView)]
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

/// `OpenAPI` schema mirror of [`astrid_core::kernel_api::InviteSummary`].
/// Never constructed; resolves the `value_type` on
/// [`ListResponse::invites`] to a typed schema. Keep it
/// field-for-field with the serialized shape of `InviteSummary` —
/// note the field is `token_fingerprint` (not `fingerprint`), and
/// `issued_at_epoch` is always present.
#[derive(ToSchema)]
pub struct InviteSummaryView {
    /// SHA-256 fingerprint (hex) of the token. Raw tokens are never
    /// leaked through list responses.
    pub token_fingerprint: String,
    /// Group the redeemer will join.
    pub group: String,
    /// Remaining redemptions.
    pub remaining_uses: u32,
    /// Unix-epoch expiry. Absent when issued with no expiry.
    pub expires_at_epoch: Option<u64>,
    /// Unix-epoch timestamp at which the token was issued.
    pub issued_at_epoch: u64,
    /// Operator-supplied label.
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ListResponse {
    #[schema(value_type = Vec<InviteSummaryView>)]
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
