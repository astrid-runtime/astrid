//! `POST /api/auth/redeem`, `GET /api/auth/me`.
//!
//! The redeem path is the gateway's most security-sensitive route:
//! it accepts an unauthenticated invite token, calls the kernel's
//! `InviteRedeem` admin op (which is special-cased to bypass the
//! cap-gate because the caller principal does not yet exist), and
//! returns a freshly-minted session bearer.

use std::net::SocketAddr;
use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_core::kernel_api::{
    AdminRequestKind, AdminResponseBody, PairTokenIssued, PairTokenRedeemed,
};
use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::Request;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{CallerContext, mint_bearer};
use crate::error::{ErrorBody, GatewayError, GatewayResult};
use crate::state::GatewayState;

/// Inbound body for `POST /api/auth/redeem`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct RedeemRequest {
    /// The opaque token from an `astrid invite issue` (or
    /// dashboard-issued) invite.
    #[schema(example = "AAAA...")]
    pub token: String,
    /// Hex-encoded ed25519 public key. Bare 64 hex chars or the
    /// `ed25519:<hex>` form.
    #[schema(example = "ed25519:a1b2c3...")]
    pub public_key: String,
    /// Optional human-friendly name for the new principal.
    #[serde(default)]
    pub display_name: Option<String>,
}

/// Outbound response for `POST /api/auth/redeem`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RedeemResponse {
    /// Freshly minted principal id.
    #[schema(value_type = String, example = "agent-alice")]
    pub principal: PrincipalId,
    /// Group the new principal joined.
    pub group: String,
    /// SHA-256 fingerprint of the registered ed25519 key — lets the
    /// redeemer verify the gateway didn't swap their key.
    pub public_key_fingerprint: String,
    /// Signed bearer token for subsequent requests.
    pub session_token: String,
    /// Wall-clock epoch the bearer expires.
    pub session_expires_at_epoch: u64,
}

/// Outbound response for `GET /api/auth/me`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MeResponse {
    /// The authenticated principal.
    #[schema(value_type = String, example = "agent-alice")]
    pub principal: PrincipalId,
    /// Bearer expiry — clients can use this to schedule a refresh.
    pub expires_at_epoch: u64,
}

/// Handler: redeem an invite token, mint a principal, return a
/// session bearer.
#[utoipa::path(
    post,
    path = "/api/auth/redeem",
    tag = "auth",
    security(()),
    request_body = RedeemRequest,
    responses(
        (status = 200, body = RedeemResponse, description = "New principal minted; session bearer attached."),
        (status = 400, body = ErrorBody, description = "Malformed token / public key."),
        (status = 429, body = ErrorBody, description = "Per-IP rate limit hit; respect `retry_after_secs`."),
        (status = 500, body = ErrorBody, description = "Kernel rejected the redeem or upstream is unreachable."),
    )
)]
pub async fn post_redeem(
    State(state): State<Arc<GatewayState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<RedeemRequest>,
) -> GatewayResult<Json<RedeemResponse>> {
    // Rate-limit per source IP. Defends the redeem path against
    // brute-force token enumeration — even at 1 attempt per second,
    // a 192-bit token space is unreachable.
    let interval = state.config.redeem_rate_limit();
    if !interval.is_zero() {
        let mut limiter = state.redeem_limiter.lock().await;
        if let Some(wait) = limiter.check(peer.ip(), interval) {
            return Err(GatewayError::RateLimited {
                retry_after_secs: wait.as_secs().max(1),
            });
        }
    }

    // `InviteRedeem` doesn't need a verified caller principal — the
    // token is the auth and the kernel's admin dispatcher bypasses
    // the cap-gate for this variant. Stamp the IPC message with the
    // `default` principal so the kernel's `resolve_caller` has *a*
    // value to log; the handler ignores it.
    let client = state.admin_client(PrincipalId::default())?;
    let resp = client
        .request(AdminRequestKind::InviteRedeem {
            token: body.token,
            public_key: body.public_key,
            display_name: body.display_name,
        })
        .await
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("daemon request: {e}")))?;
    let redeemed = match resp {
        AdminResponseBody::InviteRedeemed(r) => r,
        AdminResponseBody::Error(msg) => return Err(GatewayError::Kernel(msg)),
        other => {
            return Err(GatewayError::Internal(anyhow::anyhow!(
                "unexpected response shape: {other:?}"
            )));
        },
    };

    let session_token = mint_bearer(
        &state.signing.signer,
        &redeemed.principal,
        state.config.session_lifetime_secs,
    );
    let session_expires_at_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        .saturating_add(state.config.session_lifetime_secs);

    Ok(Json(RedeemResponse {
        principal: redeemed.principal,
        group: redeemed.group,
        public_key_fingerprint: redeemed.public_key_fingerprint,
        session_token,
        session_expires_at_epoch,
    }))
}

/// Handler: reflect the verified caller back to the dashboard.
#[utoipa::path(
    get,
    path = "/api/auth/me",
    tag = "auth",
    responses(
        (status = 200, body = MeResponse, description = "Current session info — principal + expiry."),
        (status = 401, body = ErrorBody, description = "Missing / invalid bearer."),
    )
)]
pub async fn get_me(req: Request<axum::body::Body>) -> GatewayResult<Json<MeResponse>> {
    let caller: &CallerContext = req
        .extensions()
        .get::<CallerContext>()
        .ok_or(GatewayError::Unauthorized)?;
    Ok(Json(MeResponse {
        principal: caller.principal.clone(),
        expires_at_epoch: caller.expires_at_epoch,
    }))
}

/// Outbound response for `POST /api/auth/refresh`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RefreshResponse {
    /// Same principal as the inbound bearer — refresh never
    /// switches identities.
    #[schema(value_type = String, example = "agent-alice")]
    pub principal: PrincipalId,
    /// Freshly signed bearer.
    pub session_token: String,
    /// Wall-clock epoch the new bearer expires.
    pub session_expires_at_epoch: u64,
}

/// Inbound body for `POST /api/auth/pair-device`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct PairDeviceIssueRequest {
    /// Token lifetime in seconds. `None` defaults kernel-side
    /// (typically 5 minutes). Capped at 1 hour kernel-side.
    #[serde(default)]
    pub expires_secs: Option<u64>,
    /// Optional human-friendly label persisted alongside the new
    /// key entry on `AuthConfig.public_keys` once redeemed.
    #[serde(default)]
    pub label: Option<String>,
}

/// Inbound body for `POST /api/auth/pair-device/redeem`. Unauthenticated
/// route — the pair-token is the auth.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct PairDeviceRedeemRequest {
    /// Opaque pair-token from a prior issue.
    pub token: String,
    /// Hex-encoded ed25519 public key. Bare 64 hex or
    /// `ed25519:<hex>`.
    #[schema(example = "ed25519:a1b2c3...")]
    pub public_key: String,
}

/// Outbound response for `POST /api/auth/pair-device/redeem` — the
/// new device's session bearer for the bound principal.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PairDeviceRedeemResponse {
    /// The principal the new device is now bound to.
    #[schema(value_type = String, example = "agent-alice")]
    pub principal: PrincipalId,
    /// SHA-256 fingerprint of the registered key.
    pub public_key_fingerprint: String,
    /// Signed bearer token for subsequent requests.
    pub session_token: String,
    /// Wall-clock epoch the bearer expires.
    pub session_expires_at_epoch: u64,
}

/// `POST /api/auth/pair-device` — issue a pair-token tied to the
/// authenticated caller's principal. Returns the opaque token,
/// which the caller hands to the new device out-of-band (QR code,
/// NFC, etc.).
#[utoipa::path(
    post,
    path = "/api/auth/pair-device",
    tag = "auth",
    request_body = PairDeviceIssueRequest,
    responses(
        (status = 200, description = "Pair-token (single-use, time-limited). Schema mirrors `astrid_core::kernel_api::PairTokenIssued`: `{ token, principal, expires_at_epoch, label? }`.", content_type = "application/json"),
        (status = 401, body = ErrorBody, description = "Missing / invalid bearer."),
        (status = 500, body = ErrorBody, description = "Kernel rejected the issue or upstream is unreachable."),
    )
)]
pub async fn post_pair_device_issue(
    State(state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<PairTokenIssued>> {
    let caller: CallerContext = req
        .extensions()
        .get::<CallerContext>()
        .cloned()
        .ok_or(GatewayError::Unauthorized)?;
    let body: PairDeviceIssueRequest = crate::routes::principals::read_json_body(req).await?;
    let client = state.admin_client(caller.principal)?;
    let resp = client
        .request(AdminRequestKind::PairDeviceIssue {
            expires_secs: body.expires_secs,
            label: body.label,
        })
        .await
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("daemon request: {e}")))?;
    match resp {
        AdminResponseBody::PairToken(issued) => Ok(Json(issued)),
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(GatewayError::Internal(anyhow::anyhow!(
            "unexpected response shape: {other:?}"
        ))),
    }
}

/// `POST /api/auth/pair-device/redeem` — unauthenticated. The
/// pair-token is the auth. The kernel registers the supplied key
/// on the bound principal and the gateway mints a session bearer
/// so the new device is immediately usable.
#[utoipa::path(
    post,
    path = "/api/auth/pair-device/redeem",
    tag = "auth",
    security(()),
    request_body = PairDeviceRedeemRequest,
    responses(
        (status = 200, body = PairDeviceRedeemResponse, description = "Device's key registered; session bearer attached."),
        (status = 400, body = ErrorBody, description = "Malformed token / public key."),
        (status = 500, body = ErrorBody, description = "Kernel rejected the redeem or upstream is unreachable."),
    )
)]
pub async fn post_pair_device_redeem(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<PairDeviceRedeemRequest>,
) -> GatewayResult<Json<PairDeviceRedeemResponse>> {
    // Same trust posture as invite-redeem: connect as the bootstrap
    // default principal (the gateway has system.token access), let
    // the kernel's special-cased dispatcher verify the token.
    let client = state.admin_client(PrincipalId::default())?;
    let resp = client
        .request(AdminRequestKind::PairDeviceRedeem {
            token: body.token,
            public_key: body.public_key,
        })
        .await
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("daemon request: {e}")))?;
    let redeemed: PairTokenRedeemed = match resp {
        AdminResponseBody::PairTokenRedeemed(r) => r,
        AdminResponseBody::Error(msg) => return Err(GatewayError::Kernel(msg)),
        other => {
            return Err(GatewayError::Internal(anyhow::anyhow!(
                "unexpected response shape: {other:?}"
            )));
        },
    };

    let session_token = mint_bearer(
        &state.signing.signer,
        &redeemed.principal,
        state.config.session_lifetime_secs,
    );
    let session_expires_at_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        .saturating_add(state.config.session_lifetime_secs);

    Ok(Json(PairDeviceRedeemResponse {
        principal: redeemed.principal,
        public_key_fingerprint: redeemed.public_key_fingerprint,
        session_token,
        session_expires_at_epoch,
    }))
}

/// Handler: `POST /api/auth/refresh`. Issues a new bearer for the
/// same principal, extending the session without forcing the user
/// back through invite redeem. Behind the auth middleware, so the
/// inbound bearer is already verified — we just re-mint with a
/// fresh expiry.
///
/// No additional rate limiting beyond what the bearer check already
/// implies (an attacker without a valid bearer can't reach this
/// route at all). Per-principal refresh tracking (one outstanding
/// refresh per principal) is a future hardening if abuse appears.
#[utoipa::path(
    post,
    path = "/api/auth/refresh",
    tag = "auth",
    responses(
        (status = 200, body = RefreshResponse, description = "Re-minted bearer with a fresh expiry."),
        (status = 401, body = ErrorBody, description = "Missing / invalid bearer."),
    )
)]
pub async fn post_refresh(
    State(state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<RefreshResponse>> {
    let caller: &CallerContext = req
        .extensions()
        .get::<CallerContext>()
        .ok_or(GatewayError::Unauthorized)?;
    let session_token = mint_bearer(
        &state.signing.signer,
        &caller.principal,
        state.config.session_lifetime_secs,
    );
    let session_expires_at_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        .saturating_add(state.config.session_lifetime_secs);
    Ok(Json(RefreshResponse {
        principal: caller.principal.clone(),
        session_token,
        session_expires_at_epoch,
    }))
}
