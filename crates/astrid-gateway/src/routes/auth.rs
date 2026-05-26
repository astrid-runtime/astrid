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
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody};
use astrid_uplink::AdminClient;
use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::Request;
use serde::{Deserialize, Serialize};

use crate::auth::{CallerContext, mint_bearer};
use crate::error::{GatewayError, GatewayResult};
use crate::state::GatewayState;

/// Inbound body for `POST /api/auth/redeem`.
#[derive(Debug, Clone, Deserialize)]
pub struct RedeemRequest {
    /// The opaque token from an `astrid invite issue` (or
    /// dashboard-issued) invite.
    pub token: String,
    /// Hex-encoded ed25519 public key. Bare 64 hex chars or the
    /// `ed25519:<hex>` form.
    pub public_key: String,
    /// Optional human-friendly name for the new principal.
    #[serde(default)]
    pub display_name: Option<String>,
}

/// Outbound response for `POST /api/auth/redeem`.
#[derive(Debug, Clone, Serialize)]
pub struct RedeemResponse {
    /// Freshly minted principal id.
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
#[derive(Debug, Clone, Serialize)]
pub struct MeResponse {
    /// The authenticated principal.
    pub principal: PrincipalId,
    /// Bearer expiry — clients can use this to schedule a refresh.
    pub expires_at_epoch: u64,
}

/// Handler: redeem an invite token, mint a principal, return a
/// session bearer.
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
    let mut client = AdminClient::connect(PrincipalId::default())
        .await
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("daemon connect: {e}")))?;
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
