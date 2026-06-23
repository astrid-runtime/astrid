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

use crate::auth::{CallerContext, mint_bearer, mint_bearer_scoped};
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
    /// The device `key_id` this session is bound to, when the bearer is
    /// device-scoped. Omitted for a legacy full-authority session. Lets a
    /// client see (and surface to the user) which paired device it is acting
    /// as, and what scope dimension a refresh will preserve.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_key_id: Option<String>,
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
        (status = 500, body = ErrorBody, description = "Upstream daemon unreachable or an unexpected response shape."),
        (status = 502, body = ErrorBody, description = "Kernel rejected the redeem (e.g. invalid / expired / consumed token)."),
    )
)]
pub async fn post_redeem(
    State(state): State<Arc<GatewayState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RedeemRequest>,
) -> GatewayResult<Json<RedeemResponse>> {
    // Rate-limit per source IP. Defends the redeem path against
    // brute-force token enumeration — even at 1 attempt per second,
    // a 192-bit token space is unreachable.
    //
    // Behind a reverse proxy `peer.ip()` is the proxy's address, so
    // one abusive client would trip the limit for *every* user.
    // When the immediate peer is on `trust_forwarded_from`, trust
    // `X-Forwarded-For` (first hop) / `X-Real-IP`. Otherwise stick
    // with the connection address.
    let client_ip = resolve_client_ip(&state, peer.ip(), &headers);
    let interval = state.config.redeem_rate_limit();
    if !interval.is_zero() {
        let mut limiter = state.redeem_limiter.lock().await;
        if let Some(wait) = limiter.check(client_ip, interval) {
            return Err(GatewayError::RateLimited {
                // Round UP: a strict client that honours `Retry-After`
                // must not retry before the window actually elapses (e.g.
                // 4.5s remaining → 5, not 4). `.max(1)` keeps a positive
                // floor since the limiter only returns `Some(wait)` while
                // backing off.
                retry_after_secs: wait
                    .as_secs()
                    .saturating_add(u64::from(wait.subsec_nanos() > 0))
                    .max(1),
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
        device_key_id: caller.device_key_id.clone(),
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
    /// Capability scope the redeemed device authenticates under.
    ///
    /// A friendly preset name: `"full"` (unattenuated — requires the issuer
    /// to hold `self:auth:pair:admin`) or `"use-only"` (the device may act
    /// with the principal's self-scoped caps but cannot pair further devices
    /// or delegate). Omitted ⇒ `"full"`, preserving the prior behaviour.
    ///
    /// For a custom allow/deny scope, leave `scope` unset (or `"full"`) and
    /// supply `allow` / `deny` instead — any non-empty `allow`/`deny` selects
    /// an explicit scope, validated to be a subset of the issuer's authority.
    #[serde(default)]
    pub scope: Option<String>,
    /// Explicit allow patterns for a custom scope. When non-empty (or `deny`
    /// is), the request is an explicit scope and `scope` is ignored. Every
    /// pattern must be held by the issuer (no escalation).
    #[serde(default)]
    pub allow: Vec<String>,
    /// Explicit deny patterns for a custom scope (deny wins). Purely
    /// restrictive — needs no subset validation.
    #[serde(default)]
    pub deny: Vec<String>,
}

impl PairDeviceIssueRequest {
    /// Map the friendly HTTP scope fields to the kernel [`PairScopeArg`].
    ///
    /// Precedence: a non-empty `allow`/`deny` ⇒ `Explicit`; otherwise a
    /// `scope` of `"full"`/absent ⇒ `Full`, and any other `scope` string ⇒
    /// `Preset { name }` (the kernel rejects an unknown preset). This keeps
    /// the common cases one field while still exposing explicit caps.
    fn to_scope_arg(&self) -> astrid_core::kernel_api::PairScopeArg {
        use astrid_core::kernel_api::PairScopeArg;
        if !self.allow.is_empty() || !self.deny.is_empty() {
            return PairScopeArg::Explicit {
                allow: self.allow.clone(),
                deny: self.deny.clone(),
            };
        }
        match self.scope.as_deref() {
            None | Some("full") => PairScopeArg::Full,
            Some(name) => PairScopeArg::Preset {
                name: name.to_string(),
            },
        }
    }
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
    /// Deterministic `key_id` of the registered device key. The session
    /// bearer is scoped to this `key_id`, so the device authenticates with —
    /// and is attenuated to — its own registered key at the kernel cap-gate.
    pub key_id: String,
    /// Signed bearer token for subsequent requests. Device-scoped: it carries
    /// `key_id` so the kernel applies this device's scope.
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
    let scope = body.to_scope_arg();
    // Carry the issuer's device scope to the kernel: a use-only paired device
    // calling `pair-device issue` must be denied at the cap-gate even though
    // its principal holds `self:auth:pair` — the device's deny-list fences it.
    // The requested child scope is validated kernel-side against the issuer's
    // attenuated effective set (no escalation) and the full-mint gate.
    let client = state.admin_client_for(&caller)?;
    let resp = client
        .request(AdminRequestKind::PairDeviceIssue {
            expires_secs: body.expires_secs,
            label: body.label,
            scope,
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
        (status = 429, body = ErrorBody, description = "Per-IP rate limit hit; respect `retry_after_secs`."),
        (status = 500, body = ErrorBody, description = "Upstream daemon unreachable or an unexpected response shape."),
        (status = 502, body = ErrorBody, description = "Kernel rejected the redeem (e.g. invalid / expired / consumed token)."),
    )
)]
pub async fn post_pair_device_redeem(
    State(state): State<Arc<GatewayState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(body): Json<PairDeviceRedeemRequest>,
) -> GatewayResult<Json<PairDeviceRedeemResponse>> {
    // Rate-limit per source IP, exactly like `post_redeem`. This is
    // the ONLY brute-force fence in front of the kernel's
    // constant-time pair-token scan: the route is public/unauthenticated
    // and the token is the auth, so without this an attacker could
    // enumerate pair-tokens as fast as the network allows.
    //
    // We deliberately share `redeem_limiter` (not a second limiter) so
    // the per-IP budget is spent across BOTH unauthenticated redeem
    // routes — an attacker cannot dodge the throttle by alternating
    // `/api/auth/redeem` and `/api/auth/pair-device/redeem`.
    // `resolve_client_ip` honours `X-Forwarded-For` only behind a
    // configured trusted proxy.
    let client_ip = resolve_client_ip(&state, peer.ip(), &headers);
    let interval = state.config.redeem_rate_limit();
    if !interval.is_zero() {
        let mut limiter = state.redeem_limiter.lock().await;
        if let Some(wait) = limiter.check(client_ip, interval) {
            return Err(GatewayError::RateLimited {
                // Round UP: a strict client that honours `Retry-After`
                // must not retry before the window actually elapses (e.g.
                // 4.5s remaining → 5, not 4). `.max(1)` keeps a positive
                // floor since the limiter only returns `Some(wait)` while
                // backing off.
                retry_after_secs: wait
                    .as_secs()
                    .saturating_add(u64::from(wait.subsec_nanos() > 0))
                    .max(1),
            });
        }
    }

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

    // The new device's bearer is scoped to ITS key_id (returned by the kernel
    // redeem), so the device authenticates as — and is attenuated to — its own
    // registered key at the cap-gate, not the principal's full authority.
    let session_token = mint_bearer_scoped(
        &state.signing.signer,
        &redeemed.principal,
        &redeemed.key_id,
        state.config.session_lifetime_secs,
    );
    let session_expires_at_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        .saturating_add(state.config.session_lifetime_secs);

    Ok(Json(PairDeviceRedeemResponse {
        principal: redeemed.principal,
        public_key_fingerprint: redeemed.public_key_fingerprint,
        key_id: redeemed.key_id,
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
    // A refresh must NEVER drop or change the device-scope dimension: a
    // scoped bearer re-mints scoped to the SAME key_id, a legacy bearer
    // re-mints as legacy. Otherwise a scoped device could shed its
    // attenuation simply by refreshing.
    let session_token = match &caller.device_key_id {
        Some(key_id) => mint_bearer_scoped(
            &state.signing.signer,
            &caller.principal,
            key_id,
            state.config.session_lifetime_secs,
        ),
        None => mint_bearer(
            &state.signing.signer,
            &caller.principal,
            state.config.session_lifetime_secs,
        ),
    };
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

/// Resolve the real client IP for rate-limiting purposes.
///
/// Returns the `X-Forwarded-For` (left-most hop) or `X-Real-IP`
/// value **only** when the immediate peer is on
/// `config.trust_forwarded_from`. Otherwise falls back to the
/// connection's peer address.
///
/// The trust gate is critical: without it, any client could send
/// `X-Forwarded-For: 1.2.3.4` and dodge the per-IP rate limit by
/// rotating the claimed address. Trusting forwarded headers only
/// from a configured proxy fence keeps the limiter honest.
fn resolve_client_ip(
    state: &GatewayState,
    peer: std::net::IpAddr,
    headers: &axum::http::HeaderMap,
) -> std::net::IpAddr {
    if !state.config.trust_forwarded_from.contains(&peer) {
        return peer;
    }
    // X-Forwarded-For is comma-separated `client, proxy1, proxy2`.
    // The left-most entry is the original client per RFC 7239 / de
    // facto convention. Reject obviously malformed values.
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(first) = xff.split(',').next()
        && let Ok(ip) = first.trim().parse::<std::net::IpAddr>()
    {
        return ip;
    }
    if let Some(xri) = headers.get("x-real-ip").and_then(|v| v.to_str().ok())
        && let Ok(ip) = xri.trim().parse::<std::net::IpAddr>()
    {
        return ip;
    }
    peer
}
