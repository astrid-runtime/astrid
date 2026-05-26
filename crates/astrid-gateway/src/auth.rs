//! Bearer-token signing, verification, and the principal-extraction
//! middleware.
//!
//! ## Wire format
//!
//! ```text
//! base64url(principal_id) "." base64url(expiry_epoch_secs) "." hex(ed25519_sig)
//! ```
//!
//! The signature covers `principal_id || ":" || expiry_epoch_secs`
//! as raw bytes. Compact, easy to debug by eye, and tied to the
//! same ed25519 primitive the rest of Astrid uses.
//!
//! ## Trust shape
//!
//! Middleware verifies the signature against the gateway's
//! boot-time public key (see [`crate::state::SigningMaterial`]) and
//! returns the embedded `PrincipalId`. Handlers consume the
//! principal via axum's [`Extension`] so there is one obvious place
//! the value is bound — handlers never read it out of the request
//! body.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use astrid_core::PrincipalId;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};

use crate::error::GatewayError;
use crate::state::GatewayState;

/// The authenticated caller, attached to every request after the
/// auth middleware runs.
#[derive(Debug, Clone)]
pub struct CallerContext {
    /// The verified principal id from the bearer token.
    pub principal: PrincipalId,
    /// Wall-clock epoch the bearer expires.
    pub expires_at_epoch: u64,
}

/// Mint a fresh session bearer for `principal`.
#[must_use]
pub fn mint_bearer(signer: &SigningKey, principal: &PrincipalId, lifetime_secs: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let expires = now.saturating_add(lifetime_secs);
    let msg = format!("{principal}:{expires}");
    let sig: Signature = signer.sign(msg.as_bytes());

    let p_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(principal.as_str());
    let e_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expires.to_string());
    let s_hex = hex::encode(sig.to_bytes());
    format!("{p_b64}.{e_b64}.{s_hex}")
}

/// Parse and verify a bearer token. Returns the [`CallerContext`] on
/// success, or `Err` with a generic shape so callers can't tell
/// which check failed (avoids leaking validity oracle).
pub fn verify_bearer(state: &GatewayState, raw: &str) -> Result<CallerContext, GatewayError> {
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() != 3 {
        return Err(GatewayError::Unauthorized);
    }
    let p_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| GatewayError::Unauthorized)?;
    let e_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| GatewayError::Unauthorized)?;
    let s_bytes = hex::decode(parts[2]).map_err(|_| GatewayError::Unauthorized)?;
    if s_bytes.len() != ed25519_dalek::SIGNATURE_LENGTH {
        return Err(GatewayError::Unauthorized);
    }

    let principal_str = std::str::from_utf8(&p_bytes).map_err(|_| GatewayError::Unauthorized)?;
    let expires_str = std::str::from_utf8(&e_bytes).map_err(|_| GatewayError::Unauthorized)?;
    let expires_at_epoch: u64 = expires_str
        .parse()
        .map_err(|_| GatewayError::Unauthorized)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let msg = format!("{principal_str}:{expires_at_epoch}");
    let mut sig_arr = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
    sig_arr.copy_from_slice(&s_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    state
        .signing
        .verifier
        .verify(msg.as_bytes(), &sig)
        .map_err(|_| GatewayError::Unauthorized)?;

    // Now that signature is verified, surface expiry as the
    // authoritative rejection.
    if expires_at_epoch <= now {
        return Err(GatewayError::Unauthorized);
    }

    let principal = PrincipalId::new(principal_str).map_err(|_| GatewayError::Unauthorized)?;
    Ok(CallerContext {
        principal,
        expires_at_epoch,
    })
}

/// Axum middleware that extracts the bearer token, verifies it, and
/// attaches the resolved [`CallerContext`] to request extensions.
pub async fn require_session(
    State(state): State<Arc<GatewayState>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, GatewayError> {
    let header_val = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or(GatewayError::Unauthorized)?;
    let raw = header_val
        .strip_prefix("Bearer ")
        .ok_or(GatewayError::Unauthorized)?;
    let caller = verify_bearer(&state, raw)?;
    req.extensions_mut().insert(caller);
    Ok(next.run(req).await)
}

/// Extract the caller from request extensions. Panics if the
/// middleware did not run — guarded against by route composition.
pub fn caller_from(req: &Request<Body>) -> Result<&CallerContext, GatewayError> {
    req.extensions()
        .get::<CallerContext>()
        .ok_or(GatewayError::Unauthorized)
}

/// `StatusCode::UNAUTHORIZED` shortcut so route modules don't have
/// to depend on `axum::http` directly.
#[must_use]
pub const fn unauthorized_status() -> StatusCode {
    StatusCode::UNAUTHORIZED
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SigningMaterial;

    fn test_state() -> Arc<GatewayState> {
        let cfg = crate::config::GatewayConfig::default();
        Arc::new(GatewayState {
            config: cfg,
            signing: SigningMaterial::fresh(),
            distro_toml: None,
            redeem_limiter: tokio::sync::Mutex::default(),
        })
    }

    #[test]
    fn fresh_bearer_round_trips() {
        let state = test_state();
        let principal = PrincipalId::new("alice").unwrap();
        let raw = mint_bearer(&state.signing.signer, &principal, 3600);
        let caller = verify_bearer(&state, &raw).expect("verify");
        assert_eq!(caller.principal, principal);
    }

    #[test]
    fn tampered_signature_rejected() {
        let state = test_state();
        let principal = PrincipalId::new("alice").unwrap();
        let mut raw = mint_bearer(&state.signing.signer, &principal, 3600);
        // Flip the last hex char — invalidates the signature.
        let last = raw.pop().unwrap();
        raw.push(if last == 'a' { 'b' } else { 'a' });
        assert!(verify_bearer(&state, &raw).is_err());
    }

    #[test]
    fn expired_bearer_rejected() {
        let state = test_state();
        let principal = PrincipalId::new("alice").unwrap();
        // mint with 0s lifetime: epoch-equal "now" → reject as expired.
        let raw = mint_bearer(&state.signing.signer, &principal, 0);
        assert!(verify_bearer(&state, &raw).is_err());
    }

    #[test]
    fn principal_substituted_in_payload_rejected() {
        let state = test_state();
        let principal = PrincipalId::new("alice").unwrap();
        let raw = mint_bearer(&state.signing.signer, &principal, 3600);
        // Replace the encoded principal with `eve` but keep the sig:
        // the verifier rebuilds the signed message from the parts, so
        // any swap invalidates the check.
        let parts: Vec<&str> = raw.split('.').collect();
        let eve = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("eve");
        let tampered = format!("{eve}.{}.{}", parts[1], parts[2]);
        assert!(verify_bearer(&state, &tampered).is_err());
    }

    #[test]
    fn malformed_token_rejected() {
        let state = test_state();
        assert!(verify_bearer(&state, "garbage").is_err());
        assert!(verify_bearer(&state, "a.b.c").is_err());
    }
}
