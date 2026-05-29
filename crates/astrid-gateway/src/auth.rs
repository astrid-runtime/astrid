//! Bearer-token signing, verification, and the principal-extraction
//! middleware.
//!
//! ## Wire format (v2)
//!
//! ```text
//! base64url(principal_id) "." base64url(issued_at_epoch) "." base64url(expires_at_epoch) "." hex(ed25519_sig)
//! ```
//!
//! The signature covers
//! `principal_id || ":" || issued_at_epoch || ":" || expires_at_epoch`
//! as raw bytes. Compact, easy to debug by eye, and tied to the
//! same ed25519 primitive the rest of Astrid uses.
//!
//! The `issued_at_epoch` (`iat`) claim was added in v0.7.1 so the
//! gateway can mint cryptographically-scoped revocations: when an
//! admin deletes a principal at time `T`, every bearer for that
//! principal whose `iat <= T` is rejected on verify. Without `iat`
//! the only revocation semantics available are "blanket reject
//! forever" which would surprise an operator who later re-creates a
//! principal with the same id. v1 bearers (3 segments) no longer
//! verify — dashboard sessions issued by the v0.7.0 gateway must
//! re-redeem after upgrade.
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
    /// Wall-clock epoch the bearer was minted (`iat`). Used by
    /// revocation: if the principal was deleted at time `T`, every
    /// bearer with `iat <= T` is rejected.
    pub issued_at_epoch: u64,
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
    let msg = format!("{principal}:{now}:{expires}");
    let sig: Signature = signer.sign(msg.as_bytes());

    let p_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(principal.as_str());
    let i_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(now.to_string());
    let e_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expires.to_string());
    let s_hex = hex::encode(sig.to_bytes());
    format!("{p_b64}.{i_b64}.{e_b64}.{s_hex}")
}

/// Parse and verify a bearer token. Returns the [`CallerContext`] on
/// success, or `Err` with a generic shape so callers can't tell
/// which check failed (avoids leaking validity oracle).
///
/// # Panics
/// Panics if the revocation map's `RwLock` is poisoned. A poisoned
/// lock means another thread crashed while holding the write lock —
/// continuing to authenticate against an undefined revocation
/// snapshot would be worse than crashing the request handler, so we
/// fail-stop on the auth path.
pub fn verify_bearer(state: &GatewayState, raw: &str) -> Result<CallerContext, GatewayError> {
    // `splitn(5, '.')` caps allocation at five slices regardless of
    // input length. Without the cap, an attacker sending an
    // Authorization header packed with dots would coerce `split('.')`
    // into materialising millions of empty slices — a cheap path to
    // memory / CPU exhaustion against an unauthenticated route.
    // The cap is one beyond the expected segment count so a 5+
    // segment input lands the trailing dots in `parts[3]` (the hex
    // signature), where `hex::decode` will reject it.
    let parts: Vec<&str> = raw.splitn(5, '.').collect();
    if parts.len() != 4 {
        return Err(GatewayError::Unauthorized);
    }
    let p_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| GatewayError::Unauthorized)?;
    let i_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| GatewayError::Unauthorized)?;
    let e_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| GatewayError::Unauthorized)?;
    let s_bytes = hex::decode(parts[3]).map_err(|_| GatewayError::Unauthorized)?;
    if s_bytes.len() != ed25519_dalek::SIGNATURE_LENGTH {
        return Err(GatewayError::Unauthorized);
    }

    let principal_str = std::str::from_utf8(&p_bytes).map_err(|_| GatewayError::Unauthorized)?;
    let issued_str = std::str::from_utf8(&i_bytes).map_err(|_| GatewayError::Unauthorized)?;
    let expires_str = std::str::from_utf8(&e_bytes).map_err(|_| GatewayError::Unauthorized)?;
    let issued_at_epoch: u64 = issued_str.parse().map_err(|_| GatewayError::Unauthorized)?;
    let expires_at_epoch: u64 = expires_str
        .parse()
        .map_err(|_| GatewayError::Unauthorized)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let msg = format!("{principal_str}:{issued_at_epoch}:{expires_at_epoch}");
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

    // Revocation: a bearer minted before its principal was deleted is
    // a dead session. The kernel's `AgentDelete` admin op publishes a
    // success audit event; the gateway subscribes and stores
    // `revoked_at[principal] = ts_epoch`. A bearer with
    // `iat <= revoked_at` cannot be the one minted *after* a possible
    // recreate, so reject it.
    if let Some(&revoked_at) = state
        .revoked_at
        .read()
        .expect("revocation map poisoned — fail-stop on the auth path")
        .get(&principal)
        && issued_at_epoch <= revoked_at
    {
        return Err(GatewayError::Unauthorized);
    }

    Ok(CallerContext {
        principal,
        issued_at_epoch,
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
            distribution: Arc::new(crate::routes::distribution::DistributionInfo::single_tenant()),
            onboarding: Arc::new(crate::routes::distribution::OnboardingFields::default()),
            redeem_limiter: tokio::sync::Mutex::default(),
            metrics_handle: crate::metrics::install_recorder().expect("recorder"),
            event_bus: None,
            revoked_at: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
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
        // any swap invalidates the check. Keep all four segments so
        // the rejection comes from the signature check, not the
        // segment-count guard.
        let parts: Vec<&str> = raw.split('.').collect();
        let eve = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("eve");
        let tampered = format!("{eve}.{}.{}.{}", parts[1], parts[2], parts[3]);
        assert!(verify_bearer(&state, &tampered).is_err());
    }

    #[test]
    fn malformed_token_rejected() {
        let state = test_state();
        assert!(verify_bearer(&state, "garbage").is_err());
        assert!(verify_bearer(&state, "a.b.c").is_err());
    }

    #[test]
    fn dot_flood_does_not_allocate_unboundedly() {
        // 10k dots → 10k+1 slices under split, but splitn(5) caps the
        // alloc at 5 slices. We only assert behaviour (rejection +
        // bounded work); the real DoS proof is in the splitn contract.
        let state = test_state();
        let dot_bomb = ".".repeat(10_000);
        assert!(verify_bearer(&state, &dot_bomb).is_err());
    }

    #[test]
    fn bearer_carries_iat_claim() {
        let state = test_state();
        let principal = PrincipalId::new("alice").unwrap();
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let raw = mint_bearer(&state.signing.signer, &principal, 3600);
        let caller = verify_bearer(&state, &raw).expect("verify");
        assert!(
            caller.issued_at_epoch >= before,
            "iat must reflect mint time (got {} < {before})",
            caller.issued_at_epoch
        );
        assert!(
            caller.expires_at_epoch > caller.issued_at_epoch,
            "exp must be strictly after iat"
        );
    }

    #[test]
    fn revoked_principal_rejects_pre_revoke_bearer() {
        let state = test_state();
        let principal = PrincipalId::new("alice").unwrap();
        let raw = mint_bearer(&state.signing.signer, &principal, 3600);
        let caller_pre = verify_bearer(&state, &raw).expect("pre-revoke verify passes");

        // Simulate an AgentDelete event landing at `iat + 1` (i.e.
        // strictly after the bearer was minted but before it would
        // naturally expire).
        state
            .revoked_at
            .write()
            .expect("write")
            .insert(principal.clone(), caller_pre.issued_at_epoch + 1);

        assert!(
            verify_bearer(&state, &raw).is_err(),
            "bearer with iat <= revoked_at must be rejected"
        );
    }

    #[test]
    fn revoked_principal_does_not_affect_other_principals() {
        let state = test_state();
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        let alice_bearer = mint_bearer(&state.signing.signer, &alice, 3600);
        let bob_bearer = mint_bearer(&state.signing.signer, &bob, 3600);

        // Revoke alice well into the future — every alice bearer dies.
        let far_future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
            + 10_000;
        state
            .revoked_at
            .write()
            .expect("write")
            .insert(alice, far_future);

        assert!(verify_bearer(&state, &alice_bearer).is_err());
        assert!(
            verify_bearer(&state, &bob_bearer).is_ok(),
            "revoking alice must not affect bob"
        );
    }

    #[test]
    fn bearer_minted_after_revocation_passes() {
        // Models the principal-recreate case: admin deletes alice
        // (revoked_at = T), then re-creates alice and issues a new
        // bearer. The new bearer's iat > T, so it must verify.
        let state = test_state();
        let alice = PrincipalId::new("alice").unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        // Set revoked_at *before* minting so the new bearer's iat
        // strictly follows.
        state
            .revoked_at
            .write()
            .expect("write")
            .insert(alice.clone(), now.saturating_sub(60));

        let raw = mint_bearer(&state.signing.signer, &alice, 3600);
        let caller = verify_bearer(&state, &raw)
            .expect("bearer minted after the recorded revocation epoch must still verify");
        assert_eq!(caller.principal, alice);
    }
}
