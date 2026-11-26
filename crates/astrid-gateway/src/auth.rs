//! Bearer-token signing, verification, and the principal-extraction
//! middleware.
//!
//! Device registrations use a seven-segment bearer (v4). The first five segments
//! match v3, followed by the persisted registration UUID and signature. The v4
//! signature covers a protocol tag and the six dot-separated wire segments.
//! Refresh preserves the authenticated generation, including its absence on a legacy key.
//!
//! ## Wire format (v3)
//!
//! ```text
//! b64(principal) "." b64(iat) "." b64(exp) "." b64(key_id)-or-`~` "." request_owner_uuid "." hex(sig)
//! ```
//!
//! The signature covers
//! `principal_id:issued_at_epoch:expires_at_epoch:key_id-or-~:request_owner_uuid`.
//! The random request owner makes independently minted bearers distinct even
//! when they are issued for the same principal during the same second.
//!
//! ## Device-scoped bearers (v2.1)
//!
//! A bearer may OPTIONALLY carry the `key_id` of the registered device key it
//! was minted for, so a paired device's per-device scope can be enforced at
//! the kernel cap-gate. The fourth segment is `~` for full-authority sessions
//! and contains the base64url key id for device-scoped sessions. Legacy
//! 4-segment full-authority and 5-segment device-scoped bearers keep verifying
//! unchanged; their request owner is deterministically derived from the signed
//! bearer because those formats did not carry a session nonce.
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
use astrid_core::profile::{DeviceKeyId, DeviceRegistrationId};
use astrid_core::session_token::registration_transcript;
use astrid_events::ipc::{IpcMessage, MessageOrigin, RequestOwnerId};
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
    /// The registered device `key_id` this bearer was minted for, when the
    /// token is device-scoped (5-segment form). `None` for a legacy
    /// full-authority (4-segment) bearer. Stamped onto every gateway→kernel
    /// admin request so the cap-gate can apply the device's scope as an
    /// attenuation floor. Cryptographically bound: it is part of the signed
    /// message, so a tampered or stripped `key_id` fails verification.
    pub device_key_id: Option<String>,
    /// Registration signed into the bearer when it was paired.
    pub registration_id: Option<DeviceRegistrationId>,
    /// Opaque owner of this authenticated bearer session.
    ///
    /// Derived from the verified bearer rather than supplied by an HTTP body,
    /// so two independently authenticated sessions for one principal cannot
    /// observe or answer each other's approval prompts. Reusing the same bearer
    /// intentionally means reusing the same authenticated session.
    pub request_owner: RequestOwnerId,
}

impl CallerContext {
    /// Bind a gateway-originated publication to this authenticated bearer.
    /// Downstream capability checks use the device and transport origin, and
    /// interactive replies use the request owner to reach the issuing client.
    pub(crate) fn stamp_ipc(&self, mut message: IpcMessage) -> IpcMessage {
        message.device_key_id.clone_from(&self.device_key_id);
        message.device_registration_id = self.registration_id.map(Into::into);
        message
            .with_principal(self.principal.to_string())
            .with_request_owner(self.request_owner)
            .with_origin(MessageOrigin::RemoteGateway)
    }
}

/// Stable, non-secret comparison handle for one authenticated bearer.
///
/// UUID v5 is used only as a compact deterministic encoding. The namespace is
/// private to this protocol and the bearer contains an Ed25519 signature, so
/// the resulting handle is not a credential and does not expose the bearer.
fn request_owner_for_bearer(raw: &str) -> RequestOwnerId {
    const NAMESPACE: uuid::Uuid = uuid::uuid!("b5742a04-3466-5af3-a65c-42b062736f86");
    uuid::Uuid::new_v5(&NAMESPACE, raw.as_bytes())
        .to_string()
        .parse()
        .expect("UUID v5 always parses as a request owner")
}

/// Mint a fresh session bearer for `principal`.
#[must_use]
pub fn mint_bearer(signer: &SigningKey, principal: &PrincipalId, lifetime_secs: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let expires = now.saturating_add(lifetime_secs);
    let request_owner = RequestOwnerId::generate();
    let msg = format!("{principal}:{now}:{expires}:~:{request_owner}");
    let sig: Signature = signer.sign(msg.as_bytes());

    let p_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(principal.as_str());
    let i_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(now.to_string());
    let e_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expires.to_string());
    let s_hex = hex::encode(sig.to_bytes());
    format!("{p_b64}.{i_b64}.{e_b64}.~.{request_owner}.{s_hex}")
}

/// Mint a device-scoped session bearer for `principal` bound to the registered
/// device `key_id`.
///
/// The five-segment form carries `key_id` as a fourth base64url segment and
/// signs `principal:iat:exp:key_id`, so the kernel cap-gate can resolve the
/// device's scope and attenuate the principal's authority. Used for a new
/// device's bearer at pair-device redeem, and to preserve the device dimension
/// across a refresh of an already-scoped bearer.
#[must_use]
pub fn mint_bearer_scoped(
    signer: &SigningKey,
    principal: &PrincipalId,
    key_id: &str,
    lifetime_secs: u64,
) -> String {
    mint_device_bearer(signer, principal, key_id, None, lifetime_secs)
}

/// Mint a bearer for the registration selected by pairing or by a verified refresh.
pub(crate) fn mint_device_bearer(
    signer: &SigningKey,
    principal: &PrincipalId,
    key_id: &str,
    registration: Option<DeviceRegistrationId>,
    lifetime_secs: u64,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let expires = now.saturating_add(lifetime_secs);
    let request_owner = RequestOwnerId::generate();
    let p_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(principal.as_str());
    let i_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(now.to_string());
    let e_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expires.to_string());
    let k_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_id);
    let mut unsigned = format!("{p_b64}.{i_b64}.{e_b64}.{k_b64}.{request_owner}");
    let transcript = if let Some(id) = registration {
        let registration = id.to_string();
        let transcript = registration_transcript(&unsigned, &registration);
        unsigned.push('.');
        unsigned.push_str(&registration);
        transcript
    } else {
        format!("{principal}:{now}:{expires}:{key_id}:{request_owner}")
    };
    let sig = signer.sign(transcript.as_bytes());
    format!("{unsigned}.{}", hex::encode(sig.to_bytes()))
}

fn decode_device(
    key: Option<&str>,
    has_owner: bool,
    registration: Option<&str>,
) -> Result<(Option<String>, Option<DeviceRegistrationId>), GatewayError> {
    let key_id = match key {
        None => None,
        Some("~") if has_owner => None,
        Some(encoded) => {
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| GatewayError::Unauthorized)?;
            Some(String::from_utf8(bytes).map_err(|_| GatewayError::Unauthorized)?)
        },
    };
    let generation = if let Some(raw) = registration {
        DeviceKeyId::new(key_id.as_deref().ok_or(GatewayError::Unauthorized)?)
            .map_err(|_| GatewayError::Unauthorized)?;
        let id: DeviceRegistrationId = raw.parse().map_err(|_| GatewayError::Unauthorized)?;
        if id.to_string() != raw {
            return Err(GatewayError::Unauthorized);
        }
        Some(id)
    } else {
        None
    };
    Ok((key_id, generation))
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
    // One slice beyond the largest wire format bounds allocation and rejects extra fields.
    let parts: Vec<&str> = raw.splitn(8, '.').collect();
    let (key_id_seg, owner_seg, registration_seg, sig_seg) = match parts.len() {
        4 => (None, None, None, 3),
        5 => (Some(3), None, None, 4),
        6 => (Some(3), Some(4), None, 5),
        7 => (Some(3), Some(4), Some(5), 6),
        _ => return Err(GatewayError::Unauthorized),
    };

    let p_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| GatewayError::Unauthorized)?;
    let i_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| GatewayError::Unauthorized)?;
    let e_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| GatewayError::Unauthorized)?;
    let (device_key_id, registration_id) = decode_device(
        key_id_seg.map(|idx| parts[idx]),
        owner_seg.is_some(),
        registration_seg.map(|idx| parts[idx]),
    )?;
    let request_owner = owner_seg
        .map(|idx| parts[idx].parse::<RequestOwnerId>())
        .transpose()
        .map_err(|_| GatewayError::Unauthorized)?;
    let s_bytes = hex::decode(parts[sig_seg]).map_err(|_| GatewayError::Unauthorized)?;
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
    if issued_str != issued_at_epoch.to_string() || expires_str != expires_at_epoch.to_string() {
        return Err(GatewayError::Unauthorized);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    // Reconstruct the signed message for the bearer's generation. Current
    // tokens bind both the optional key id and request-owner nonce. Legacy
    // tokens retain their historical message shape.
    let msg = match (registration_id, &request_owner, &device_key_id) {
        (Some(_), _, _) => registration_transcript(&parts[..5].join("."), parts[5]),
        (None, Some(owner), key_id) => format!(
            "{principal_str}:{issued_at_epoch}:{expires_at_epoch}:{}:{owner}",
            key_id.as_deref().unwrap_or("~")
        ),
        (None, None, Some(key_id)) => {
            format!("{principal_str}:{issued_at_epoch}:{expires_at_epoch}:{key_id}")
        },
        (None, None, None) => format!("{principal_str}:{issued_at_epoch}:{expires_at_epoch}"),
    };
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

    // Per-device revocation: a device-scoped bearer minted at-or-before the
    // moment its `key_id` was revoked (`PairDeviceRevoke`) is a dead session —
    // stop it immediately rather than waiting for its TTL. Defense in depth: the
    // key is already gone from the principal's `public_keys`, so every kernel
    // request would fail closed anyway, but this rejects the HTTP bearer at the
    // edge. The `iat <= revoked_at` comparison (mirroring principal revocation)
    // means a bearer minted *after* the same deterministic key was re-paired
    // still authenticates — the map is not a permanent deny-list.
    if let Some(key_id) = &device_key_id
        && let Some(&revoked_at) = state
            .revoked_key_ids
            .read()
            .expect("revoked-key-id map poisoned — fail-stop on the auth path")
            .get(key_id)
        && issued_at_epoch <= revoked_at
    {
        return Err(GatewayError::Unauthorized);
    }

    Ok(CallerContext {
        principal,
        issued_at_epoch,
        expires_at_epoch,
        device_key_id,
        registration_id,
        request_owner: request_owner.unwrap_or_else(|| request_owner_for_bearer(raw)),
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

    fn mint_legacy_bearer(
        signer: &SigningKey,
        principal: &PrincipalId,
        key_id: Option<&str>,
    ) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let expires = now.saturating_add(3600);
        let msg = key_id.map_or_else(
            || format!("{principal}:{now}:{expires}"),
            |key_id| format!("{principal}:{now}:{expires}:{key_id}"),
        );
        let sig: Signature = signer.sign(msg.as_bytes());
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(principal.as_str());
        let i = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(now.to_string());
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expires.to_string());
        let sig = hex::encode(sig.to_bytes());
        match key_id {
            Some(key_id) => {
                let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_id);
                format!("{p}.{i}.{e}.{key}.{sig}")
            },
            None => format!("{p}.{i}.{e}.{sig}"),
        }
    }

    fn test_state() -> Arc<GatewayState> {
        let cfg = crate::config::GatewayConfig::default();
        Arc::new(GatewayState {
            config: cfg,
            storage_kv: None,
            signing: SigningMaterial::fresh(),
            distribution: Arc::new(crate::routes::distribution::DistributionInfo::single_tenant()),
            onboarding: Arc::new(crate::routes::distribution::OnboardingFields::default()),
            redeem_limiter: tokio::sync::Mutex::default(),
            metrics_handle: crate::metrics::install_recorder().expect("recorder"),
            event_bus: None,
            revoked_at: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            revoked_key_ids: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            audit_log: None,
            session_id: None,
            gateway_route_uuid: uuid::Uuid::new_v4(),
            readiness_probe: None,
            topic_probe: None,
            registry_timeout: None,
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
    fn request_owner_is_stable_per_bearer_and_distinct_across_sessions() {
        let state = test_state();
        let alice = PrincipalId::new("alice").unwrap();
        let alice_raw = mint_bearer(&state.signing.signer, &alice, 3600);
        let other_alice_raw = mint_bearer(&state.signing.signer, &alice, 3600);

        let first = verify_bearer(&state, &alice_raw).expect("first verify");
        let repeated = verify_bearer(&state, &alice_raw).expect("repeated verify");
        let other = verify_bearer(&state, &other_alice_raw).expect("other verify");

        assert_ne!(alice_raw, other_alice_raw);
        assert_eq!(first.request_owner, repeated.request_owner);
        assert_ne!(first.request_owner, other.request_owner);
    }

    #[test]
    fn unscoped_bearer_carries_no_device_key_id() {
        let state = test_state();
        let principal = PrincipalId::new("alice").unwrap();
        let raw = mint_bearer(&state.signing.signer, &principal, 3600);
        assert_eq!(raw.split('.').count(), 6);
        let caller = verify_bearer(&state, &raw).expect("verify");
        assert_eq!(caller.device_key_id, None);
    }

    #[tokio::test]
    async fn http_refresh_preserves_the_signed_device_registration() {
        use tower::ServiceExt;
        let state = test_state();
        let principal = PrincipalId::new("paired").unwrap();
        let key = "0123456789abcdef";
        let generation: DeviceRegistrationId = uuid::Uuid::new_v4().to_string().parse().unwrap();
        for registration in [Some(generation), None] {
            let token =
                mint_device_bearer(&state.signing.signer, &principal, key, registration, 600);
            let original = verify_bearer(&state, &token).unwrap();
            assert_eq!(original.registration_id, registration);
            let response = crate::routes::build(state.clone())
                .oneshot(
                    axum::http::Request::post("/api/auth/refresh")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let reply: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let refreshed =
                verify_bearer(&state, reply["session_token"].as_str().unwrap()).unwrap();
            assert_eq!(refreshed.registration_id, registration);
            assert_eq!(refreshed.principal, principal);
            assert_eq!(refreshed.device_key_id.as_deref(), Some(key));
            assert_ne!(refreshed.request_owner, original.request_owner);
        }
    }

    #[test]
    fn scoped_bearer_round_trips_and_carries_key_id() {
        // A current device-scoped bearer verifies and surfaces the bound
        // key_id, so the cap-gate can apply that device's scope.
        let state = test_state();
        let principal = PrincipalId::new("alice").unwrap();
        let raw = mint_bearer_scoped(&state.signing.signer, &principal, "dev-abc123", 3600);
        let caller = verify_bearer(&state, &raw).expect("verify");
        assert_eq!(caller.principal, principal);
        assert_eq!(
            caller.device_key_id.as_deref(),
            Some("dev-abc123"),
            "a scoped bearer must surface its device key_id"
        );
    }

    #[test]
    fn legacy_bearers_remain_valid_after_session_owner_upgrade() {
        let state = test_state();
        let principal = PrincipalId::new("alice").unwrap();
        let unscoped = mint_legacy_bearer(&state.signing.signer, &principal, None);
        let scoped = mint_legacy_bearer(&state.signing.signer, &principal, Some("dev-legacy"));

        let unscoped_caller = verify_bearer(&state, &unscoped).expect("legacy unscoped verify");
        let scoped_caller = verify_bearer(&state, &scoped).expect("legacy scoped verify");

        assert_eq!(unscoped_caller.device_key_id, None);
        assert_eq!(scoped_caller.device_key_id.as_deref(), Some("dev-legacy"));
        assert_eq!(
            unscoped_caller.request_owner,
            request_owner_for_bearer(&unscoped)
        );
        assert_eq!(
            scoped_caller.request_owner,
            request_owner_for_bearer(&scoped)
        );
    }

    #[test]
    fn legacy_bearer_with_non_canonical_numeric_claim_rejected() {
        let state = test_state();
        let principal = PrincipalId::new("alice").unwrap();
        let raw = mint_legacy_bearer(&state.signing.signer, &principal, None);
        let parts: Vec<&str> = raw.split('.').collect();
        let issued = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("issued claim decodes");
        let issued = std::str::from_utf8(&issued).expect("issued claim utf8");
        let tampered_issued =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("0{issued}"));
        let tampered = format!("{}.{tampered_issued}.{}.{}", parts[0], parts[2], parts[3]);

        assert!(
            verify_bearer(&state, &tampered).is_err(),
            "legacy numeric claims must use their canonical signed encoding"
        );
    }

    #[test]
    fn scoped_bearer_tampered_key_id_rejected() {
        // The key_id is part of the signed message, so swapping it for a
        // different (e.g. full-scope) device's id invalidates the signature —
        // a scoped device cannot escalate by re-labelling its bearer.
        let state = test_state();
        let principal = PrincipalId::new("alice").unwrap();
        let raw = mint_bearer_scoped(&state.signing.signer, &principal, "dev-scoped", 3600);
        let parts: Vec<&str> = raw.split('.').collect();
        assert_eq!(parts.len(), 6, "scoped bearer must be 6 segments");
        // Replace the encoded key_id with a different device id but keep the
        // original signature.
        let forged_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("dev-full-admin");
        let tampered = format!(
            "{}.{}.{}.{forged_key}.{}.{}",
            parts[0], parts[1], parts[2], parts[4], parts[5]
        );
        assert!(
            verify_bearer(&state, &tampered).is_err(),
            "a tampered key_id must fail signature verification"
        );
    }

    #[test]
    fn scoped_bearer_stripped_to_unscoped_rejected() {
        // Emptying the key_id segment to forge a full-authority bearer must
        // fail because the key id is part of the signed message.
        let state = test_state();
        let principal = PrincipalId::new("alice").unwrap();
        let raw = mint_bearer_scoped(&state.signing.signer, &principal, "dev-scoped", 3600);
        let parts: Vec<&str> = raw.split('.').collect();
        let stripped = format!(
            "{}.{}.{}.~.{}.{}",
            parts[0], parts[1], parts[2], parts[4], parts[5]
        );
        assert!(
            verify_bearer(&state, &stripped).is_err(),
            "stripping the key_id to forge a legacy bearer must fail"
        );
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
        let tampered = std::iter::once(eve.as_str())
            .chain(parts[1..].iter().copied())
            .collect::<Vec<_>>()
            .join(".");
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
        // 10k dots → 10k+1 slices under split, but splitn(7) caps the
        // alloc at 7 slices. We only assert behaviour (rejection +
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
