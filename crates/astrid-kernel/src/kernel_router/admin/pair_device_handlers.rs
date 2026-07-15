//! Layer 6 pair-device handlers (issue #756).
//!
//! Two operations:
//!
//! * `pair_device_issue` — mints a token tied to the verified
//!   caller's principal. The kernel binds the token to `caller`
//!   regardless of any wire-level hint, so the holder of a
//!   pair-token can never claim a key on someone else's principal.
//! * `pair_device_redeem` — the kernel dispatcher bypasses the
//!   cap-gate for this variant (token IS the auth). The handler
//!   verifies the token, appends the supplied ed25519 key to the
//!   bound principal's `AuthConfig.public_keys`, and removes the
//!   token (single-use).
//!
//! The store at `etc/pair-tokens.toml` persists only SHA-256
//! hashes — same posture as `etc/invites.toml`. Audit redaction
//! lives in `admin::mod::sanitize_admin_audit_params` so neither
//! the raw token nor the ed25519 key ever reaches the audit log.

use std::sync::Arc;

use astrid_capabilities::{CapabilityCheck, device_scope_within};
use astrid_core::PrincipalId;
use astrid_core::groups::GroupConfig;
use astrid_core::kernel_api::{
    AdminResponseBody, DeviceKeyInfo, PairScopeArg, PairTokenIssued, PairTokenRedeemed,
};
use astrid_core::profile::{
    AuthMethod, CapabilityPattern, DeviceKey, DeviceKeyId, DevicePubkey, DeviceScope,
    PrincipalProfile,
};
use tracing::{info, warn};

use crate::kernel_router::AuthorizedRequest;
use crate::pair_token::{self, MAX_EXPIRY_SECS, PairToken, PairTokenStore};

/// Default token lifetime when the issuer doesn't specify. Matches
/// the QR-scan window — a few minutes is plenty for the pairing
/// device to be close at hand.
const DEFAULT_EXPIRY_SECS: u64 = 5 * 60;

type PairIssuerAuthority = (Arc<PrincipalProfile>, Arc<GroupConfig>, Option<DeviceScope>);

fn resolve_pair_issuer_authority(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    authorization: Option<&AuthorizedRequest>,
    issuer_device_key_id: Option<&str>,
) -> Result<PairIssuerAuthority, AdminResponseBody> {
    if let Some(authorization) = authorization {
        return Ok((
            Arc::clone(&authorization.profile),
            Arc::clone(&authorization.groups),
            authorization.device_scope.clone(),
        ));
    }

    let profile_path = kernel.astrid_home.profile_path(caller);
    if !profile_path.exists() {
        return Err(err_bad_input(format!(
            "caller principal {caller} does not exist (no profile.toml)"
        )));
    }
    let profile = kernel
        .profile_cache
        .resolve(caller)
        .map_err(|error| err_internal(format!("issuer profile resolution failed: {error}")))?;
    let issuer_scope = crate::kernel_router::resolve_device_scope(
        profile.as_ref(),
        caller,
        issuer_device_key_id,
        "self:auth:pair",
    )
    .map_err(|error| err_unauthorized(error.to_string()))?;
    Ok((profile, kernel.groups.load_full(), issuer_scope))
}

pub(super) async fn pair_device_issue(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    authorization: Option<&AuthorizedRequest>,
    issuer_device_key_id: Option<&str>,
    expires_secs: Option<u64>,
    label: Option<String>,
    requested: PairScopeArg,
) -> AdminResponseBody {
    let (lifetime, requested_scope) = match validate_pair_issue(expires_secs, &requested) {
        Ok(values) => values,
        Err(error) => return err_bad_input(error),
    };

    let (profile, groups, issuer_scope) =
        match resolve_pair_issuer_authority(kernel, caller, authorization, issuer_device_key_id) {
            Ok(authority) => authority,
            Err(response) => return response,
        };
    let stored_scope = match validate_pair_issue_authority(
        caller,
        profile.as_ref(),
        groups.as_ref(),
        issuer_scope.as_ref(),
        &requested_scope,
    ) {
        Ok(scope) => scope,
        Err(error) => return err_unauthorized(error),
    };
    // Release the pinned authority snapshot before awaiting the write lock.
    drop(profile);
    drop(groups);

    let _guard = kernel.admin_write_lock.lock().await;
    let store = PairTokenStore::new(PairTokenStore::path_for(&kernel.astrid_home));
    let mut tokens = match store.load() {
        Ok(v) => v,
        Err(e) => return err_internal(format!("pair-tokens.toml load failed: {e}")),
    };
    let _ = pair_token::prune_expired(&mut tokens);

    let now = pair_token::now_epoch();
    let expires_at_epoch = now.saturating_add(lifetime);
    let token = pair_token::generate_token();
    let token_hash = pair_token::hash_token(&token);

    tokens.push(PairToken {
        token_hash: token_hash.clone(),
        principal: caller.clone(),
        expires_at_epoch,
        issued_at_epoch: now,
        label: label.clone(),
        scope: stored_scope.clone(),
    });

    if let Err(e) = store.save(&tokens) {
        return err_internal(format!("pair-tokens.toml save failed: {e}"));
    }

    info!(
        token_fingerprint = %token_hash,
        principal = %caller,
        expires_at_epoch,
        scope = ?stored_scope,
        "Layer 6 auth.pair.issue"
    );

    AdminResponseBody::PairToken(PairTokenIssued {
        token,
        principal: caller.clone(),
        expires_at_epoch,
        label,
    })
}

fn validate_pair_issue(
    expires_secs: Option<u64>,
    requested: &PairScopeArg,
) -> Result<(u64, DeviceScope), String> {
    let lifetime = expires_secs.unwrap_or(DEFAULT_EXPIRY_SECS);
    if lifetime == 0 {
        return Err("expires_secs must be greater than 0".into());
    }
    if lifetime > MAX_EXPIRY_SECS {
        return Err(format!(
            "expires_secs {lifetime} exceeds the 1-hour cap ({MAX_EXPIRY_SECS}s) — pair-tokens are intended for immediate use"
        ));
    }

    let scope = resolve_pair_scope(requested)?;
    validate_pair_scope_patterns(&scope)?;
    Ok((lifetime, scope))
}

/// Return whether the requested scope confers unattenuated authority and must
/// therefore pass the pair-admin capability preamble.
pub(super) fn pair_scope_requires_admin(scope: &PairScopeArg) -> bool {
    match scope {
        PairScopeArg::Full => true,
        PairScopeArg::Preset { name } => {
            matches!(DeviceScope::preset(name), Some(DeviceScope::Full))
        },
        PairScopeArg::Explicit { allow, .. } => allow.iter().any(|pattern| pattern == "*"),
    }
}

/// Pair-issuance failure class used to keep audit authorization and operation
/// outcomes distinct without changing the public error wire shape.
pub(super) enum PairIssuePreflightError {
    /// The caller was authorized, but the requested expiry or scope is invalid.
    BadInput(String),
    /// The requested scope exceeds the issuer's effective authority.
    Unauthorized(String),
}

/// Validate pair issuance against the exact policy snapshot pinned by the
/// router before it records an authorization success audit row.
pub(super) fn preflight_pair_device_issue(
    authorization: &AuthorizedRequest,
    expires_secs: Option<u64>,
    requested: &PairScopeArg,
) -> Result<(), PairIssuePreflightError> {
    let (_, requested_scope) =
        validate_pair_issue(expires_secs, requested).map_err(PairIssuePreflightError::BadInput)?;
    validate_pair_issue_authority(
        &authorization.principal,
        authorization.profile.as_ref(),
        authorization.groups.as_ref(),
        authorization.device_scope.as_ref(),
        &requested_scope,
    )
    .map_err(PairIssuePreflightError::Unauthorized)?;
    Ok(())
}

fn validate_pair_issue_authority(
    caller: &PrincipalId,
    profile: &PrincipalProfile,
    groups: &GroupConfig,
    issuer_scope: Option<&DeviceScope>,
    requested_scope: &DeviceScope,
) -> Result<DeviceScope, String> {
    let mut issuer_check = CapabilityCheck::new(profile, groups, caller.clone());
    if let Some(scope @ DeviceScope::Scoped { .. }) = issuer_scope {
        issuer_check = issuer_check.with_device_scope(scope);
    }
    if !issuer_check.has("self:auth:pair") {
        return Err(format!(
            "minting a paired device requires self:auth:pair, which {caller} does not effectively hold"
        ));
    }

    match requested_scope {
        DeviceScope::Full => {
            if matches!(issuer_scope, Some(DeviceScope::Scoped { .. })) {
                return Err(format!(
                    "a scoped device cannot mint a full-scope (unattenuated) device; issue a scoped device instead — {caller}"
                ));
            }
            if !issuer_check.has("self:auth:pair:admin") {
                return Err(format!(
                    "minting a full-scope device requires self:auth:pair:admin, which {caller} does not effectively hold"
                ));
            }
        },
        DeviceScope::Scoped { allow, .. } => {
            let requests_universal_scope = allow.iter().any(|pattern| pattern == "*");
            if requests_universal_scope && !issuer_check.has("self:auth:pair:admin") {
                return Err(format!(
                    "minting a device scope with universal `*` requires self:auth:pair:admin, which {caller} does not effectively hold"
                ));
            }
            if let Err(error) = device_scope_within(&issuer_check, requested_scope) {
                return Err(format!(
                    "requested device scope exceeds your authority: {error}"
                ));
            }
        },
    }

    Ok(inherit_issuer_denies(requested_scope.clone(), issuer_scope))
}

fn validate_pair_scope_patterns(scope: &DeviceScope) -> Result<(), String> {
    let DeviceScope::Scoped { allow, deny } = scope else {
        return Ok(());
    };
    for pattern in allow.iter().chain(deny) {
        CapabilityPattern::new(pattern.as_str()).map_err(|error| {
            format!("invalid device scope capability pattern {pattern:?}: {error}")
        })?;
    }
    Ok(())
}

/// Resolve a [`PairScopeArg`] to a concrete [`DeviceScope`]. An unknown preset
/// name is rejected (fail-closed) rather than silently defaulting.
fn resolve_pair_scope(arg: &PairScopeArg) -> Result<DeviceScope, String> {
    match arg {
        PairScopeArg::Full => Ok(DeviceScope::Full),
        PairScopeArg::Preset { name } => {
            DeviceScope::preset(name).ok_or_else(|| format!("unknown device scope preset {name:?}"))
        },
        PairScopeArg::Explicit { allow, deny } => Ok(DeviceScope::Scoped {
            allow: allow.clone(),
            deny: deny.clone(),
        }),
    }
}

/// Fold the issuer's own device-scope denies into the child scope so the child
/// can never exceed the parent (monotonic narrowing). A `Full` child from a
/// scoped issuer would have already been rejected by the full-mint gate, so
/// only the `Scoped` child path inherits; a `Full`/`None` issuer adds nothing.
fn inherit_issuer_denies(child: DeviceScope, issuer_scope: Option<&DeviceScope>) -> DeviceScope {
    let (
        Some(DeviceScope::Scoped {
            deny: issuer_deny, ..
        }),
        DeviceScope::Scoped { allow, deny },
    ) = (issuer_scope, &child)
    else {
        return child;
    };
    let mut merged_deny = deny.clone();
    for pattern in issuer_deny {
        if !merged_deny.contains(pattern) {
            merged_deny.push(pattern.clone());
        }
    }
    DeviceScope::Scoped {
        allow: allow.clone(),
        deny: merged_deny,
    }
}

pub(crate) async fn pair_device_redeem(
    kernel: &Arc<crate::Kernel>,
    token: String,
    public_key: String,
) -> AdminResponseBody {
    // Validate the key shape first so a malformed key takes the
    // same time as a valid one — no key-shape oracle on the token
    // comparison.
    let normalised_key = match DevicePubkey::normalize(&public_key) {
        Ok(k) => k,
        Err(e) => return err_bad_input(e),
    };

    let _guard = kernel.admin_write_lock.lock().await;
    let store = PairTokenStore::new(PairTokenStore::path_for(&kernel.astrid_home));
    let mut tokens = match store.load() {
        Ok(v) => v,
        Err(e) => return err_internal(format!("pair-tokens.toml load failed: {e}")),
    };
    let _ = pair_token::prune_expired(&mut tokens);

    let token_hash = pair_token::hash_token(&token);
    let now = pair_token::now_epoch();

    // Constant-time scan over live tokens — no early-return on
    // partial match.
    let mut matched_index: Option<usize> = None;
    for (i, t) in tokens.iter().enumerate() {
        let live = t.expires_at_epoch > now;
        let hit = pair_token::ct_hash_eq(&t.token_hash, &token_hash) && live;
        if hit && matched_index.is_none() {
            matched_index = Some(i);
        }
    }

    let Some(idx) = matched_index else {
        return err_unauthorized("pair-device token invalid or expired".into());
    };

    let chosen = tokens[idx].clone();

    // Load the bound principal's profile and append the key.
    let profile_path = kernel.astrid_home.profile_path(&chosen.principal);
    if !profile_path.exists() {
        return err_internal(format!(
            "bound principal {} disappeared between issue and redeem",
            chosen.principal
        ));
    }
    let mut profile = match PrincipalProfile::load_from_path(&profile_path) {
        Ok(p) => p,
        Err(e) => return err_internal(format!("profile load failed: {e}")),
    };

    // Dedup by canonical pubkey so re-redeeming the same key is idempotent
    // (the deterministic key_id makes the device handle stable). The redeemed
    // device is registered with the scope the token was issued under (resolved
    // + validated at issue time, with the issuer's denies already folded in),
    // so the paired device is attenuated to exactly that scope on every
    // transport — not hard-coded to Full.
    if profile
        .auth
        .device_by_typed_pubkey(&normalised_key)
        .is_none()
    {
        profile.auth.public_keys.push(DeviceKey::new(
            normalised_key.as_str().to_string(),
            chosen.scope.clone(),
            chosen.label.clone(),
            i64::try_from(now).unwrap_or(0),
        ));
    }
    if !profile.auth.methods.contains(&AuthMethod::Keypair) {
        profile.auth.methods.push(AuthMethod::Keypair);
    }

    if let Err(e) = profile.validate() {
        return err_internal(format!("profile rejected after key append: {e}"));
    }
    if let Err(e) = profile.save_to_path(&profile_path) {
        return err_internal(format!("profile save failed: {e}"));
    }
    kernel.profile_cache.invalidate(&chosen.principal);

    // Single-use: remove the token.
    tokens.remove(idx);
    if let Err(e) = store.save(&tokens) {
        warn!(
            error = %e,
            principal = %chosen.principal,
            security_event = true,
            "auth.pair.redeem: pair-tokens.toml save failed AFTER key append; manual reconciliation may be required"
        );
    }

    let fingerprint =
        super::invite_handlers::fingerprint_public_key(&format!("ed25519:{normalised_key}"));
    let key_id = DeviceKeyId::for_pubkey(&normalised_key);
    info!(
        principal = %chosen.principal,
        public_key_fingerprint = %fingerprint,
        key_id = %key_id,
        label = ?chosen.label,
        "Layer 6 auth.pair.redeem"
    );

    AdminResponseBody::PairTokenRedeemed(PairTokenRedeemed {
        principal: chosen.principal,
        public_key_fingerprint: fingerprint,
        key_id: key_id.into_inner(),
    })
}

/// List the paired devices on `principal`'s profile as fingerprint-level
/// summaries. The raw ed25519 pubkey is never surfaced — only the
/// deterministic `key_id`, label, scope, and pairing timestamp.
///
/// Read-only: no write lock, no profile mutation. A missing profile is a
/// not-found error (a phantom principal has no devices to list).
pub(crate) fn pair_device_list(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
) -> AdminResponseBody {
    let profile_path = kernel.astrid_home.profile_path(principal);
    if !profile_path.exists() {
        return err_bad_input(format!(
            "principal {principal} does not exist (no profile.toml)"
        ));
    }
    let profile = match PrincipalProfile::load_from_path(&profile_path) {
        Ok(p) => p,
        Err(e) => return err_internal(format!("profile load failed: {e}")),
    };
    let devices: Vec<DeviceKeyInfo> = profile
        .auth
        .public_keys
        .iter()
        .map(|k| DeviceKeyInfo {
            key_id: k.key_id.clone(),
            label: k.label.clone(),
            scope: k.scope.clone(),
            created_at: k.created_at,
        })
        .collect();
    info!(
        principal = %principal,
        device_count = devices.len(),
        "Layer 6 auth.pair.list"
    );
    AdminResponseBody::PairDeviceListed(devices)
}

/// Revoke a single paired device by its deterministic `key_id`, removing the
/// matching [`DeviceKey`] from `principal`'s `AuthConfig.public_keys`.
///
/// If the removed key was the last keypair entry, the `AuthMethod::Keypair`
/// method is dropped too (mirrors the add side in redeem). The profile is
/// saved atomically and the profile cache invalidated so the kernel cap-gate
/// fails closed for that key immediately. A `key_id` that matches no device is
/// a not-found error (fail-closed — never a silent success).
pub(crate) async fn pair_device_revoke(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    key_id: &str,
) -> AdminResponseBody {
    let key_id = match DeviceKeyId::new(key_id) {
        Ok(key_id) => key_id,
        Err(e) => return err_bad_input(e),
    };
    let _guard = kernel.admin_write_lock.lock().await;
    let profile_path = kernel.astrid_home.profile_path(principal);
    if !profile_path.exists() {
        return err_bad_input(format!(
            "principal {principal} does not exist (no profile.toml)"
        ));
    }
    let mut profile = match PrincipalProfile::load_from_path(&profile_path) {
        Ok(p) => p,
        Err(e) => return err_internal(format!("profile load failed: {e}")),
    };

    let before = profile.auth.public_keys.len();
    profile
        .auth
        .public_keys
        .retain(|k| k.key_id != key_id.as_str());
    if profile.auth.public_keys.len() == before {
        return err_bad_input(format!(
            "no paired device with key_id {key_id} on principal {principal}"
        ));
    }

    // If that was the last keypair, drop the Keypair auth method so the
    // profile's declared auth surface matches its registered keys (mirrors the
    // add-side logic in redeem).
    if profile.auth.public_keys.is_empty() {
        profile.auth.methods.retain(|m| *m != AuthMethod::Keypair);
    }

    if let Err(e) = profile.validate() {
        return err_internal(format!("profile rejected after device removal: {e}"));
    }
    if let Err(e) = profile.save_to_path(&profile_path) {
        return err_internal(format!("profile save failed: {e}"));
    }
    kernel.profile_cache.invalidate(principal);

    info!(
        principal = %principal,
        key_id = %key_id,
        security_event = true,
        "Layer 6 auth.pair.revoke"
    );

    AdminResponseBody::PairDeviceRevoked {
        key_id: key_id.to_string(),
    }
}

fn err_bad_input(msg: String) -> AdminResponseBody {
    warn!(error = %msg, "pair-device request rejected: bad input");
    AdminResponseBody::Error(msg)
}

fn err_internal(msg: String) -> AdminResponseBody {
    warn!(error = %msg, "pair-device request failed: internal error");
    AdminResponseBody::Error(msg)
}

fn err_unauthorized(msg: String) -> AdminResponseBody {
    warn!(security_event = true, error = %msg, "pair-device request denied");
    AdminResponseBody::Error(msg)
}
