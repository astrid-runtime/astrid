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
//! The system-owner durable store persists only domain-separated BLAKE3
//! hashes. Audit redaction lives in `admin::mod::sanitize_admin_audit_params`
//! so neither the raw token nor the ed25519 key ever reaches the audit log.

mod deny_patterns;

pub(super) use super::pair_issue_result::PairIssueError;
use super::pair_issue_result::{self, Inserted};

use std::sync::Arc;

use astrid_capabilities::{CapabilityCheck, device_scope_within};
use astrid_core::PrincipalId;
use astrid_core::groups::GroupConfig;
use astrid_core::kernel_api::{
    AdminResponseBody, DeviceKeyInfo, PairScopeArg, PairTokenIssued, PairTokenRedeemed,
};
use astrid_core::profile::{
    AuthMethod, CapabilityPattern, DeviceKey, DeviceKeyId, DevicePubkey, DeviceScope,
    PrincipalProfile, ProfileError,
};
use tracing::{info, warn};

use crate::kernel_router::AuthorizedRequest;
use crate::pair_token::{self, DurablePairToken, DurablePairTokenStore, MAX_EXPIRY_SECS};

/// Default token lifetime when the issuer doesn't specify. Matches
/// the QR-scan window — a few minutes is plenty for the pairing
/// device to be close at hand.
const DEFAULT_EXPIRY_SECS: u64 = 5 * 60;

type PairIssuerAuthority = (PrincipalProfile, Arc<GroupConfig>, Option<DeviceScope>);

fn pair_token_store(kernel: &Arc<crate::Kernel>) -> Result<DurablePairTokenStore, String> {
    let unavailable = || "pair-token durable storage is unavailable".to_owned();
    let store = kernel.principal_store.as_ref().ok_or_else(unavailable)?;
    DurablePairTokenStore::new(store.kv()).map_err(|_| unavailable())
}

fn current_pair_issuer_authority(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    admitted: Option<&AuthorizedRequest>,
    issuer_device_key_id: Option<&str>,
) -> Result<PairIssuerAuthority, PairIssueError> {
    let profile =
        PrincipalProfile::load_required(&kernel.astrid_home, caller).map_err(|error| {
            if matches!(&error, ProfileError::Io(io) if io.kind() == std::io::ErrorKind::NotFound) {
                let message = format!("caller principal {caller} does not exist (no profile.toml)");
                if admitted.is_some() {
                    PairIssueError::Unauthorized(message)
                } else {
                    PairIssueError::BadInput(message)
                }
            } else {
                PairIssueError::Internal(format!("issuer profile resolution failed: {error}"))
            }
        })?;
    if !profile.enabled {
        return Err(PairIssueError::Unauthorized(format!(
            "caller principal {caller} is disabled"
        )));
    }
    let issuer_scope = if let Some(auth) = admitted {
        let device = astrid_events::ipc::DeviceStamp {
            fingerprint: auth
                .device_key_id
                .as_ref()
                .map(astrid_core::profile::DeviceKeyId::as_str),
            registration: auth.device_registration.map(Into::into),
        };
        crate::kernel_router::device_scope::resolve_stamp(
            &profile,
            caller,
            device,
            "self:auth:pair",
        )
        .map(|record| record.map(|record| record.scope.clone()))
    } else {
        crate::kernel_router::resolve_device_scope(
            &profile,
            caller,
            issuer_device_key_id,
            "self:auth:pair",
        )
    }
    .map_err(|error| PairIssueError::Unauthorized(error.to_string()))?;
    Ok((profile, kernel.groups.load_full(), issuer_scope))
}

pub(super) async fn pair_device_issue(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    authorization: Option<&AuthorizedRequest>,
    issuer_device_key_id: Option<&str>,
    expires_secs: Option<u64>,
    label: Option<String>,
    requested: &PairScopeArg,
) -> Result<PairTokenIssued, PairIssueError> {
    let (lifetime, requested_scope) =
        validate_pair_issue(expires_secs, requested).map_err(PairIssueError::BadInput)?;
    // Preserve restrictions from ingress if policy widens while this issue waits.
    let admitted_scope = if let Some(auth) = authorization {
        validate_pair_issue_authority(
            caller,
            &auth.profile,
            &auth.groups,
            auth.device_scope.as_ref(),
            &requested_scope,
        )
        .map_err(PairIssueError::Unauthorized)?
    } else {
        requested_scope
    };

    let _guard = kernel.admin_write_lock.lock().await;
    let (profile, groups, issuer_scope) =
        current_pair_issuer_authority(kernel, caller, authorization, issuer_device_key_id)?;
    let stored_scope = validate_pair_issue_authority(
        caller,
        &profile,
        &groups,
        issuer_scope.as_ref(),
        &admitted_scope,
    )
    .map_err(PairIssueError::Unauthorized)?;
    let store = pair_token_store(kernel).map_err(PairIssueError::Internal)?;
    if store
        .ensure_legacy_import(&kernel.astrid_home, &kernel.principal_directory)
        .await
        .is_err()
    {
        return Err(PairIssueError::Internal(
            "pair-token durable storage is unavailable".into(),
        ));
    }
    if store.prune().await.is_err() {
        return Err(PairIssueError::Internal(
            "pair-token durable storage could not be pruned".into(),
        ));
    }
    let Ok(principal_uid) = kernel.principal_directory.uid_for(caller) else {
        return Err(PairIssueError::Internal(
            "caller has no durable principal identity".into(),
        ));
    };

    let now = pair_token::now_epoch();
    let expires_at_epoch = now.saturating_add(lifetime);
    let token = pair_token::generate_token();
    let token_hash = pair_token::hash_token(&token);

    let record = DurablePairToken {
        token_hash: token_hash.clone(),
        principal_uid,
        expires_at_epoch,
        issued_at_epoch: now,
        label: label.clone(),
        scope: stored_scope.clone(),
    };
    let token = match pair_issue_result::finish(&store.issue(&record).await, token) {
        Inserted::Issued(value) => value,
        Inserted::Collision => {
            return Err(PairIssueError::Internal(
                "pair-token identifier collision".into(),
            ));
        },
        Inserted::Unavailable => {
            return Err(PairIssueError::Internal(
                "pair-token durable storage write failed".into(),
            ));
        },
    };

    info!(
        token_fingerprint = %token_hash,
        principal = %caller,
        expires_at_epoch,
        scope = ?stored_scope,
        "Layer 6 auth.pair.issue"
    );

    Ok(PairTokenIssued {
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

impl PairIssueError {
    pub(super) fn into_body(self) -> AdminResponseBody {
        match self {
            Self::BadInput(message) => err_bad_input(message),
            Self::Unauthorized(message) => err_unauthorized(message),
            Self::Internal(message) => err_internal(message),
        }
    }
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
    deny_patterns::inherit(&mut merged_deny, issuer_deny);
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
    let store = match pair_token_store(kernel) {
        Ok(store) => store,
        Err(error) => return err_internal(error),
    };
    if store
        .ensure_legacy_import(&kernel.astrid_home, &kernel.principal_directory)
        .await
        .is_err()
    {
        return err_internal("pair-token durable storage is unavailable".into());
    }

    let token_hash = pair_token::hash_token(&token);
    let Some(chosen) = (match store.redeemable(&token_hash).await {
        Ok(value) => value,
        Err(_) => return err_internal("pair-token durable storage read failed".into()),
    }) else {
        return err_unauthorized("pair-device token invalid or expired".into());
    };

    // Claim the exact durable record before touching the profile. Concurrent
    // daemons cannot prepare competing writes, while a failed preparation can
    // restore this exact record rather than blindly reissuing at the same key.
    match store.reserve_if_unchanged(&chosen).await {
        Ok(true) => {},
        Ok(false) => return err_unauthorized("pair-device token invalid or expired".into()),
        Err(_) => return err_internal("pair-token durable storage write failed".into()),
    }

    match pair_device_redeem_reserved(kernel, &store, chosen.clone(), normalised_key).await {
        Ok(response) => response,
        Err(response) => match store.release_reservation(&chosen).await {
            Ok(_) => response,
            Err(_) => err_internal("pair-token reservation rollback failed".into()),
        },
    }
}

async fn pair_device_redeem_reserved(
    kernel: &Arc<crate::Kernel>,
    store: &DurablePairTokenStore,
    chosen: DurablePairToken,
    normalised_key: DevicePubkey,
) -> Result<AdminResponseBody, AdminResponseBody> {
    let Ok(principal) = kernel.principal_directory.alias_for(chosen.principal_uid) else {
        return Err(err_internal(
            "paired principal identity is no longer admitted".into(),
        ));
    };
    let now = pair_token::now_epoch();

    // Load the bound principal's profile and append the key.
    let profile_path = kernel.astrid_home.profile_path(&principal);
    if !profile_path.exists() {
        return Err(err_internal(
            "bound principal disappeared between issue and redeem".into(),
        ));
    }
    let mut profile = match PrincipalProfile::load_from_path(&profile_path) {
        Ok(p) => p,
        Err(e) => return Err(err_internal(format!("profile load failed: {e}"))),
    };
    let original_profile = profile.clone();

    // Dedup by canonical pubkey so re-redeeming the same key is idempotent
    // (the deterministic key_id makes the device handle stable). The redeemed
    // device is registered with the scope the token was issued under (resolved
    // + validated at issue time, with the issuer's denies already folded in),
    // so the paired device is attenuated to exactly that scope on every
    // transport — not hard-coded to Full.
    let registration_id =
        if let Some(registered) = profile.auth.device_by_typed_pubkey(&normalised_key) {
            registered.registration_id
        } else {
            let device = DeviceKey::new(
                normalised_key.as_str().to_string(),
                chosen.scope.clone(),
                chosen.label.clone(),
                i64::try_from(now).unwrap_or(0),
            );
            let registration_id = device.registration_id;
            profile.add_device(device);
            registration_id
        };
    if !profile.auth.methods.contains(&AuthMethod::Keypair) {
        profile.auth.methods.push(AuthMethod::Keypair);
    }

    if let Err(e) = profile.validate() {
        return Err(err_internal(format!(
            "profile rejected after key append: {e}"
        )));
    }

    // Save while the exact reservation is still owned. A failed atomic
    // replacement leaves the old profile intact and permits token release.
    if let Err(e) = profile.save_to_path(&profile_path) {
        return Err(err_internal(format!("profile save failed: {e}")));
    }

    // Deleting the reservation is the token commit. A definite loss means the
    // reservation was revoked or replaced; restore the profile only if this
    // attempt's prepared value is still current, so another writer is never
    // clobbered. The reservation is already single-use; if cleanup reports an
    // ambiguous storage error, keep it unredeemable and let expiry prune it.
    match store.consume_reservation(&chosen).await {
        Ok(true) => {},
        Ok(false) => {
            match PrincipalProfile::load_from_path(&profile_path) {
                Ok(current) if current == profile => {
                    if let Err(error) = original_profile.save_to_path(&profile_path) {
                        return Ok(err_internal(format!(
                            "profile rollback failed after pair-token loss: {error}"
                        )));
                    }
                    kernel.profile_cache.invalidate(&principal);
                },
                Ok(_) => {},
                Err(error) => {
                    return Ok(err_internal(format!(
                        "profile rollback read failed after pair-token loss: {error}"
                    )));
                },
            }
            return Ok(err_unauthorized(
                "pair-device token invalid or expired".into(),
            ));
        },
        Err(error) => {
            warn!(
                error = %error,
                "pair-token reservation cleanup failed; expiry will prune it"
            );
        },
    }
    kernel.profile_cache.invalidate(&principal);

    let fingerprint =
        super::invite_handlers::fingerprint_public_key(&format!("ed25519:{normalised_key}"));
    let key_id = DeviceKeyId::for_pubkey(&normalised_key);
    info!(
        principal = %principal,
        public_key_fingerprint = %fingerprint,
        key_id = %key_id,
        label = ?chosen.label,
        "Layer 6 auth.pair.redeem"
    );

    Ok(AdminResponseBody::PairTokenRedeemed(PairTokenRedeemed {
        principal,
        public_key_fingerprint: fingerprint,
        registration_id,
        key_id: key_id.into_inner(),
    }))
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
    #[cfg(unix)]
    let confirm = confirm_profile_publication;
    #[cfg(not(unix))]
    let confirm = |_: &std::path::Path| Ok(());
    revoke_with_publication_barrier(kernel, principal, key_id, confirm).await
}

// The replacement file has already been synced. Unix filesystems also
// require the containing directory to be synced to commit the rename.
#[cfg(unix)]
fn confirm_profile_publication(path: &std::path::Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("profile has no parent"))?;
    std::fs::File::open(parent)?.sync_all()
}

#[cfg(all(test, unix))]
pub(super) async fn revoke_with_failed_directory_sync(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    key_id: &str,
) -> AdminResponseBody {
    revoke_with_publication_barrier(kernel, principal, key_id, |path| {
        assert_eq!(path, kernel.astrid_home.profile_path(principal));
        Err(std::io::Error::other("test directory sync failure"))
    })
    .await
}

async fn revoke_with_publication_barrier(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    key_id: &str,
    confirm: impl FnOnce(&std::path::Path) -> std::io::Result<()>,
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

    let Some(removed_key) = profile.auth.remove_device(&key_id) else {
        return err_bad_input(format!(
            "no paired device with key_id {key_id} on principal {principal}"
        ));
    };

    if let Err(e) = profile.validate() {
        return err_internal(format!("profile rejected after device removal: {e}"));
    }
    if let Err(e) = profile.save_to_path(&profile_path) {
        return err_internal(format!("profile save failed: {e}"));
    }
    kernel.profile_cache.invalidate(principal);
    let receipt = match kernel
        .device_sessions
        .retire_with_receipt(principal, &removed_key)
        .await
    {
        Ok(receipt) => receipt,
        Err(error) => {
            return err_internal(format!(
                "device removed but session retirement failed: {error}"
            ));
        },
    };
    if let Err(error) = confirm(&profile_path) {
        return err_internal(format!(
            "device removed from live profile but persistence is unconfirmed: {error}"
        ));
    }

    info!(
        principal = receipt.principal(),
        key_id = receipt.key_id(),
        security_event = true,
        "Layer 6 auth.pair.revoke"
    );

    AdminResponseBody::PairDeviceRevoked {
        key_id: receipt.key_id().to_owned(),
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
