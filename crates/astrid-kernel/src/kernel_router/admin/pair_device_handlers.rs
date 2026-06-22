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

use astrid_core::PrincipalId;
use astrid_core::kernel_api::{AdminResponseBody, PairTokenIssued, PairTokenRedeemed};
use astrid_core::profile::{AuthMethod, DeviceKey, DeviceScope, PrincipalProfile};
use tracing::{info, warn};

use crate::pair_token::{self, MAX_EXPIRY_SECS, PairToken, PairTokenStore};

/// Default token lifetime when the issuer doesn't specify. Matches
/// the QR-scan window — a few minutes is plenty for the pairing
/// device to be close at hand.
const DEFAULT_EXPIRY_SECS: u64 = 5 * 60;

pub(crate) async fn pair_device_issue(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    expires_secs: Option<u64>,
    label: Option<String>,
) -> AdminResponseBody {
    let lifetime = expires_secs.unwrap_or(DEFAULT_EXPIRY_SECS);
    if lifetime == 0 {
        return err_bad_input("expires_secs must be greater than 0".into());
    }
    if lifetime > MAX_EXPIRY_SECS {
        return err_bad_input(format!(
            "expires_secs {lifetime} exceeds the 1-hour cap ({MAX_EXPIRY_SECS}s) — pair-tokens are intended for immediate use"
        ));
    }

    // Caller's profile must already exist. A pair-token tied to a
    // missing principal would be a dead grant on redeem.
    let profile_path = kernel.astrid_home.profile_path(caller);
    if !profile_path.exists() {
        return err_bad_input(format!(
            "caller principal {caller} does not exist (no profile.toml)"
        ));
    }

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
    });

    if let Err(e) = store.save(&tokens) {
        return err_internal(format!("pair-tokens.toml save failed: {e}"));
    }

    info!(
        token_fingerprint = %token_hash,
        principal = %caller,
        expires_at_epoch,
        "Layer 6 auth.pair.issue"
    );

    AdminResponseBody::PairToken(PairTokenIssued {
        token,
        principal: caller.clone(),
        expires_at_epoch,
        label,
    })
}

pub(crate) async fn pair_device_redeem(
    kernel: &Arc<crate::Kernel>,
    token: String,
    public_key: String,
) -> AdminResponseBody {
    // Validate the key shape first so a malformed key takes the
    // same time as a valid one — no key-shape oracle on the token
    // comparison.
    let normalised_key = match normalise_public_key(&public_key) {
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
    // device is registered Full-scope — per-device scope wiring lands with the
    // issue/redeem path that carries a requested scope on the token.
    if profile.auth.device_by_pubkey(&normalised_key).is_none() {
        profile.auth.public_keys.push(DeviceKey::new(
            normalised_key.clone(),
            DeviceScope::Full,
            None,
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
    info!(
        principal = %chosen.principal,
        public_key_fingerprint = %fingerprint,
        label = ?chosen.label,
        "Layer 6 auth.pair.redeem"
    );

    AdminResponseBody::PairTokenRedeemed(PairTokenRedeemed {
        principal: chosen.principal,
        public_key_fingerprint: fingerprint,
    })
}

fn normalise_public_key(raw: &str) -> Result<String, String> {
    let candidate = raw
        .strip_prefix("ed25519:")
        .unwrap_or(raw)
        .trim()
        .to_ascii_lowercase();
    if candidate.len() != 64 {
        return Err(format!(
            "public_key must be 32 bytes hex-encoded (64 hex chars); got {} chars",
            candidate.len()
        ));
    }
    if !candidate.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("public_key contains non-hex characters".into());
    }
    Ok(candidate)
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
