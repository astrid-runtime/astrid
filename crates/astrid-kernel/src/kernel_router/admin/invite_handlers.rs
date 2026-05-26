//! Layer 6 invite-token handlers (issue #756).
//!
//! Sibling of [`super::handlers`]; lives in its own file to keep the
//! main admin-handler module under the 1000-line CI threshold. Each
//! function assumes the admin dispatcher has already established
//! authorization (or, for [`invite_redeem`], that the token-is-auth
//! preamble has been honoured by the caller). Every mutating handler
//! acquires [`crate::Kernel::admin_write_lock`] before touching
//! `invites.toml` or `profile.toml`.

use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_core::groups::GroupConfig;
use astrid_core::kernel_api::{AdminResponseBody, InviteIssued, InviteRedeemed, InviteSummary};
use astrid_core::profile::{AuthConfig, AuthMethod, PrincipalProfile};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::invite::{self, Invite, InviteStore, MAX_EXPIRY_SECS};

/// Hex-encoded SHA-256 of a hex-encoded ed25519 public key. Surfaced
/// as the `public_key_fingerprint` field on
/// [`AdminResponseBody::InviteRedeemed`] and used by the audit
/// sanitiser to redact the raw key from persisted audit rows.
#[must_use]
pub(crate) fn fingerprint_public_key(hex_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(hex_key.as_bytes());
    hex::encode(hasher.finalize())
}

// ── invite.issue ──────────────────────────────────────────────────────

pub(crate) async fn invite_issue(
    kernel: &Arc<crate::Kernel>,
    group: String,
    expires_secs: Option<u64>,
    max_uses: u32,
    metadata: Option<String>,
) -> AdminResponseBody {
    if max_uses == 0 {
        return err_bad_input("max_uses must be greater than 0".into());
    }
    if let Some(exp) = expires_secs
        && exp > MAX_EXPIRY_SECS
    {
        return err_bad_input(format!(
            "expires_secs {exp} exceeds the 30-day cap ({MAX_EXPIRY_SECS}s)"
        ));
    }
    // Group must already exist in the live config — typos here would
    // mint dead invites that fail on redeem with a cryptic error.
    if !group_exists(kernel, &group) {
        return err_bad_input(format!(
            "group {group:?} is not defined — create it via `astrid group create` first"
        ));
    }

    let _guard = kernel.admin_write_lock.lock().await;
    let store = InviteStore::new(InviteStore::path_for(&kernel.astrid_home));
    let mut invites = match store.load() {
        Ok(v) => v,
        Err(e) => return err_internal(format!("invites.toml load failed: {e}")),
    };
    // Lazy prune on every mutating op — cheap, bounded by store size,
    // keeps `invite.list` clean without a background sweeper.
    let _ = invite::prune_expired(&mut invites);

    let now = invite::now_epoch();
    let expires_at_epoch = expires_secs.map(|s| now.saturating_add(s));
    let token = invite::generate_token();
    let token_hash = invite::hash_token(&token);

    invites.push(Invite {
        token_hash: token_hash.clone(),
        group: group.clone(),
        remaining_uses: max_uses,
        expires_at_epoch,
        issued_at_epoch: now,
        metadata: metadata.clone(),
    });

    if let Err(e) = store.save(&invites) {
        return err_internal(format!("invites.toml save failed: {e}"));
    }

    info!(
        token_fingerprint = %token_hash,
        group = %group,
        max_uses,
        expires_at_epoch = ?expires_at_epoch,
        "Layer 6 invite.issue"
    );

    AdminResponseBody::Invite(InviteIssued {
        token,
        group,
        remaining_uses: max_uses,
        expires_at_epoch,
        metadata,
    })
}

// ── invite.redeem ─────────────────────────────────────────────────────

pub(crate) async fn invite_redeem(
    kernel: &Arc<crate::Kernel>,
    token: String,
    public_key: String,
    display_name: Option<String>,
) -> AdminResponseBody {
    // Validate the ed25519 key shape FIRST — same-shape rejection
    // before any token comparison keeps the redeem path from being a
    // hashing-oracle for malformed tokens.
    let normalised_key = match normalise_public_key(&public_key) {
        Ok(k) => k,
        Err(e) => return err_bad_input(e),
    };

    let _guard = kernel.admin_write_lock.lock().await;
    let store = InviteStore::new(InviteStore::path_for(&kernel.astrid_home));
    let mut invites = match store.load() {
        Ok(v) => v,
        Err(e) => return err_internal(format!("invites.toml load failed: {e}")),
    };
    let _ = invite::prune_expired(&mut invites);

    let token_hash = invite::hash_token(&token);
    let now = invite::now_epoch();

    // Constant-time scan over all live invites. We avoid `Vec::find`
    // short-circuiting because timing on its early-return would leak
    // partial-match length information.
    let mut matched_index: Option<usize> = None;
    for (i, inv) in invites.iter().enumerate() {
        let live = inv.remaining_uses > 0 && inv.expires_at_epoch.is_none_or(|e| e > now);
        // Always run the hash compare so a malformed/expired/consumed
        // entry takes the same time as a live one.
        let hit = invite::ct_hash_eq(&inv.token_hash, &token_hash) && live;
        if hit && matched_index.is_none() {
            matched_index = Some(i);
        }
    }

    let Some(idx) = matched_index else {
        return err_unauthorized("invite token invalid, expired, or already consumed".into());
    };

    let chosen = invites[idx].clone();

    // Mint the principal id. `display_name` is treated as a soft
    // suggestion: slugify and dedupe; on hard collision fall back to a
    // random tag so a malicious redeemer can't grief future redeemers
    // by hogging human-friendly names.
    let principal = match allocate_principal(kernel, display_name.as_deref()) {
        Ok(p) => p,
        Err(e) => return err_internal(e),
    };

    // Build the profile up-front so we can register the public key
    // before saving — no two-write race window in which a redeemer
    // sees their principal exist but the key not yet registered.
    let mut auth = AuthConfig::default();
    auth.methods.push(AuthMethod::Keypair);
    auth.public_keys.push(format!("ed25519:{normalised_key}"));

    let profile = PrincipalProfile {
        groups: vec![chosen.group.clone()],
        auth,
        ..PrincipalProfile::default()
    };
    if let Err(e) = profile.validate() {
        return err_internal(format!("profile rejected: {e}"));
    }

    // Reuse the existing identity-store + profile-save flow used by
    // the regular agent.create. We can't call `agent_create` directly
    // because the redeem path needs the pre-built `AuthConfig`, but
    // the responsibility split is identical: identity store first,
    // profile second, home tree third — with rollback at every step.
    let user = match kernel
        .identity_store
        .create_user(Some(principal.as_str()))
        .await
    {
        Ok(u) => u,
        Err(e) => return err_internal(format!("identity store create_user failed: {e}")),
    };
    if let Err(e) = kernel
        .identity_store
        .link("cli", principal.as_str(), user.id, "system")
        .await
    {
        let _ = kernel.identity_store.delete_user(user.id).await;
        return err_internal(format!("identity store link failed: {e}"));
    }
    let profile_path = kernel.astrid_home.profile_path(&principal);
    if let Err(e) = profile.save_to_path(&profile_path) {
        let _ = kernel
            .identity_store
            .unlink("cli", principal.as_str())
            .await;
        let _ = kernel.identity_store.delete_user(user.id).await;
        return err_internal(format!("profile save failed: {e}"));
    }
    if let Err(e) = kernel.astrid_home.principal_home(&principal).ensure() {
        let _ = kernel
            .identity_store
            .unlink("cli", principal.as_str())
            .await;
        let _ = kernel.identity_store.delete_user(user.id).await;
        let _ = std::fs::remove_file(&profile_path);
        return err_internal(format!("principal home tree provisioning failed: {e}"));
    }

    // Decrement / remove the invite. Saturating sub guards against
    // an externally-edited `remaining_uses = 0` slipping past the
    // live-check above.
    invites[idx].remaining_uses = invites[idx].remaining_uses.saturating_sub(1);
    if invites[idx].remaining_uses == 0 {
        invites.remove(idx);
    }
    if let Err(e) = store.save(&invites) {
        // We could roll back the principal but that would leave the
        // redeemer in a worse position than "your token is consumed
        // and your principal exists" — log loudly instead.
        warn!(
            error = %e,
            security_event = true,
            principal = %principal,
            "invite.redeem: invites.toml save failed AFTER principal mint; manual reconciliation may be required"
        );
    }

    let fingerprint = fingerprint_public_key(&format!("ed25519:{normalised_key}"));
    info!(
        %principal,
        group = %chosen.group,
        public_key_fingerprint = %fingerprint,
        "Layer 6 invite.redeem"
    );

    AdminResponseBody::InviteRedeemed(InviteRedeemed {
        principal,
        group: chosen.group,
        public_key_fingerprint: fingerprint,
    })
}

// ── invite.list ───────────────────────────────────────────────────────

pub(crate) async fn invite_list(kernel: &Arc<crate::Kernel>) -> AdminResponseBody {
    let _guard = kernel.admin_write_lock.lock().await;
    let store = InviteStore::new(InviteStore::path_for(&kernel.astrid_home));
    let mut invites = match store.load() {
        Ok(v) => v,
        Err(e) => return err_internal(format!("invites.toml load failed: {e}")),
    };
    if invite::prune_expired(&mut invites) > 0 {
        // Best-effort: a failed save just means the next prune retries.
        if let Err(e) = store.save(&invites) {
            warn!(error = %e, "invite.list: lazy prune save failed");
        }
    }
    let summaries: Vec<InviteSummary> = invites
        .into_iter()
        .map(|i| InviteSummary {
            token_fingerprint: i.token_hash,
            group: i.group,
            remaining_uses: i.remaining_uses,
            expires_at_epoch: i.expires_at_epoch,
            issued_at_epoch: i.issued_at_epoch,
            metadata: i.metadata,
        })
        .collect();
    AdminResponseBody::InviteList(summaries)
}

// ── invite.revoke ─────────────────────────────────────────────────────

pub(crate) async fn invite_revoke(kernel: &Arc<crate::Kernel>, token: String) -> AdminResponseBody {
    let _guard = kernel.admin_write_lock.lock().await;
    let store = InviteStore::new(InviteStore::path_for(&kernel.astrid_home));
    let mut invites = match store.load() {
        Ok(v) => v,
        Err(e) => return err_internal(format!("invites.toml load failed: {e}")),
    };
    // `token` here may be either the raw token (operator paste) or the
    // hex fingerprint (operator copy from `invite.list`). Hash the
    // input as raw token first; if no match, also try the input verbatim
    // (treating it as the already-hashed fingerprint). This dual lookup
    // never leaks which form matched — both produce the same
    // success/failure shape.
    let from_raw = invite::hash_token(&token);
    let pre_len = invites.len();
    invites.retain(|i| {
        !invite::ct_hash_eq(&i.token_hash, &from_raw) && !invite::ct_hash_eq(&i.token_hash, &token)
    });
    if invites.len() == pre_len {
        return err_bad_input("no invite matches the supplied token or fingerprint".into());
    }
    if let Err(e) = store.save(&invites) {
        return err_internal(format!("invites.toml save failed: {e}"));
    }
    let removed = pre_len.saturating_sub(invites.len());
    info!(removed, "Layer 6 invite.revoke");
    AdminResponseBody::Success(serde_json::json!({ "removed": removed }))
}

// ── helpers ───────────────────────────────────────────────────────────

fn group_exists(kernel: &Arc<crate::Kernel>, name: &str) -> bool {
    let cfg = kernel.groups.load_full();
    GroupConfig::is_builtin_name(name) || cfg.iter().any(|(n, _)| n == name)
}

/// Validate an ed25519 public key string. Accepts either bare 64 hex
/// chars or the `ed25519:<hex>` self-describing form. Returns the bare
/// hex form (lowercased) on success.
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

/// Allocate a fresh [`PrincipalId`]. Tries the user-supplied
/// `display_name` (slugified); on collision falls back to a random
/// `agent-<8-hex>` id. `default` and other reserved names are
/// rejected up-front.
fn allocate_principal(
    kernel: &Arc<crate::Kernel>,
    display_name: Option<&str>,
) -> Result<PrincipalId, String> {
    if let Some(name) = display_name {
        let slug = slugify_principal(name);
        if !slug.is_empty() {
            let pid = PrincipalId::new(&slug)
                .map_err(|e| format!("display_name {name:?} produces invalid principal: {e}"))?;
            if pid == PrincipalId::default() {
                return Err("`default` is the bootstrap principal and cannot be re-created".into());
            }
            let path = kernel.astrid_home.profile_path(&pid);
            if !path.exists() {
                return Ok(pid);
            }
            // Collision — fall through to random allocation rather
            // than leak whether this name is taken (the redeemer
            // sees the random id and learns nothing about other
            // principals).
        }
    }
    for _ in 0..16 {
        let candidate = format!("agent-{}", random_suffix());
        if let Ok(pid) = PrincipalId::new(&candidate) {
            let path = kernel.astrid_home.profile_path(&pid);
            if !path.exists() {
                return Ok(pid);
            }
        }
    }
    Err("failed to allocate a unique principal id after 16 attempts".into())
}

fn slugify_principal(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut last_was_dash = false;
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash && !out.is_empty() {
            out.push('-');
            last_was_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

fn random_suffix() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn err_bad_input(msg: String) -> AdminResponseBody {
    warn!(error = %msg, "invite request rejected: bad input");
    AdminResponseBody::Error(msg)
}

fn err_internal(msg: String) -> AdminResponseBody {
    warn!(error = %msg, "invite request failed: internal error");
    AdminResponseBody::Error(msg)
}

fn err_unauthorized(msg: String) -> AdminResponseBody {
    warn!(security_event = true, error = %msg, "invite request denied");
    AdminResponseBody::Error(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_public_key_accepts_bare_hex() {
        let key = "a".repeat(64);
        assert_eq!(normalise_public_key(&key).unwrap(), key);
    }

    #[test]
    fn normalise_public_key_accepts_prefixed_hex() {
        let key = "B".repeat(64);
        let normalised = normalise_public_key(&format!("ed25519:{key}")).unwrap();
        assert_eq!(normalised, "b".repeat(64));
    }

    #[test]
    fn normalise_public_key_rejects_wrong_length() {
        assert!(normalise_public_key("deadbeef").is_err());
        assert!(normalise_public_key(&"a".repeat(63)).is_err());
        assert!(normalise_public_key(&"a".repeat(65)).is_err());
    }

    #[test]
    fn normalise_public_key_rejects_non_hex() {
        let bad = "g".repeat(64);
        assert!(normalise_public_key(&bad).is_err());
    }

    #[test]
    fn slugify_principal_lowercases_and_dashes() {
        assert_eq!(slugify_principal("Alice Smith"), "alice-smith");
        assert_eq!(slugify_principal("alice@example.com"), "alice-example-com");
        assert_eq!(slugify_principal("--Alice--"), "alice");
        assert_eq!(slugify_principal(""), "");
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let a = fingerprint_public_key("ed25519:abcd");
        let b = fingerprint_public_key("ed25519:abcd");
        assert_eq!(a, b);
        assert_ne!(a, fingerprint_public_key("ed25519:abce"));
        assert_eq!(a.len(), 64);
    }
}
