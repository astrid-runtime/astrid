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
use astrid_core::profile::{AuthConfig, AuthMethod, DeviceKey, DeviceScope, PrincipalProfile};
use astrid_crypto::{IdentifierHash, PublicKeyFingerprint};
use tracing::{info, warn};

use crate::invite::{self, DurableInviteStore, Invite, MAX_EXPIRY_SECS};

/// Domain-separated BLAKE3 fingerprint of an Ed25519 public key. Surfaced as
/// the `public_key_fingerprint` field on
/// [`AdminResponseBody::InviteRedeemed`] and used by the audit
/// sanitiser to redact the raw key from persisted audit rows.
#[must_use]
pub(crate) fn fingerprint_public_key(hex_key: &str) -> String {
    PublicKeyFingerprint::from_ed25519_hex(hex_key).map_or_else(
        |_| {
            const REJECTED_INPUT_CONTEXT: &str =
                "astrid.runtime.rejected-public-key-input.fingerprint.v1";
            IdentifierHash::derive(REJECTED_INPUT_CONTEXT, hex_key.as_bytes()).to_prefixed_hex()
        },
        PublicKeyFingerprint::into_inner,
    )
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
    let store = match invite_store(kernel) {
        Ok(store) => store,
        Err(response) => return response,
    };
    if store
        .ensure_legacy_import(&kernel.astrid_home)
        .await
        .is_err()
    {
        return err_internal("invite durable storage is unavailable".into());
    }
    if store.prune().await.is_err() {
        return err_internal("invite durable storage could not be pruned".into());
    }

    let now = invite::now_epoch();
    let expires_at_epoch = expires_secs.map(|s| now.saturating_add(s));
    let token = invite::generate_token();
    let token_hash = invite::hash_token(&token);

    let record = Invite {
        token_hash: token_hash.clone(),
        group: group.clone(),
        remaining_uses: max_uses,
        expires_at_epoch,
        issued_at_epoch: now,
        metadata: metadata.clone(),
    };

    match store.issue(&record).await {
        Ok(true) => {},
        Ok(false) => return err_internal("invite identifier collision".into()),
        Err(_) => return err_internal("invite durable storage write failed".into()),
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
    let store = match invite_store(kernel) {
        Ok(store) => store,
        Err(response) => return response,
    };
    if store
        .ensure_legacy_import(&kernel.astrid_home)
        .await
        .is_err()
    {
        return err_internal("invite durable storage is unavailable".into());
    }
    let token_hash = invite::hash_token(&token);
    let Some(chosen) = (match store.redeemable(&token_hash).await {
        Ok(value) => value,
        Err(_) => return err_internal("invite durable storage read failed".into()),
    }) else {
        return err_unauthorized("invite token invalid, expired, or already consumed".into());
    };

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
    //
    // The redeemed device is registered Full-scope: an invite mints a
    // first-class principal, so its initial device acts with the principal's
    // full authority. Per-device attenuation is opt-in on the pair-device
    // path, not the invite path.
    let mut auth = AuthConfig::default();
    auth.methods.push(AuthMethod::Keypair);
    auth.public_keys.push(DeviceKey::new(
        normalised_key.clone(),
        DeviceScope::Full,
        None,
        i64::try_from(invite::now_epoch()).unwrap_or(0),
    ));

    let group = match astrid_core::GroupName::new(chosen.group.clone()) {
        Ok(group) => group,
        Err(e) => return err_internal(format!("invite group rejected: {e}")),
    };
    let profile = PrincipalProfile {
        groups: vec![group.into()],
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
    let provisioned =
        match provision_invited_principal(kernel, &principal, &normalised_key, &profile).await {
            Ok(provisioned) => provisioned,
            Err(error) => return err_internal(error),
        };

    // Provisioning is deliberately completed before consuming the bearer so
    // ordinary identity/profile failures remain retryable. `Ok(false)` is a
    // definite commit loss, so only then is this attempt's exact UID rolled
    // back. A storage error leaves the provisioned identity in place because
    // the commit may have succeeded and deleting it could invalidate a winner.
    match store.consume_if_unchanged(&chosen).await {
        Ok(true) => {},
        Ok(false) => {
            if let Err(error) = rollback_invited_principal(kernel, &principal, provisioned).await {
                return err_internal(format!("invite principal rollback failed: {error}"));
            }
            return err_unauthorized("invite token invalid, expired, or already consumed".into());
        },
        Err(_) => {
            return err_internal("invite durable storage write failed".into());
        },
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

async fn provision_invited_principal(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    normalised_key: &str,
    profile: &PrincipalProfile,
) -> Result<uuid::Uuid, String> {
    let initial_public_key = astrid_crypto::PublicKey::from_hex(normalised_key)
        .map(<[u8; 32]>::from)
        .map_err(|error| format!("validated invite key decode failed: {error}"))?;
    let user = kernel
        .identity_store
        .create_principal(principal.clone(), initial_public_key)
        .await
        .map_err(|error| format!("identity store create_user failed: {error}"))?;
    if let Err(error) = kernel
        .identity_store
        .link("cli", principal.as_str(), user.id, "system")
        .await
    {
        let _ = kernel.identity_store.delete_user(user.id).await;
        return Err(format!("identity store link failed: {error}"));
    }

    let profile_path = kernel.astrid_home.profile_path(principal);
    if let Err(error) = profile.save_to_path(&profile_path) {
        let _ = kernel
            .identity_store
            .unlink("cli", principal.as_str())
            .await;
        let _ = kernel.identity_store.delete_user(user.id).await;
        return Err(format!("profile save failed: {error}"));
    }
    // Principal state is UID-bound in the runtime store and is provisioned
    // lazily on first durable write. The released native home tree is only a
    // migration source and must not be recreated by invite redemption.
    Ok(user.id)
}

async fn rollback_invited_principal(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    user_id: uuid::Uuid,
) -> Result<(), String> {
    let mut errors = Vec::new();
    if let Err(error) = kernel
        .identity_store
        .unlink("cli", principal.as_str())
        .await
    {
        errors.push(format!("identity link removal failed: {error}"));
    }
    match kernel.identity_store.delete_user(user_id).await {
        Ok(true) => {},
        Ok(false) => errors.push(format!("identity {user_id} was not deleted")),
        Err(error) => errors.push(format!("identity deletion failed: {error}")),
    }
    if let Err(error) = std::fs::remove_file(kernel.astrid_home.profile_path(principal))
        && error.kind() != std::io::ErrorKind::NotFound
    {
        errors.push(format!("profile removal failed: {error}"));
    }
    kernel.profile_cache.invalidate(principal);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

// ── invite.list ───────────────────────────────────────────────────────

pub(crate) async fn invite_list(kernel: &Arc<crate::Kernel>) -> AdminResponseBody {
    let _guard = kernel.admin_write_lock.lock().await;
    let store = match invite_store(kernel) {
        Ok(store) => store,
        Err(response) => return response,
    };
    if store
        .ensure_legacy_import(&kernel.astrid_home)
        .await
        .is_err()
        || store.prune().await.is_err()
    {
        return err_internal("invite durable storage is unavailable".into());
    }
    let Ok(invites) = store.list().await else {
        return err_internal("invite durable storage read failed".into());
    };
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
    let store = match invite_store(kernel) {
        Ok(store) => store,
        Err(response) => return response,
    };
    if store
        .ensure_legacy_import(&kernel.astrid_home)
        .await
        .is_err()
    {
        return err_internal("invite durable storage is unavailable".into());
    }
    // `token` here may be either the raw token (operator paste) or the
    // `blake3:<hex>` fingerprint (operator copy from `invite.list`). Hash the
    // input as raw token first; if no match, also try the input verbatim
    // (treating it as the already-hashed fingerprint). This dual lookup
    // never leaks which form matched — both produce the same
    // success/failure shape.
    let from_raw = invite::hash_token(&token);
    let from_fingerprint = invite::canonical_token_fingerprint(&token);
    let fingerprint = from_fingerprint.as_deref().unwrap_or(&from_raw);
    let Ok(removed) = store.revoke(fingerprint).await else {
        return err_internal("invite durable storage write failed".into());
    };
    if !removed {
        return err_bad_input("no invite matches the supplied token or fingerprint".into());
    }
    info!(removed = 1, "Layer 6 invite.revoke");
    AdminResponseBody::Success(serde_json::json!({ "removed": removed }))
}

fn invite_store(kernel: &Arc<crate::Kernel>) -> Result<DurableInviteStore, AdminResponseBody> {
    let Some(store) = kernel.principal_store.as_ref() else {
        return Err(err_internal("invite durable storage is unavailable".into()));
    };
    DurableInviteStore::new(store.kv())
        .map_err(|_| err_internal("invite durable storage is unavailable".into()))
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

/// Maximum length of a slugified principal id. Bounded so an attacker
/// supplying a multi-megabyte `display_name` cannot force the kernel
/// to (a) iterate the full string and (b) produce a profile path
/// longer than the filesystem's `NAME_MAX` (typically 255 on Unix,
/// 143 on legacy eCryptfs). 64 is well under every supported limit
/// and matches the ergonomic ceiling for human-friendly names.
const MAX_PRINCIPAL_SLUG_LEN: usize = 64;

fn slugify_principal(input: &str) -> String {
    let mut out = String::with_capacity(input.len().min(MAX_PRINCIPAL_SLUG_LEN));
    let mut last_was_dash = false;
    // `.take(MAX_PRINCIPAL_SLUG_LEN)` short-circuits the iterator so
    // the oversize-input case is O(MAX) not O(input.len()), preventing
    // the CPU-exhaustion shape of "redeem with a giant display_name".
    for ch in input.chars().take(MAX_PRINCIPAL_SLUG_LEN) {
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
    use rand::{TryRng, rngs::SysRng};
    let mut bytes = [0u8; 4];
    SysRng
        .try_fill_bytes(&mut bytes)
        .expect("OS CSPRNG unavailable while generating invite suffix");
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
    use astrid_core::dirs::AstridHome;
    use tempfile::TempDir;

    async fn fixture() -> (TempDir, Arc<crate::Kernel>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(dir.path());
        let kernel = crate::test_kernel_with_home(home).await;
        (dir, kernel)
    }

    async fn issue_token(kernel: &Arc<crate::Kernel>) -> String {
        match invite_issue(
            kernel,
            "agent".into(),
            Some(300),
            1,
            Some("test invite".into()),
        )
        .await
        {
            AdminResponseBody::Invite(issued) => issued.token,
            other => panic!("invite issue failed: {other:?}"),
        }
    }

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
    fn slugify_principal_caps_oversize_input() {
        let monster = "a".repeat(10_000);
        let out = slugify_principal(&monster);
        assert!(
            out.len() <= MAX_PRINCIPAL_SLUG_LEN,
            "expected len <= {MAX_PRINCIPAL_SLUG_LEN}, got {}",
            out.len()
        );
        assert_eq!(out, "a".repeat(MAX_PRINCIPAL_SLUG_LEN));
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let key = "ab".repeat(32);
        let other = "ac".repeat(32);
        let a = fingerprint_public_key(&format!("ed25519:{key}"));
        let b = fingerprint_public_key(&key);
        assert_eq!(a, b);
        assert_ne!(a, fingerprint_public_key(&other));
        assert_eq!(a.len(), 71);
    }

    #[test]
    fn malformed_public_key_is_still_redacted_deterministically() {
        let a = fingerprint_public_key("not-a-key");
        let b = fingerprint_public_key("not-a-key");
        assert_eq!(a, b);
        assert_ne!(a, "not-a-key");
        assert_eq!(a.len(), 71);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn issue_persists_schema_one_and_redeems_after_reload() {
        let (_dir, kernel) = fixture().await;
        let token = issue_token(&kernel).await;
        assert!(token.starts_with(invite::TOKEN_PREFIX));

        let store = invite_store(&kernel).expect("open invite storage");
        let persisted = store.list().await.expect("reload issued invite");
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].token_hash, invite::hash_token(&token));
        assert!(!invite::InviteStore::path_for(&kernel.astrid_home).exists());

        let response =
            invite_redeem(&kernel, token, "ab".repeat(32), Some("BLAKE3 Test".into())).await;
        assert!(matches!(response, AdminResponseBody::InviteRedeemed(_)));
        assert!(
            !kernel
                .astrid_home
                .principal_home(&PrincipalId::new("agent").unwrap())
                .root()
                .exists(),
            "invite redemption must not recreate the released native home tree"
        );
        assert!(
            store
                .list()
                .await
                .expect("reload consumed store")
                .is_empty()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failed_invite_provisioning_does_not_burn_the_token() {
        let (_dir, kernel) = fixture().await;
        let token = issue_token(&kernel).await;
        let principal = PrincipalId::new("retryable-invite").expect("principal id");

        // Occupy the durable identity alias without creating its profile. The
        // first redeem therefore fails after token selection but before
        // provisioning can complete, deterministically exercising the failure
        // window without filesystem timing or permissions.
        let existing = kernel
            .identity_store
            .create_principal(principal.clone(), [9; 32])
            .await
            .expect("seed identity collision");
        let failed = invite_redeem(
            &kernel,
            token.clone(),
            "ab".repeat(32),
            Some(principal.as_str().to_owned()),
        )
        .await;
        assert!(
            matches!(failed, AdminResponseBody::Error(_)),
            "identity provisioning collision must fail the first redeem: {failed:?}"
        );

        let store = invite_store(&kernel).expect("open invite store");
        assert_eq!(
            store
                .list()
                .await
                .expect("read invite after failed redeem")
                .len(),
            1,
            "a provisioning failure must leave the invite available for retry"
        );

        // Remove only the injected conflict, then retry with the exact same
        // bearer. A consumed-before-provisioning implementation rejects this
        // second attempt; the durable invariant requires it to succeed.
        kernel
            .identity_store
            .delete_user(existing.id)
            .await
            .expect("remove injected identity collision");
        let retried = invite_redeem(
            &kernel,
            token,
            "ab".repeat(32),
            Some(principal.as_str().to_owned()),
        )
        .await;
        assert!(
            matches!(retried, AdminResponseBody::InviteRedeemed(_)),
            "the same invite must remain retryable after provisioning failure: {retried:?}"
        );
        assert!(
            store.list().await.expect("read consumed invite").is_empty(),
            "successful retry consumes the invite exactly once"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn revoke_accepts_raw_and_copied_uppercase_fingerprints() {
        let (_dir, kernel) = fixture().await;

        let raw = issue_token(&kernel).await;
        assert!(matches!(
            invite_revoke(&kernel, raw).await,
            AdminResponseBody::Success(_)
        ));

        let copied = issue_token(&kernel).await;
        let uppercase = invite::hash_token(&copied).to_ascii_uppercase();
        assert!(matches!(
            invite_revoke(&kernel, uppercase).await,
            AdminResponseBody::Success(_)
        ));

        let store = invite_store(&kernel).expect("open invite storage");
        assert!(store.list().await.expect("reload revoked store").is_empty());
    }
}
