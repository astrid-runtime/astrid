//! `admin.agent.create` provisioning + keypair-backfill helpers.
//!
//! Carved out of `handlers.rs` to keep that file under the per-file CI line
//! cap. `agent_create` stays a thin dispatcher there; this module owns the
//! heavy lifting:
//!
//! - [`provision_new_principal`] — build + register + provision a genuinely
//!   new principal (no profile on disk).
//! - [`backfill_keypair`] — surgically heal an EXISTING keyless principal by
//!   adding only its missing ed25519 credential.
//! - [`build_create_profile`] / [`mint_principal_keypair`] — shared by both.
//!
//! Everything here must run under the admin write lock held by the caller.

use std::path::Path;
use std::sync::Arc;

use astrid_core::principal::PrincipalId;
use astrid_core::profile::{CapabilityPattern, GroupName, PrincipalProfile};
use astrid_events::kernel_api::AdminResponseBody;
use tracing::info;

use super::handlers::{
    AGENT_IDENTITY_PLATFORM, err_bad_input, err_internal, err_profile, principal_profile_path,
    require_principal_exists, success_json,
};

/// Build, register, and provision a genuinely-new principal.
///
/// The collision + backfill decision is made by the caller (`agent_create`);
/// this runs only when no profile exists on disk. Must run under the admin
/// write lock held by the caller (the clone/inherit source is pinned across the
/// reads here).
#[allow(clippy::too_many_arguments)]
pub(super) async fn provision_new_principal(
    kernel: &Arc<crate::Kernel>,
    principal: PrincipalId,
    profile_path: std::path::PathBuf,
    groups: Vec<String>,
    grants: Vec<String>,
    inherit_from: Option<PrincipalId>,
    clone_from: Option<PrincipalId>,
    allow_admin_clone: bool,
) -> AdminResponseBody {
    // Build the profile: a `clone_from` replica (validated + admin-guarded) or
    // a fresh profile from the supplied groups/grants. Runs under the lock so
    // the clone source is pinned across the read.
    let mut profile = match build_create_profile(
        kernel,
        &principal,
        groups,
        grants,
        clone_from.as_ref(),
        allow_admin_clone,
    ) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    // Mint a per-principal ed25519 keypair so this principal can authenticate
    // its local socket connections (issue #45/#852): the private key lands in
    // system custody under `keys/` (NOT the principal home — the agent sandbox
    // denies it, but the operator/OS-user CLI can read it to sign), and the
    // public key + the `Keypair` auth method are registered on the profile so
    // the handshake can verify a signature against it.
    if let Err(resp) = mint_principal_keypair(kernel, &principal, &mut profile) {
        return resp;
    }

    if let Err(e) = profile.validate() {
        return err_bad_input(format!("profile rejected: {e}"));
    }

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
        .link(
            AGENT_IDENTITY_PLATFORM,
            principal.as_str(),
            user.id,
            "system",
        )
        .await
    {
        // Best-effort rollback so partial state doesn't persist.
        let _ = kernel.identity_store.delete_user(user.id).await;
        return err_internal(format!("identity store link failed: {e}"));
    }

    if let Err(e) = profile.save_to_path(&profile_path) {
        let _ = kernel
            .identity_store
            .unlink(AGENT_IDENTITY_PLATFORM, principal.as_str())
            .await;
        let _ = kernel.identity_store.delete_user(user.id).await;
        return err_internal(format!("profile save failed: {e}"));
    }

    // Provision the per-principal home tree so per-invocation KV, log,
    // tmp, secrets, audit, and capability tokens have a place to land.
    //
    // Fail-closed: if the home tree cannot be created, downstream
    // per-invocation lookups silently fall back to the `default`
    // principal's namespace — a confidentiality break across tenants.
    // Roll back identity + profile so the agent isn't left in a state
    // where future invocations would leak into someone else's data.
    if let Err(e) = kernel.astrid_home.principal_home(&principal).ensure() {
        let _ = kernel
            .identity_store
            .unlink(AGENT_IDENTITY_PLATFORM, principal.as_str())
            .await;
        let _ = kernel.identity_store.delete_user(user.id).await;
        let _ = std::fs::remove_file(&profile_path);
        return err_internal(format!(
            "principal home tree provisioning failed (rolled back): {e}"
        ));
    }

    // State inheritance is OPT-IN. By default the new principal inherits
    // NOTHING — least privilege, and no silent leak of `default`'s env
    // JSON, KV namespaces, or (critically) secret files / API keys into
    // every created agent. When the operator names a source — `inherit_from`
    // (state only) or `clone_from` (which copied the profile above and now
    // takes the same state copy) — we perform a full copy from THAT
    // principal: env JSON (non-secret config), per-capsule KV namespaces, and
    // per-capsule secret files. The two are mutually exclusive, so at most one
    // is set. Best-effort — a copy failure logs a warn and leaves the agent in
    // a "needs manual setup" state but doesn't roll back the profile or the
    // home tree (those already succeeded; the confidentiality boundary holds
    // regardless). The source's existence was validated above.
    if let Some(source) = clone_from.as_ref().or(inherit_from.as_ref()) {
        super::inheritance::inherit_from_principal(kernel, source, &principal).await;
    }

    info!(%principal, user_id = %user.id, "Layer 6 agent.create");
    success_json(serde_json::json!({
        "principal": principal.as_str(),
        "astrid_user_id": user.id,
    }))
}

/// Build the [`PrincipalProfile`] for a new agent.
///
/// With `clone_from`, the result is a full replica of that source's
/// capability and resource profile (groups, grants, revokes, network, process,
/// quotas). Deliberately NOT copied: the source's `auth` (each principal keeps
/// its own keys / authenticators — cloning is profile+state, never
/// credentials) and `enabled` flag (a fresh clone is enabled even if the
/// source was disabled); both fall back to [`PrincipalProfile::default`].
/// Without `clone_from`, a fresh profile from the supplied `groups`/`grants`
/// (empty groups yields the built-in `agent` group).
///
/// Must run under the admin write lock — it reads the clone source's profile
/// from disk and the source must be pinned across the read. Returns the
/// [`AdminResponseBody`] error to propagate on rejection (bad source, or an
/// admin-conferring source without `allow_admin_clone`).
fn build_create_profile(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    groups: Vec<String>,
    grants: Vec<String>,
    clone_from: Option<&PrincipalId>,
    allow_admin_clone: bool,
) -> Result<PrincipalProfile, AdminResponseBody> {
    let Some(source) = clone_from else {
        let resolved_groups = if groups.is_empty() {
            vec![astrid_core::groups::BUILTIN_AGENT.to_string()]
        } else {
            groups
        };
        let groups = match resolved_groups
            .into_iter()
            .map(GroupName::new)
            .map(|result| result.map(String::from))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(groups) => groups,
            Err(e) => return Err(err_bad_input(format!("group rejected: {e}"))),
        };
        let grants = match grants
            .into_iter()
            .map(CapabilityPattern::new)
            .map(|result| result.map(String::from))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(grants) => grants,
            Err(e) => return Err(err_bad_input(format!("grant rejected: {e}"))),
        };
        return Ok(PrincipalProfile {
            groups,
            grants,
            ..PrincipalProfile::default()
        });
    };

    // Validate the clone source: a non-existent source must fail loudly rather
    // than silently producing an empty agent, and self-clone is meaningless.
    if source == principal {
        return Err(err_bad_input(format!(
            "clone_from source {source} is the same as the new principal"
        )));
    }
    let source_path = principal_profile_path(kernel, source);
    if let Err(e) = require_principal_exists(source, &source_path) {
        return Err(err_bad_input(format!("clone_from source rejected: {e}")));
    }
    let source_profile = match PrincipalProfile::load_from_path(&source_path) {
        Ok(p) => p,
        Err(e) => return Err(err_profile(source, &e)),
    };

    // Admin-source guard: replicating a profile that resolves to the universal
    // `*` mints a SECOND admin. Refuse unless the operator explicitly
    // acknowledges — mirrors `caps grant '*'` / `group create --caps '*'`.
    // Resolving through the live GroupConfig (not a literal scan) catches a
    // custom `unsafe_admin` group that confers `*`, not just the built-in
    // `admin` group or a bare `*` grant.
    let groups_cfg = kernel.groups.load_full();
    let confers_admin = astrid_capabilities::CapabilityCheck::new(
        &source_profile,
        groups_cfg.as_ref(),
        source.clone(),
    )
    .has("*");
    if confers_admin && !allow_admin_clone {
        return Err(err_bad_input(format!(
            "clone_from source {source} confers admin (resolves to `*`); pass \
             --unsafe-admin to clone an admin profile"
        )));
    }

    Ok(PrincipalProfile {
        groups: source_profile.groups,
        grants: source_profile.grants,
        revokes: source_profile.revokes,
        network: source_profile.network,
        process: source_profile.process,
        quotas: source_profile.quotas,
        ..PrincipalProfile::default()
    })
}

/// Mint a per-principal ed25519 keypair and register it on `profile`.
///
/// The private key is written to `keys/<principal>.key` in SYSTEM custody
/// (0600) — outside the principal home, so the spawned-agent sandbox can deny
/// it while the operator's CLI (running as the OS user) can read it to sign a
/// handshake challenge. The public key is appended to `AuthConfig.public_keys`
/// as `ed25519:<hex>` and `AuthMethod::Keypair` is recorded, so the kernel-side
/// handshake can verify a signature against it (issue #45/#852). Returns the
/// error response to propagate on a filesystem failure.
fn mint_principal_keypair(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    profile: &mut PrincipalProfile,
) -> Result<(), AdminResponseBody> {
    let keypair = astrid_crypto::KeyPair::generate();
    let keys_dir = kernel.astrid_home.keys_dir();
    if let Err(e) = std::fs::create_dir_all(&keys_dir) {
        return Err(err_internal(format!("keys dir create failed: {e}")));
    }
    let key_path = keys_dir.join(format!("{principal}.key"));
    // Create the key file 0600 atomically (via `OpenOptions::mode`) BEFORE
    // writing the secret bytes, so the ed25519 private key is never momentarily
    // group/world readable in the (0755) keys dir between a `write` and a
    // follow-up `set_permissions` chmod — the TOCTOU a co-tenant could race.
    // Mirrors `mint_default_principal_keypair` in the kernel bootstrap.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let write_result = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&key_path)
            .and_then(|mut f| f.write_all(&keypair.secret_key_bytes()));
        if let Err(e) = write_result {
            return Err(err_internal(format!("principal key write failed: {e}")));
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(e) = std::fs::write(&key_path, keypair.secret_key_bytes()) {
            return Err(err_internal(format!("principal key write failed: {e}")));
        }
    }
    // Register the minted public key Full-scope: a principal's own bootstrap
    // keypair acts with the principal's full authority. Dedup by canonical
    // pubkey so a re-mint is idempotent.
    let pubkey_hex = keypair.export_public_key().to_hex();
    if profile.auth.device_by_pubkey(&pubkey_hex).is_none() {
        profile
            .auth
            .public_keys
            .push(astrid_core::profile::DeviceKey::new(
                pubkey_hex,
                astrid_core::profile::DeviceScope::Full,
                None,
                // Stamp the real mint epoch — `0` is the migrated-legacy-key
                // sentinel, so using it for a freshly minted key would show a
                // 1970 timestamp in `pair-device list` / audit.
                i64::try_from(crate::invite::now_epoch()).unwrap_or(0),
            ));
    }
    if !profile
        .auth
        .methods
        .contains(&astrid_core::profile::AuthMethod::Keypair)
    {
        profile
            .auth
            .methods
            .push(astrid_core::profile::AuthMethod::Keypair);
    }
    Ok(())
}

/// Backfill a missing per-principal keypair onto an EXISTING profile.
///
/// Per-connection auth (#45/#852) makes a freshly-created principal
/// mint+register a per-principal ed25519 keypair so it can sign the socket
/// handshake and be stamped as its own scoped identity. Principals created
/// BEFORE that feature landed are keyless (`auth.methods = []`,
/// `auth.public_keys = []`, no `keys/<principal>.key`), so the kernel falls
/// back to stamping their connections the no-capability `anonymous`.
///
/// This is the surgical heal for those principals: it adds the missing ed25519
/// credential and NOTHING else. It NEVER widens groups or grants, never alters
/// an existing keypair, and never touches network/process/quotas/home/state —
/// it is purely security-positive (moves a principal from "stamped `anonymous`,
/// no capability" to "authenticates as its own scoped identity").
///
/// `has_shaping_inputs` is true when the caller passed `clone_from`,
/// `inherit_from`, `groups`, or `grants`. A backfill is not a re-create, so any
/// shaping input against an existing principal keeps the hard "already exists"
/// error rather than being silently ignored.
///
/// Runs under the admin write lock held by the caller.
pub(super) fn backfill_keypair(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    profile_path: &Path,
    has_shaping_inputs: bool,
) -> AdminResponseBody {
    // Shaping inputs against an existing principal: the caller meant create,
    // not heal. Reject loudly — never partially honour a re-create request.
    if has_shaping_inputs {
        return err_bad_input(format!("principal {principal} already exists"));
    }

    let mut profile = match PrincipalProfile::load_from_path(profile_path) {
        Ok(p) => p,
        Err(e) => return err_profile(principal, &e),
    };

    // "Keyless" = the profile carries no ed25519 credential.
    // `mint_principal_keypair` registers BOTH the `Keypair` auth method and an
    // `ed25519:<hex>` public key, so a principal with a keypair has at least one
    // of them. Treat the presence of EITHER as "already has a keypair" — we
    // never clobber or re-mint an existing credential. A present
    // `keys/<principal>.key` is corroborating, but the profile is the source of
    // truth the handshake verifies against, so we key the decision off it.
    let has_keypair = profile
        .auth
        .methods
        .contains(&astrid_core::profile::AuthMethod::Keypair)
        || !profile.auth.public_keys.is_empty();
    if has_keypair {
        return err_bad_input(format!("principal {principal} already exists"));
    }

    // Keyless: mint + register the missing keypair on the loaded profile. This
    // writes the private key to system custody under `keys/` (NOT the principal
    // home) and appends the public key + `Keypair` method — exactly as the
    // create path does, reusing the same helper.
    if let Err(resp) = mint_principal_keypair(kernel, principal, &mut profile) {
        return resp;
    }

    if let Err(e) = profile.validate() {
        return err_bad_input(format!("profile rejected: {e}"));
    }

    // Persist via the same save path create uses. Groups, grants, network,
    // process, quotas, and home are untouched — only `auth` changed.
    if let Err(e) = profile.save_to_path(profile_path) {
        return err_profile(principal, &e);
    }
    // Drop any cached pre-backfill profile so the next handshake re-reads the
    // freshly-minted credential rather than the stale keyless copy.
    kernel.profile_cache.invalidate(principal);

    info!(%principal, "Layer 6 agent.create backfilled missing keypair");
    success_json(serde_json::json!({
        "principal": principal.as_str(),
        "backfilled_keypair": true,
        "message": format!("backfilled missing keypair for existing principal {principal}"),
    }))
}
