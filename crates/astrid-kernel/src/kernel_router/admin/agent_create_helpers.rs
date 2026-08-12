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

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use astrid_core::principal::PrincipalId;
use astrid_core::profile::{
    CapabilityPattern, CapsuleGrant, GroupName, NetworkConfig, PrincipalProfile,
};
use astrid_events::kernel_api::AdminResponseBody;
use tracing::info;

use super::handlers::{
    AGENT_IDENTITY_PLATFORM, err_bad_input, err_internal, err_profile, principal_profile_path,
    require_principal_exists, success_json,
};

/// Provision the explicit, restricted runtime shape used by `agent spawn`.
#[allow(clippy::too_many_arguments)]
pub(super) async fn provision_derived_principal(
    kernel: &Arc<crate::Kernel>,
    principal: PrincipalId,
    profile_path: std::path::PathBuf,
    source: PrincipalId,
    load_capsules: Vec<String>,
    allow_capsules: Vec<String>,
    inherit_capsule_state: Vec<String>,
    network_egress: Vec<String>,
) -> AdminResponseBody {
    if source == principal {
        return err_bad_input("derived principal cannot use itself as its source".to_string());
    }
    if let Err(response) = ensure_derived_target_clean(kernel, &principal, &profile_path).await {
        return response;
    }
    let source_path = principal_profile_path(kernel, &source);
    if let Err(e) = require_principal_exists(&source, &source_path) {
        return err_bad_input(format!("derive source rejected: {e}"));
    }
    if let Err(response) = validate_derived_capsules(
        kernel,
        &source,
        &load_capsules,
        &allow_capsules,
        &inherit_capsule_state,
    ) {
        return response;
    }
    if let Err(response) = validate_derived_network(&network_egress) {
        return response;
    }

    let response = provision_new_principal(
        kernel,
        principal.clone(),
        profile_path.clone(),
        vec![astrid_core::groups::BUILTIN_RESTRICTED.to_string()],
        Vec::new(),
        None,
        None,
        false,
        false,
    )
    .await;
    if !matches!(response, AdminResponseBody::Success(_)) {
        return response;
    }

    let mut profile = match PrincipalProfile::load_from_path(&profile_path) {
        Ok(profile) => profile,
        Err(e) => {
            return rollback_after_failure(kernel, &principal, err_profile(&principal, &e)).await;
        },
    };
    profile.capsules = allow_capsules;
    profile.network.egress = network_egress;
    if let Err(e) = profile.validate() {
        return rollback_after_failure(
            kernel,
            &principal,
            err_bad_input(format!("derived profile rejected: {e}")),
        )
        .await;
    }

    if let Err(e) = materialize_cloned_capsule_installs(kernel, &source, &principal, &load_capsules)
    {
        return rollback_after_failure(
            kernel,
            &principal,
            err_internal(format!("derived capsule materialization failed: {e}")),
        )
        .await;
    }
    if let Err(e) = profile.save_to_path(&profile_path) {
        return rollback_after_failure(kernel, &principal, err_profile(&principal, &e)).await;
    }
    kernel.profile_cache.invalidate(&principal);
    if let Err(e) = super::inheritance::inherit_selected_capsule_state(
        kernel,
        &source,
        &principal,
        &inherit_capsule_state,
    )
    .await
    {
        return rollback_after_failure(
            kernel,
            &principal,
            err_internal(format!("derived state inheritance failed: {e}")),
        )
        .await;
    }
    finish_derived_principal(kernel, principal, source, load_capsules, profile).await
}

async fn finish_derived_principal(
    kernel: &Arc<crate::Kernel>,
    principal: PrincipalId,
    source: PrincipalId,
    load_capsules: Vec<String>,
    profile: PrincipalProfile,
) -> AdminResponseBody {
    if let Err(error) = kernel
        .ensure_principal_capsules_ready(&principal, &load_capsules)
        .await
    {
        return rollback_after_failure(
            kernel,
            &principal,
            err_internal(format!("derived capsule readiness failed: {error}")),
        )
        .await;
    }
    kernel.publish_capsules_loaded().await;
    info!(%principal, %source, ?load_capsules, "Layer 6 agent.derive");
    success_json(serde_json::json!({
        "principal": principal.as_str(),
        "source": source.as_str(),
        "loaded_capsules": load_capsules,
        "allowed_capsules": profile.capsules,
        "network_egress": profile.network.egress,
    }))
}

async fn ensure_derived_target_clean(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    profile_path: &Path,
) -> Result<(), AdminResponseBody> {
    let home = kernel
        .astrid_home
        .principal_home(principal)
        .root()
        .to_path_buf();
    let key = kernel
        .astrid_home
        .keys_dir()
        .join(format!("{principal}.key"));
    let secrets = kernel.astrid_home.secrets_dir().join(principal.as_str());
    let identity = kernel
        .identity_store
        .resolve(AGENT_IDENTITY_PLATFORM, principal.as_str())
        .await
        .map_err(|e| err_internal(format!("identity store resolve failed: {e}")))?;
    if identity.is_some()
        || profile_path.exists()
        || home.exists()
        || key.exists()
        || secrets.exists()
    {
        return Err(err_bad_input(format!(
            "derived principal '{principal}' has residual identity or filesystem state"
        )));
    }
    Ok(())
}

fn validate_derived_capsules(
    kernel: &crate::Kernel,
    source: &PrincipalId,
    load: &[String],
    allowed: &[String],
    inherited: &[String],
) -> Result<(), AdminResponseBody> {
    if load.is_empty() {
        return Err(err_bad_input(
            "at least one load_capsule is required".to_string(),
        ));
    }
    let mut seen = HashSet::new();
    for capsule in load {
        if !seen.insert(capsule) {
            return Err(err_bad_input(format!("duplicate load capsule '{capsule}'")));
        }
        CapsuleGrant::new(capsule)
            .map_err(|e| err_bad_input(format!("load capsule rejected: {e}")))?;
        validate_derived_capsule_install(kernel, source, capsule)?;
    }
    for (kind, capsules) in [("allow", allowed), ("state inheritance", inherited)] {
        seen.clear();
        for capsule in capsules {
            if !seen.insert(capsule) {
                return Err(err_bad_input(format!(
                    "duplicate {kind} capsule '{capsule}'"
                )));
            }
            if !load.contains(capsule) {
                return Err(err_bad_input(format!(
                    "capsule '{capsule}' must be loaded before it can be allowed or inherit state"
                )));
            }
        }
    }
    Ok(())
}

fn validate_derived_capsule_install(
    kernel: &crate::Kernel,
    source: &PrincipalId,
    capsule: &str,
) -> Result<(), AdminResponseBody> {
    let source_install = kernel
        .astrid_home
        .principal_home(source)
        .capsules_dir()
        .join(capsule);
    if !source_install.is_dir() {
        return Err(err_bad_input(format!(
            "source capsule install '{capsule}' is missing at {}",
            source_install.display()
        )));
    }
    let manifest = astrid_capsule::discovery::load_manifest(&source_install.join("Capsule.toml"))
        .map_err(|e| {
        err_bad_input(format!(
            "source capsule '{capsule}' has an invalid manifest: {e}"
        ))
    })?;
    if manifest.package.name != capsule {
        return Err(err_bad_input(format!(
            "source capsule directory '{capsule}' contains manifest for '{}'",
            manifest.package.name
        )));
    }
    if !manifest.mcp_servers.is_empty() {
        return Err(err_bad_input(format!(
            "source capsule '{capsule}' declares a host MCP server; derived principals require WASM-only capsules"
        )));
    }
    Ok(())
}

fn validate_derived_network(egress: &[String]) -> Result<(), AdminResponseBody> {
    NetworkConfig {
        egress: egress.to_vec(),
        ..NetworkConfig::default()
    }
    .validate()
    .map_err(|e| err_bad_input(format!("derived network policy rejected: {e}")))?;
    for endpoint in egress {
        validate_derived_egress_endpoint(endpoint).map_err(err_bad_input)?;
    }
    Ok(())
}

fn validate_derived_egress_endpoint(endpoint: &str) -> Result<(), String> {
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return Err(format!(
            "derived network endpoint '{endpoint}' must use host:port"
        ));
    };
    if host.is_empty() || port.is_empty() {
        return Err(format!(
            "derived network endpoint '{endpoint}' must use a non-empty host and port"
        ));
    }
    if port != "*" && port.parse::<u16>().is_err() {
        return Err(format!(
            "derived network endpoint '{endpoint}' has an invalid port"
        ));
    }
    Ok(())
}

async fn rollback_after_failure(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    original: AdminResponseBody,
) -> AdminResponseBody {
    match rollback_derived_principal(kernel, principal).await {
        Ok(()) => original,
        Err(error) => err_internal(format!(
            "derived principal provisioning failed and rollback could not complete: {error}"
        )),
    }
}

async fn rollback_derived_principal(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
) -> Result<(), String> {
    let pending = super::agent_delete::prepare_identity_removal(kernel, principal)
        .await
        .map_err(|response| format!("identity removal preparation returned {response:?}"))?;
    kernel
        .capabilities
        .begin_principal_retirement(principal.clone())
        .await;
    kernel
        .allowance_store
        .begin_principal_retirement(principal)
        .map_err(|error| format!("allowance retirement fence failed: {error}"))?;
    kernel
        .identity_store
        .unlink(AGENT_IDENTITY_PLATFORM, principal.as_str())
        .await
        .map_err(|error| format!("identity unlink failed: {error}"))?;
    let mut cleanup_errors = Vec::new();
    if let Err(error) = kernel.unload_principal_capsules(principal).await {
        cleanup_errors.push(format!("capsule retirement failed: {error}"));
    }
    let capsule_dir = kernel.astrid_home.principal_home(principal).capsules_dir();
    if let Ok(entries) = std::fs::read_dir(capsule_dir) {
        for capsule in entries.flatten().filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(std::fs::FileType::is_dir)
                .and_then(|_| entry.file_name().into_string().ok())
        }) {
            if let Err(error) = kernel
                .kv
                .clear_namespace(&format!("{principal}:capsule:{capsule}"))
                .await
            {
                cleanup_errors.push(format!("KV namespace for capsule '{capsule}': {error}"));
            }
        }
    }
    collect_remove_file(
        &principal_profile_path(kernel, principal),
        "profile",
        &mut cleanup_errors,
    );
    collect_remove_dir(
        kernel.astrid_home.principal_home(principal).root(),
        "principal home",
        &mut cleanup_errors,
    );
    collect_remove_file(
        &kernel
            .astrid_home
            .keys_dir()
            .join(format!("{principal}.key")),
        "principal key",
        &mut cleanup_errors,
    );
    collect_remove_dir(
        &kernel.astrid_home.secrets_dir().join(principal.as_str()),
        "principal secrets",
        &mut cleanup_errors,
    );
    kernel.profile_cache.invalidate(principal);
    if !cleanup_errors.is_empty() {
        // Dropping `pending` intentionally retains its durable ownership
        // reservation. The capability and allowance retirement fences also
        // remain closed. A retry must finish reclamation before this alias can
        // acquire fresh authority.
        return Err(cleanup_errors.join("; "));
    }
    super::agent_delete::finish_identity_removal(kernel, principal, pending)
        .await
        .map_err(|response| format!("identity removal completion returned {response:?}"))
}

fn collect_remove_file(path: &Path, label: &str, errors: &mut Vec<String>) {
    if let Err(error) = std::fs::remove_file(path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        errors.push(format!("{label} {}: {error}", path.display()));
    }
}

fn collect_remove_dir(path: &Path, label: &str, errors: &mut Vec<String>) {
    if let Err(error) = std::fs::remove_dir_all(path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        errors.push(format!("{label} {}: {error}", path.display()));
    }
}

#[cfg(test)]
mod rollback_cleanup_tests {
    use super::*;

    #[test]
    fn cleanup_collectors_preserve_every_reclamation_error() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("directory");
        let file = temp.path().join("file");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(&file, b"state").unwrap();
        let mut errors = Vec::new();

        collect_remove_file(&directory, "profile", &mut errors);
        collect_remove_dir(&file, "home", &mut errors);

        assert_eq!(errors.len(), 2, "both independent failures must survive");
        assert!(errors[0].contains("profile"));
        assert!(errors[1].contains("home"));
    }
}

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
    warm_after_create: bool,
) -> AdminResponseBody {
    if let Err(error) = kernel
        .ownership_store
        .ensure_alias_available(&principal)
        .await
    {
        return err_bad_input(format!(
            "principal alias `{principal}` is unavailable: {error}"
        ));
    }

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
    let initial_public_key = match mint_principal_keypair(kernel, &principal, &mut profile) {
        Ok(public_key) => public_key,
        Err(resp) => return resp,
    };

    if let Err(e) = profile.validate() {
        remove_principal_key(kernel, &principal);
        return err_bad_input(format!("profile rejected: {e}"));
    }

    let user = match kernel
        .identity_store
        .create_principal(principal.clone(), initial_public_key)
        .await
    {
        Ok(u) => u,
        Err(e) => {
            remove_principal_key(kernel, &principal);
            return err_internal(format!("identity store create_user failed: {e}"));
        },
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
        rollback_created_identity(kernel, &principal, user.id, &profile_path, false).await;
        return err_internal(format!("identity store link failed: {e}"));
    }

    if let Err(e) = profile.save_to_path(&profile_path) {
        rollback_created_identity(kernel, &principal, user.id, &profile_path, false).await;
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
        rollback_created_identity(kernel, &principal, user.id, &profile_path, true).await;
        return err_internal(format!(
            "principal home tree provisioning failed (rolled back): {e}"
        ));
    }

    if let Some(source) = clone_from.as_ref()
        && let Err(e) =
            materialize_cloned_capsule_installs(kernel, source, &principal, &profile.capsules)
    {
        rollback_created_identity(kernel, &principal, user.id, &profile_path, true).await;
        return err_internal(format!("capsule install clone failed (rolled back): {e}"));
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

    if warm_after_create {
        warm_created_principal(kernel, principal.clone());
    }

    info!(%principal, user_id = %user.id, "Layer 6 agent.create");
    success_json(serde_json::json!({
        "principal": principal.as_str(),
        "astrid_user_id": user.id,
    }))
}

async fn rollback_created_identity(
    kernel: &crate::Kernel,
    principal: &PrincipalId,
    user_id: uuid::Uuid,
    profile_path: &Path,
    remove_home: bool,
) {
    let _ = kernel
        .identity_store
        .unlink(AGENT_IDENTITY_PLATFORM, principal.as_str())
        .await;
    let _ = kernel.identity_store.delete_user(user_id).await;
    let _ = std::fs::remove_file(profile_path);
    if remove_home {
        let _ = std::fs::remove_dir_all(kernel.astrid_home.principal_home(principal).root());
    }
    remove_principal_key(kernel, principal);
}

fn remove_principal_key(kernel: &crate::Kernel, principal: &PrincipalId) {
    let _ = std::fs::remove_file(
        kernel
            .astrid_home
            .keys_dir()
            .join(format!("{principal}.key")),
    );
}

fn warm_created_principal(kernel: &Arc<crate::Kernel>, principal: PrincipalId) {
    let kernel = Arc::clone(kernel);
    astrid_runtime::spawn(async move {
        kernel.ensure_principal_loaded(&principal).await;
        kernel.publish_capsules_loaded().await;
    });
}

fn materialize_cloned_capsule_installs(
    kernel: &crate::Kernel,
    source: &PrincipalId,
    target: &PrincipalId,
    capsules: &[String],
) -> Result<(), String> {
    let source_capsules = kernel.astrid_home.principal_home(source).capsules_dir();
    let target_capsules = kernel.astrid_home.principal_home(target).capsules_dir();

    for capsule in capsules {
        let source = source_capsules.join(capsule);
        let target = target_capsules.join(capsule);
        if target.exists() {
            continue;
        }
        if !source.exists() {
            return Err(format!(
                "source capsule install '{}' is missing at {}",
                capsule,
                source.display()
            ));
        }
        if let Some(parent) = target.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            return Err(format!("create capsule install parent: {e}"));
        }
        astrid_capsule_install::copy_capsule_dir(&source, &target).map_err(|e| {
            format!(
                "materialize capsule '{capsule}' for {}: {e:#}",
                target.display()
            )
        })?;
        let target_env = target.join(".env.json");
        if target_env.exists()
            && let Err(e) = std::fs::remove_file(&target_env)
        {
            return Err(format!(
                "remove copied capsule env for '{capsule}' under {}: {e}",
                target.display()
            ));
        }
    }
    Ok(())
}

/// Build the [`PrincipalProfile`] for a new agent.
///
/// With `clone_from`, the result is a full replica of that source's
/// capability and resource profile (groups, grants, revokes, capsule grants,
/// network, process, quotas). Deliberately NOT copied: the source's `auth`
/// (each principal keeps its own keys / authenticators — cloning is
/// profile+state, never credentials) and `enabled` flag (a fresh clone is
/// enabled even if the source was disabled); both fall back to
/// [`PrincipalProfile::default`].
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
        capsules: source_profile.capsules,
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
) -> Result<[u8; 32], AdminResponseBody> {
    let keys_dir = kernel.astrid_home.keys_dir();
    if let Err(e) = std::fs::create_dir_all(&keys_dir) {
        return Err(err_internal(format!("keys dir create failed: {e}")));
    }
    let key_path = keys_dir.join(format!("{principal}.key"));
    // Reuse a key left by an interrupted provisioning attempt. The crypto
    // helper durably creates an owner-only key without replacement and returns
    // the winner if another process claimed the path first.
    let keypair = astrid_crypto::load_or_generate_keypair(&key_path)
        .map_err(|e| err_internal(format!("principal key load/create failed: {e}")))?;
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
    Ok(*keypair.public_key_bytes())
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
pub(super) async fn backfill_keypair(
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
    let original_profile = profile.clone();

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
    let initial_public_key = match mint_principal_keypair(kernel, principal, &mut profile) {
        Ok(public_key) => public_key,
        Err(resp) => return resp,
    };

    if let Err(e) = profile.validate() {
        return err_bad_input(format!("profile rejected: {e}"));
    }

    let user = match kernel
        .identity_store
        .resolve(AGENT_IDENTITY_PLATFORM, principal.as_str())
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            return err_internal(format!(
                "principal {principal} has no identity record for keypair backfill"
            ));
        },
        Err(error) => {
            return err_internal(format!(
                "identity store lookup failed during keypair backfill: {error}"
            ));
        },
    };
    // Persist via the same save path create uses. Groups, grants, network,
    // process, quotas, and home are untouched — only `auth` changed.
    if let Err(e) = profile.save_to_path(profile_path) {
        return err_profile(principal, &e);
    }
    if let Err(error) = kernel
        .identity_store
        .bind_principal_identity(user.id, principal.clone(), initial_public_key)
        .await
    {
        return match original_profile.save_to_path(profile_path) {
            Ok(()) => err_internal(format!(
                "principal identity backfill failed; profile rolled back: {error}"
            )),
            Err(rollback) => err_internal(format!(
                "principal identity backfill failed ({error}) and profile rollback failed ({rollback})"
            )),
        };
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
