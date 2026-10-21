use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use astrid_core::principal::PrincipalId;
use astrid_core::profile::{CapsuleGrant, NetworkConfig, PrincipalProfile};
use astrid_events::kernel_api::AdminResponseBody;
use tracing::info;

use super::super::handlers::{
    AGENT_IDENTITY_PLATFORM, err_bad_input, err_internal, err_profile, principal_profile_path,
    require_principal_exists, success_json,
};
use super::create::{materialize_cloned_capsule_installs, provision_new_principal};
use super::rollback::rollback_after_failure;

pub(crate) struct DerivedPrincipalTarget {
    pub(crate) principal: PrincipalId,
    pub(crate) profile_path: std::path::PathBuf,
    pub(crate) ownership: astrid_storage::ownership::DerivedPrincipalOwnership,
}

/// Provision the explicit, restricted runtime shape used by `agent spawn`.
pub(crate) async fn provision_derived_principal(
    kernel: &Arc<crate::Kernel>,
    target: DerivedPrincipalTarget,
    source: PrincipalId,
    load_capsules: Vec<String>,
    allow_capsules: Vec<String>,
    inherit_capsule_state: Vec<String>,
    network_egress: Vec<String>,
) -> AdminResponseBody {
    let DerivedPrincipalTarget {
        principal,
        profile_path,
        ownership,
    } = target;
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
        None,
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
    if let Err(e) = super::super::inheritance::inherit_selected_capsule_state(
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
    finish_derived_principal(
        kernel,
        principal,
        source,
        load_capsules,
        profile,
        &ownership,
    )
    .await
}

async fn finish_derived_principal(
    kernel: &Arc<crate::Kernel>,
    principal: PrincipalId,
    source: PrincipalId,
    load_capsules: Vec<String>,
    profile: PrincipalProfile,
    ownership: &astrid_storage::ownership::DerivedPrincipalOwnership,
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
    let uid = match kernel.principal_directory.uid_for(&principal) {
        Ok(uid) => uid,
        Err(error) => {
            return rollback_after_failure(kernel, &principal, err_internal(error.to_string()))
                .await;
        },
    };
    if let Err(error) = kernel
        .ownership_store
        .assign_derived_principal(uid, ownership)
        .await
    {
        return rollback_after_failure(
            kernel,
            &principal,
            err_internal(format!("spawn ownership assignment failed: {error}")),
        )
        .await;
    }
    kernel.publish_capsules_loaded_for(&principal).await;
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
    // Legacy file-secret roots are only collision evidence during migration.
    // Use no-follow metadata so a dangling or malicious symlink cannot make a
    // released legacy source appear absent.
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
        || std::fs::symlink_metadata(&secrets).is_ok()
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
    let Some(store) = kernel.principal_store.as_ref() else {
        return Err(err_internal(
            "authoritative principal store is unavailable".to_owned(),
        ));
    };
    let uid = kernel
        .principal_directory
        .uid_for(source)
        .map_err(|error| err_bad_input(format!("resolve source principal UID: {error}")))?;
    let owner = astrid_storage::StateOwner::Principal(uid);
    let snapshot = store
        .capsules()
        .get_snapshot(&owner, capsule)
        .map_err(|error| err_internal(format!("read source capsule package: {error}")))?
        .ok_or_else(|| err_bad_input(format!("source capsule '{capsule}' is not installed")))?;
    let temporary = tempfile::tempdir()
        .map_err(|error| err_internal(format!("create source capsule inspection root: {error}")))?;
    let source_install = temporary.path().join(capsule);
    astrid_capsule_install::materialize_capsule_package(snapshot.package(), &source_install)
        .map_err(|error| {
            err_bad_input(format!("source capsule '{capsule}' is invalid: {error:#}"))
        })?;
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
