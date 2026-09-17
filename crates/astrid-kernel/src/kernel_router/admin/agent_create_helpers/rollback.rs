use std::path::Path;
use std::sync::Arc;

use astrid_core::principal::PrincipalId;
use astrid_events::kernel_api::AdminResponseBody;

use super::super::handlers::{AGENT_IDENTITY_PLATFORM, err_internal, principal_profile_path};

pub(super) async fn rollback_after_failure(
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
    crate::legacy_migration_barrier::ensure_principal_delete_allowed(
        &kernel.astrid_home,
        principal,
    )
    .map_err(|error| format!("legacy migration barrier blocked rollback: {error}"))?;
    ensure_legacy_secret_rollback_allowed(kernel, principal)?;
    let pending = super::super::agent_delete::prepare_identity_removal(kernel, principal)
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
    let capsule_ids = pending
        .principal_uid()
        .and_then(|uid| kernel.principal_store.as_ref().map(|store| (store, uid)))
        .map(|(store, uid)| {
            store
                .capsules()
                .list(&astrid_storage::StateOwner::Principal(uid))
                .map(|summaries| {
                    summaries
                        .into_iter()
                        .map(|summary| summary.id().to_owned())
                        .collect::<Vec<String>>()
                })
        })
        .transpose()
        .map_err(|error| format!("list durable capsule packages: {error}"))?
        .unwrap_or_default();
    for capsule in capsule_ids {
        if let Err(error) = kernel
            .kv
            .clear_namespace(&format!("{principal}:capsule:{capsule}"))
            .await
        {
            cleanup_errors.push(format!("KV namespace for capsule '{capsule}': {error}"));
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
    let legacy_secrets = kernel.astrid_home.secrets_dir().join(principal.as_str());
    let secret_source_must_be_absent = match pending.principal_uid() {
        Some(uid) => crate::legacy_migration_barrier::legacy_secret_source_must_be_absent(
            &kernel.astrid_home,
            uid,
        )
        .map_err(|error| format!("legacy secret migration provenance: {error}"))?,
        None => false,
    };
    if let Err(error) = super::super::agent_delete::reclaim_legacy_secret_root(
        &legacy_secrets,
        secret_source_must_be_absent,
    ) {
        cleanup_errors.push(format!(
            "principal secrets {}: {error}",
            legacy_secrets.display()
        ));
    }
    kernel.profile_cache.invalidate(principal);
    if !cleanup_errors.is_empty() {
        // Dropping `pending` intentionally retains its durable ownership
        // reservation. The capability and allowance retirement fences also
        // remain closed. A retry must finish reclamation before this alias can
        // acquire fresh authority.
        return Err(cleanup_errors.join("; "));
    }
    super::super::agent_delete::finish_identity_removal(kernel, principal, pending)
        .await
        .map_err(|response| format!("identity removal completion returned {response:?}"))
}

fn ensure_legacy_secret_rollback_allowed(
    kernel: &crate::Kernel,
    principal: &PrincipalId,
) -> Result<(), String> {
    if let Ok(uid) = kernel.principal_directory().uid_for(principal)
        && let Err(error) = crate::legacy_migration_barrier::ensure_legacy_secret_deletion_allowed(
            &kernel.astrid_home,
            principal,
            uid,
        )
    {
        return Err(format!(
            "legacy secret provenance blocked rollback: {error}"
        ));
    }
    Ok(())
}

pub(super) fn collect_remove_file(path: &Path, label: &str, errors: &mut Vec<String>) {
    if let Err(error) = std::fs::remove_file(path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        errors.push(format!("{label} {}: {error}", path.display()));
    }
}

pub(super) fn collect_remove_dir(path: &Path, label: &str, errors: &mut Vec<String>) {
    if let Err(error) = super::super::agent_delete::reclaim_empty_dir(path) {
        errors.push(format!("{label} {}: {error}", path.display()));
    }
}

/// Roll back a freshly provisioned identity only when ownership assignment
/// is confirmed absent. An unreadable graph or an existing assignment is
/// treated as unconfirmed/committed: deleting identity would orphan a UID
/// the graph already owns.
pub(super) async fn rollback_created_identity_unless_assigned(
    kernel: &crate::Kernel,
    principal: &PrincipalId,
    user_id: uuid::Uuid,
    profile_path: &Path,
) {
    let assigned = match kernel.principal_directory.uid_for(principal) {
        Ok(uid) => match kernel.ownership_store.load().await {
            Ok(graph) => graph.principal_owner(uid).is_some(),
            Err(_) => true,
        },
        Err(_) => false,
    };
    if assigned {
        tracing::warn!(
            %principal,
            "preserving provisioned identity after ownership assignment error because assignment is present or unconfirmed"
        );
        return;
    }
    rollback_created_identity(kernel, principal, user_id, profile_path, true).await;
}

pub(super) async fn rollback_created_identity(
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
        if crate::legacy_migration_barrier::ensure_principal_delete_allowed(
            &kernel.astrid_home,
            principal,
        )
        .is_ok()
        {
            let _ = std::fs::remove_dir(kernel.astrid_home.principal_home(principal).root());
        } else {
            tracing::warn!(%principal, "preserving principal home during rollback because legacy migration is incomplete");
        }
    }
    remove_principal_key(kernel, principal);
}

pub(super) fn remove_principal_key(kernel: &crate::Kernel, principal: &PrincipalId) {
    let _ = std::fs::remove_file(
        kernel
            .astrid_home
            .keys_dir()
            .join(format!("{principal}.key")),
    );
}
