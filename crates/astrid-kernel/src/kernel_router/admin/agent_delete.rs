//! Principal deletion: close authority, retire live capsule views, reclaim state.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use astrid_core::principal::PrincipalId;
use astrid_events::kernel_api::AdminResponseBody;
use tracing::{info, warn};

use super::handlers::{
    AGENT_IDENTITY_PLATFORM, err_bad_input, err_internal, principal_profile_path, success_json,
};

pub(super) async fn agent_delete(
    kernel: &Arc<crate::Kernel>,
    principal: PrincipalId,
) -> AdminResponseBody {
    if principal == PrincipalId::default() {
        return err_bad_input(
            "cannot delete the `default` principal — it is the single-tenant bootstrap anchor"
                .to_string(),
        );
    }

    let _guard = kernel.admin_write_lock.lock().await;
    if let Err(error) = crate::legacy_migration_barrier::ensure_principal_delete_allowed(
        &kernel.astrid_home,
        &principal,
    ) {
        return err_internal(format!(
            "principal deletion blocked by legacy migration barrier: {error}"
        ));
    }
    if let Ok(uid) = kernel.principal_directory().uid_for(&principal)
        && let Err(error) = crate::legacy_migration_barrier::ensure_legacy_secret_deletion_allowed(
            &kernel.astrid_home,
            &principal,
            uid,
        )
    {
        return err_internal(format!(
            "principal deletion blocked by legacy secret provenance: {error}"
        ));
    }
    let pending = match prepare_identity_removal(kernel, &principal).await {
        Ok(pending) => pending,
        Err(response) => return response,
    };
    {
        // Serialize the retirement edge against capsule construction and live
        // replacement. A loader that won the lock finishes before retirement;
        // one that follows observes the tombstone and fails closed.
        let _load_guard = kernel.capsule_load_lock.lock().await;
        kernel
            .capabilities
            .begin_principal_retirement(principal.clone())
            .await;
        if let Err(error) = kernel
            .allowance_store
            .begin_principal_retirement(&principal)
        {
            return err_internal(format!("allowance retirement fence failed: {error}"));
        }
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    if let Err(error) =
        crate::storage_mount::revoke_all_leases_for_principal(kernel, &principal).await
    {
        return err_internal(format!("storage mount lease drain failed: {error}"));
    }

    if let Err(e) = kernel
        .identity_store
        .unlink(AGENT_IDENTITY_PLATFORM, principal.as_str())
        .await
    {
        return err_internal(format!("identity store unlink failed: {e}"));
    }

    let (unloaded_capsules, reclaimed, cleanup_errors) =
        match retire_and_reclaim(kernel, &principal, pending.principal_uid).await {
            Ok(result) => result,
            Err(e) => return err_internal(e),
        };

    if !cleanup_errors.is_empty() {
        return err_internal(format!(
            "principal reclamation incomplete; alias remains reserved: {}",
            cleanup_errors.join("; ")
        ));
    }

    // Native state reclamation resolves quota policy through the profile. Keep
    // it until that purge has committed, while the capability retirement fence
    // and identity unlink keep every authority and capsule-load edge closed.
    let path = principal_profile_path(kernel, &principal);
    if let Err(e) = std::fs::remove_file(&path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return err_internal(format!(
            "failed to remove profile.toml at {}: {e}",
            path.display()
        ));
    }
    kernel.profile_cache.invalidate(&principal);

    if let Err(response) = finish_identity_removal(kernel, &principal, pending).await {
        return response;
    }

    info!(%principal, ?unloaded_capsules, ?reclaimed, ?cleanup_errors, "Layer 6 agent.delete");
    success_json(serde_json::json!({
        "principal": principal.as_str(),
        "unloaded_capsules": unloaded_capsules,
        "reclaimed": reclaimed,
        "cleanup_errors": cleanup_errors,
    }))
}

pub(super) struct PendingIdentityRemoval {
    user: Option<astrid_core::AstridUserId>,
    principal_uid: Option<astrid_core::PrincipalUid>,
    ownership_guard: Option<astrid_storage::PrincipalDeletionGuard>,
}

impl PendingIdentityRemoval {
    pub(super) const fn principal_uid(&self) -> Option<astrid_core::PrincipalUid> {
        self.principal_uid
    }
}

pub(super) async fn prepare_identity_removal(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
) -> Result<PendingIdentityRemoval, AdminResponseBody> {
    let linked = kernel
        .identity_store
        .resolve(AGENT_IDENTITY_PLATFORM, principal.as_str())
        .await
        .map_err(|e| err_internal(format!("identity store resolve failed: {e}")))?;
    let resolved = if linked.is_some() {
        linked
    } else {
        kernel
            .identity_store
            .list_users()
            .await
            .map_err(|e| err_internal(format!("identity store list_users failed: {e}")))?
            .into_iter()
            .find(|user| user.principal == *principal)
    };

    let (principal_uid, ownership_guard) = if let Some(user) = resolved.as_ref() {
        let identity = kernel
            .identity_store
            .get_principal_identity(user.id)
            .await
            .map_err(|e| {
                err_internal(format!(
                    "identity store principal identity lookup failed: {e}"
                ))
            })?;
        if let Some(identity) = identity {
            match kernel
                .ownership_store
                .guard_principal_deletion_for_alias(identity.uid, principal.clone())
                .await
            {
                Ok(guard) => (Some(identity.uid), Some(guard)),
                Err(astrid_storage::OwnershipError::PrincipalAlreadyOwned { fleet, .. }) => {
                    return Err(err_bad_input(format!(
                        "cannot delete principal `{principal}` while it is assigned to fleet {fleet}"
                    )));
                },
                Err(e) => {
                    return Err(err_internal(format!(
                        "ownership store deletion guard failed: {e}"
                    )));
                },
            }
        } else {
            let guard = recover_or_reserve_legacy_alias(kernel, principal).await?;
            (None, Some(guard))
        }
    } else {
        let guard = recover_or_reserve_legacy_alias(kernel, principal).await?;
        (Some(guard.principal_uid()), Some(guard))
    };

    Ok(PendingIdentityRemoval {
        user: resolved,
        principal_uid,
        ownership_guard,
    })
}

async fn recover_or_reserve_legacy_alias(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
) -> Result<astrid_storage::PrincipalDeletionGuard, AdminResponseBody> {
    if let Some(guard) = kernel
        .ownership_store
        .resume_principal_deletion_by_alias(principal)
        .await
        .map_err(|e| err_internal(format!("ownership store deletion recovery failed: {e}")))?
    {
        return Ok(guard);
    }
    kernel
        .ownership_store
        .guard_legacy_alias_deletion(principal.clone())
        .await
        .map_err(|e| err_internal(format!("ownership store legacy deletion guard failed: {e}")))
}

pub(super) async fn finish_identity_removal(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    pending: PendingIdentityRemoval,
) -> Result<(), AdminResponseBody> {
    let PendingIdentityRemoval {
        user,
        principal_uid,
        ownership_guard,
    } = pending;
    if let Some(user) = user {
        match kernel.identity_store.delete_user(user.id).await {
            Ok(true) => {},
            Ok(false) => {
                return Err(err_internal(
                    "identity store user disappeared during principal deletion".to_string(),
                ));
            },
            Err(e) => {
                return Err(err_internal(format!(
                    "identity store delete_user failed: {e}"
                )));
            },
        }
    }
    // Deleting the durable identity removes the alias→UID directory entry,
    // fencing every principal-scoped KV resolver. Purge once more after that
    // fence so a late write from an invocation dispatched before unload cannot
    // recreate state behind the reclaimed root.
    kernel.allowance_store.clear_for_principal(principal);
    kernel
        .capabilities
        .purge_principal(principal)
        .await
        .map_err(|e| err_internal(format!("post-identity capability purge failed: {e}")))?;
    if let (Some(store), Some(uid)) = (&kernel.principal_store, principal_uid) {
        store.purge_principal_kv(uid).map_err(|e| {
            err_internal(format!("post-identity principal state purge failed: {e}"))
        })?;
    }
    if let Some(guard) = ownership_guard {
        guard.finish().await.map_err(|e| {
            err_internal(format!(
                "ownership store deletion reservation cleanup failed: {e}"
            ))
        })?;
    }
    kernel
        .capabilities
        .finish_principal_retirement(principal)
        .await;
    kernel
        .allowance_store
        .finish_principal_retirement(principal);
    Ok(())
}

type ReclaimOutcome = (
    Vec<astrid_capsule_types::CapsuleId>,
    Vec<&'static str>,
    Vec<String>,
);

async fn retire_and_reclaim(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    principal_uid: Option<astrid_core::PrincipalUid>,
) -> Result<ReclaimOutcome, String> {
    let unloaded = kernel
        .unload_principal_capsules(principal)
        .await
        .map_err(|e| format!("failed to retire capsule views for `{principal}`: {e}"))?;

    kernel.allowance_store.clear_for_principal(principal);
    let mut authority_errors = Vec::new();
    if let Err(error) = kernel.capabilities.purge_principal(principal).await {
        authority_errors.push(format!("capabilities: {error}"));
    }

    // Native storage has an authoritative immutable-UID root. Removing it
    // reclaims every capsule namespace, including already-uninstalled or
    // corrupt/missing installations. Legacy/test compositions without the
    // native store retain the prior best-effort namespace fallback.
    if let (Some(store), Some(uid)) = (&kernel.principal_store, principal_uid) {
        if let Err(error) = store.purge_principal_kv(uid) {
            authority_errors.push(format!("principal state: {error}"));
        }
    } else {
        // Portable/test kernels without a principal store have no durable
        // package registry to enumerate. Never recover authority by scanning
        // a host capsule directory; only namespaces observed in the live
        // registry are safe to clear in this compatibility branch.
        let capsule_ids: BTreeSet<String> = unloaded.iter().map(ToString::to_string).collect();
        for capsule in capsule_ids {
            let namespace = format!("{principal}:capsule:{capsule}");
            if let Err(error) = kernel.kv.clear_namespace(&namespace).await {
                authority_errors.push(format!("kv namespace {namespace}: {error}"));
            }
        }
    }

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
    let secret_source_must_be_absent = match principal_uid {
        Some(uid) => crate::legacy_migration_barrier::legacy_secret_source_must_be_absent(
            &kernel.astrid_home,
            uid,
        )
        .map_err(|error| format!("legacy secret migration provenance: {error}"))?,
        None => false,
    };
    let outcomes = tokio::task::spawn_blocking(move || {
        [
            ("home", reclaim_empty_dir(&home)),
            ("keys", reclaim_file(&key)),
            // Legacy file-secrets are no longer authoritative.  Retire only
            // the caller-owned, verified root; never recursively follow a
            // symlink or delete an arbitrary home tree.
            (
                "secrets",
                reclaim_legacy_secret_root(&secrets, secret_source_must_be_absent),
            ),
        ]
    })
    .await
    .map_err(|e| format!("agent footprint reclamation task failed: {e}"))?;

    let mut reclaimed = Vec::new();
    let mut cleanup_errors = authority_errors;
    if cleanup_errors.is_empty() {
        reclaimed.push("kv");
    }
    for (what, outcome) in outcomes {
        match outcome {
            Ok(()) => reclaimed.push(what),
            Err(msg) => {
                warn!(%principal, %what, error = %msg, "agent.delete: footprint reclamation failed");
                cleanup_errors.push(format!("{what}: {msg}"));
            },
        }
    }
    Ok((unloaded, reclaimed, cleanup_errors))
}

/// Retire only an already-empty legacy root.  Agent deletion is not a layout
/// migration and must never recursively remove a native source; the global
/// migration barrier owns that operation.  Re-checking immediately before
/// `remove_dir` makes a source that appears after the admission check fail
/// closed instead of being discarded.
pub(super) fn reclaim_empty_dir(path: &Path) -> Result<(), String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "{}: refusing to retire a non-directory legacy root",
            path.display()
        ));
    }
    astrid_core::platform_fs::verify_no_redirects(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let mut entries =
        std::fs::read_dir(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if entries
        .next()
        .transpose()
        .map_err(|error| format!("{}: {error}", path.display()))?
        .is_some()
    {
        return Err(format!(
            "{}: legacy root became non-empty; migration retirement is required",
            path.display()
        ));
    }
    std::fs::remove_dir(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn reclaim_file(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

pub(super) fn reclaim_legacy_secret_root(
    path: &Path,
    secret_source_must_be_absent: bool,
) -> Result<(), String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    if secret_source_must_be_absent {
        return Err(format!(
            "{}: legacy secret source reappeared after completed migration",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "{}: legacy secret root is not a directory",
            path.display()
        ));
    }
    let entries =
        std::fs::read_dir(path).map_err(|error| format!("{}: {error}", path.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", path.display()))?;
        let entry_path = entry.path();
        let entry_metadata = std::fs::symlink_metadata(&entry_path)
            .map_err(|error| format!("{}: {error}", entry_path.display()))?;
        if !entry_metadata.file_type().is_file() {
            return Err(format!(
                "{}: refusing to retire non-regular legacy secret entry",
                entry_path.display()
            ));
        }
        std::fs::remove_file(&entry_path)
            .map_err(|error| format!("{}: {error}", entry_path.display()))?;
    }
    std::fs::remove_dir(path).map_err(|error| format!("{}: {error}", path.display()))
}
