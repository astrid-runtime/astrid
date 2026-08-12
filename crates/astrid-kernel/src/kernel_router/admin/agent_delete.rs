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
    let pending = match prepare_identity_removal(kernel, &principal).await {
        Ok(pending) => pending,
        Err(response) => return response,
    };

    if let Err(e) = kernel
        .identity_store
        .unlink(AGENT_IDENTITY_PLATFORM, principal.as_str())
        .await
    {
        return err_internal(format!("identity store unlink failed: {e}"));
    }

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

    let (unloaded_capsules, reclaimed, cleanup_errors) =
        match retire_and_reclaim(kernel, &principal).await {
            Ok(result) => result,
            Err(e) => return err_internal(e),
        };

    if let Err(response) = finish_identity_removal(kernel, pending).await {
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

struct PendingIdentityRemoval {
    user: Option<astrid_core::AstridUserId>,
    ownership_guard: Option<astrid_storage::PrincipalDeletionGuard>,
}

async fn prepare_identity_removal(
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

    let ownership_guard = if let Some(user) = resolved.as_ref() {
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
                Ok(guard) => Some(guard),
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
            None
        }
    } else {
        kernel
            .ownership_store
            .finish_principal_deletion_by_alias(principal)
            .await
            .map_err(|e| err_internal(format!("ownership store deletion recovery failed: {e}")))?;
        None
    };

    Ok(PendingIdentityRemoval {
        user: resolved,
        ownership_guard,
    })
}

async fn finish_identity_removal(
    kernel: &Arc<crate::Kernel>,
    pending: PendingIdentityRemoval,
) -> Result<(), AdminResponseBody> {
    if let Some(user) = pending.user {
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
    if let Some(guard) = pending.ownership_guard {
        guard.finish().await.map_err(|e| {
            err_internal(format!(
                "ownership store deletion reservation cleanup failed: {e}"
            ))
        })?;
    }
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
) -> Result<ReclaimOutcome, String> {
    let unloaded = kernel
        .unload_principal_capsules(principal)
        .await
        .map_err(|e| format!("failed to retire capsule views for `{principal}`: {e}"))?;

    // KV lives in the kernel store rather than below the principal home, so
    // reclaim each capsule namespace explicitly before deleting the install
    // tree. The live view covers active capsules; the on-disk set also covers
    // installed capsules that failed to load.
    let capsule_dir = kernel.astrid_home.principal_home(principal).capsules_dir();
    let mut capsule_ids: BTreeSet<String> = unloaded.iter().map(ToString::to_string).collect();
    if let Ok(entries) = std::fs::read_dir(&capsule_dir) {
        capsule_ids.extend(entries.flatten().filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(std::fs::FileType::is_dir)
                .and_then(|_| entry.file_name().into_string().ok())
        }));
    }
    let mut kv_errors = Vec::new();
    for capsule in capsule_ids {
        let namespace = format!("{principal}:capsule:{capsule}");
        if let Err(error) = kernel.kv.clear_namespace(&namespace).await {
            kv_errors.push(format!("kv namespace {namespace}: {error}"));
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
    let outcomes = tokio::task::spawn_blocking(move || {
        [
            ("home", reclaim_dir_all(&home)),
            ("keys", reclaim_file(&key)),
            ("secrets", reclaim_dir_all(&secrets)),
        ]
    })
    .await
    .map_err(|e| format!("agent footprint reclamation task failed: {e}"))?;

    let mut reclaimed = Vec::new();
    let mut cleanup_errors = kv_errors;
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

fn reclaim_dir_all(path: &Path) -> Result<(), String> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn reclaim_file(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}
