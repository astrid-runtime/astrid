//! Authenticated durable capsule removal and optional state reclamation.

use astrid_capsule_types::CapsuleId;
use astrid_core::PrincipalId;
use astrid_storage::CapsuleInstallExpectation;

use crate::{CapsuleViewGuard, Kernel};

impl Kernel {
    /// Unload a single capsule by id without a daemon restart.
    ///
    /// The keyed lifecycle fence remains held until the old view has quiesced,
    /// its final runtime has unloaded, and the refreshed capsule inventory has
    /// been published.
    ///
    /// # Errors
    ///
    /// Returns an error only if the registry fails to unregister a capsule it
    /// reported as present.
    pub(crate) async fn unload_one_capsule(
        &self,
        id: &CapsuleId,
        principal: &PrincipalId,
    ) -> Result<bool, anyhow::Error> {
        let view_guard = self.lock_capsule_view(principal, id).await;
        self.unload_one_capsule_with_view_guard(id, principal, &view_guard)
            .await
    }

    /// Unload one capsule while the caller retains its keyed lifecycle fence.
    async fn unload_one_capsule_with_view_guard(
        &self,
        id: &CapsuleId,
        principal: &PrincipalId,
        _view_guard: &CapsuleViewGuard,
    ) -> Result<bool, anyhow::Error> {
        let load_guard = self.capsule_load_lock.lock().await;
        let removed = {
            let mut registry = self.capsules.write().await;
            match registry.unregister_for(principal, id) {
                Ok(removed) => removed,
                Err(astrid_capsule_types::error::CapsuleError::NotFound(_)) => return Ok(false),
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "failed to unregister capsule '{id}': {error}"
                    ));
                },
            }
        };

        if removed.torn_down {
            removed.capsule.retire();
            removed.capsule.request_cancel();
        }
        drop(load_guard);
        removed.capsule.quiesce_for(principal).await;

        if removed.torn_down {
            let mut old = removed.capsule;
            let mut unloaded = false;
            for retry in 0..20_u32 {
                if let Some(capsule) = std::sync::Arc::get_mut(&mut old) {
                    if let Err(error) = capsule.unload().await {
                        tracing::warn!(
                            capsule_id = %id,
                            %error,
                            "Capsule unload failed during unload request"
                        );
                    }
                    unloaded = true;
                    break;
                }
                if retry < 19 {
                    astrid_runtime::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
            if !unloaded {
                tracing::warn!(
                    capsule_id = %id,
                    strong_count = std::sync::Arc::strong_count(&old),
                    "Cannot call unload - Arc still held by in-flight task"
                );
            }
        } else {
            tracing::debug!(
                capsule_id = %id,
                principal = %principal,
                "Unloaded one view of a SystemResident runtime; other principals still \
                 reference it, so the runtime is left running and only the \
                 departing principal's in-flight host calls were cancelled"
            );
        }

        self.publish_capsules_loaded().await;
        Ok(true)
    }

    /// Atomically remove one capsule package from the authenticated owner's
    /// durable registry, then tear down the corresponding live view. Native
    /// install directories are never consulted or deleted by this path.
    ///
    /// A purge is deliberately retryable after package deletion: if state
    /// reclamation was interrupted, the operator can repeat the same command
    /// without reinstalling untrusted package bytes first.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable store or owner mapping is unavailable,
    /// the registry mutation fails, the live view cannot be unloaded, or the
    /// selected capsule's KV namespace cannot be reclaimed.
    #[cfg(not(target_family = "wasm"))]
    pub(crate) async fn remove_one_capsule(
        &self,
        id: &CapsuleId,
        principal: &PrincipalId,
        purge: bool,
    ) -> Result<bool, anyhow::Error> {
        // Identity mutations use the same barrier. Keep the mutable alias
        // bound to one immutable UID until every alias-addressed state
        // mutation below has committed.
        let _identity_guard = self.admin_write_lock.lock().await;
        let view_guard = self.lock_capsule_view(principal, id).await;
        let store = self
            .principal_store
            .clone()
            .ok_or_else(|| anyhow::anyhow!("authoritative principal store is unavailable"))?;
        let uid = self
            .principal_directory
            .uid_for(principal)
            .map_err(|error| anyhow::anyhow!("resolve durable owner for {principal}: {error}"))?;
        let owner = astrid_storage::StateOwner::Principal(uid);
        let snapshot = store
            .capsules()
            .get_snapshot(&owner, id.as_str())
            .map_err(|error| anyhow::anyhow!("read durable capsule package '{id}': {error}"))?;
        let Some(snapshot) = snapshot else {
            if purge {
                purge_capsule_state(&store, principal, uid, id).await?;
                return Ok(true);
            }
            return Ok(false);
        };

        // Quiesce and unload before deleting the durable package. If unload
        // fails, the package remains authoritative and can be retried on the
        // next request; no live runtime is left without its registry source.
        let _ = self
            .unload_one_capsule_with_view_guard(id, principal, &view_guard)
            .await?;
        let removed = match store.capsules().remove_checked(
            &owner,
            id.as_str(),
            CapsuleInstallExpectation::Generation(snapshot.generation()),
        ) {
            Ok(removed) => removed,
            Err(error) => {
                // A replacement may have published while its activation was
                // waiting on `view_guard`. Release that fence before restoring
                // the currently authoritative generation.
                drop(view_guard);
                self.ensure_principal_loaded(principal).await;
                return Err(anyhow::anyhow!(
                    "remove durable capsule package '{id}': {error}"
                ));
            },
        };
        if !removed {
            drop(view_guard);
            self.ensure_principal_loaded(principal).await;
            return Err(anyhow::anyhow!(
                "durable capsule package '{id}' disappeared during removal"
            ));
        }
        if purge {
            purge_capsule_state(&store, principal, uid, id).await?;
        }
        Ok(true)
    }

    #[cfg(target_family = "wasm")]
    pub(crate) async fn remove_one_capsule(
        &self,
        _id: &CapsuleId,
        _principal: &PrincipalId,
        _purge: bool,
    ) -> Result<bool, anyhow::Error> {
        Err(anyhow::anyhow!(
            "durable capsule removal is unavailable on portable hosts"
        ))
    }
}

#[cfg(not(target_family = "wasm"))]
async fn purge_capsule_state(
    store: &astrid_storage::RuntimePrincipalStore,
    principal: &PrincipalId,
    expected_uid: astrid_core::PrincipalUid,
    id: &CapsuleId,
) -> Result<(), anyhow::Error> {
    store
        .purge_capsule_kv_for_owner(expected_uid, principal, id.as_str())
        .await
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("purge capsule state for '{id}': {error}"))
}
