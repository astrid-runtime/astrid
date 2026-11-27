//! Principal-scoped replacement with lifecycle admission.

use super::{Kernel, capsule_audit};
use astrid_capsule::registry::RestartSnapshot;
use astrid_capsule_types::error::CapsuleError;
use astrid_core::PrincipalId;
use std::sync::Arc;

impl Kernel {
    /// Reload a single capsule by id without a daemon restart.
    ///
    /// If the capsule is already registered, [`Self::restart_capsule`] re-reads
    /// its source directory — picking up the new content-addressed bytes a
    /// reinstall wrote (a live upgrade / hot-swap). If it isn't registered yet,
    /// the currently-installed set is discovered and loaded (a fresh add;
    /// already-loaded capsules are skipped by `load_capsule`'s guard). Either
    /// way `astrid.v1.capsules_loaded` is published so the tool surface
    /// refreshes. Backs [`astrid_core::kernel_api::KernelRequest::ReloadCapsule`].
    pub(crate) async fn reload_one_capsule(
        &self,
        id: &astrid_capsule_types::CapsuleId,
        principal: &PrincipalId,
    ) -> Result<(), anyhow::Error> {
        self.reload_capsule_for_owner(id, principal, None).await
    }

    pub(crate) async fn reload_capsule_for_owner(
        &self,
        id: &astrid_capsule_types::CapsuleId,
        principal: &PrincipalId,
        admitted_uid: Option<astrid_core::PrincipalUid>,
    ) -> Result<(), anyhow::Error> {
        let view_guard = self.lock_capsule_view(principal, id).await;
        let registered = self.capsules.read().await.runtime_id_for(principal, id);
        if let Some(expected) = admitted_uid {
            self.principal_directory
                .bound_uid(principal, Some(expected))?;
        }
        if let Some(runtime) = registered {
            if admitted_uid.is_some_and(|uid| !runtime.key().scope().matches_view_owner(uid)) {
                anyhow::bail!("capsule '{id}' belongs to a different principal UID");
            }
            if self.capabilities.is_principal_retiring(principal).await {
                anyhow::bail!("cannot reload capsule '{id}' for retiring principal '{principal}'");
            }
            match self.restart_capsule(id, principal, Some(&runtime)).await? {
                RestartOutcome::Clean | RestartOutcome::OldInstanceLingering => {},
                RestartOutcome::OldInstanceUnloadFailed(error) => {
                    tracing::warn!(capsule_id = %id, %principal, %error,
                        "Capsule reloaded but the old runtime failed to unload");
                },
                RestartOutcome::Superseded => {
                    anyhow::bail!("capsule '{id}' changed generation during reload")
                },
            }
            self.publish_capsules_loaded().await;
        } else {
            drop(view_guard);
            // Build or refresh this principal's view from its installed set.
            self.ensure_principal_loaded_for_owner(principal, admitted_uid)
                .await;
            if self.capsules.read().await.get_for(principal, id).is_none()
                && let Some((_, dir)) = self
                    .sorted_principal_capsules(principal, admitted_uid)
                    .into_iter()
                    .find(|(manifest, _)| manifest.package.name == id.as_str())
            {
                self.load_capsule_for_owner(dir, principal, admitted_uid)
                    .await
                    .map_err(|error| anyhow::anyhow!("capsule '{id}' failed to load: {error:#}"))?;
            }
            {
                let registry = self.capsules.read().await;
                let runtime = registry.runtime_id_for(principal, id).ok_or_else(|| {
                    anyhow::anyhow!(
                        "capsule '{id}' was not found in the install directories or failed to load"
                    )
                })?;
                if let Some(uid) = admitted_uid {
                    self.principal_directory.bound_uid(principal, Some(uid))?;
                    if !runtime.key().scope().matches_view_owner(uid) {
                        anyhow::bail!("capsule '{id}' belongs to a different principal UID");
                    }
                }
            }
            self.publish_capsules_loaded().await;
        }
        Ok(())
    }

    /// Restart the exact runtime generation visible to `principal`. Principal
    /// failures affect only that immutable UID. A `SystemResident` failure
    /// rebuilds its explicit singleton and restores its dependent views.
    ///
    /// The replacement is activated behind a closed route-admission gate and
    /// must become ready before it is atomically published. Returns
    /// [`RestartOutcome::Clean`] when the old runtime was then fully unloaded,
    /// [`RestartOutcome::OldInstanceUnloadFailed`] if its unload returned an error,
    /// or [`RestartOutcome::OldInstanceLingering`] when another `Arc` still
    /// holds its already-cancelled resources.
    ///
    /// # Errors
    ///
    /// Returns an error if the capsule has no source directory, cannot be
    /// unregistered, or fails to reload.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(super) async fn restart_capsule(
        &self,
        id: &astrid_capsule_types::CapsuleId,
        principal: &PrincipalId,
        expected_runtime: Option<&astrid_capsule::registry::RuntimeId>,
    ) -> Result<RestartOutcome, anyhow::Error> {
        let _work = self
            .runtime_work
            .admit()
            .ok_or_else(|| anyhow::anyhow!("runtime is shutting down"))?;
        self.restart_capsule_admitted(id, principal, expected_runtime)
            .await
    }

    async fn restart_capsule_admitted(
        &self,
        id: &astrid_capsule_types::CapsuleId,
        principal: &PrincipalId,
        expected_runtime: Option<&astrid_capsule::registry::RuntimeId>,
    ) -> Result<RestartOutcome, anyhow::Error> {
        let (source_dir, current_runtime) = {
            let registry = self.capsules.read().await;
            let (runtime_id, capsule) =
                match registry.restart_snapshot_for(principal, id, expected_runtime) {
                    RestartSnapshot::Missing => {
                        anyhow::bail!("capsule '{id}' not found in registry")
                    },
                    RestartSnapshot::Superseded => return Ok(RestartOutcome::Superseded),
                    RestartSnapshot::Current(runtime_id, capsule) => (runtime_id, capsule),
                };
            let source_dir = capsule
                .source_dir()
                .map(std::path::Path::to_path_buf)
                .ok_or_else(|| anyhow::anyhow!("capsule '{id}' has no source directory"))?;
            (source_dir, runtime_id)
        };

        // Prepare and prove a route-gated replacement while the current
        // generation remains visible and healthy. A preparation or readiness
        // failure leaves the running view untouched.
        let prepared = self
            .prepare_runtime_replacement(id, &source_dir, principal, current_runtime.key().scope())
            .await?;

        self.publish_runtime_replacement(id, principal, current_runtime, prepared)
            .await
    }

    async fn publish_runtime_replacement(
        &self,
        id: &astrid_capsule_types::CapsuleId,
        principal: &PrincipalId,
        current_runtime: astrid_capsule::registry::RuntimeId,
        mut prepared: super::PreparedRuntimeReplacement,
    ) -> Result<RestartOutcome, anyhow::Error> {
        let identity = capsule_audit::CapsuleIdentity::of(prepared.capsule.as_ref());
        let load_guard = self.capsule_load_lock.lock().await;
        if self.capabilities.is_principal_retiring(principal).await {
            drop(load_guard);
            prepared.capsule.retire();
            super::capsule_removal::unload_rejected_runtime(prepared.capsule, id).await;
            anyhow::bail!("cannot replace capsule '{id}' for retiring principal '{principal}'");
        }
        let (mut previous, replacement) = {
            let mut registry = self.capsules.write().await;
            if !registry.is_current_runtime(principal, id, &current_runtime) {
                drop(registry);
                drop(load_guard);
                prepared.capsule.request_cancel();
                prepared.capsule.unload().await?;
                return Ok(RestartOutcome::Superseded);
            }
            if prepared.system_runtime
                && let Err(error) = registry.validate_system_runtime_replacement(
                    &current_runtime,
                    prepared.capsule.as_ref(),
                    &prepared.runtime_id,
                )
            {
                drop(registry);
                drop(load_guard);
                prepared.capsule.retire();
                super::capsule_removal::unload_rejected_runtime(prepared.capsule, id).await;
                return Err(anyhow::anyhow!(error));
            }
            let replaced = if prepared.system_runtime {
                registry.replace_system_runtime_reserved(
                    &current_runtime,
                    prepared.capsule,
                    prepared.runtime_id,
                )?
            } else {
                let uid = prepared
                    .principal_uid
                    .expect("principal replacement resolved durable uid");
                let publication = self.principal_directory.with_bound_input(
                    principal,
                    uid,
                    prepared,
                    |candidate| {
                        registry.replace_principal_runtime_reserved(
                            &current_runtime,
                            candidate.capsule,
                            candidate.runtime_id,
                            principal,
                            uid,
                        )
                    },
                );
                match publication {
                    Ok(replacement) => replacement?,
                    Err(mut candidate) => {
                        drop(registry);
                        drop(load_guard);
                        candidate.capsule.retire();
                        candidate.capsule.request_cancel();
                        candidate.capsule.unload().await?;
                        anyhow::bail!(
                            "owner of '{principal}' changed before publishing capsule '{id}'"
                        );
                    },
                }
            };
            let replacement = replaced
                .installed(&registry)
                .expect("the write guard still holds the newly installed generation");

            // Close the old generation before publishing the candidate's
            // already-ready routes. Dispatcher lookups already resolve the new
            // view, so no interval admits fresh work to both generations.
            replaced.previous.retire();
            replaced.previous.request_cancel();
            for viewer in registry.principals_viewing_runtime(&replaced.runtime_id) {
                replacement.resume_for(&viewer);
            }
            replacement.publish();
            (replaced.previous, replacement)
        };
        drop(load_guard);
        capsule_audit::record_capsule_loaded(self, principal, identity, "replace").await;

        let outcome = unload_replaced_runtime(id, &mut previous).await;
        if let Err(error) = replacement
            .invoke_interceptor("handle_lifecycle_restart", &[], None)
            .await
        {
            tracing::debug!(
                capsule_id = %id,
                error = %error,
                "Capsule does not handle lifecycle restart (optional)"
            );
        }

        Ok(outcome)
    }
}

/// Whether [`Kernel::restart_capsule`] fully tore the old instance down.
///
/// A restart publishes a fresh generation either way; this is a diagnostic of what
/// happened to the OLD one. It deliberately does NOT drive the retry cap: the
/// cap counts consecutive HEALTH failures (a lingering old instance is a normal,
/// harmless state for a busy capsule whose dispatcher consumer still holds a
/// clone — it is NOT a restart failure), and the health monitor prunes a
/// tracker when the capsule RECOVERS, not on the restart-call outcome.
#[derive(Debug)]
pub(super) enum RestartOutcome {
    /// The old runtime was exclusively unloaded after the fresh generation was
    /// atomically published.
    Clean,
    /// The replacement was published and exclusive unload returned the engine error.
    OldInstanceUnloadFailed(CapsuleError),
    /// The old runtime's exclusive `unload` was skipped because an `Arc` clone
    /// (e.g. a live dispatcher consumer holding a clone for up to its idle
    /// grace) was still held. Its run-loop and subprocesses were cooperatively
    /// cancelled — no CPU/process leak — and its memory reclaims when the last
    /// clone drops. This is common for a capsule under load and is NOT counted
    /// as a restart failure.
    OldInstanceLingering,
    /// The observed failed generation was already replaced before restart.
    Superseded,
}

async fn unload_replaced_runtime(
    id: &astrid_capsule_types::CapsuleId,
    previous: &mut Arc<dyn astrid_capsule::capsule::Capsule>,
) -> RestartOutcome {
    for retry in 0..20_u32 {
        if let Some(capsule) = Arc::get_mut(previous) {
            return match capsule.unload().await {
                Ok(()) => RestartOutcome::Clean,
                Err(error) => RestartOutcome::OldInstanceUnloadFailed(error),
            };
        }
        if retry < 19 {
            astrid_runtime::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
    tracing::warn!(
        capsule_id = %id,
        strong_count = Arc::strong_count(previous),
        "Old capsule generation remains referenced after replacement; autonomous \
         work was cancelled and memory reclaims when the last reference drops"
    );
    RestartOutcome::OldInstanceLingering
}

#[cfg(test)]
mod tests;
