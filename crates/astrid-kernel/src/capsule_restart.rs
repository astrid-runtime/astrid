//! Principal-scoped replacement with lifecycle admission.

use super::{Kernel, capsule_audit};
use astrid_capsule_types::error::CapsuleError;
use astrid_core::PrincipalId;
use std::sync::Arc;

impl Kernel {
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
            let capsule = registry
                .get_for(principal, id)
                .ok_or_else(|| anyhow::anyhow!("capsule '{id}' not found in registry"))?;
            let runtime_id = registry
                .runtime_id_for(principal, id)
                .ok_or_else(|| anyhow::anyhow!("capsule '{id}' not found in registry"))?;
            if expected_runtime.is_some_and(|expected| expected != &runtime_id) {
                return Ok(RestartOutcome::Superseded);
            }
            let source_dir = capsule
                .source_dir()
                .map(std::path::Path::to_path_buf)
                .ok_or_else(|| anyhow::anyhow!("capsule '{id}' has no source directory"))?;
            (source_dir, runtime_id)
        };

        // Prepare and prove a route-gated replacement while the current
        // generation remains visible and healthy. A preparation or readiness
        // failure leaves the running view untouched.
        let mut prepared = self
            .prepare_runtime_replacement(id, &source_dir, principal, current_runtime.key().scope())
            .await?;

        let identity = capsule_audit::CapsuleIdentity::of(prepared.capsule.as_ref());
        let load_guard = self.capsule_load_lock.lock().await;
        if self.capabilities.is_principal_retiring(principal).await {
            drop(load_guard);
            prepared.capsule.retire();
            prepared.capsule.request_cancel();
            if let Err(cleanup) = prepared.capsule.unload().await {
                tracing::warn!(capsule_id = %id, %cleanup, "Failed to unload replacement rejected by principal retirement");
            }
            anyhow::bail!("cannot replace capsule '{id}' for retiring principal '{principal}'");
        }
        let (mut previous, replacement) = {
            let mut registry = self.capsules.write().await;
            if registry.runtime_id_for(principal, id).as_ref() != Some(&current_runtime) {
                drop(registry);
                drop(load_guard);
                prepared.capsule.request_cancel();
                prepared.capsule.unload().await?;
                return Ok(RestartOutcome::Superseded);
            }
            let replaced = if prepared.system_runtime {
                match registry.try_replace_system_runtime_reserved(
                    &current_runtime,
                    prepared.capsule,
                    prepared.runtime_id,
                ) {
                    Ok(replaced) => replaced,
                    Err(mut rejected) => {
                        drop(registry);
                        drop(load_guard);
                        rejected.capsule.retire();
                        rejected.capsule.request_cancel();
                        if let Err(cleanup) = rejected.capsule.unload().await {
                            tracing::warn!(capsule_id = %id, %cleanup, "Failed to unload rejected replacement publication");
                        }
                        return Err(anyhow::anyhow!(rejected.error));
                    },
                }
            } else {
                registry.replace_principal_runtime_reserved(
                    &current_runtime,
                    prepared.capsule,
                    prepared.runtime_id,
                    principal,
                    prepared
                        .principal_uid
                        .expect("principal replacement resolved durable uid"),
                )?
            };
            let replacement = registry
                .get_for(principal, id)
                .expect("replacement generation was atomically published");

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
