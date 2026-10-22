//! Principal-scoped replacement with lifecycle admission.

use super::{Kernel, RestartOutcome, capsule_audit, unload_replaced_runtime};
use astrid_core::PrincipalId;

impl Kernel {
    /// Restart the exact runtime generation visible to `principal`. Principal
    /// failures affect only that immutable UID. A `SystemResident` failure
    /// rebuilds its explicit singleton and restores its dependent views.
    ///
    /// The replacement is activated behind a closed route-admission gate and
    /// must become ready before it is atomically published. Returns
    /// [`RestartOutcome::Clean`] when the old runtime was then fully unloaded,
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
                prepared.capsule.request_cancel();
                if let Err(cleanup) = prepared.capsule.unload().await {
                    tracing::warn!(capsule_id = %id, %cleanup, "Failed to unload rejected replacement publication");
                }
                return Err(anyhow::anyhow!(error));
            }
            let replaced = if prepared.system_runtime {
                registry.replace_system_runtime_reserved(
                    &current_runtime,
                    prepared.capsule,
                    prepared.runtime_id,
                )?
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
