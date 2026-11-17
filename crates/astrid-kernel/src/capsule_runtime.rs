//! Construct private capsule engines with kernel-shared host services.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{Kernel, PrincipalId, explicit_workspace_portal_root};
#[cfg(test)]
use super::{capsule_adversarial_tests, ingress_readiness};

pub(super) fn capture_native_log_root(
    home: &astrid_core::dirs::AstridHome,
) -> Option<Arc<astrid_capsule::engine::wasm::NativeLogRoot>> {
    match astrid_capsule::engine::wasm::NativeLogRoot::capture(home) {
        Ok(root) => Some(Arc::new(root)),
        Err(error) => {
            tracing::warn!(%error, "native log deferral unavailable; retaining eager logs");
            None
        },
    }
}

impl Kernel {
    /// Build and load one mutable runtime. `Some(principal)` installs that
    /// principal's concrete KV/home/env authority from construction onward.
    /// `None` is reserved for an explicitly classified `SystemResident` service
    /// and receives a neutral system namespace rather than `default` authority.
    ///
    /// # Errors
    ///
    /// Returns an error if the capsule cannot be created, the KV scope cannot be
    /// built, or `capsule.load` fails.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(super) async fn build_capsule_runtime(
        &self,
        manifest: astrid_capsule_types::manifest::CapsuleManifest,
        dir: &std::path::Path,
        principal: Option<&PrincipalId>,
        runtime_id: astrid_capsule::registry::RuntimeId,
    ) -> Result<Box<dyn astrid_capsule::capsule::Capsule>, anyhow::Error> {
        self.verify_workspace_capsule_tree(dir)?;
        let load_principal = principal.cloned().unwrap_or_default();

        let loader = astrid_capsule::loader::CapsuleLoader::new(
            self.mcp.clone(),
            self.fuel_ledger.clone(),
            self.fuel_rate.clone(),
            self.memory_ledger.clone(),
            self.runtime_limits,
            self.http_limits,
        )
        .with_compiled_wasm_cache(self.compiled_wasm.clone())
        .with_native_log_root(self.native_log_root.clone())
        .with_runtime_id(runtime_id)
        .with_deferred_background_activation();
        let mut capsule = loader.create_capsule(manifest, dir.to_path_buf())?;
        let capsule_name = capsule.id().to_string();

        let kv = astrid_storage::ScopedKvStore::new(
            Arc::clone(&self.kv),
            principal.map_or_else(
                || format!("system:capsule:{}", capsule.id()),
                |principal| format!("{principal}:capsule:{}", capsule.id()),
            ),
        )?;

        // Environment configuration is loaded from the host-only typed
        // control namespace during invocation setup. Never read a capsule
        // directory `.env.json` or a principal-home env file here: those paths
        // are legacy import sources only and are not authoritative runtime
        // state.
        self.verify_workspace_capsule_tree(dir)?;

        let capsule_listener = (!self.native_uplink_owns_listener.load(Ordering::Acquire))
            .then(|| self.cli_socket_listener.clone())
            .flatten();
        let mut ctx = astrid_capsule::context::CapsuleContext::new(
            load_principal,
            self.workspace_root.clone(),
            // Durable home VFS authority is threaded separately through the
            // UID-bound principal store. Do not pass a native PrincipalHome
            // path into the steady-state capsule context.
            None,
            kv,
            Arc::clone(&self.event_bus),
            capsule_listener,
        )
        .with_astrid_workspace()
        .with_principal_storage(
            self.principal_store.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "native capsule runtime requires the authoritative principal store"
                )
            })?,
            self.principal_directory.clone(),
        )
        .with_workspace_branches(self.workspace_branches.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "canonical Astrid workspace requires the kernel workspace branch service"
            )
        })?)
        .with_process_storage_mount_broker(
            self.process_storage_mount_broker
                .get()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("native process storage mount broker unavailable"))?,
        )
        .with_registry(Arc::clone(&self.capsules))
        .with_session_token(Arc::clone(&self.session_token))
        .with_allowance_store(Arc::clone(&self.allowance_store))
        .with_identity_store(Arc::clone(&self.identity_store))
        .with_profile_cache(Arc::clone(&self.profile_cache))
        .with_overlay_registry(Arc::clone(&self.overlay_registry))
        // Thread the live group config so capsule invocation checks observe
        // runtime group mutations without requiring capsule reloads. Load-time
        // run-loop decisions take their own explicit snapshot.
        .with_live_group_config(Arc::clone(&self.groups))
        // Hand this capsule its operator-approved local-egress allowlist (if
        // any) so the SSRF airlock can exempt sanctioned loopback/private
        // endpoints for it. Absent entry = empty = no exemptions.
        .with_local_egress(
            self.local_egress
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .and_then(|snapshot| snapshot.get(&capsule_name))
                .cloned()
                .unwrap_or_default(),
        )
        // Hand the engine the signed per-action audit sink so sensitive
        // fs/net/process host calls (allowed, failed, OR denied) land on the
        // kernel's durable, hash-chained audit log — not just the
        // off-by-default observability tracing targets.
        .with_audit_sink(self.audit_sink.as_ref().clone());
        ctx.user_cpu = Some(Arc::clone(&self.user_cpu));
        #[cfg(not(target_family = "wasm"))]
        {
            ctx.secret_elicits = self.native_secret_inputs.get().cloned();
        }
        if let Some(project_root) = explicit_workspace_portal_root(dir) {
            ctx = ctx.with_hosted_portal(project_root);
        }
        #[cfg(test)]
        capsule_adversarial_tests::record_workspace_source(&capsule_name, &ctx.workspace_source);
        capsule.load(&ctx).await?;
        #[cfg(test)]
        ingress_readiness::tests::pause_after_load(&capsule_name).await;
        Ok(capsule)
    }
}
