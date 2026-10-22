//! Construct authority-scoped engines while sharing immutable manifest data.

use super::{Arc, CapsuleManifest, CompiledWasmCache, PathBuf, WasmEngine, limits};

impl WasmEngine {
    /// Construct a WASM engine for one capsule.
    ///
    /// `fuel_ledger` is the kernel-owned, shared per-principal CPU ledger; the
    /// kernel passes the *same* handle to every capsule's engine so per-principal
    /// CPU is aggregated cross-capsule. Tests that don't care about aggregation
    /// pass `FuelLedger::default()` for an isolated ledger.
    ///
    /// `fuel_rate` is the matching kernel-owned, shared per-principal CPU-rate
    /// limiter (the deny side); pass `FuelRateLimiter::default()` for an
    /// isolated limiter in tests.
    ///
    /// `runtime_limits` is the host-derived (operator-overridable) concurrency
    /// ceiling pair the daemon resolves once and hands to every engine; pass
    /// [`CapsuleRuntimeLimits::default`](limits::CapsuleRuntimeLimits::default)
    /// for all-host-derived sizing in tests.
    ///
    /// `http_limits` is the resolved `astrid:http` host ceilings (timeouts,
    /// redirect/stream caps, buffered-body limit) from the `[http]` config
    /// section — a global value, the same for every engine; pass
    /// [`HttpLimits::default`](limits::HttpLimits::default) for the host's
    /// historical constants in tests.
    pub fn new(
        manifest: CapsuleManifest,
        capsule_dir: PathBuf,
        fuel_ledger: crate::FuelLedger,
        fuel_rate: crate::FuelRateLimiter,
        memory_ledger: crate::MemoryLedger,
        runtime_limits: limits::CapsuleRuntimeLimits,
        http_limits: limits::HttpLimits,
    ) -> Self {
        Self::new_shared(
            Arc::new(manifest),
            capsule_dir,
            fuel_ledger,
            fuel_rate,
            memory_ledger,
            runtime_limits,
            http_limits,
        )
    }

    pub(crate) fn new_shared(
        manifest: Arc<CapsuleManifest>,
        capsule_dir: PathBuf,
        fuel_ledger: crate::FuelLedger,
        fuel_rate: crate::FuelRateLimiter,
        memory_ledger: crate::MemoryLedger,
        runtime_limits: limits::CapsuleRuntimeLimits,
        http_limits: limits::HttpLimits,
    ) -> Self {
        Self {
            manifest,
            _capsule_dir: capsule_dir,
            wasmtime_engine: None,
            compiled_cache: CompiledWasmCache::default(),
            compiled_artifact: None,
            pool: None,
            inbound_rx: None,
            run_handles: Vec::new(),
            activation_tx: None,
            defer_activation: false,
            route_admission_gate: astrid_events::RouteAdmissionGate::default(),
            ready_rxs: Vec::new(),
            cancel_token: None,
            principal_cancel_tokens: None,
            principal_invocations: None,
            profile_cache: None,
            owner_principal: None,
            system_runtime: false,
            runtime_id: None,
            overlay_registry: None,
            fuel_ledger,
            memory_ledger,
            fuel_rate,
            user_cpu: None,
            group_config: None,
            runtime_limits,
            http_limits,
            workspace_cow: None,
            #[cfg(not(target_family = "wasm"))]
            workspace_branches: None,
            process_tracker: None,
            persistent_processes: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::{Capsule, CompositeCapsule};

    #[test]
    fn composite_and_wasm_share_one_immutable_manifest_snapshot() {
        let manifest: CapsuleManifest = toml::from_str(
            r#"[package]
name = "shared-manifest"
version = "0.0.1"
"#,
        )
        .unwrap();
        let manifest = Arc::new(manifest);
        let capsule = CompositeCapsule::new(Arc::clone(&manifest)).unwrap();
        let engine = WasmEngine::new_shared(
            Arc::clone(&manifest),
            PathBuf::new(),
            crate::FuelLedger::default(),
            crate::FuelRateLimiter::default(),
            crate::MemoryLedger::default(),
            limits::CapsuleRuntimeLimits::default(),
            limits::HttpLimits::default(),
        );
        assert_eq!(Arc::strong_count(&manifest), 3);
        assert!(std::ptr::eq(capsule.manifest(), Arc::as_ref(&manifest)));
        assert!(Arc::ptr_eq(&engine.manifest, &manifest));
        let gate =
            crate::security::ManifestSecurityGate::new(Arc::clone(&manifest), PathBuf::new(), None);
        assert_eq!(Arc::strong_count(&manifest), 4);
        let gate_clone = gate.clone();
        assert_eq!(Arc::strong_count(&manifest), 5);
        drop((gate, gate_clone));
        assert_eq!(Arc::strong_count(&manifest), 3);
        drop(engine);
        assert_eq!(Arc::strong_count(&manifest), 2);
        drop(capsule);
        assert_eq!(Arc::strong_count(&manifest), 1);
    }
}
