//! Factory and routing logic for instantiating Composite Capsules.

use std::path::PathBuf;

use crate::capsule::{Capsule, CompositeCapsule};
use crate::engine::wasm::limits::CapsuleRuntimeLimits;
use crate::error::CapsuleResult;
use crate::fuel_ledger::{FuelLedger, FuelRateLimiter};
use crate::manifest::CapsuleManifest;
use crate::memory_ledger::MemoryLedger;

use astrid_mcp::SecureMcpClient;

/// Responsible for translating a declarative `Capsule.toml` manifest into
/// a live, unified `CompositeCapsule` packed with the correct execution engines.
pub struct CapsuleLoader {
    mcp_client: SecureMcpClient,
    /// Kernel-owned shared per-principal CPU ledger. The loader hands this same
    /// handle to every capsule's `WasmEngine` so CPU is aggregated per principal
    /// across all capsules (not per-capsule). See [`FuelLedger`].
    fuel_ledger: FuelLedger,
    /// Kernel-owned shared per-principal CPU-rate limiter (the deny side). Like
    /// `fuel_ledger`, handed to every `WasmEngine` so a principal's 1-second CPU
    /// rate is throttled cross-capsule. See [`FuelRateLimiter`].
    fuel_rate: FuelRateLimiter,
    /// Kernel-owned shared per-principal peak-memory ledger. Like `fuel_ledger`,
    /// handed to every `WasmEngine` so a principal's memory peak is the max
    /// across all capsules. See [`MemoryLedger`].
    memory_ledger: MemoryLedger,
    /// Host-derived (operator-overridable) concurrency ceilings, resolved once
    /// by the daemon and handed to every `WasmEngine` to size its host-call
    /// semaphores. A plain `Copy` value, not a shared handle. See
    /// [`CapsuleRuntimeLimits`].
    runtime_limits: CapsuleRuntimeLimits,
}

impl CapsuleLoader {
    /// Create a new Capsule Loader.
    ///
    /// `fuel_ledger` is the kernel-owned, shared per-principal CPU ledger
    /// (clone of the kernel's single instance); pass `FuelLedger::default()` in
    /// tests that don't exercise cross-capsule CPU aggregation. `fuel_rate` is
    /// the matching shared per-principal CPU-rate limiter (the deny side); pass
    /// `FuelRateLimiter::default()` in tests that don't exercise enforcement.
    /// `runtime_limits` is the resolved per-host concurrency ceiling pair; pass
    /// [`CapsuleRuntimeLimits::default()`] for all-host-derived sizing in tests.
    #[must_use]
    pub fn new(
        mcp_client: SecureMcpClient,
        fuel_ledger: FuelLedger,
        fuel_rate: FuelRateLimiter,
        memory_ledger: MemoryLedger,
        runtime_limits: CapsuleRuntimeLimits,
    ) -> Self {
        Self {
            mcp_client,
            fuel_ledger,
            fuel_rate,
            memory_ledger,
            runtime_limits,
        }
    }

    /// Parse a `CapsuleManifest` and build a unified `CompositeCapsule`.
    ///
    /// This method is the "router" of the Manifest-First architecture. It inspects
    /// the declarative TOML and provisions the correct runtime environments (WASM,
    /// Host Process, Static Context) securely into a single Capsule object.
    ///
    /// # Errors
    /// Returns a `CapsuleError` if the manifest is invalid or requests an
    /// unsupported engine configuration.
    pub fn create_capsule(
        &self,
        manifest: CapsuleManifest,
        capsule_dir: PathBuf,
    ) -> CapsuleResult<Box<dyn Capsule>> {
        let mut composite = CompositeCapsule::new(manifest.clone())?;

        // 1. WASM Component Engine
        if !manifest.components.is_empty() {
            composite.add_engine(Box::new(crate::engine::WasmEngine::new(
                manifest.clone(),
                capsule_dir.clone(),
                self.fuel_ledger.clone(),
                self.fuel_rate.clone(),
                self.memory_ledger.clone(),
                self.runtime_limits,
            )));
        }

        // 2. Legacy Host MCP Engine (The Airlock Override)
        for server in &manifest.mcp_servers {
            // If server.server_type == "stdio", then the user is explicitly requesting
            // a host process breakout.
            if server.server_type.as_deref() == Some("stdio") {
                composite.add_engine(Box::new(crate::engine::McpHostEngine::new(
                    manifest.clone(),
                    server.clone(),
                    capsule_dir.clone(),
                    self.mcp_client.clone(),
                )));
            }
        }
        // 3. Static Context Engine
        // Always added. Handles injecting context_files, static commands, and skills
        // directly into the OS memory without booting any VMs or Processes.
        composite.add_engine(Box::new(crate::engine::StaticEngine::new(
            manifest.clone(),
            capsule_dir.clone(),
        )));

        composite.set_source_dir(capsule_dir);

        Ok(Box::new(composite))
    }
}
