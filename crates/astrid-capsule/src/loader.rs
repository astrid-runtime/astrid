//! Factory and routing logic for instantiating Composite Capsules.

use std::path::PathBuf;

use crate::capsule::{Capsule, CompositeCapsule};
use crate::engine::wasm::limits::{CapsuleRuntimeLimits, HttpLimits};
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
    /// Kernel-owned aggregate generic-compute reservation ledger.
    compute_ledger: astrid_compute::ComputeLedger,
    /// Operator policy for generic compute groups.
    compute_limits: crate::ComputeRuntimeLimits,
    /// Host-derived (operator-overridable) concurrency ceilings, resolved once
    /// by the daemon and handed to every `WasmEngine` to size its host-call
    /// semaphores. A plain `Copy` value, not a shared handle. See
    /// [`CapsuleRuntimeLimits`].
    runtime_limits: CapsuleRuntimeLimits,
    /// Resolved `astrid:http` host ceilings (timeouts, redirect/stream caps,
    /// buffered-body limit), resolved once by the daemon from the `[http]`
    /// config section and handed to every `WasmEngine`. A global `Copy` value.
    /// See [`HttpLimits`].
    http_limits: HttpLimits,
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
    /// `http_limits` is the resolved `astrid:http` host ceilings; pass
    /// [`HttpLimits::default()`] for the host's historical constants in tests.
    #[must_use]
    pub fn new(
        mcp_client: SecureMcpClient,
        fuel_ledger: FuelLedger,
        fuel_rate: FuelRateLimiter,
        memory_ledger: MemoryLedger,
        runtime_limits: CapsuleRuntimeLimits,
        http_limits: HttpLimits,
    ) -> Self {
        Self::new_with_compute(
            mcp_client,
            fuel_ledger,
            fuel_rate,
            memory_ledger,
            runtime_limits,
            http_limits,
            astrid_compute::ComputeLedger::default(),
        )
    }

    /// Create a loader sharing the kernel's aggregate compute ledger.
    #[must_use]
    pub fn new_with_compute(
        mcp_client: SecureMcpClient,
        fuel_ledger: FuelLedger,
        fuel_rate: FuelRateLimiter,
        memory_ledger: MemoryLedger,
        runtime_limits: CapsuleRuntimeLimits,
        http_limits: HttpLimits,
        compute_ledger: astrid_compute::ComputeLedger,
    ) -> Self {
        Self::new_with_compute_policy(
            mcp_client,
            fuel_ledger,
            fuel_rate,
            memory_ledger,
            runtime_limits,
            http_limits,
            compute_ledger,
            crate::ComputeRuntimeLimits::default(),
        )
    }

    /// Create a loader sharing aggregate compute accounting and policy.
    #[allow(
        clippy::too_many_arguments,
        reason = "additive composition-root constructor preserves existing public APIs"
    )]
    #[must_use]
    pub fn new_with_compute_policy(
        mcp_client: SecureMcpClient,
        fuel_ledger: FuelLedger,
        fuel_rate: FuelRateLimiter,
        memory_ledger: MemoryLedger,
        runtime_limits: CapsuleRuntimeLimits,
        http_limits: HttpLimits,
        compute_ledger: astrid_compute::ComputeLedger,
        compute_limits: crate::ComputeRuntimeLimits,
    ) -> Self {
        Self {
            mcp_client,
            fuel_ledger,
            fuel_rate,
            memory_ledger,
            compute_ledger,
            compute_limits,
            runtime_limits,
            http_limits,
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
            composite.add_engine(Box::new(
                crate::engine::WasmEngine::new_with_compute_policy(
                    manifest.clone(),
                    capsule_dir.clone(),
                    self.fuel_ledger.clone(),
                    self.fuel_rate.clone(),
                    self.memory_ledger.clone(),
                    self.runtime_limits,
                    self.http_limits,
                    self.compute_ledger.clone(),
                    self.compute_limits,
                ),
            ));
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
        // Always added. Handles injecting context files and static commands
        // directly into the OS memory without booting any VMs or processes.
        composite.add_engine(Box::new(crate::engine::StaticEngine::new(
            manifest.clone(),
            capsule_dir.clone(),
        )));

        composite.set_source_dir(capsule_dir);

        Ok(Box::new(composite))
    }
}
