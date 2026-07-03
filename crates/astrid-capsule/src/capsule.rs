//! Capsule trait and core types.

use std::path::{Path, PathBuf};

use async_trait::async_trait;

use crate::context::CapsuleContext;
use crate::error::{CapsuleError, CapsuleResult};
use crate::manifest::CapsuleManifest;

// `CapsuleId` is an engine-agnostic identifier; it lives in
// `astrid-capsule-types` and is re-exported here at its original path
// (`astrid_capsule::capsule::CapsuleId`) so consumers compile unchanged.
pub use astrid_capsule_types::CapsuleId;

/// Result of an interceptor invocation, determining how the dispatcher
/// continues the middleware chain.
///
/// Interceptors are called in priority order (lower fires first). Each
/// interceptor can pass the event through, short-circuit with a final
/// response, or deny the event entirely.
///
/// # Wire Format
///
/// WASM guests encode this as a discriminant byte followed by payload:
/// - `0x00` + payload = `Continue` (pass through, possibly modified)
/// - `0x01` + payload = `Final` (short-circuit success)
/// - `0x02` + UTF-8 reason = `Deny` (short-circuit denial)
/// - Empty bytes = `Continue` with empty payload (backward compatible)
#[derive(Debug, Clone)]
pub enum InterceptResult {
    /// Pass the (possibly modified) payload to the next interceptor in the chain.
    Continue(Vec<u8>),
    /// Short-circuit the chain with a final response. No further interceptors fire.
    Final(Vec<u8>),
    /// Deny the event. No further interceptors fire. The reason is audit-logged.
    Deny { reason: String },
}

impl InterceptResult {
    /// Decode an `InterceptResult` from raw WASM guest output bytes.
    ///
    /// Empty output is treated as `Continue` with empty payload for
    /// backward compatibility with interceptors that don't return a result.
    pub fn from_guest_bytes(bytes: Vec<u8>) -> Self {
        if bytes.is_empty() {
            return Self::Continue(Vec::new());
        }
        match bytes[0] {
            0x00 => Self::Continue(bytes[1..].to_vec()),
            0x01 => Self::Final(bytes[1..].to_vec()),
            0x02 => {
                let reason = String::from_utf8_lossy(&bytes[1..]).into_owned();
                Self::Deny { reason }
            },
            // Unknown discriminant — treat as Continue for forward compatibility.
            _ => Self::Continue(bytes),
        }
    }

    /// Construct an `InterceptResult` from a typed Component Model `capsule-result`.
    ///
    /// The `action` field maps to the variant:
    /// - `"continue"` → `Continue` (data as payload bytes)
    /// - `"final"` → `Final` (data as payload bytes)
    /// - `"deny"` / `"abort"` → `Deny` (data as reason string)
    /// - anything else → `Continue` (forward compatibility)
    pub fn from_capsule_result(action: &str, data: Option<&str>) -> Self {
        let payload = data.map(|d| d.as_bytes().to_vec()).unwrap_or_default();
        match action {
            "continue" => Self::Continue(payload),
            "final" => Self::Final(payload),
            "deny" | "abort" => Self::Deny {
                reason: data.unwrap_or("denied by interceptor").to_string(),
            },
            _ => Self::Continue(payload),
        }
    }
}

/// Result of waiting for a capsule or engine to signal readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadyStatus {
    /// The capsule signaled ready (or has no background task).
    Ready,
    /// The timeout expired before readiness was signaled.
    Timeout,
    /// The capsule's run loop exited or crashed before signaling ready.
    Crashed,
}

impl ReadyStatus {
    /// Returns `true` if the status is [`ReadyStatus::Ready`].
    #[must_use]
    pub fn is_ready(self) -> bool {
        self == Self::Ready
    }
}

/// The lifecycle state of a capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleState {
    Unloaded,
    Loading,
    Ready,
    Failed(String),
    Unloading,
}

/// A loaded capsule that can provide tools and integrations to the runtime.
#[async_trait]
pub trait Capsule: Send + Sync {
    /// The unique identifier for this capsule.
    fn id(&self) -> &CapsuleId;

    /// The manifest that describes this capsule.
    fn manifest(&self) -> &CapsuleManifest;

    /// Current lifecycle state.
    fn state(&self) -> CapsuleState;

    /// Load the capsule, initializing all of its execution engines.
    async fn load(&mut self, ctx: &CapsuleContext) -> CapsuleResult<()>;

    /// Unload the capsule, terminating all of its execution engines.
    async fn unload(&mut self) -> CapsuleResult<()>;

    /// Request cooperative cancellation before exclusive unload is available.
    ///
    /// In-flight dispatcher tasks can hold `Arc<dyn Capsule>` clones, which
    /// prevents callers from obtaining `&mut self` for `unload`. This hook lets
    /// engines interrupt blocking host calls first so those tasks can release
    /// their references and the normal unload path can finish.
    fn request_cancel(&self) {}

    /// Request cooperative cancellation of ONE principal's in-flight blocking
    /// work, leaving every other principal's work running.
    ///
    /// A shared-by-hash runtime survives a single principal's view release
    /// (issue #1069) — but that principal's blocked host calls (approval/
    /// elicit waits, net/io/ipc waits) would otherwise keep running inside the
    /// shared instance with nothing left to answer them, wedging it for every
    /// remaining principal. The kernel calls this on the non-last view release
    /// so exactly the departing principal's waits are interrupted.
    ///
    /// Default no-op — fail-safe: a capsule implementation without
    /// per-principal wait tracking keeps today's instance-scoped semantics
    /// (its waits end only on a full [`request_cancel`](Self::request_cancel))
    /// rather than risking cancellation of another principal's work.
    fn request_cancel_for(&self, _principal: &astrid_core::principal::PrincipalId) {}

    /// Extract the inbound receiver for uplink messages.
    /// This is typically called exactly once by the OS router after loading.
    fn take_inbound_rx(
        &mut self,
    ) -> Option<tokio::sync::mpsc::Receiver<astrid_core::InboundMessage>> {
        None
    }

    /// Wait for the capsule's background tasks to signal readiness.
    ///
    /// Returns [`ReadyStatus::Ready`] if all engines are ready or have no
    /// background tasks. Returns [`ReadyStatus::Timeout`] if the timeout
    /// expires, or [`ReadyStatus::Crashed`] if the run loop exited before
    /// signaling ready.
    async fn wait_ready(&self, _timeout: std::time::Duration) -> ReadyStatus {
        ReadyStatus::Ready
    }

    /// Invoke an interceptor handler by action name.
    ///
    /// Called by the event dispatcher when an IPC event matches one of
    /// this capsule's registered interceptor patterns. `action` is the
    /// handler name (e.g., `handle_user_prompt`), `payload` is the
    /// serialized IPC payload bytes. `caller` is the originating IPC
    /// message (if any) — used to set per-invocation principal context.
    ///
    /// Returns an [`InterceptResult`] that controls the middleware chain:
    /// - `Continue` — pass (possibly modified) payload to the next interceptor
    /// - `Final` — short-circuit the chain with a response
    /// - `Deny` — short-circuit the chain, audit-logged
    async fn invoke_interceptor(
        &self,
        _action: &str,
        _payload: &[u8],
        _caller: Option<&astrid_events::ipc::IpcMessage>,
    ) -> CapsuleResult<InterceptResult> {
        Err(CapsuleError::NotSupported(
            "interceptors not supported".into(),
        ))
    }

    /// Probe liveness beyond what `state()` reports.
    ///
    /// Returns the current state by default. Composite capsules delegate
    /// to their engines, which can detect silently exited background tasks.
    fn check_health(&self) -> CapsuleState {
        self.state()
    }

    /// The directory this capsule was loaded from.
    ///
    /// Used by the kernel health monitor to restart crashed capsules.
    /// Returns `None` for capsules that don't have a filesystem source
    /// (e.g., test mocks).
    fn source_dir(&self) -> Option<&Path> {
        None
    }
}

/// The universal, additive implementation of a Capsule.
///
/// Instead of choosing between WASM or MCP execution, the `CompositeCapsule`
/// owns a collection of `ExecutionEngine`s. When loaded, it iterates through
/// all of them, providing a unified lifecycle and security boundary for
/// everything declared in the `Capsule.toml`.
pub(crate) struct CompositeCapsule {
    id: CapsuleId,
    manifest: CapsuleManifest,
    state: CapsuleState,
    engines: Vec<Box<dyn crate::engine::ExecutionEngine>>,
    capsule_dir: Option<PathBuf>,
}

impl CompositeCapsule {
    /// Create a new, empty Composite Capsule from a manifest.
    pub(crate) fn new(manifest: CapsuleManifest) -> CapsuleResult<Self> {
        let id = CapsuleId::new(manifest.package.name.clone())?;
        Ok(Self {
            id,
            manifest,
            state: CapsuleState::Unloaded,
            engines: Vec::new(),
            capsule_dir: None,
        })
    }

    /// Set the source directory this capsule was loaded from.
    pub(crate) fn set_source_dir(&mut self, dir: PathBuf) {
        self.capsule_dir = Some(dir);
    }

    /// Add an execution engine (e.g., WasmEngine, McpEngine) to this capsule.
    pub(crate) fn add_engine(&mut self, engine: Box<dyn crate::engine::ExecutionEngine>) {
        self.engines.push(engine);
    }
}

#[async_trait]
impl Capsule for CompositeCapsule {
    fn id(&self) -> &CapsuleId {
        &self.id
    }

    fn manifest(&self) -> &CapsuleManifest {
        &self.manifest
    }

    fn state(&self) -> CapsuleState {
        self.state.clone()
    }

    async fn load(&mut self, ctx: &CapsuleContext) -> CapsuleResult<()> {
        self.state = CapsuleState::Loading;
        for engine in &mut self.engines {
            if let Err(e) = engine.load(ctx).await {
                self.state = CapsuleState::Failed(e.to_string());
                return Err(e);
            }
        }
        self.state = CapsuleState::Ready;
        Ok(())
    }

    async fn unload(&mut self) -> CapsuleResult<()> {
        self.state = CapsuleState::Unloading;
        for engine in &mut self.engines {
            // Unload on a best-effort basis so a failing engine doesn't
            // prevent others from shutting down gracefully.
            let _ = engine.unload().await;
        }
        self.state = CapsuleState::Unloaded;
        Ok(())
    }

    fn request_cancel(&self) {
        for engine in &self.engines {
            engine.request_cancel();
        }
    }

    fn request_cancel_for(&self, principal: &astrid_core::principal::PrincipalId) {
        for engine in &self.engines {
            engine.request_cancel_for(principal);
        }
    }

    async fn wait_ready(&self, timeout: std::time::Duration) -> ReadyStatus {
        let deadline = astrid_runtime::time::Instant::now() + timeout;
        for engine in &self.engines {
            let remaining =
                deadline.saturating_duration_since(astrid_runtime::time::Instant::now());
            if remaining.is_zero() {
                return ReadyStatus::Timeout;
            }
            let status = engine.wait_ready(remaining).await;
            if !status.is_ready() {
                return status;
            }
        }
        ReadyStatus::Ready
    }

    fn take_inbound_rx(
        &mut self,
    ) -> Option<tokio::sync::mpsc::Receiver<astrid_core::InboundMessage>> {
        for engine in &mut self.engines {
            if let Some(rx) = engine.take_inbound_rx() {
                return Some(rx);
            }
        }
        None
    }

    async fn invoke_interceptor(
        &self,
        action: &str,
        payload: &[u8],
        caller: Option<&astrid_events::ipc::IpcMessage>,
    ) -> CapsuleResult<InterceptResult> {
        for engine in &self.engines {
            match engine.invoke_interceptor(action, payload, caller).await {
                Ok(result) => return Ok(result),
                // Engine doesn't support interceptors — try the next one.
                Err(CapsuleError::NotSupported(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(CapsuleError::NotSupported(
            "no engine supports interceptors".into(),
        ))
    }

    fn check_health(&self) -> CapsuleState {
        for engine in &self.engines {
            let health = engine.check_health();
            if let CapsuleState::Failed(_) = &health {
                return health;
            }
        }
        self.state.clone()
    }

    fn source_dir(&self) -> Option<&Path> {
        self.capsule_dir.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::ExecutionEngine;
    use crate::manifest::{CapabilitiesDef, PackageDef};
    use async_trait::async_trait;

    /// A mock engine that always reports healthy.
    struct HealthyEngine;

    #[async_trait]
    impl ExecutionEngine for HealthyEngine {
        async fn load(&mut self, _ctx: &crate::context::CapsuleContext) -> CapsuleResult<()> {
            Ok(())
        }
        async fn unload(&mut self) -> CapsuleResult<()> {
            Ok(())
        }
    }

    /// A mock engine that reports failed health.
    struct FailedEngine;

    #[async_trait]
    impl ExecutionEngine for FailedEngine {
        async fn load(&mut self, _ctx: &crate::context::CapsuleContext) -> CapsuleResult<()> {
            Ok(())
        }
        async fn unload(&mut self) -> CapsuleResult<()> {
            Ok(())
        }
        fn check_health(&self) -> CapsuleState {
            CapsuleState::Failed("engine crashed".into())
        }
    }

    fn test_manifest() -> CapsuleManifest {
        CapsuleManifest {
            package: PackageDef {
                name: "test-capsule".into(),
                version: "0.0.1".into(),
                description: None,
                authors: Vec::new(),
                repository: None,
                homepage: None,
                documentation: None,
                license: None,
                license_file: None,
                readme: None,
                keywords: Vec::new(),
                categories: Vec::new(),
                astrid_version: None,
                publish: None,
                include: None,
                exclude: None,
                metadata: None,
            },
            components: Vec::new(),
            imports: std::collections::HashMap::new(),
            exports: std::collections::HashMap::new(),
            capabilities: CapabilitiesDef::default(),
            env: std::collections::HashMap::new(),
            context_files: Vec::new(),
            commands: Vec::new(),
            mcp_servers: Vec::new(),
            skills: Vec::new(),
            uplinks: Vec::new(),
            publishes: ::std::collections::HashMap::new(),
            subscribes: ::std::collections::HashMap::new(),
            tools: ::std::vec::Vec::new(),
        }
    }

    #[test]
    fn composite_check_health_all_healthy() {
        let mut capsule = CompositeCapsule::new(test_manifest()).unwrap();
        capsule.state = CapsuleState::Ready;
        capsule.add_engine(Box::new(HealthyEngine));
        capsule.add_engine(Box::new(HealthyEngine));

        assert_eq!(capsule.check_health(), CapsuleState::Ready);
    }

    #[test]
    fn composite_check_health_returns_first_failure() {
        let mut capsule = CompositeCapsule::new(test_manifest()).unwrap();
        capsule.state = CapsuleState::Ready;
        capsule.add_engine(Box::new(HealthyEngine));
        capsule.add_engine(Box::new(FailedEngine));

        assert_eq!(
            capsule.check_health(),
            CapsuleState::Failed("engine crashed".into())
        );
    }

    #[test]
    fn composite_check_health_no_engines_returns_state() {
        let mut capsule = CompositeCapsule::new(test_manifest()).unwrap();
        capsule.state = CapsuleState::Ready;

        assert_eq!(capsule.check_health(), CapsuleState::Ready);
    }

    // -- wait_ready tests --

    /// A mock engine that never signals ready (simulates slow startup).
    struct SlowEngine;

    #[async_trait]
    impl ExecutionEngine for SlowEngine {
        async fn load(&mut self, _ctx: &crate::context::CapsuleContext) -> CapsuleResult<()> {
            Ok(())
        }
        async fn unload(&mut self) -> CapsuleResult<()> {
            Ok(())
        }
        async fn wait_ready(&self, timeout: std::time::Duration) -> ReadyStatus {
            tokio::time::sleep(timeout).await;
            ReadyStatus::Timeout
        }
    }

    #[tokio::test]
    async fn composite_wait_ready_first_engine_timeout_starves_second() {
        // With a shared deadline, if the first engine consumes the entire
        // budget, the second engine gets zero time and returns Timeout
        // immediately. This test locks in the shared-deadline contract.
        let mut capsule = CompositeCapsule::new(test_manifest()).unwrap();
        capsule.add_engine(Box::new(SlowEngine));
        capsule.add_engine(Box::new(HealthyEngine));

        let status = capsule
            .wait_ready(std::time::Duration::from_millis(50))
            .await;
        assert_eq!(status, ReadyStatus::Timeout);
    }

    #[tokio::test]
    async fn composite_wait_ready_all_healthy() {
        let mut capsule = CompositeCapsule::new(test_manifest()).unwrap();
        capsule.add_engine(Box::new(HealthyEngine));
        capsule.add_engine(Box::new(HealthyEngine));

        let status = capsule
            .wait_ready(std::time::Duration::from_millis(100))
            .await;
        assert_eq!(status, ReadyStatus::Ready);
    }
}
