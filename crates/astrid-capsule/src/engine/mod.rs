//! Execution engine trait for Composite Capsules.
//!
//! Because a single `Capsule.toml` can define multiple execution units
//! (e.g. a WASM component AND a legacy MCP host process), the OS uses
//! an additive "Composite" architecture. The capsule iterates over its
//! registered engines to handle lifecycle events.

// The MCP host engine spawns OS processes via `astrid-mcp`; native-only.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod mcp;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod mcp_teardown;
#[cfg(all(test, not(all(target_arch = "wasm32", target_os = "unknown"))))]
mod mcp_tests;
mod static_engine;
// The Wasmtime execution engine and its host functions are native-only; an
// alternate host supplies its own `ExecutionEngine` behind the same trait.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod wasm;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) use mcp::McpHostEngine;
pub(crate) use static_engine::StaticEngine;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) use wasm::WasmEngine;

use async_trait::async_trait;

use crate::context::CapsuleContext;
use crate::error::CapsuleResult;

/// A runtime environment capable of executing capsule logic.
///
/// Examples include `WasmEngine`, `McpHostEngine`, and `StaticEngine`.
#[async_trait]
pub(crate) trait ExecutionEngine: Send + Sync {
    /// Load the engine (e.g., spawn the WASM VM or start the Node.js process).
    async fn load(&mut self, ctx: &CapsuleContext) -> CapsuleResult<()>;

    /// Unload the engine (e.g., drop WASM memory or SIGTERM the child process).
    async fn unload(&mut self) -> CapsuleResult<()>;

    /// Start a prepared engine behind closed external-route admission.
    ///
    /// Engines without autonomous work are already usable after `load` and
    /// therefore keep the default no-op. The kernel proves readiness before
    /// publishing the generation and opening its routes.
    async fn activate(&mut self) -> CapsuleResult<()> {
        Ok(())
    }

    /// Open externally visible routes after this prepared engine is ready.
    fn publish(&self) {}

    /// Close externally visible route admission for a retiring generation.
    fn retire(&self) {}

    /// Request cooperative cancellation of blocking work before exclusive unload.
    ///
    /// This is intentionally synchronous and `&self`: callers may still have
    /// in-flight `Arc` clones that prevent `unload(&mut self)`, but those same
    /// in-flight tasks need a cancellation signal so they can release the Arc.
    fn request_cancel(&self) {}

    /// Request cooperative cancellation of ONE principal's in-flight blocking
    /// work, leaving every other principal's work running.
    ///
    /// Called when a principal releases a view of an explicit system runtime:
    /// the singleton survives, but the departing principal's blocked host
    /// calls must not wedge it for remaining views.
    ///
    /// Default no-op — fail-safe: an engine without per-principal wait
    /// tracking keeps today's instance-scoped semantics (its waits end only
    /// on a full [`request_cancel`](Self::request_cancel)), which merely
    /// leaves the pre-existing wedge window open rather than cancelling work
    /// that belongs to someone else.
    fn request_cancel_for(&self, _principal: &astrid_core::principal::PrincipalId) {}

    /// Re-open per-principal work after a new dispatch view is registered.
    ///
    /// Engines that retain a cancellation tombstone use this explicit view
    /// lifecycle edge to distinguish a legitimate delete-then-recreate from an
    /// invocation that raced the previous view's removal.
    fn resume_for(&self, _principal: &astrid_core::principal::PrincipalId) {}

    /// Close admission, cancel principal-scoped waits, and wait until every
    /// interceptor admitted before the fence has returned.
    async fn quiesce_for(&self, principal: &astrid_core::principal::PrincipalId) {
        self.request_cancel_for(principal);
    }

    /// Extract the inbound receiver if this engine provides one.
    fn take_inbound_rx(
        &mut self,
    ) -> Option<tokio::sync::mpsc::Receiver<astrid_core::InboundMessage>> {
        None
    }

    /// Wait for the engine's background task to signal readiness.
    ///
    /// Returns [`ReadyStatus::Ready`] if the engine is ready or has no
    /// background task. Returns [`ReadyStatus::Timeout`] or
    /// [`ReadyStatus::Crashed`] on failure.
    /// Engines without background tasks return `Ready` immediately.
    async fn wait_ready(&self, _timeout: std::time::Duration) -> crate::capsule::ReadyStatus {
        crate::capsule::ReadyStatus::Ready
    }

    /// Invoke an interceptor handler by action name.
    ///
    /// `action` is the handler name (e.g., `handle_user_prompt`) and
    /// `payload` is the serialized IPC payload. `caller` is the originating
    /// IPC message used to set per-invocation principal context on `HostState`.
    ///
    /// The default implementation returns an error. Engines that support
    /// interceptors (e.g., `WasmEngine`) override this.
    ///
    /// **Async contract:** the future returned by this method MAY be
    /// cancelled (e.g. the dispatcher task is aborted). Implementations
    /// must ensure any per-invocation state set on the engine is cleared
    /// before any `.await` that may not return — typically via an RAII
    /// guard that runs in `Drop`. The wasm engine uses `ClearOnDrop`
    /// across the `call_async` await.
    async fn invoke_interceptor(
        &self,
        _action: &str,
        _payload: &[u8],
        _caller: Option<&astrid_events::ipc::IpcMessage>,
    ) -> CapsuleResult<crate::capsule::InterceptResult> {
        Err(crate::error::CapsuleError::NotSupported(
            "interceptors not supported by this engine".into(),
        ))
    }

    /// Probe engine liveness beyond what `state()` reports.
    ///
    /// The default implementation returns the capsule's current state.
    /// Engines with background tasks (e.g., `WasmEngine`) override this
    /// to detect when a run loop has silently exited.
    fn check_health(&self) -> crate::capsule::CapsuleState {
        crate::capsule::CapsuleState::Ready
    }

    /// Commit this engine's OS-level copy-on-write workspace changes into the
    /// pristine workspace (the gate's "approve"). Returns `Ok(true)` if this
    /// engine committed a copy-on-write workspace, `Ok(false)` if it has none
    /// (git-managed, an explicitly rejected non-isolated portal, or an engine
    /// with no workspace).
    ///
    /// Default: `Ok(false)`. `WasmEngine` overrides to drive its
    /// [`WorkspaceCow`](astrid_vfs::WorkspaceCow) backend.
    async fn promote_workspace(&self, caller: &astrid_core::PrincipalId) -> CapsuleResult<bool> {
        let _ = caller;
        Ok(false)
    }

    /// Discard this engine's OS-level copy-on-write workspace changes (the
    /// gate's "reject"). Returns `Ok(true)` if this engine rolled back a
    /// copy-on-write workspace, `Ok(false)` if it has none. Default: `Ok(false)`.
    async fn rollback_workspace(&self, caller: &astrid_core::PrincipalId) -> CapsuleResult<bool> {
        let _ = caller;
        Ok(false)
    }
}

mod env;
#[cfg(test)]
pub(crate) use env::build_onboarding_field;
pub(crate) use env::resolve_env;
