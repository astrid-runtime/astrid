//! WASM hook handler powered by wasmtime Component Model.
//!
//! Loads a WASM component and calls its `astrid-hook-trigger` export, passing a
//! serialized [`HookAbiContext`] as `list<u8>` and interpreting the returned
//! bytes as a [`HookAbiResult`].
//!
//! Host functions are provided via `Kernel::add_to_linker` (wasmtime
//! bindgen) — no wasi:* interfaces are exposed; the host ABI is fully
//! Astrid-owned for audit and capability uniformity.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use astrid_capsule::capsule::CapsuleId;
use astrid_capsule::engine::wasm::bindings;
use astrid_capsule::engine::wasm::host_state::HostState;
use astrid_storage::kv::ScopedKvStore;
use tracing::{debug, warn};
use wasmtime::Store;
use wasmtime::component::{Component, Linker};

use super::{HandlerError, HandlerResult};
use crate::hook::HookHandler;
use crate::result::{HookContext, HookExecutionResult, HookResult};

/// Context passed to a WASM hook (serialized as JSON bytes).
#[derive(serde::Serialize)]
struct HookAbiContext {
    event: String,
    session_id: String,
    user_id: Option<String>,
    data: Option<String>,
}

/// Result returned by a WASM hook (deserialized from JSON bytes).
#[derive(serde::Deserialize)]
struct HookAbiResult {
    action: String,
    data: Option<String>,
}

/// Handler for WASM components.
///
/// Lazily compiles the WASM component on first invocation and caches the
/// compiled [`Component`] (immutable, thread-safe) for subsequent calls.
/// A fresh [`Store`] is created for each invocation.
pub(crate) struct WasmHandler {
    /// Cached wasmtime engine (shared across all components).
    engine: wasmtime::Engine,
    /// Cached compiled components (lazy-loaded, keyed by module path).
    cached_components: Mutex<HashMap<String, Arc<Component>>>,
    /// Configuration for WASM execution.
    config: WasmConfig,
    /// KV store for hook state (scoped to `hook:wasm`).
    kv: Option<ScopedKvStore>,
    /// Workspace root for file operations.
    workspace_root: PathBuf,
    /// Epoch ticker stop signal + thread handle (cleaned up on drop).
    epoch_stop: Arc<std::sync::atomic::AtomicBool>,
    epoch_handle: Option<std::thread::JoinHandle<()>>,
}

impl WasmHandler {
    /// Create a new WASM handler.
    #[must_use]
    pub(crate) fn new(workspace_root: PathBuf) -> Self {
        let mut wt_config = wasmtime::Config::new();
        wt_config
            .wasm_component_model(true)
            .epoch_interruption(true);
        let engine =
            wasmtime::Engine::new(&wt_config).expect("failed to create wasmtime engine for hooks");

        // Spawn epoch ticker so that epoch deadlines on Store actually fire.
        let epoch_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_clone = epoch_stop.clone();
        let ticker_engine = engine.clone();
        let epoch_handle = std::thread::Builder::new()
            .name("hook-epoch-ticker".into())
            .spawn(move || {
                while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(100));
                    ticker_engine.increment_epoch();
                }
            })
            .expect("failed to spawn hook epoch ticker");

        Self {
            engine,
            cached_components: Mutex::new(HashMap::new()),
            config: WasmConfig::default(),
            kv: None,
            workspace_root,
            epoch_stop,
            epoch_handle: Some(epoch_handle),
        }
    }

    /// Set the KV store for hook state persistence.
    #[must_use]
    pub(crate) fn with_kv(mut self, kv: ScopedKvStore) -> Self {
        self.kv = Some(kv);
        self
    }

    /// Set the WASM execution configuration.
    #[must_use]
    pub(crate) fn with_config(mut self, config: WasmConfig) -> Self {
        self.config = config;
        self
    }

    /// Execute a WASM handler.
    ///
    /// Compiles the component (or uses the cached one), creates a fresh
    /// [`Store`], instantiates, and calls `astrid-hook-trigger` with a
    /// JSON-serialized `CapsuleAbiContext`.
    ///
    /// # Errors
    ///
    /// Returns an error if the module fails to load or the function call fails.
    #[expect(clippy::unused_async)]
    pub(crate) async fn execute(
        &self,
        handler: &HookHandler,
        context: &HookContext,
        _timeout: Duration,
    ) -> HandlerResult<HookExecutionResult> {
        let HookHandler::Wasm {
            module_path,
            function,
        } = handler
        else {
            return Err(HandlerError::InvalidConfiguration(
                "expected Wasm handler".to_string(),
            ));
        };

        debug!(module_path = %module_path, function = %function, "executing WASM hook handler");

        // Get or compile cached component
        let component = self
            .get_or_compile_component(module_path)
            .map_err(|e| HandlerError::WasmFailed(format!("failed to load WASM module: {e}")))?;

        // Build CapsuleAbiContext from HookContext
        let capsule_context = HookAbiContext {
            event: context.event.to_string(),
            session_id: context
                .session_id
                .map_or_else(String::new, |id| id.to_string()),
            user_id: context.user_id.map(|id| id.to_string()),
            data: if context.data.is_empty() {
                None
            } else {
                serde_json::to_string(&context.data).ok()
            },
        };

        let input_bytes = serde_json::to_vec(&capsule_context)
            .map_err(|e| HandlerError::WasmFailed(format!("failed to serialize context: {e}")))?;

        // Build a fresh Store + HostState for this invocation
        let host_state = self.build_host_state(module_path)?;
        let mut store = Store::new(&self.engine, host_state);

        // Set epoch deadline for timeout enforcement.
        // Epoch ticks at 100ms intervals; convert max_execution_time to ticks.
        let deadline_ticks =
            u64::try_from(self.config.max_execution_time.as_millis() / 100).unwrap_or(u64::MAX);
        store.set_epoch_deadline(deadline_ticks.max(1));

        // Build linker with Astrid host interfaces only — no wasi:*
        // exposure, matching the main capsule load path.
        let mut linker: Linker<HostState> = Linker::new(&self.engine);

        astrid_capsule::engine::wasm::configure_kernel_linker(&mut linker).map_err(|e| {
            HandlerError::WasmFailed(format!("failed to add Astrid host to linker: {e}"))
        })?;

        // Instantiate the component without world enforcement (the per-
        // domain WIT split removed the bundled `Capsule` world; exports
        // are looked up by name).
        let instance = linker.instantiate(&mut store, &component).map_err(|e| {
            HandlerError::WasmFailed(format!("failed to instantiate WASM component: {e}"))
        })?;

        // Call `astrid-hook-trigger` via typed func lookup.
        let capsule_result = tokio::task::block_in_place(|| {
            let func = instance
                .get_typed_func::<(String, Vec<u8>), (bindings::astrid::guest::lifecycle::CapsuleResult,)>(
                    &mut store,
                    "astrid-hook-trigger",
                )
                .map_err(|e| {
                    HandlerError::WasmFailed(format!(
                        "capsule does not export `astrid-hook-trigger`: {e}"
                    ))
                })?;
            func.call(&mut store, (function.clone(), input_bytes.clone()))
                .map(|(cr,)| cr)
                .map_err(|e| {
                    HandlerError::WasmFailed(format!("astrid-hook-trigger call failed: {e}"))
                })
        })?;

        // Map the typed CapsuleResult to HookResult.
        let hook_result = map_capsule_result_to_hook_result(&HookAbiResult {
            action: capsule_result.action,
            data: capsule_result.data,
        });

        Ok(HookExecutionResult::Success {
            result: hook_result,
            stdout: None,
        })
    }

    /// Check if the WASM runtime is available.
    #[must_use]
    pub(crate) fn is_available() -> bool {
        true
    }

    /// Get a cached compiled component or compile it from disk.
    fn get_or_compile_component(&self, module_path: &str) -> Result<Arc<Component>, HandlerError> {
        let mut cache = self
            .cached_components
            .lock()
            .map_err(|e| HandlerError::WasmFailed(format!("cache lock poisoned: {e}")))?;

        if let Some(component) = cache.get(module_path) {
            return Ok(Arc::clone(component));
        }

        // Resolve the WASM module path
        let wasm_path = PathBuf::from(module_path);
        let resolved = if wasm_path.is_absolute() {
            wasm_path
        } else {
            self.workspace_root.join(&wasm_path)
        };

        let wasm_bytes = std::fs::read(&resolved).map_err(|e| {
            HandlerError::WasmFailed(format!(
                "failed to read WASM module {}: {e}",
                resolved.display()
            ))
        })?;

        // Compile the WASM component
        let component = Component::from_binary(&self.engine, &wasm_bytes).map_err(|e| {
            HandlerError::WasmFailed(format!("failed to compile WASM component: {e}"))
        })?;

        let component_arc = Arc::new(component);
        cache.insert(module_path.to_string(), Arc::clone(&component_arc));

        Ok(component_arc)
    }

    /// Build a [`HostState`] with minimal permissions for hook execution.
    fn build_host_state(&self, module_path: &str) -> Result<HostState, HandlerError> {
        let kv = if let Some(kv) = &self.kv {
            kv.clone()
        } else {
            let store = Arc::new(astrid_storage::MemoryKvStore::new());
            ScopedKvStore::new(store, "hook:wasm")
                .map_err(|e| HandlerError::WasmFailed(format!("failed to create KV store: {e}")))?
        };

        let vfs = astrid_vfs::HostVfs::new();
        let root_handle = astrid_capabilities::DirHandle::new();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(vfs.register_dir(root_handle.clone(), self.workspace_root.clone()))
        })
        .map_err(|e| HandlerError::WasmFailed(format!("Failed to register VFS root dir: {e}")))?;

        // Derive a per-module identity from the WASM file stem so each hook
        // module gets its own isolated keychain service / KV namespace.
        let hook_identity = std::path::Path::new(module_path).file_stem().map_or_else(
            || "hook:unknown".to_string(),
            |s| format!("hook:{}", s.to_string_lossy()),
        );

        let secret_store = astrid_storage::build_secret_store(
            &hook_identity,
            kv.clone(),
            tokio::runtime::Handle::current(),
        );

        Ok(HostState {
            wasi_ctx: wasmtime_wasi::WasiCtxBuilder::new().build(),
            resource_table: wasmtime::component::ResourceTable::new(),
            store_limits: wasmtime::StoreLimitsBuilder::new()
                .memory_size(usize::try_from(self.config.max_memory_bytes).unwrap_or(usize::MAX))
                .build(),
            principal: astrid_core::PrincipalId::default(),
            capsule_uuid: uuid::Uuid::new_v4(),
            caller_context: None,
            interceptor_active: false,
            invocation_kv: None,
            capsule_log: None,
            capsule_id: CapsuleId::from_static(&hook_identity),
            workspace_root: self.workspace_root.clone(),
            vfs: Arc::new(vfs),
            vfs_root_handle: root_handle,
            // Hooks intentionally do not support home:// or /tmp access — they run
            // outside the full capsule manifest/security-gate lifecycle.
            home: None,
            tmp: None,
            invocation_home: None,
            invocation_tmp: None,
            invocation_secret_store: None,
            invocation_capsule_log: None,
            invocation_profile: None,
            overlay_vfs: None,
            upper_dir: None,
            kv,
            event_bus: astrid_events::EventBus::with_capacity(128),
            ipc_limiter: astrid_events::ipc::IpcRateLimiter::new(),
            config: HashMap::new(),
            secret_env: std::collections::HashSet::new(),
            ipc_publish_patterns: vec!["hook.v1.result.*".into()],
            ipc_subscribe_patterns: Vec::new(),
            security: None,
            hook_manager: None,
            capsule_registry: None,
            runtime_handle: tokio::runtime::Handle::current(),
            has_uplink_capability: false,
            inbound_tx: None,
            registered_uplinks: Vec::new(),
            cli_socket_listener: None,
            active_http_streams: HashMap::new(),
            next_http_stream_id: 1,
            lifecycle_phase: None,
            secret_store,
            ready_tx: None,
            host_semaphore: HostState::default_host_semaphore(),
            cancel_token: tokio_util::sync::CancellationToken::new(),
            session_token: None,
            interceptor_handles: Vec::new(),
            allowance_store: None,
            // Hooks run outside the full capsule lifecycle and intentionally
            // do not receive the identity store. Identity resolution requires
            // a kernel-managed security gate which hooks don't have.
            identity_store: None,
            process_tracker: Arc::new(
                astrid_capsule::engine::wasm::host::process::ProcessTracker::new(),
            ),
            net_stream_count: 0,
            subscription_count: 0,
            process_count_total: 0,
            process_count_by_principal: HashMap::new(),
        })
    }
}

impl Drop for WasmHandler {
    fn drop(&mut self) {
        self.epoch_stop
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.epoch_handle.take() {
            let _ = h.join();
        }
    }
}

impl std::fmt::Debug for WasmHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmHandler")
            .field("config", &self.config)
            .field("workspace_root", &self.workspace_root)
            .finish_non_exhaustive()
    }
}

/// Map a `CapsuleAbiResult` action string to a `HookResult`.
fn map_capsule_result_to_hook_result(result: &HookAbiResult) -> HookResult {
    match result.action.as_str() {
        "continue" => HookResult::Continue,
        "block" => {
            let reason = result.data.as_deref().unwrap_or("blocked by WASM hook");
            HookResult::block(reason)
        },
        "ask" => {
            let question = result
                .data
                .as_deref()
                .unwrap_or("WASM hook requests user input");
            HookResult::ask(question)
        },
        "modify" => {
            // Parse modifications from data JSON
            if let Some(data) = &result.data
                && let Ok(modifications) = serde_json::from_str(data)
            {
                return HookResult::ContinueWith { modifications };
            }
            HookResult::Continue
        },
        other => {
            warn!(action = %other, "unknown CapsuleAbiResult action, treating as continue");
            HookResult::Continue
        },
    }
}

/// Configuration for WASM execution.
#[derive(Debug, Clone)]
pub(crate) struct WasmConfig {
    /// Maximum memory in bytes.
    pub max_memory_bytes: u64,
    /// Maximum execution time.
    pub max_execution_time: Duration,
    /// Enable WASI.
    pub enable_wasi: bool,
}

impl Default for WasmConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024, // 64 MB
            max_execution_time: Duration::from_secs(30),
            enable_wasi: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::HookEvent;

    #[test]
    fn test_wasm_available() {
        assert!(WasmHandler::is_available());
    }

    #[test]
    fn test_wasm_config_default() {
        let config = WasmConfig::default();
        assert_eq!(config.max_memory_bytes, 64 * 1024 * 1024);
        assert!(config.enable_wasi);
    }

    #[test]
    fn test_map_capsule_result_continue() {
        let result = HookAbiResult {
            action: "continue".into(),
            data: None,
        };
        let hook = map_capsule_result_to_hook_result(&result);
        assert!(matches!(hook, HookResult::Continue));
    }

    #[test]
    fn test_map_capsule_result_block() {
        let result = HookAbiResult {
            action: "block".into(),
            data: Some("policy violation".into()),
        };
        let hook = map_capsule_result_to_hook_result(&result);
        assert!(matches!(hook, HookResult::Block { reason } if reason == "policy violation"));
    }

    #[test]
    fn test_map_capsule_result_ask() {
        let result = HookAbiResult {
            action: "ask".into(),
            data: Some("Are you sure?".into()),
        };
        let hook = map_capsule_result_to_hook_result(&result);
        assert!(matches!(hook, HookResult::Ask { question, .. } if question == "Are you sure?"));
    }

    #[test]
    fn test_map_capsule_result_unknown() {
        let result = HookAbiResult {
            action: "unknown".into(),
            data: None,
        };
        let hook = map_capsule_result_to_hook_result(&result);
        assert!(matches!(hook, HookResult::Continue));
    }

    #[tokio::test]
    async fn test_wasm_handler_invalid_handler_type() {
        let handler = WasmHandler::new(PathBuf::from("/tmp"));
        let hook_handler = HookHandler::command("echo");
        let context = HookContext::new(HookEvent::PreToolCall);

        let result = handler
            .execute(&hook_handler, &context, Duration::from_secs(5))
            .await;

        assert!(result.is_err());
    }
}
