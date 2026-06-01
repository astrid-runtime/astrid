//! Shared test fixtures for `engine::wasm` tests.
//!
//! Replaces several near-identical ~90-line `HostState { ... }` literals
//! across `host_state_tests.rs`, `host/sys.rs`, and `host/elicit.rs` with
//! one parameterised builder. Tests fill in only the fields that matter
//! to them via post-construction mutation.
//!
//! Not exported: `pub(crate)` only. Anything exposed here is test-only
//! scaffolding and must not be depended on from production code paths.

#![cfg(test)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use astrid_storage::ScopedKvStore;
use astrid_storage::secret::SecretStore;

use super::host::process::ProcessTracker;
use super::host_state::HostState;
use crate::capsule::CapsuleId;

/// Fresh in-memory [`ScopedKvStore`] for the given namespace.
///
/// Each call returns an independent store — callers that want two stores
/// sharing a backing KV should construct one and derive the other via
/// [`ScopedKvStore::with_namespace`].
pub(crate) fn mem_kv(namespace: &str) -> ScopedKvStore {
    let store = Arc::new(astrid_storage::MemoryKvStore::new());
    ScopedKvStore::new(store, namespace).expect("valid namespace")
}

/// Fresh KV-backed [`SecretStore`] over an independent in-memory KV.
///
/// Bypasses `build_secret_store` (and thus `FallbackSecretStore`'s keychain
/// probe) — tests never want to hit the real OS keychain.
pub(crate) fn mem_secret_store(
    namespace: &str,
    rt: tokio::runtime::Handle,
) -> Arc<dyn SecretStore> {
    Arc::new(astrid_storage::KvSecretStore::new(mem_kv(namespace), rt))
}

/// Open (or create) an append-mode log file at `path`, wrapped in the
/// `Arc<Mutex<File>>` shape `HostState.capsule_log` / `invocation_capsule_log`
/// expect.
pub(crate) fn open_log(path: &std::path::Path) -> Arc<std::sync::Mutex<std::fs::File>> {
    let f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("open log file");
    Arc::new(std::sync::Mutex::new(f))
}

/// Build a minimal [`HostState`] suitable for host-function unit tests.
///
/// Every field is a neutral default (`None`, `Vec::new()`, `HashMap::new()`,
/// empty pattern lists). Tests should mutate the specific fields they care
/// about on the returned state rather than add parameters here.
///
/// Passes a tokio [`Handle`](tokio::runtime::Handle) explicitly so callers
/// can run inside a `#[tokio::test]` or own their own `Builder`-created
/// runtime (sync `#[test]`s do the latter).
pub(crate) fn minimal_host_state(rt: tokio::runtime::Handle) -> HostState {
    let kv = mem_kv("capsule:test");
    let secret_store: Arc<dyn SecretStore> =
        Arc::new(astrid_storage::KvSecretStore::new(kv.clone(), rt.clone()));

    HostState {
        wasi_ctx: wasmtime_wasi::WasiCtxBuilder::new().build(),
        resource_table: wasmtime::component::ResourceTable::new(),
        store_limits: wasmtime::StoreLimitsBuilder::new().build(),
        principal: astrid_core::PrincipalId::default(),
        capsule_uuid: uuid::Uuid::new_v4(),
        caller_context: None,
        interceptor_active: false,
        invocation_kv: None,
        capsule_log: None,
        capsule_id: CapsuleId::from_static("test"),
        workspace_root: PathBuf::from("/tmp"),
        vfs: Arc::new(astrid_vfs::HostVfs::new()),
        vfs_root_handle: astrid_capabilities::DirHandle::new(),
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
        ipc_publish_patterns: Vec::new(),
        ipc_subscribe_patterns: Vec::new(),
        security: None,
        hook_manager: None,
        capsule_registry: None,
        runtime_handle: rt,
        has_uplink_capability: false,
        inbound_tx: None,
        registered_uplinks: Vec::new(),
        cli_socket_listener: None,
        active_http_streams: HashMap::new(),
        next_http_stream_id: 1,
        lifecycle_phase: None,
        secret_store,
        ready_tx: None,
        host_semaphore: Arc::new(Semaphore::new(2)),
        cancel_token: CancellationToken::new(),
        session_token: None,
        interceptor_handles: Vec::new(),
        allowance_store: None,
        identity_store: None,
        process_tracker: Arc::new(ProcessTracker::new()),
        net_stream_count: 0,
        subscription_count: 0,
        process_count_total: 0,
        process_count_by_principal: HashMap::new(),
    }
}
