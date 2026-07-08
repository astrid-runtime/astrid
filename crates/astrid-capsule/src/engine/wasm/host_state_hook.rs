//! [`HostState::for_hook`] — the transient WASM-hook `HostState` constructor.
//! Split out of `host_state.rs` to stay under the 1000-line CI cap; included via
//! `#[path]`. See [`HookHostStateParams`] for the caller-supplied inputs.

use super::*;

impl HostState {
    /// Build a minimal [`HostState`] for a transient WASM hook invocation.
    ///
    /// Hooks run OUTSIDE the full capsule manifest / security-gate lifecycle: a
    /// one-shot, single-principal execution scoped to a per-module identity, not
    /// a pooled shared runtime. This constructor centralises the hook-side shape
    /// so `astrid-hooks` does not have to name every [`HostState`] field — which
    /// also keeps `HostState` free to gain fields (`#[non_exhaustive]`) without
    /// breaking the hooks crate.
    ///
    /// Everything the caller genuinely varies (identity, VFS, KV, secret store,
    /// HTTP limits, runtime handle, process registries) is supplied via
    /// [`HookHostStateParams`]; every other field is the fail-closed hook default:
    /// no home/tmp mounts, no security gate, no identity/allowance/registry, no
    /// per-invocation overlays, no held capabilities or local-egress exemptions,
    /// no inbound/uplink/socket state, and no audit-firehose. The single publish
    /// pattern is `hook.v1.result.*`.
    ///
    /// Unlike a shared runtime, a hook's `kv` legitimately IS its own store (a
    /// single-principal one-shot), so no `invocation_*` overlays are installed;
    /// `kv_backend` mirrors `kv` for API completeness.
    #[must_use]
    pub fn for_hook(params: HookHostStateParams) -> Self {
        let HookHostStateParams {
            store_meter,
            capsule_id,
            workspace_root,
            vfs,
            vfs_root_handle,
            kv,
            kv_backend,
            secret_store,
            http_limits,
            event_bus,
            runtime_handle,
            process_tracker,
            persistent_processes,
        } = params;

        Self {
            wasi_ctx: wasmtime_wasi::WasiCtxBuilder::new().build(),
            resource_table: wasmtime::component::ResourceTable::new(),
            store_meter,
            principal: astrid_core::PrincipalId::default(),
            capsule_uuid: uuid::Uuid::new_v4(),
            caller_context: None,
            interceptor_active: false,
            // Hooks run a transient one-shot, not a bound run loop, so the
            // run-loop CPU cooperative-yield state is inert here.
            recv_yielded: false,
            no_yield_windows: 0,
            // Hooks do not exercise the per-action fs/net/process audit seam;
            // no sink is threaded into a transient hook's HostState (fail-secure
            // to "no per-action audit" — the report is a no-op).
            audit_sink: None,
            invocation_kv: None,
            capsule_log: None,
            capsule_id,
            workspace_root,
            // Hooks run a transient one-shot on a plain HostVfs with no CoW.
            spawn_mask_paths: Vec::new(),
            vfs,
            vfs_root_handle,
            // Hooks intentionally do not support home:// or /tmp access — they run
            // outside the full capsule manifest/security-gate lifecycle.
            home: None,
            tmp: None,
            invocation_home: None,
            invocation_tmp: None,
            invocation_secret_store: None,
            invocation_capsule_log: None,
            invocation_profile: None,
            profile_cache: None,
            invocation_env_overlay: None,
            kv_backend,
            kv,
            event_bus,
            ipc_limiter: Arc::new(astrid_events::ipc::IpcRateLimiter::new()),
            config: HashMap::new(),
            secret_env: std::collections::HashSet::new(),
            ipc_publish_patterns: vec!["hook.v1.result.*".into()],
            ipc_subscribe_patterns: Vec::new(),
            security: None,
            hook_manager: None,
            capsule_registry: None,
            runtime_handle,
            has_uplink_capability: false,
            // Hooks run outside the manifest/security-gate lifecycle: no held
            // capabilities and no local-egress exemptions (both fail-closed).
            capability_names: Vec::new(),
            local_egress: Vec::new(),
            http_limits,
            // Transient hook execution never subscribes to the audit feed;
            // fail-secure to scoped.
            audit_firehose: false,
            inbound_tx: None,
            registered_uplinks: Vec::new(),
            cli_socket_listener: None,
            active_http_streams: HashMap::new(),
            next_http_stream_id: 1,
            lifecycle_phase: None,
            secret_store,
            ready_tx: None,
            blocking_semaphore: Self::default_blocking_semaphore(),
            io_semaphore: Self::default_io_semaphore(),
            cancel_token: CancellationToken::new(),
            // Hooks are single-principal one-shots: no per-principal overlays
            // are installed, the map stays empty, and every wait uses the
            // instance token above.
            principal_cancel_tokens: Self::new_principal_cancel_tokens(),
            invocation_cancel_token: None,
            session_token: None,
            interceptor_handles: Vec::new(),
            allowance_store: None,
            // Hooks have no kernel-managed security gate, so no identity store.
            identity_store: None,
            process_tracker,
            persistent_processes,
            net_stream_count: 0,
            subscription_count: 0,
            process_count_total: 0,
            process_count_by_principal: HashMap::new(),
            // Transient hook execution never accepts socket connections; a
            // throwaway registry satisfies the field (issue #45/#852).
            connection_principals: Self::new_connection_principals(),
            // Hooks never accept inbound uplink connections, so no client
            // lifecycle events are ever emitted; a throwaway registry satisfies
            // the field. Keyed by the verified principal directly (distinct from
            // the device-aware `connection_principals` registry).
            client_connections: Self::new_client_connections(),
            // No client frame in flight; hooks never forward over publish-as, so
            // neither the ingress principal nor its device id / origin is set.
            ingress_principal: None,
            ingress_device_key_id: None,
            ingress_origin: None,
        }
    }
}
