#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![allow(clippy::module_name_repetitions)]

//! Astrid Kernel - The core execution engine and IPC router.
//!
//! The Kernel is a pure, decentralized WASM runner. It contains no business
//! logic, no cognitive loops, and no network servers. Its sole responsibility
//! is to instantiate `astrid_events::EventBus`, load `.capsule` files into
//! the Extism sandbox, and route IPC bytes between them.

/// Passive event-bus storm diagnostics (publish-rate monitor).
mod bus_monitor;
/// Persistent invite-token store (issue #756).
pub mod invite;
/// The Management API router listening to the `EventBus`.
pub mod kernel_router;
/// Persistent pair-device token store (issue #756).
pub mod pair_token;
/// The Unix Domain Socket manager.
pub mod socket;

use arc_swap::ArcSwap;
use astrid_audit::AuditLog;
use astrid_capabilities::{CapabilityStore, DirHandle};
use astrid_capsule::profile_cache::PrincipalProfileCache;
use astrid_capsule::registry::CapsuleRegistry;
use astrid_core::SessionId;
use astrid_core::groups::GroupConfig;
use astrid_core::principal::PrincipalId;
use astrid_crypto::KeyPair;
use astrid_events::EventBus;
use astrid_mcp::{McpClient, SecureMcpClient, ServerManager, ServersConfig};
use astrid_vfs::{HostVfs, OverlayVfsRegistry, Vfs};
use dashmap::DashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::{Mutex, RwLock};

/// The core Operating System Kernel.
pub struct Kernel {
    /// The unique identifier for this kernel session.
    pub session_id: SessionId,
    /// The global IPC message bus.
    pub event_bus: Arc<EventBus>,
    /// The process manager (loaded WASM capsules).
    pub capsules: Arc<RwLock<CapsuleRegistry>>,
    /// The secure MCP client with capability-based authorization and audit logging.
    pub mcp: SecureMcpClient,
    /// The capability store for this session.
    pub capabilities: Arc<CapabilityStore>,
    /// The global Virtual File System mount.
    ///
    /// Points at the unmodified workspace (no overlay). Principal-scoped
    /// overlays live in [`overlay_registry`](Self::overlay_registry) — this
    /// field is kept for kernel-internal paths that do not know a principal
    /// (discovery, capsule load scan).
    pub vfs: Arc<dyn Vfs>,
    /// Per-principal overlay registry (Layer 4, issue #668).
    ///
    /// Each invoking principal resolves their own
    /// [`OverlayVfs`](astrid_vfs::OverlayVfs) from this registry on first
    /// use — lower layer is the shared workspace, upper layer is a
    /// principal-private tempdir. Agent A's uncommitted writes are never
    /// visible to Agent B.
    pub overlay_registry: Arc<OverlayVfsRegistry>,
    /// The global physical root handle (cap-std) for the VFS.
    pub vfs_root_handle: DirHandle,
    /// The physical path the VFS is mounted to.
    pub workspace_root: PathBuf,
    /// The principal home resources directory (`~/.astrid/home/{principal}/`).
    /// Capsules declaring `fs_read = ["home://"]` can read files under this
    /// root. Scoped to the principal's home so that keys, databases, and
    /// system config in `~/.astrid/` are NOT accessible.
    ///
    /// Always `Some` in production (boot requires `AstridHome`). Remains
    /// `Option` for compatibility with `CapsuleContext` and test fixtures.
    pub home_root: Option<PathBuf>,
    /// The natively bound Unix Socket for the CLI proxy.
    pub cli_socket_listener: Option<Arc<tokio::sync::Mutex<tokio::net::UnixListener>>>,
    /// Exclusive advisory lock enforcing a single kernel instance, held for
    /// the daemon's lifetime (see [`socket::bind_session_socket`]). `None` for
    /// test kernels that don't bind a real socket. Never read — the point is
    /// that its `Drop` (or process exit) releases the lock so a restart isn't
    /// wedged.
    #[expect(
        dead_code,
        reason = "held for the process lifetime; Drop releases the singleton flock"
    )]
    singleton_lock: Option<std::fs::File>,
    /// Shared KV store backing all capsule-scoped stores and kernel state.
    pub kv: Arc<astrid_storage::SurrealKvStore>,
    /// Chain-linked cryptographic audit log with persistent storage.
    pub audit_log: Arc<AuditLog>,
    /// Per-principal active connection counters (Layer 4, issue #668).
    ///
    /// Keyed by [`PrincipalId`]. When a principal's counter hits zero the
    /// kernel clears that principal's session allowances only — other
    /// principals' state is untouched. Ephemeral shutdown still waits on
    /// the global sum via [`total_connection_count`](Self::total_connection_count).
    active_connections: DashMap<PrincipalId, AtomicUsize>,
    /// Shared per-principal CPU fuel ledger, cloned into every capsule's
    /// `WasmEngine` (via the loader) so a principal's interceptor CPU is summed
    /// across all capsules into one per-principal total. Telemetry today; the
    /// substrate for a per-principal CPU budget. See
    /// [`FuelLedger`](astrid_capsule::FuelLedger).
    fuel_ledger: astrid_capsule::FuelLedger,
    /// Ephemeral mode: shut down immediately when the last client disconnects.
    pub ephemeral: AtomicBool,
    /// Instant when the kernel was booted (for uptime calculation).
    pub boot_time: std::time::Instant,
    /// Sender for the API-initiated shutdown signal. The daemon's main loop
    /// selects on the receiver to exit gracefully without `process::exit`.
    pub shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Session token for socket authentication. Generated at boot, written to
    /// `~/.astrid/run/system.token`. CLI sends this as its first message.
    pub session_token: Arc<astrid_core::session_token::SessionToken>,
    /// Path where the session token was written at boot. Stored so shutdown
    /// uses the exact same path (avoids fallback mismatch if env changes).
    token_path: PathBuf,
    /// Shared allowance store for capsule-level approval decisions.
    ///
    /// Capsules can check existing allowances and create new ones when
    /// users approve actions with session/always scope.
    pub allowance_store: Arc<astrid_approval::AllowanceStore>,
    /// System-wide identity store for platform user resolution.
    identity_store: Arc<dyn astrid_storage::IdentityStore>,
    /// System-wide per-principal profile cache (Layer 3 quota enforcement).
    ///
    /// One instance per kernel boot. Every capsule load plumbs this into
    /// [`CapsuleContext::with_profile_cache`](astrid_capsule::context::CapsuleContext::with_profile_cache),
    /// where [`WasmEngine`](astrid_capsule::engine::wasm::WasmEngine) consumes
    /// it to apply per-invocation memory / timeout / IPC / process caps.
    /// Invalidation model: kernel restart. Layer 6 will add explicit
    /// management IPC to clear entries at runtime (issue #666 tracks that
    /// follow-up).
    pub(crate) profile_cache: Arc<PrincipalProfileCache>,
    /// Static group-to-capability configuration (issue #670), made
    /// hot-reloadable in Layer 6 (issue #672).
    ///
    /// Loaded once at boot from `$ASTRID_HOME/etc/groups.toml`. The
    /// enforcement preamble in [`kernel_router::handle_request`] /
    /// `handle_admin_request` calls `groups.load_full()` on each request
    /// — a lock-free `Arc` clone. Group admin topics
    /// (`astrid.v1.admin.group.*`) rewrite `groups.toml` and then
    /// `groups.store(Arc::new(new_config))` atomically; in-flight checks
    /// holding the old `Arc` finish under the old config, the next check
    /// sees the new one.
    pub(crate) groups: Arc<ArcSwap<GroupConfig>>,
    /// Home directory captured at boot — retained for the admin write
    /// path (`groups.toml`, per-principal `profile.toml`) so handlers
    /// don't re-resolve `$ASTRID_HOME` and risk a mid-life drift.
    pub(crate) astrid_home: astrid_core::dirs::AstridHome,
    /// Serializes mutating admin topics on `profile.toml` / `groups.toml`.
    ///
    /// Read-only admin topics (`agent.list`, `group.list`, `quota.get`)
    /// and the hot authz path do NOT take this lock — the `ArcSwap` on
    /// [`Kernel::groups`] and the `RwLock` on
    /// [`PrincipalProfileCache`](astrid_capsule::profile_cache::PrincipalProfileCache)
    /// cover reads. Tokio's `Mutex` is not poisonable — no
    /// `PoisonError::into_inner` dance required.
    pub(crate) admin_write_lock: Mutex<()>,
}

impl Kernel {
    /// Boot a new Kernel instance mounted at the specified directory.
    ///
    /// # Panics
    ///
    /// Panics if called on a single-threaded tokio runtime. The capsule
    /// system uses `block_in_place` which requires a multi-threaded runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if the VFS mount paths cannot be registered.
    #[expect(
        clippy::too_many_lines,
        reason = "boot sequence: sequential setup that does not benefit from splitting"
    )]
    pub async fn new(
        session_id: SessionId,
        workspace_root: PathBuf,
    ) -> Result<Arc<Self>, std::io::Error> {
        use astrid_core::dirs::AstridHome;

        assert!(
            tokio::runtime::Handle::current().runtime_flavor()
                == tokio::runtime::RuntimeFlavor::MultiThread,
            "Kernel requires a multi-threaded tokio runtime (block_in_place panics on \
             single-threaded). Use #[tokio::main] or Runtime::new() instead of current_thread."
        );

        let event_bus = Arc::new(EventBus::new());
        let capsules = Arc::new(RwLock::new(CapsuleRegistry::new()));

        // Resolve the Astrid home directory. Required for persistent KV store
        // and audit log. Fails boot if neither $ASTRID_HOME nor $HOME is set.
        let home = AstridHome::resolve().map_err(|e| {
            std::io::Error::other(format!(
                "Failed to resolve Astrid home (set $ASTRID_HOME or $HOME): {e}"
            ))
        })?;

        // Resolve the home directory for the `home://` VFS scheme.
        // Points to `~/.astrid/home/{principal}/` — NOT the full `~/.astrid/`
        // root — so capsules cannot access keys, databases, or config.
        let default_principal = astrid_core::PrincipalId::default();
        let principal_home = home.principal_home(&default_principal);
        let home_root = Some(principal_home.root().to_path_buf());

        // 1. Open the persistent KV store (needed by capability store below).
        let kv_path = home.state_db_path();
        let kv = Arc::new(
            astrid_storage::SurrealKvStore::open(&kv_path)
                .map_err(|e| std::io::Error::other(format!("Failed to open KV store: {e}")))?,
        );
        // TODO: clear ephemeral keys (e: prefix) on boot when the key
        // lifecycle tier convention is established.

        // 2. Initialize MCP process manager with security layer.
        //    Set workspace_root so sandboxed MCP servers have a writable directory.
        let mcp_config = ServersConfig::load_default().unwrap_or_default();
        let mcp_manager = ServerManager::new(mcp_config)
            .with_workspace_root(workspace_root.clone())
            .with_capsule_log_dir(principal_home.log_dir());
        let mcp_client = McpClient::new(mcp_manager);

        // 3. Bootstrap capability store (persistent) and audit log.
        //    Key rotation invalidates persisted tokens (fail-secure by design).
        let capabilities = Arc::new(
            CapabilityStore::with_kv_store(Arc::clone(&kv) as Arc<dyn astrid_storage::KvStore>)
                .map_err(|e| {
                    std::io::Error::other(format!("Failed to init capability store: {e}"))
                })?,
        );
        let audit_log = open_audit_log()?;
        let mcp = SecureMcpClient::new(
            mcp_client,
            Arc::clone(&capabilities),
            Arc::clone(&audit_log),
            session_id.clone(),
        );

        // 4. Establish the physical security boundary (sandbox handle)
        let root_handle = DirHandle::new();

        // 5. Principal-scoped overlay registry: each invoking principal
        //    gets a fresh OverlayVfs on first use (Layer 4, issue #668).
        //    The kernel-internal `vfs` field keeps pointing at a plain
        //    HostVfs over the workspace for paths that don't yet know a
        //    principal (discovery, capsule load scan).
        let kernel_host_vfs = HostVfs::new();
        kernel_host_vfs
            .register_dir(root_handle.clone(), workspace_root.clone())
            .await
            .map_err(|_| std::io::Error::other("Failed to register kernel workspace vfs"))?;
        let overlay_registry = Arc::new(OverlayVfsRegistry::new(
            workspace_root.clone(),
            root_handle.clone(),
        ));

        // 6. Bind the secure Unix socket and generate session token.
        // The socket is bound here, but not yet listened on. The token is
        // generated before any capsule can accept connections, preventing
        // a race where a client connects before the token file exists.
        let (listener, singleton_lock) = socket::bind_session_socket(&home)?;
        let (session_token, token_path) = socket::generate_session_token()?;

        let allowance_store = Arc::new(astrid_approval::AllowanceStore::new());
        // Create system-wide identity store backed by the shared KV.
        let identity_kv = astrid_storage::ScopedKvStore::new(
            Arc::clone(&kv) as Arc<dyn astrid_storage::KvStore>,
            "system:identity",
        )
        .map_err(|e| std::io::Error::other(format!("Failed to create identity KV: {e}")))?;
        let identity_store: Arc<dyn astrid_storage::IdentityStore> =
            Arc::new(astrid_storage::KvIdentityStore::new(identity_kv));

        // Load group config (issue #670). Boot-loaded once, then swapped
        // atomically by Layer 6 admin topics (issue #672). Missing file
        // → built-ins only; malformed TOML is a hard boot failure
        // (fail-closed).
        let groups_loaded = GroupConfig::load(&home)
            .map_err(|e| std::io::Error::other(format!("Failed to load groups config: {e}")))?;
        let groups = Arc::new(ArcSwap::from_pointee(groups_loaded));

        // Bootstrap the CLI root user (idempotent). Also seeds the
        // default principal's profile with `groups = ["admin"]` so
        // single-tenant deployments get full management-API access.
        bootstrap_cli_root_user(&identity_store, &home)
            .await
            .map_err(|e| {
                std::io::Error::other(format!("Failed to bootstrap CLI root user: {e}"))
            })?;

        // Apply pre-configured identity links from config.
        apply_identity_config(&identity_store, &workspace_root).await;

        let kernel = Arc::new(Self {
            session_id,
            event_bus,
            capsules,
            mcp,
            capabilities,
            vfs: Arc::new(kernel_host_vfs) as Arc<dyn Vfs>,
            overlay_registry,
            vfs_root_handle: root_handle,
            workspace_root,
            home_root,
            cli_socket_listener: Some(Arc::new(tokio::sync::Mutex::new(listener))),
            singleton_lock: Some(singleton_lock),
            kv,
            audit_log,
            active_connections: DashMap::new(),
            fuel_ledger: astrid_capsule::FuelLedger::default(),
            ephemeral: AtomicBool::new(false),
            boot_time: std::time::Instant::now(),
            shutdown_tx: tokio::sync::watch::channel(false).0,
            session_token: Arc::new(session_token),
            token_path,
            allowance_store,
            identity_store,
            profile_cache: Arc::new(PrincipalProfileCache::with_home(home.clone())),
            groups,
            astrid_home: home,
            admin_write_lock: Mutex::new(()),
        });

        drop(kernel_router::spawn_kernel_router(Arc::clone(&kernel)));
        drop(spawn_idle_monitor(Arc::clone(&kernel)));
        drop(spawn_react_watchdog(Arc::clone(&kernel.event_bus)));
        drop(spawn_capsule_health_monitor(Arc::clone(&kernel)));
        // Passive storm diagnostics — subscribes synchronously inside the
        // call (before the debug-assert below) so it counts toward
        // `INTERNAL_SUBSCRIBER_COUNT`.
        drop(bus_monitor::spawn_bus_activity_monitor(&kernel.event_bus));

        // Spawn the event dispatcher — routes EventBus events to capsule interceptors.
        // Wire the identity store so auto-provisioning is gated.
        let dispatcher = astrid_capsule::dispatcher::EventDispatcher::new(
            Arc::clone(&kernel.capsules),
            Arc::clone(&kernel.event_bus),
        )
        .with_identity_store(Arc::clone(&kernel.identity_store));
        tokio::spawn(dispatcher.run());

        debug_assert_eq!(
            kernel.event_bus.subscriber_count(),
            INTERNAL_SUBSCRIBER_COUNT,
            "INTERNAL_SUBSCRIBER_COUNT is stale; update it when adding permanent subscribers"
        );

        Ok(kernel)
    }

    /// Load a capsule into the Kernel from a directory containing a Capsule.toml
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest cannot be loaded, the capsule cannot be created, or registration fails.
    async fn load_capsule(&self, dir: PathBuf) -> Result<(), anyhow::Error> {
        let manifest_path = dir.join("Capsule.toml");
        let manifest = astrid_capsule::discovery::load_manifest(&manifest_path)
            .map_err(|e| anyhow::anyhow!(e))?;

        // Skip if already registered (prevents double-load from overlapping
        // discovery paths like principal home + workspace capsules).
        {
            let registry = self.capsules.read().await;
            let id = astrid_capsule::capsule::CapsuleId::from_static(&manifest.package.name);
            if registry.get(&id).is_some() {
                return Ok(());
            }
        }

        let loader =
            astrid_capsule::loader::CapsuleLoader::new(self.mcp.clone(), self.fuel_ledger.clone());
        let mut capsule = loader.create_capsule(manifest, dir.clone())?;

        // Build the context — use the shared kernel KV so capsules can
        // communicate state through overlapping KV namespaces.
        let principal = astrid_core::PrincipalId::default();
        let kv = astrid_storage::ScopedKvStore::new(
            Arc::clone(&self.kv) as Arc<dyn astrid_storage::KvStore>,
            format!("{principal}:capsule:{}", capsule.id()),
        )?;

        // Pre-load env config into the KV store.
        // Check principal config first, fall back to capsule dir's .env.json.
        let capsule_name = capsule.id().to_string();
        let env_path = if let Ok(home) = astrid_core::dirs::AstridHome::resolve() {
            let ph = home.principal_home(&principal);
            let principal_env = ph.env_dir().join(format!("{capsule_name}.env.json"));
            if principal_env.exists() {
                principal_env
            } else {
                dir.join(".env.json")
            }
        } else {
            dir.join(".env.json")
        };
        if env_path.exists()
            && let Ok(contents) = std::fs::read_to_string(&env_path)
            && let Ok(env_map) =
                serde_json::from_str::<std::collections::HashMap<String, String>>(&contents)
        {
            for (k, v) in env_map {
                let _ = kv.set(&k, v.into_bytes()).await;
            }
        }

        let ctx = astrid_capsule::context::CapsuleContext::new(
            principal.clone(),
            self.workspace_root.clone(),
            self.home_root.clone(),
            kv,
            Arc::clone(&self.event_bus),
            self.cli_socket_listener.clone(),
        )
        .with_registry(Arc::clone(&self.capsules))
        .with_session_token(Arc::clone(&self.session_token))
        .with_allowance_store(Arc::clone(&self.allowance_store))
        .with_identity_store(Arc::clone(&self.identity_store))
        .with_profile_cache(Arc::clone(&self.profile_cache))
        .with_overlay_registry(Arc::clone(&self.overlay_registry))
        // Snapshot the live group config so the capsule load path can resolve
        // the run-loop resource-exemption capability (CAP_RESOURCES_UNBOUNDED)
        // against the owner principal's groups/grants/revokes.
        .with_group_config(self.groups.load_full());

        capsule.load(&ctx).await?;

        let mut registry = self.capsules.write().await;
        registry
            .register(capsule)
            .map_err(|e| anyhow::anyhow!("Failed to register capsule: {e}"))?;

        Ok(())
    }

    /// Restart a capsule by unloading it and re-loading from its source directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the capsule has no source directory, cannot be
    /// unregistered, or fails to reload.
    async fn restart_capsule(
        &self,
        id: &astrid_capsule::capsule::CapsuleId,
    ) -> Result<(), anyhow::Error> {
        // Get source directory before unregistering.
        let source_dir = {
            let registry = self.capsules.read().await;
            let capsule = registry
                .get(id)
                .ok_or_else(|| anyhow::anyhow!("capsule '{id}' not found in registry"))?;
            capsule
                .source_dir()
                .map(std::path::Path::to_path_buf)
                .ok_or_else(|| anyhow::anyhow!("capsule '{id}' has no source directory"))?
        };

        // Unregister and explicitly unload. There is no Drop impl that
        // calls unload() (it's async), so we must do it here to avoid
        // leaking MCP subprocesses and other engine resources.
        let old_capsule = {
            let mut registry = self.capsules.write().await;
            registry
                .unregister(id)
                .map_err(|e| anyhow::anyhow!("failed to unregister capsule '{id}': {e}"))?
        };
        // Explicitly unload the old capsule. There is no Drop impl that
        // calls unload() (it's async), so we must do it here to avoid
        // leaking MCP subprocesses and other engine resources.
        // Arc::get_mut requires exclusive ownership (strong_count == 1).
        {
            let mut old = old_capsule;
            if let Some(capsule) = std::sync::Arc::get_mut(&mut old) {
                if let Err(e) = capsule.unload().await {
                    tracing::warn!(
                        capsule_id = %id,
                        error = %e,
                        "Capsule unload failed during restart"
                    );
                }
            } else {
                tracing::warn!(
                    capsule_id = %id,
                    "Cannot call unload during restart - Arc still held by in-flight task"
                );
            }
        }

        // Re-load from disk.
        self.load_capsule(source_dir).await?;

        // Signal the newly loaded capsule to clean up ephemeral state
        // from the previous incarnation. Capsules that don't implement
        // `handle_lifecycle_restart` will return an error, which is fine.
        //
        // Clone the capsule Arc under a brief read lock, then drop the
        // guard before invoke_interceptor which calls block_in_place.
        // Holding the RwLock across block_in_place parks the worker thread
        // and starves registry writers (health monitor, capsule loading).
        let capsule = {
            let registry = self.capsules.read().await;
            registry.get(id)
        };
        if let Some(capsule) = capsule
            && let Err(e) = capsule
                .invoke_interceptor("handle_lifecycle_restart", &[], None)
                .await
        {
            tracing::debug!(
                capsule_id = %id,
                error = %e,
                "Capsule does not handle lifecycle restart (optional)"
            );
        }

        Ok(())
    }

    /// Auto-discover and load all capsules from the standard directories (`~/.astrid/capsules` and `.astrid/capsules`).
    ///
    /// Capsules are loaded in dependency order (topological sort) with
    /// uplink/daemon capsules loaded first. Each uplink must signal
    /// readiness before non-uplink capsules are loaded.
    ///
    /// After all capsules are loaded, tool schemas are injected into every
    /// capsule's KV namespace and the `astrid.v1.capsules_loaded` event is published.
    pub async fn load_all_capsules(&self) {
        use astrid_capsule::toposort::toposort_manifests;
        use astrid_core::dirs::AstridHome;

        // Discovery paths in priority order: principal > workspace.
        let mut paths = Vec::new();
        if let Ok(home) = AstridHome::resolve() {
            let principal = astrid_core::PrincipalId::default();
            paths.push(home.principal_home(&principal).capsules_dir());
        }

        let discovered = astrid_capsule::discovery::discover_manifests(Some(&paths));

        // Topological sort ALL capsules together so cross-partition
        // requirements (e.g. a non-uplink requiring an uplink's capability)
        // resolve correctly without spurious "not provided" warnings.
        let sorted = match toposort_manifests(discovered) {
            Ok(sorted) => sorted,
            Err((e, original)) => {
                tracing::error!(
                    cycle = %e,
                    "Dependency cycle in capsules, falling back to discovery order"
                );
                original
            },
        };

        // Defence-in-depth: manifest validation in discovery.rs rejects
        // uplinks with [imports], but warn here in case a manifest bypasses
        // the normal load path.
        for (manifest, _) in &sorted {
            if manifest.capabilities.uplink && manifest.has_imports() {
                tracing::warn!(
                    capsule = %manifest.package.name,
                    "Uplink capsule has [imports] - \
                     this should have been rejected at manifest load time"
                );
            }
        }

        // Validate imports/exports: every required import must have a matching export.
        validate_imports_exports(&sorted);

        // Partition after sorting: uplinks first, then the rest.
        // The relative order within each partition is preserved from the
        // toposort, so dependency edges are still respected. Cross-partition
        // edges (non-uplink requiring an uplink) are satisfied by construction
        // since all uplinks load first. The inverse (uplink requiring a
        // non-uplink) is rejected above.
        let (uplinks, others): (Vec<_>, Vec<_>) =
            sorted.into_iter().partition(|(m, _)| m.capabilities.uplink);

        // Load uplinks first so their event bus subscriptions are ready.
        let uplink_names: Vec<String> = uplinks
            .iter()
            .map(|(m, _)| m.package.name.clone())
            .collect();
        for (manifest, dir) in &uplinks {
            if let Err(e) = self.load_capsule(dir.clone()).await {
                tracing::warn!(
                    capsule = %manifest.package.name,
                    error = %e,
                    "Failed to load uplink capsule during discovery"
                );
            }
        }

        // Wait for uplink capsules to signal readiness before loading
        // non-uplink capsules. This ensures IPC subscriptions are active.
        self.await_capsule_readiness(&uplink_names).await;

        for (manifest, dir) in &others {
            if let Err(e) = self.load_capsule(dir.clone()).await {
                tracing::warn!(
                    capsule = %manifest.package.name,
                    error = %e,
                    "Failed to load capsule during discovery"
                );
            }
        }

        // Wait for non-uplink run-loop capsules too, so any future
        // dependency edges between them are respected.
        let other_names: Vec<String> = others.iter().map(|(m, _)| m.package.name.clone()).collect();
        self.await_capsule_readiness(&other_names).await;

        // Signal that all capsules have been loaded so uplink capsules
        // (like the registry) can proceed with discovery instead of
        // polling with arbitrary timeouts.
        let msg = astrid_events::ipc::IpcMessage::new(
            "astrid.v1.capsules_loaded",
            astrid_events::ipc::IpcPayload::RawJson(serde_json::json!({"status": "ready"})),
            self.session_id.0,
        );
        let _ = self.event_bus.publish(astrid_events::AstridEvent::Ipc {
            metadata: astrid_events::EventMetadata::new("kernel"),
            message: msg,
        });
    }

    /// Record that a new client connection for `principal` has been established.
    pub fn connection_opened(&self, principal: &PrincipalId) {
        self.active_connections
            .entry(principal.clone())
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);
        metrics::counter!(METRIC_CONNECTIONS_OPENED_TOTAL).increment(1);
        metrics::gauge!(METRIC_ACTIVE_CONNECTIONS).increment(1.0);
    }

    /// Record that a client connection for `principal` has been closed.
    ///
    /// Uses `fetch_update` for atomic saturating decrement - avoids the
    /// TOCTOU window where `fetch_sub` wraps to `usize::MAX` before a
    /// corrective store.
    ///
    /// When *this* principal's counter reaches zero, clears only that
    /// principal's session-scoped allowances — other principals' state is
    /// untouched. The global ephemeral-shutdown path remains gated on the
    /// sum across every principal (see
    /// [`total_connection_count`](Self::total_connection_count)).
    pub fn connection_closed(&self, principal: &PrincipalId) {
        // Hold the DashMap entry guard across the decrement AND the
        // session-scoped clears. While we hold the guard any concurrent
        // `connection_opened(principal)` on the same key blocks on the
        // shard lock, so its new session allowances cannot be born and
        // then nuked by the tail-end cleanup here (pre-Layer-4 bug
        // surfaced more narrowly under per-principal scoping).
        //
        // The downstream stores do not re-enter `active_connections`, so
        // holding this guard while calling into them cannot deadlock.
        let entry = self
            .active_connections
            .entry(principal.clone())
            .or_insert_with(|| AtomicUsize::new(0));
        let result = entry.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            if n == 0 {
                None
            } else {
                Some(n.saturating_sub(1))
            }
        });

        // Only count a real close: `Err` means the counter was already 0
        // (no connection to drop), so the gauge must not go negative.
        if result.is_ok() {
            metrics::counter!(METRIC_CONNECTIONS_CLOSED_TOTAL).increment(1);
            metrics::gauge!(METRIC_ACTIVE_CONNECTIONS).decrement(1.0);
        }

        if result == Ok(1) {
            self.allowance_store.clear_session_allowances(principal);
            if let Err(e) = self.capabilities.clear_session_for(principal) {
                tracing::warn!(%principal, error = %e, "failed to clear capability session");
            }
            tracing::info!(
                %principal,
                "last connection for principal disconnected, session state cleared"
            );
        }
        // Release the shard lock before touching the map again — `remove_if`
        // re-acquires it.
        drop(entry);

        if result == Ok(1) {
            self.active_connections
                .remove_if(principal, |_, count| count.load(Ordering::Relaxed) == 0);
        }
    }

    /// Enable or disable ephemeral mode (immediate shutdown on last disconnect).
    pub fn set_ephemeral(&self, val: bool) {
        self.ephemeral.store(val, Ordering::Relaxed);
    }

    /// Total number of active client connections across all principals.
    ///
    /// Used by the ephemeral-shutdown gate: the kernel shuts down only
    /// when *every* principal's counter has reached zero.
    pub fn total_connection_count(&self) -> usize {
        self.active_connections
            .iter()
            .map(|e| e.value().load(Ordering::Relaxed))
            .sum()
    }

    /// Snapshot of `(principal, count)` for every principal with a
    /// non-zero active connection. The `astrid who` admin surface
    /// reads this to attribute connections to specific agents
    /// instead of fabricating a `default`-only row from the bare
    /// total.
    ///
    /// Not a hot-path call site — taken at status-RPC time. Iterating
    /// the `DashMap` snapshots the shard guards individually, so the
    /// total may not be perfectly consistent with a concurrent
    /// connect/disconnect, but each entry is internally consistent
    /// and the operator-facing accuracy bound (a flickering one-off
    /// count) is acceptable.
    pub fn connections_by_principal(&self) -> Vec<(PrincipalId, usize)> {
        self.active_connections
            .iter()
            .filter_map(|e| {
                let count = e.value().load(Ordering::Relaxed);
                if count == 0 {
                    None
                } else {
                    Some((e.key().clone(), count))
                }
            })
            .collect()
    }

    /// Gracefully shut down the kernel.
    ///
    /// 1. Publish `KernelShutdown` event on the bus.
    /// 2. Drain and unload all capsules (stops MCP child processes, WASM engines).
    /// 3. Flush and close the persistent KV store.
    /// 4. Remove the Unix socket file.
    pub async fn shutdown(&self, reason: Option<String>) {
        tracing::info!(reason = ?reason, "Kernel shutting down");

        // 1. Notify all subscribers so capsules can react.
        let _ = self
            .event_bus
            .publish(astrid_events::AstridEvent::KernelShutdown {
                metadata: astrid_events::EventMetadata::new("kernel"),
                reason: reason.clone(),
            });

        // Clear every principal's session-only state in one sweep. Belt-
        // and-suspenders for a process that is exiting anyway, but load-
        // bearing the moment session allowances are ever persisted
        // (Layer 7) — without this call a persisted-allowance layer would
        // inherit stale per-session grants from the previous process.
        self.allowance_store.clear_all_session_allowances();
        if let Err(e) = self.capabilities.clear_session() {
            tracing::warn!(error = %e, "failed to clear capability session on shutdown");
        }

        // 2. Drain the registry so the dispatcher cannot hand out new Arc clones,
        // then unload each capsule. MCP engine unload is critical - it calls
        // `mcp_client.disconnect()` to gracefully terminate child processes.
        // Without explicit unload, MCP child processes become orphaned.
        //
        // The `EventDispatcher` temporarily clones `Arc<dyn Capsule>` into
        // spawned interceptor tasks. After draining, no new clones can be
        // created, but in-flight tasks may still hold references. We retry
        // `Arc::get_mut` with brief yields to let them complete.
        let capsules = {
            let mut reg = self.capsules.write().await;
            reg.drain()
        };
        for mut arc in capsules {
            let id = arc.id().clone();
            let mut unloaded = false;

            for retry in 0..20_u32 {
                if let Some(capsule) = Arc::get_mut(&mut arc) {
                    if let Err(e) = capsule.unload().await {
                        tracing::warn!(
                            capsule_id = %id,
                            error = %e,
                            "Failed to unload capsule during shutdown"
                        );
                    }
                    unloaded = true;
                    break;
                }
                if retry < 19 {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }

            if !unloaded {
                tracing::warn!(
                    capsule_id = %id,
                    strong_count = Arc::strong_count(&arc),
                    "Dropping capsule without explicit unload after retries exhausted; \
                     MCP child processes may be orphaned"
                );
            }
            drop(arc);
        }

        // 3. Flush the persistent KV store.
        if let Err(e) = self.kv.close().await {
            tracing::warn!(error = %e, "Failed to flush KV store during shutdown");
        }

        // 4. Remove the socket and token files so stale-socket detection works
        // on next boot and the auth token doesn't persist on disk after shutdown.
        // This runs AFTER capsule unload, which is the correct order: MCP child
        // processes communicate via stdio pipes (not this Unix socket), so they
        // are already terminated by step 2. The socket is only used for
        // CLI-to-kernel IPC.
        let socket_path = crate::socket::kernel_socket_path();
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_file(&self.token_path);
        crate::socket::remove_readiness_file();

        tracing::info!("Kernel shutdown complete");
    }

    /// Wait for a set of capsules to signal readiness, in parallel.
    ///
    /// Collects `Arc<dyn Capsule>` handles under a short-lived read lock,
    /// then drops the lock before awaiting. Capsules without a run loop
    /// return `Ready` immediately and don't contribute to wait time.
    async fn await_capsule_readiness(&self, names: &[String]) {
        use astrid_capsule::capsule::ReadyStatus;

        if names.is_empty() {
            return;
        }

        let timeout = std::time::Duration::from_millis(500);
        let capsules: Vec<(String, std::sync::Arc<dyn astrid_capsule::capsule::Capsule>)> = {
            let registry = self.capsules.read().await;
            names
                .iter()
                .filter_map(
                    |name| match astrid_capsule::capsule::CapsuleId::new(name.clone()) {
                        Ok(capsule_id) => registry.get(&capsule_id).map(|c| (name.clone(), c)),
                        Err(e) => {
                            tracing::warn!(
                                capsule = %name,
                                error = %e,
                                "Invalid capsule ID, skipping readiness wait"
                            );
                            None
                        },
                    },
                )
                .collect()
        };

        // Await all capsules concurrently - independent capsules shouldn't
        // compound each other's timeout.
        let mut set = tokio::task::JoinSet::new();
        for (name, capsule) in capsules {
            set.spawn(async move {
                let status = capsule.wait_ready(timeout).await;
                (name, status)
            });
        }
        while let Some(result) = set.join_next().await {
            if let Ok((name, status)) = result {
                match status {
                    ReadyStatus::Ready => {},
                    ReadyStatus::Timeout => {
                        tracing::warn!(
                            capsule = %name,
                            timeout_ms = timeout.as_millis(),
                            "Capsule did not signal ready within timeout"
                        );
                    },
                    ReadyStatus::Crashed => {
                        tracing::error!(
                            capsule = %name,
                            "Capsule run loop exited before signaling ready"
                        );
                    },
                }
            }
        }
    }
}

/// Test-only lightweight constructor (issue #672) that builds a
/// [`Kernel`] with just the fields the admin handlers touch:
/// `event_bus`, `session_id`, `audit_log`, `profile_cache`,
/// `identity_store`, `groups`, `astrid_home`, `admin_write_lock`, plus
/// the shared allowance / capability / kv store handles. Skips the
/// heavy boot bits (socket bind, MCP init, token generation, capsule
/// discovery) that aren't load-bearing for admin-topic tests.
///
/// The `home` argument is used verbatim — tests pass a tempdir-rooted
/// [`astrid_core::dirs::AstridHome`] so every call is fully isolated
/// from the process-global `$ASTRID_HOME`.
#[cfg(test)]
pub(crate) async fn test_kernel_with_home(home: astrid_core::dirs::AstridHome) -> Arc<Kernel> {
    use astrid_capsule::profile_cache::PrincipalProfileCache;

    home.ensure()
        .expect("test kernel: ensure astrid home dir tree");

    let session_id = SessionId::SYSTEM;
    let event_bus = Arc::new(EventBus::new());
    let capsules = Arc::new(RwLock::new(CapsuleRegistry::new()));

    // Persistent KV backing capabilities + identity store.
    let kv = Arc::new(
        astrid_storage::SurrealKvStore::open(&home.state_db_path()).expect("test kernel: open kv"),
    );
    let capabilities = Arc::new(
        CapabilityStore::with_kv_store(Arc::clone(&kv) as Arc<dyn astrid_storage::KvStore>)
            .expect("test kernel: capability store"),
    );

    // Audit log at the tempdir — chain verification is trivially Ok on a
    // fresh log, no historical entries.
    let runtime_key =
        load_or_generate_runtime_key(&home.keys_dir()).expect("test kernel: runtime key");
    let default_principal = astrid_core::PrincipalId::default();
    let principal_home = home.principal_home(&default_principal);
    principal_home
        .ensure()
        .expect("test kernel: ensure principal home");
    let audit_log = Arc::new(
        AuditLog::open(principal_home.audit_dir(), runtime_key)
            .expect("test kernel: open audit log"),
    );

    // MCP: use a no-op secure client wrapped around an empty manager.
    // Admin handlers do not touch MCP.
    let mcp_manager = ServerManager::new(ServersConfig::default());
    let mcp_client = McpClient::new(mcp_manager);
    let mcp = SecureMcpClient::new(
        mcp_client,
        Arc::clone(&capabilities),
        Arc::clone(&audit_log),
        session_id.clone(),
    );

    let root_handle = DirHandle::new();
    let kernel_host_vfs = HostVfs::new();
    kernel_host_vfs
        .register_dir(root_handle.clone(), home.root().to_path_buf())
        .await
        .expect("test kernel: register workspace vfs");
    let overlay_registry = Arc::new(OverlayVfsRegistry::new(
        home.root().to_path_buf(),
        root_handle.clone(),
    ));

    let allowance_store = Arc::new(astrid_approval::AllowanceStore::new());
    let identity_kv = astrid_storage::ScopedKvStore::new(
        Arc::clone(&kv) as Arc<dyn astrid_storage::KvStore>,
        "system:identity",
    )
    .expect("test kernel: identity kv scope");
    let identity_store: Arc<dyn astrid_storage::IdentityStore> =
        Arc::new(astrid_storage::KvIdentityStore::new(identity_kv));

    let groups = Arc::new(ArcSwap::from_pointee(
        GroupConfig::load(&home).expect("test kernel: load groups"),
    ));

    let kernel = Arc::new(Kernel {
        session_id,
        event_bus,
        capsules,
        mcp,
        capabilities,
        vfs: Arc::new(kernel_host_vfs) as Arc<dyn Vfs>,
        overlay_registry,
        vfs_root_handle: root_handle,
        workspace_root: home.root().to_path_buf(),
        home_root: Some(principal_home.root().to_path_buf()),
        cli_socket_listener: None,
        singleton_lock: None,
        kv,
        audit_log,
        active_connections: DashMap::new(),
        fuel_ledger: astrid_capsule::FuelLedger::default(),
        ephemeral: AtomicBool::new(false),
        boot_time: std::time::Instant::now(),
        shutdown_tx: tokio::sync::watch::channel(false).0,
        session_token: Arc::new(astrid_core::session_token::SessionToken::generate()),
        token_path: home.token_path(),
        allowance_store,
        identity_store,
        profile_cache: Arc::new(PrincipalProfileCache::with_home(home.clone())),
        groups,
        astrid_home: home,
        admin_write_lock: Mutex::new(()),
    });
    // Spawn the Layer 6 admin dispatcher so IPC-driven tests can drive
    // the full publish → response loop. State-mutating tests that call
    // `handlers::dispatch` directly are unaffected — those messages
    // never hit the bus.
    drop(kernel_router::admin::spawn_admin_router(Arc::clone(
        &kernel,
    )));
    kernel
}

/// Loads the runtime signing key from `~/.astrid/keys/runtime.key`, generating a
/// new one if it doesn't exist. Opens the `SurrealKV`-backed audit database at
/// `~/.astrid/audit.db` and runs `verify_all()` to detect any tampering of
/// historical entries. Verification failures are logged at `error!` level but
/// do not block boot (fail-open for availability, loud alert for integrity).
fn open_audit_log() -> std::io::Result<Arc<AuditLog>> {
    use astrid_core::dirs::AstridHome;

    let home = AstridHome::resolve()
        .map_err(|e| std::io::Error::other(format!("cannot resolve Astrid home: {e}")))?;
    home.ensure()
        .map_err(|e| std::io::Error::other(format!("cannot create Astrid home dirs: {e}")))?;

    let runtime_key = load_or_generate_runtime_key(&home.keys_dir())?;
    let default_principal = astrid_core::PrincipalId::default();
    let principal_home = home.principal_home(&default_principal);
    principal_home
        .ensure()
        .map_err(|e| std::io::Error::other(format!("cannot create principal home dirs: {e}")))?;
    let audit_log = AuditLog::open(principal_home.audit_dir(), runtime_key)
        .map_err(|e| std::io::Error::other(format!("cannot open audit log: {e}")))?;

    // Verify all historical chains on boot.
    match audit_log.verify_all() {
        Ok(results) => {
            let total_sessions = results.len();
            let mut tampered_sessions: usize = 0;

            for (session_id, result) in &results {
                if !result.valid {
                    tampered_sessions = tampered_sessions.saturating_add(1);
                    for issue in &result.issues {
                        tracing::error!(
                            session_id = %session_id,
                            issue = %issue,
                            "Audit chain integrity violation detected"
                        );
                    }
                }
            }

            if tampered_sessions > 0 {
                tracing::error!(
                    total_sessions,
                    tampered_sessions,
                    "Audit chain verification found tampered sessions"
                );
            } else if total_sessions > 0 {
                tracing::info!(
                    total_sessions,
                    "Audit chain verification passed for all sessions"
                );
            }
        },
        Err(e) => {
            tracing::error!(error = %e, "Audit chain verification failed to run");
        },
    }

    Ok(Arc::new(audit_log))
}

/// Load the runtime ed25519 signing key from disk, or generate and persist a new one.
///
/// The key file is 32 bytes of raw secret key material at `{keys_dir}/runtime.key`.
fn load_or_generate_runtime_key(keys_dir: &Path) -> std::io::Result<KeyPair> {
    let key_path = keys_dir.join("runtime.key");

    if key_path.exists() {
        let bytes = std::fs::read(&key_path)?;
        KeyPair::from_secret_key(&bytes).map_err(|e| {
            std::io::Error::other(format!(
                "invalid runtime key at {}: {e}",
                key_path.display()
            ))
        })
    } else {
        let keypair = KeyPair::generate();
        std::fs::create_dir_all(keys_dir)?;
        std::fs::write(&key_path, keypair.secret_key_bytes())?;

        // Secure permissions (owner-only) on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }

        tracing::info!(key_id = %keypair.key_id_hex(), "Generated new runtime signing key");
        Ok(keypair)
    }
}

/// Spawns a background task that cleanly shuts down the Kernel if there is no activity.
///
/// Uses dual-signal idle detection:
/// - **Primary:** explicit `active_connections` counter (incremented on first IPC
///   message per source, decremented on `Disconnect`).
/// - **Secondary:** `EventBus::subscriber_count()` minus the kernel router's own
///   subscription. When a CLI process dies without sending `Disconnect`, its
///   broadcast receiver is dropped so the subscriber count falls.
///
/// Takes the minimum of both signals to handle ungraceful disconnects.
///
/// Idle shutdown is on by default in `--ephemeral` mode (30s after the
/// last client disconnects) and **off by default** in persistent mode
/// (`astrid start`). Both modes respect `ASTRID_IDLE_TIMEOUT_SECS` —
/// setting it in persistent mode opts the operator into auto-shutdown,
/// setting it in ephemeral mode overrides the 30s default.
/// Number of permanent internal event bus subscribers that are not client
/// connections: `KernelRouter` (`kernel.request.*`), `AdminRouter`
/// (`kernel.admin.*`), `ConnectionTracker` (`client.*`),
/// `EventDispatcher` (all events), and the bus activity monitor (all events,
/// storm diagnostics — see [`bus_monitor::spawn_bus_activity_monitor`]).
const INTERNAL_SUBSCRIBER_COUNT: usize = 5;

/// Gauge: current active client connections (sum across principals).
/// Mirrors [`Kernel::total_connection_count`]; lets a dashboard graph
/// "who is connected" without polling.
const METRIC_ACTIVE_CONNECTIONS: &str = "astrid_daemon_active_connections";
/// Counter: client connections opened (cumulative).
const METRIC_CONNECTIONS_OPENED_TOTAL: &str = "astrid_daemon_connections_opened_total";
/// Counter: client connections closed (cumulative). `opened - closed`
/// cross-checks the gauge.
const METRIC_CONNECTIONS_CLOSED_TOTAL: &str = "astrid_daemon_connections_closed_total";
/// Counter: background monitor-loop iterations, labelled by `loop`. A
/// flat `rate()` is a parked loop; a runaway `rate()` is a spin loop —
/// the direct signal for the idle-CPU class of incident. Shared with
/// [`bus_monitor`], hence `pub(crate)`.
pub(crate) const METRIC_BACKGROUND_TICKS_TOTAL: &str = "astrid_daemon_background_ticks_total";

/// Initial grace period before idle checking begins.
const IDLE_INITIAL_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
/// Additional grace for non-ephemeral daemons to let capsules fully initialize.
const IDLE_NON_EPHEMERAL_GRACE: std::time::Duration = std::time::Duration::from_secs(25);
/// How often the idle monitor polls when running in ephemeral mode.
const IDLE_EPHEMERAL_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
/// How often the idle monitor polls when running in persistent mode.
const IDLE_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);
fn spawn_idle_monitor(kernel: Arc<Kernel>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Initial grace period — wait for capsules to boot and first client
        // to connect before checking idle status.
        tokio::time::sleep(IDLE_INITIAL_GRACE).await;

        // Read ephemeral flag after grace period (set by daemon after boot).
        let ephemeral = kernel.ephemeral.load(Ordering::Relaxed);
        let idle_timeout = if ephemeral {
            // Give the CLI time to reconnect after brief disconnects (e.g.
            // during tool execution when the TUI might momentarily drop
            // the socket). Zero timeout caused premature shutdowns.
            //
            // Operators may still override via `ASTRID_IDLE_TIMEOUT_SECS`
            // when they want a longer ephemeral window (e.g. headless
            // batch runs that pause between prompts).
            std::env::var("ASTRID_IDLE_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .map_or(
                    std::time::Duration::from_secs(30),
                    std::time::Duration::from_secs,
                )
        } else {
            // Persistent (`astrid start`) mode: idle shutdown is opt-in.
            // The operator explicitly chose persistent — honour that.
            // Setting `ASTRID_IDLE_TIMEOUT_SECS` switches the monitor on
            // for housekeeping flows that genuinely want auto-shutdown.
            // Without it, the monitor task exits immediately and the
            // daemon stays up until SIGTERM.
            let Some(secs) = std::env::var("ASTRID_IDLE_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
            else {
                tracing::debug!(
                    "Non-ephemeral daemon: idle shutdown disabled \
                     (set ASTRID_IDLE_TIMEOUT_SECS to enable)."
                );
                return;
            };
            std::time::Duration::from_secs(secs)
        };
        let check_interval = if ephemeral {
            IDLE_EPHEMERAL_CHECK_INTERVAL
        } else {
            IDLE_CHECK_INTERVAL
        };

        // Non-ephemeral: additional grace to let capsules fully initialize.
        if !ephemeral {
            tokio::time::sleep(IDLE_NON_EPHEMERAL_GRACE).await;
        }
        let mut idle_since: Option<tokio::time::Instant> = None;

        loop {
            tokio::time::sleep(check_interval).await;
            metrics::counter!(METRIC_BACKGROUND_TICKS_TOTAL, "loop" => "idle").increment(1);

            let connections = kernel.total_connection_count();

            // Use the explicit connection counter as the sole signal.
            // The previous bus_subscribers heuristic (subscriber_count minus
            // internal subscribers) was fragile: capsule run-loop crashes
            // reduce subscriber_count, causing false "0 connections" readings
            // that trigger premature idle shutdown while a client is active.
            let effective_connections = connections;

            let has_daemons = {
                let reg = kernel.capsules.read().await;
                reg.values().any(|c| {
                    let m = c.manifest();
                    !m.uplinks.is_empty()
                })
            };

            if effective_connections == 0 && !has_daemons {
                let now = tokio::time::Instant::now();
                let start = *idle_since.get_or_insert(now);
                let elapsed = now.duration_since(start);

                tracing::debug!(
                    idle_secs = elapsed.as_secs(),
                    timeout_secs = idle_timeout.as_secs(),
                    connections,
                    "Kernel idle, monitoring timeout"
                );

                if elapsed >= idle_timeout {
                    tracing::info!("Idle timeout reached, initiating shutdown");
                    kernel.shutdown(Some("idle_timeout".to_string())).await;
                    std::process::exit(0);
                }
            } else {
                if idle_since.is_some() {
                    tracing::debug!(
                        effective_connections,
                        has_daemons,
                        "Activity detected, resetting idle timer"
                    );
                }
                idle_since = None;
            }
        }
    })
}

/// Tracks restart attempts for a single capsule with exponential backoff.
struct RestartTracker {
    attempts: u32,
    last_attempt: std::time::Instant,
    backoff: std::time::Duration,
}

impl RestartTracker {
    const MAX_ATTEMPTS: u32 = 5;
    const INITIAL_BACKOFF: std::time::Duration = std::time::Duration::from_secs(2);
    const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_mins(2);

    fn new() -> Self {
        Self {
            attempts: 0,
            last_attempt: std::time::Instant::now(),
            backoff: Self::INITIAL_BACKOFF,
        }
    }

    /// Returns `true` if a restart should be attempted now.
    fn should_restart(&self) -> bool {
        self.attempts < Self::MAX_ATTEMPTS && self.last_attempt.elapsed() >= self.backoff
    }

    /// Record a restart attempt and advance the backoff.
    fn record_attempt(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
        self.last_attempt = std::time::Instant::now();
        self.backoff = self.backoff.saturating_mul(2).min(Self::MAX_BACKOFF);
    }

    /// Returns `true` if all retry attempts have been exhausted.
    fn exhausted(&self) -> bool {
        self.attempts >= Self::MAX_ATTEMPTS
    }
}

/// Attempts to restart a failed capsule, respecting backoff and max retries.
///
/// Returns `true` if the tracker should be removed (successful restart).
async fn attempt_capsule_restart(
    kernel: &Kernel,
    id_str: &str,
    tracker: &mut RestartTracker,
) -> bool {
    if tracker.exhausted() {
        return false;
    }

    if !tracker.should_restart() {
        tracing::debug!(
            capsule_id = %id_str,
            next_attempt_in = ?tracker.backoff.saturating_sub(tracker.last_attempt.elapsed()),
            "Waiting for backoff before next restart attempt"
        );
        return false;
    }

    tracker.record_attempt();
    let attempt = tracker.attempts;

    tracing::warn!(
        capsule_id = %id_str,
        attempt,
        max_attempts = RestartTracker::MAX_ATTEMPTS,
        "Attempting capsule restart"
    );

    let capsule_id = astrid_capsule::capsule::CapsuleId::from_static(id_str);
    match kernel.restart_capsule(&capsule_id).await {
        Ok(()) => {
            tracing::info!(capsule_id = %id_str, attempt, "Capsule restarted successfully");
            true
        },
        Err(e) => {
            tracing::error!(capsule_id = %id_str, attempt, error = %e, "Capsule restart failed");
            if tracker.exhausted() {
                tracing::error!(
                    capsule_id = %id_str,
                    "All restart attempts exhausted - capsule will remain down"
                );
            }
            false
        },
    }
}

/// Spawns a background task that periodically probes capsule health.
///
/// Every 10 seconds, reads the capsule registry and calls `check_health()` on
/// each capsule that is currently in `Ready` state. If a capsule reports
/// `Failed`, attempts to restart it with exponential backoff (max 5 attempts).
/// Publishes `astrid.v1.health.failed` IPC events for each detected failure.
fn spawn_capsule_health_monitor(kernel: Arc<Kernel>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        interval.tick().await; // Skip the first immediate tick.

        let mut restart_trackers: std::collections::HashMap<String, RestartTracker> =
            std::collections::HashMap::new();

        loop {
            interval.tick().await;
            metrics::counter!(METRIC_BACKGROUND_TICKS_TOTAL, "loop" => "capsule_health")
                .increment(1);

            // Collect ready capsules under a brief read lock, then drop
            // the lock before calling check_health() or publishing events.
            let ready_capsules: Vec<std::sync::Arc<dyn astrid_capsule::capsule::Capsule>> = {
                let registry = kernel.capsules.read().await;
                registry
                    .list()
                    .into_iter()
                    .filter_map(|id| {
                        let capsule = registry.get(id)?;
                        if capsule.state() == astrid_capsule::capsule::CapsuleState::Ready {
                            Some(capsule)
                        } else {
                            None
                        }
                    })
                    .collect()
            };

            // Probe health once per capsule, collect failures, then drop
            // the Arc Vec before restarting. This ensures restart_capsule's
            // Arc::get_mut can succeed (no other strong references held).
            let mut failures: Vec<(String, String)> = Vec::new();
            for capsule in &ready_capsules {
                let health = capsule.check_health();
                if let astrid_capsule::capsule::CapsuleState::Failed(reason) = health {
                    let id_str = capsule.id().to_string();
                    tracing::error!(capsule_id = %id_str, reason = %reason, "Capsule health check failed");

                    let msg = astrid_events::ipc::IpcMessage::new(
                        "astrid.v1.health.failed",
                        astrid_events::ipc::IpcPayload::Custom {
                            data: serde_json::json!({
                                "capsule_id": &id_str,
                                "reason": &reason,
                            }),
                        },
                        uuid::Uuid::new_v4(),
                    );
                    let _ = kernel.event_bus.publish(astrid_events::AstridEvent::Ipc {
                        metadata: astrid_events::EventMetadata::new("kernel"),
                        message: msg,
                    });
                    failures.push((id_str, reason));
                }
            }

            // Drop all Arc clones so restart_capsule's Arc::get_mut can
            // obtain exclusive access for calling unload().
            drop(ready_capsules);

            let failed_this_tick: std::collections::HashSet<&str> =
                failures.iter().map(|(id, _)| id.as_str()).collect();

            let mut restarted = Vec::new();
            for (id_str, _reason) in &failures {
                let tracker = restart_trackers
                    .entry(id_str.clone())
                    .or_insert_with(RestartTracker::new);

                if attempt_capsule_restart(&kernel, id_str, tracker).await {
                    restarted.push(id_str.clone());
                }
            }

            // Remove trackers for successfully restarted capsules.
            for id in &restarted {
                restart_trackers.remove(id);
            }

            // Prune trackers for capsules that recovered (healthy this tick).
            // Keep exhausted trackers and trackers still in their backoff
            // window (capsule may have been unregistered by a failed restart
            // attempt and won't appear in ready_capsules next tick).
            restart_trackers.retain(|id, tracker| {
                if tracker.exhausted() {
                    return true;
                }
                // Keep if still within backoff - the capsule may be absent
                // from the registry after a failed reload.
                if tracker.last_attempt.elapsed() < tracker.backoff {
                    return true;
                }
                failed_this_tick.contains(id.as_str())
            });
        }
    })
}

/// Spawns a periodic watchdog that publishes `astrid.v1.watchdog.tick` events every 5 seconds.
///
/// The `ReAct` capsule (WASM guest) cannot use async timers, so this kernel-side task
/// drives timeout enforcement by waking the capsule on a fixed interval. Each tick
/// causes the capsule's `handle_watchdog_tick` interceptor to run `check_phase_timeout`.
fn spawn_react_watchdog(event_bus: Arc<EventBus>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        // The first tick fires immediately - skip it to give capsules time to load.
        interval.tick().await;

        loop {
            interval.tick().await;
            metrics::counter!(METRIC_BACKGROUND_TICKS_TOTAL, "loop" => "react_watchdog")
                .increment(1);

            let msg = astrid_events::ipc::IpcMessage::new(
                "astrid.v1.watchdog.tick",
                astrid_events::ipc::IpcPayload::Custom {
                    data: serde_json::json!({}),
                },
                uuid::Uuid::new_v4(),
            );
            let _ = event_bus.publish(astrid_events::AstridEvent::Ipc {
                metadata: astrid_events::EventMetadata::new("kernel"),
                message: msg,
            });
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_or_generate_creates_new_key() {
        let dir = tempfile::tempdir().unwrap();
        let keys_dir = dir.path().join("keys");

        let keypair = load_or_generate_runtime_key(&keys_dir).unwrap();
        let key_path = keys_dir.join("runtime.key");

        // Key file should exist with 32 bytes.
        assert!(key_path.exists());
        let bytes = std::fs::read(&key_path).unwrap();
        assert_eq!(bytes.len(), 32);

        // The written bytes should reconstruct the same public key.
        let reloaded = KeyPair::from_secret_key(&bytes).unwrap();
        assert_eq!(
            keypair.public_key_bytes(),
            reloaded.public_key_bytes(),
            "reloaded key should match generated key"
        );
    }

    #[test]
    fn test_load_or_generate_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let keys_dir = dir.path().join("keys");

        let first = load_or_generate_runtime_key(&keys_dir).unwrap();
        let second = load_or_generate_runtime_key(&keys_dir).unwrap();

        assert_eq!(
            first.public_key_bytes(),
            second.public_key_bytes(),
            "loading the same key file should produce the same keypair"
        );
    }

    #[test]
    fn test_load_or_generate_rejects_bad_key_length() {
        let dir = tempfile::tempdir().unwrap();
        let keys_dir = dir.path().join("keys");
        std::fs::create_dir_all(&keys_dir).unwrap();

        // Write a key file with wrong length.
        std::fs::write(keys_dir.join("runtime.key"), [0u8; 16]).unwrap();

        let result = load_or_generate_runtime_key(&keys_dir);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid runtime key"),
            "expected 'invalid runtime key' error, got: {err}"
        );
    }

    #[test]
    fn test_connection_counter_increment_decrement() {
        let counter = AtomicUsize::new(0);

        // Simulate connection_opened (fetch_add)
        counter.fetch_add(1, Ordering::Relaxed);
        counter.fetch_add(1, Ordering::Relaxed);
        assert_eq!(counter.load(Ordering::Relaxed), 2);

        // Simulate connection_closed using the same fetch_update logic
        // as the real implementation to exercise the actual code path.
        for expected in [1, 0] {
            let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                if n == 0 {
                    None
                } else {
                    Some(n.saturating_sub(1))
                }
            });
            assert_eq!(counter.load(Ordering::Relaxed), expected);
        }
    }

    #[test]
    fn test_connection_counter_underflow_guard() {
        // Test the saturating behavior: decrementing from 0 should stay at 0.
        // Mirrors the fetch_update logic in connection_closed().
        let counter = AtomicUsize::new(0);

        let result = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            if n == 0 { None } else { Some(n - 1) }
        });
        // fetch_update returns Err(0) when the closure returns None (no-op).
        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    /// Mirrors the `connection_closed(&principal)` logic: only `Ok(1)`
    /// (previous value 1, now 0) triggers `clear_session_allowances` for
    /// that principal. Update this test if `connection_closed()` is
    /// refactored.
    #[test]
    fn test_last_disconnect_clears_session_allowances_scoped() {
        use astrid_approval::AllowanceStore;
        use astrid_approval::allowance::{Allowance, AllowanceId, AllowancePattern};
        use astrid_core::principal::PrincipalId;
        use astrid_core::types::Timestamp;
        use astrid_crypto::KeyPair;

        let store = AllowanceStore::new();
        let keypair = KeyPair::generate();
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();

        // Alice: session + persistent.
        store
            .add_allowance(Allowance {
                id: AllowanceId::new(),
                principal: alice.clone(),
                action_pattern: AllowancePattern::ServerTools {
                    server: "alice-session".to_string(),
                },
                created_at: Timestamp::now(),
                expires_at: None,
                max_uses: None,
                uses_remaining: None,
                session_only: true,
                workspace_root: None,
                signature: keypair.sign(b"test"),
            })
            .unwrap();
        store
            .add_allowance(Allowance {
                id: AllowanceId::new(),
                principal: alice.clone(),
                action_pattern: AllowancePattern::ServerTools {
                    server: "alice-persistent".to_string(),
                },
                created_at: Timestamp::now(),
                expires_at: None,
                max_uses: None,
                uses_remaining: None,
                session_only: false,
                workspace_root: None,
                signature: keypair.sign(b"test"),
            })
            .unwrap();
        // Bob: session (must NOT be cleared by alice disconnecting).
        store
            .add_allowance(Allowance {
                id: AllowanceId::new(),
                principal: bob.clone(),
                action_pattern: AllowancePattern::ServerTools {
                    server: "bob-session".to_string(),
                },
                created_at: Timestamp::now(),
                expires_at: None,
                max_uses: None,
                uses_remaining: None,
                session_only: true,
                workspace_root: None,
                signature: keypair.sign(b"test"),
            })
            .unwrap();
        assert_eq!(store.count(), 3);

        let alice_counter = AtomicUsize::new(1);
        let simulate_alice_disconnect = || {
            let result = alice_counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                if n == 0 {
                    None
                } else {
                    Some(n.saturating_sub(1))
                }
            });
            if result == Ok(1) {
                store.clear_session_allowances(&alice);
            }
        };

        simulate_alice_disconnect();
        // Alice's session gone; alice's persistent + bob's session remain.
        assert_eq!(store.count(), 2);
        assert_eq!(store.count_for(&alice), 1);
        assert_eq!(store.count_for(&bob), 1);
    }

    #[cfg(unix)]
    #[test]
    fn test_load_or_generate_sets_secure_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let keys_dir = dir.path().join("keys");

        let _ = load_or_generate_runtime_key(&keys_dir).unwrap();

        let key_path = keys_dir.join("runtime.key");
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "key file should have 0o600 permissions, got {mode:#o}"
        );
    }

    #[test]
    fn restart_tracker_initial_state() {
        let tracker = RestartTracker::new();
        assert!(!tracker.exhausted());
        // Should not restart immediately (backoff hasn't elapsed).
        assert!(!tracker.should_restart());
    }

    #[test]
    fn restart_tracker_allows_restart_after_backoff() {
        let mut tracker = RestartTracker::new();
        // Simulate time passing by setting last_attempt in the past.
        tracker.last_attempt = std::time::Instant::now()
            - RestartTracker::INITIAL_BACKOFF
            - std::time::Duration::from_millis(1);
        assert!(tracker.should_restart());
    }

    #[test]
    fn restart_tracker_doubles_backoff() {
        let mut tracker = RestartTracker::new();
        assert_eq!(tracker.backoff, RestartTracker::INITIAL_BACKOFF);

        tracker.record_attempt();
        assert_eq!(
            tracker.backoff,
            RestartTracker::INITIAL_BACKOFF.saturating_mul(2)
        );
        assert_eq!(tracker.attempts, 1);

        tracker.record_attempt();
        assert_eq!(
            tracker.backoff,
            RestartTracker::INITIAL_BACKOFF.saturating_mul(4)
        );
        assert_eq!(tracker.attempts, 2);
    }

    #[test]
    fn restart_tracker_backoff_caps_at_max() {
        let mut tracker = RestartTracker::new();
        for _ in 0..20 {
            tracker.record_attempt();
        }
        assert_eq!(tracker.backoff, RestartTracker::MAX_BACKOFF);
    }

    #[test]
    fn restart_tracker_exhausted_at_max_attempts() {
        let mut tracker = RestartTracker::new();
        for _ in 0..RestartTracker::MAX_ATTEMPTS {
            assert!(!tracker.exhausted());
            tracker.record_attempt();
        }
        assert!(tracker.exhausted());
    }

    #[test]
    fn restart_tracker_should_restart_false_when_exhausted() {
        let mut tracker = RestartTracker::new();
        for _ in 0..RestartTracker::MAX_ATTEMPTS {
            tracker.record_attempt();
        }
        // Even if backoff has elapsed, exhausted tracker should not restart.
        tracker.last_attempt = std::time::Instant::now() - RestartTracker::MAX_BACKOFF;
        assert!(!tracker.should_restart());
    }

    // ── Bootstrap admin-group seeding (issue #670) ───────────────────

    fn scratch_home() -> (tempfile::TempDir, astrid_core::dirs::AstridHome) {
        let dir = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(dir.path());
        (dir, home)
    }

    #[test]
    fn seed_admin_writes_fresh_profile_when_missing() {
        let (_d, home) = scratch_home();
        let default = astrid_core::PrincipalId::default();
        let path = astrid_core::PrincipalProfile::path_for(&home, &default);
        assert!(!path.exists());

        seed_default_principal_admin_profile(&home).unwrap();

        let profile = astrid_core::PrincipalProfile::load_from_path(&path).unwrap();
        assert_eq!(profile.groups, vec!["admin".to_string()]);
        assert!(profile.grants.is_empty());
        assert!(profile.revokes.is_empty());
    }

    #[test]
    fn seed_admin_is_idempotent_across_reboots() {
        let (_d, home) = scratch_home();
        let default = astrid_core::PrincipalId::default();

        seed_default_principal_admin_profile(&home).unwrap();
        seed_default_principal_admin_profile(&home).unwrap();
        seed_default_principal_admin_profile(&home).unwrap();

        let path = astrid_core::PrincipalProfile::path_for(&home, &default);
        let profile = astrid_core::PrincipalProfile::load_from_path(&path).unwrap();
        // Still exactly one `admin` entry — no duplication.
        assert_eq!(profile.groups, vec!["admin".to_string()]);
    }

    #[test]
    fn seed_admin_leaves_operator_configured_groups_intact() {
        let (_d, home) = scratch_home();
        let default = astrid_core::PrincipalId::default();

        // Operator wrote their own config pre-bootstrap.
        let mut existing = astrid_core::PrincipalProfile::default();
        existing.groups = vec!["agent".to_string()];
        let path = astrid_core::PrincipalProfile::path_for(&home, &default);
        std::fs::create_dir_all(home.profiles_dir()).unwrap();
        existing.save_to_path(&path).unwrap();

        seed_default_principal_admin_profile(&home).unwrap();

        let profile = astrid_core::PrincipalProfile::load_from_path(&path).unwrap();
        assert_eq!(profile.groups, vec!["agent".to_string()]);
    }

    #[test]
    fn seed_admin_leaves_operator_configured_grants_intact() {
        let (_d, home) = scratch_home();
        let default = astrid_core::PrincipalId::default();

        let mut existing = astrid_core::PrincipalProfile::default();
        existing.grants = vec!["system:status".to_string()];
        let path = astrid_core::PrincipalProfile::path_for(&home, &default);
        std::fs::create_dir_all(home.profiles_dir()).unwrap();
        existing.save_to_path(&path).unwrap();

        seed_default_principal_admin_profile(&home).unwrap();

        let profile = astrid_core::PrincipalProfile::load_from_path(&path).unwrap();
        // admin not auto-added because grants are non-empty.
        assert!(profile.groups.is_empty());
        assert_eq!(profile.grants, vec!["system:status".to_string()]);
    }

    #[test]
    fn seed_admin_leaves_operator_configured_revokes_intact() {
        let (_d, home) = scratch_home();
        let default = astrid_core::PrincipalId::default();

        let mut existing = astrid_core::PrincipalProfile::default();
        existing.revokes = vec!["system:shutdown".to_string()];
        let path = astrid_core::PrincipalProfile::path_for(&home, &default);
        std::fs::create_dir_all(home.profiles_dir()).unwrap();
        existing.save_to_path(&path).unwrap();

        seed_default_principal_admin_profile(&home).unwrap();

        let profile = astrid_core::PrincipalProfile::load_from_path(&path).unwrap();
        assert!(profile.groups.is_empty());
        assert_eq!(profile.revokes, vec!["system:shutdown".to_string()]);
    }

    // ── Legacy profile path migration (issue #672) ──────────────────

    #[test]
    fn migrate_legacy_profile_relocates_to_etc() {
        // Pre-#672 deployments wrote profile.toml under
        // home/{principal}/.config/. The migration moves it to
        // etc/profiles/{principal}.toml on first boot.
        let (_d, home) = scratch_home();
        let default = astrid_core::PrincipalId::default();
        let legacy_path = home
            .principal_home(&default)
            .config_dir()
            .join("profile.toml");
        std::fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
        let mut existing = astrid_core::PrincipalProfile::default();
        existing.groups = vec!["operator-configured".to_string()];
        existing.save_to_path(&legacy_path).unwrap();

        seed_default_principal_admin_profile(&home).unwrap();

        // Legacy path gone, new path holds the migrated content.
        assert!(!legacy_path.exists());
        let new_path = astrid_core::PrincipalProfile::path_for(&home, &default);
        let migrated = astrid_core::PrincipalProfile::load_from_path(&new_path).unwrap();
        assert_eq!(migrated.groups, vec!["operator-configured".to_string()]);
    }

    #[test]
    fn migrate_legacy_profile_drops_stale_legacy_when_new_already_exists() {
        // Operator already migrated by hand (or a prior boot did) —
        // the new path holds the canonical config. Don't clobber it
        // with the legacy file; just remove the legacy so capsules
        // can't reach it through home://.
        let (_d, home) = scratch_home();
        let default = astrid_core::PrincipalId::default();

        // Stale legacy with operator-stale content.
        let legacy_path = home
            .principal_home(&default)
            .config_dir()
            .join("profile.toml");
        std::fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
        let mut stale = astrid_core::PrincipalProfile::default();
        stale.groups = vec!["stale".to_string()];
        stale.save_to_path(&legacy_path).unwrap();

        // Fresh new-path content (migrated already).
        let new_path = astrid_core::PrincipalProfile::path_for(&home, &default);
        std::fs::create_dir_all(new_path.parent().unwrap()).unwrap();
        let mut canonical = astrid_core::PrincipalProfile::default();
        canonical.groups = vec!["canonical".to_string()];
        canonical.save_to_path(&new_path).unwrap();

        seed_default_principal_admin_profile(&home).unwrap();

        // Legacy removed, canonical preserved.
        assert!(!legacy_path.exists());
        let result = astrid_core::PrincipalProfile::load_from_path(&new_path).unwrap();
        assert_eq!(result.groups, vec!["canonical".to_string()]);
    }
}

// ---------------------------------------------------------------------------
// Boot validation
// ---------------------------------------------------------------------------

/// Validate that every capsule's required imports have a matching export
/// from another loaded capsule. Logs errors for unsatisfied required imports
/// and info messages for unsatisfied optional imports. Also warns about
/// duplicate exports of the same interface from multiple capsules.
fn validate_imports_exports(
    manifests: &[(
        astrid_capsule::manifest::CapsuleManifest,
        std::path::PathBuf,
    )],
) {
    // Track (namespace, interface) → list of (capsule_name, version).
    let mut exports_by_interface: std::collections::HashMap<
        (&str, &str),
        Vec<(&str, &semver::Version)>,
    > = std::collections::HashMap::new();

    for (m, _) in manifests {
        for (ns, name, ver) in m.export_triples() {
            exports_by_interface
                .entry((ns, name))
                .or_default()
                .push((&m.package.name, ver));
        }
    }

    // Warn about duplicate exports — two capsules providing the same interface
    // will both fire on matching events, causing double-processing.
    for ((ns, name), providers) in &exports_by_interface {
        if providers.len() > 1 {
            let names: Vec<&str> = providers.iter().map(|(n, _)| *n).collect();
            tracing::warn!(
                interface = %format!("{ns}/{name}"),
                providers = ?names,
                "Multiple capsules export the same interface — events may be double-processed. \
                 Consider removing one with `astrid capsule remove`."
            );
        }
    }

    let mut satisfied_count: u32 = 0;
    let mut warning_count: u32 = 0;

    for (manifest, _) in manifests {
        for (ns, name, req, optional) in manifest.import_tuples() {
            let has_provider = exports_by_interface
                .get(&(ns, name))
                .is_some_and(|providers| providers.iter().any(|(_, v)| req.matches(v)));

            if has_provider {
                satisfied_count = satisfied_count.saturating_add(1);
            } else if optional {
                tracing::info!(
                    capsule = %manifest.package.name,
                    import = %format!("{ns}/{name} {req}"),
                    "Optional import not satisfied — capsule will boot with reduced functionality"
                );
                warning_count = warning_count.saturating_add(1);
            } else {
                tracing::error!(
                    capsule = %manifest.package.name,
                    import = %format!("{ns}/{name} {req}"),
                    "Required import not satisfied — no loaded capsule exports this interface"
                );
                warning_count = warning_count.saturating_add(1);
            }
        }
    }

    tracing::info!(
        capsules = manifests.len(),
        imports_satisfied = satisfied_count,
        warnings = warning_count,
        "Boot validation complete"
    );
}

// ---------------------------------------------------------------------------
// Identity bootstrap helpers
// ---------------------------------------------------------------------------

/// Bootstrap the CLI root user identity at kernel boot.
///
/// Creates a deterministic root `AstridUserId` on first boot, or reloads it
/// on subsequent boots. Auto-links with `platform="cli"`,
/// `platform_user_id="local"`, `method="system"`.
///
/// Also seeds the default principal's profile on disk with
/// `groups = ["admin"]` (issue #670) so single-tenant deployments reach
/// the management API with full capabilities. The profile write is
/// **idempotent** — if the default principal already has a profile with
/// an `admin` group, any explicit `grants` / `revokes`, or non-empty
/// `groups`, we leave it untouched.
///
/// Idempotent: skips creation if the root user already exists.
async fn bootstrap_cli_root_user(
    store: &Arc<dyn astrid_storage::IdentityStore>,
    home: &astrid_core::dirs::AstridHome,
) -> Result<(), astrid_storage::IdentityError> {
    // Seed the default principal profile with the admin group. Runs
    // before the identity-link short-circuit below so a deleted profile
    // between boots is restored even when the identity record persists.
    if let Err(e) = seed_default_principal_admin_profile(home) {
        tracing::warn!(error = %e, "Failed to seed default admin profile — continuing boot");
    }

    // Check if root user already exists by trying to resolve the CLI link.
    if let Some(_user) = store.resolve("cli", "local").await? {
        tracing::debug!("CLI root user already linked");
        return Ok(());
    }

    // No CLI link exists. Create or find the root user.
    let user = store.create_user(Some("root")).await?;
    tracing::info!(user_id = %user.id, "Created CLI root user");

    // Link the CLI platform identity.
    store.link("cli", "local", user.id, "system").await?;
    tracing::info!(user_id = %user.id, "Linked CLI root user (cli/local)");

    Ok(())
}

/// Migrate a legacy per-principal `profile.toml` from the pre-#672
/// location (`home/{principal}/.config/profile.toml`) to the
/// system-managed `etc/profiles/{principal}.toml`. Idempotent across
/// boots: if the new path exists, the old one is removed (assumed
/// already migrated); if neither exists, no-op.
///
/// Profile contents are 100% system policy (enabled, groups, grants,
/// revokes, quotas, auth public keys) and a capsule running with
/// `fs_read = ["home://"]` could read its own policy from the legacy
/// location. Moving it under `etc/` puts it outside the `home://` VFS
/// scheme entirely.
fn migrate_legacy_profile_path(
    home: &astrid_core::dirs::AstridHome,
    principal: &astrid_core::PrincipalId,
) -> Result<(), std::io::Error> {
    let legacy_path = home
        .principal_home(principal)
        .config_dir()
        .join("profile.toml");
    let new_path = home.profile_path(principal);
    if !legacy_path.exists() {
        return Ok(());
    }
    if new_path.exists() {
        // Operator already migrated, or a prior boot did the rename.
        // Drop the stale legacy file so capsules can no longer reach
        // it via `home://.config/profile.toml`.
        let _ = std::fs::remove_file(&legacy_path);
        return Ok(());
    }
    if let Some(parent) = new_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(&legacy_path, &new_path)?;
    tracing::warn!(
        %principal,
        legacy = %legacy_path.display(),
        new = %new_path.display(),
        "Migrated profile.toml out of principal home directory \
         (security: capsules with home:// fs_read could read the legacy file)"
    );
    Ok(())
}

/// Idempotently ensure the default principal's profile on disk has the
/// built-in `admin` group, so the single-tenant CLI path carries full
/// management-API capabilities (issue #670).
///
/// - Missing profile → writes a fresh default with `groups = ["admin"]`.
/// - Existing profile with any non-empty `groups` OR any `grants` OR
///   any `revokes` → treated as operator-configured, left untouched.
/// - Existing profile with `groups = []`, `grants = []`, `revokes = []`
///   → adds `admin` to `groups`. This covers the fresh-default case
///   where a prior boot wrote a `PrincipalProfile::default()`.
///
/// Also migrates the legacy `profile.toml` location
/// (`home/{principal}/.config/`) to the new system-managed location
/// (`etc/profiles/`) on first boot post-#672, see
/// [`migrate_legacy_profile_path`].
fn seed_default_principal_admin_profile(
    home: &astrid_core::dirs::AstridHome,
) -> Result<(), astrid_core::ProfileError> {
    use astrid_core::PrincipalProfile;

    let default_principal = astrid_core::PrincipalId::default();

    // Move any legacy file in front of load — load_from_path on the new
    // path would otherwise return Default and clobber the operator's
    // existing groups/grants/revokes.
    if let Err(e) = migrate_legacy_profile_path(home, &default_principal) {
        tracing::warn!(error = %e, "Failed to migrate legacy profile path — continuing");
    }

    let path = PrincipalProfile::path_for(home, &default_principal);
    let profile = PrincipalProfile::load_from_path(&path)?;

    if !profile.groups.is_empty() || !profile.grants.is_empty() || !profile.revokes.is_empty() {
        tracing::debug!(
            principal = %default_principal,
            "Default principal profile already has group/grant/revoke entries — leaving intact"
        );
        return Ok(());
    }

    let mut updated = profile;
    updated
        .groups
        .push(astrid_core::groups::BUILTIN_ADMIN.to_string());
    updated.save_to_path(&path)?;
    tracing::info!(
        principal = %default_principal,
        "Seeded default principal with built-in `admin` group"
    );
    Ok(())
}

/// Apply pre-configured identity links from the config file.
///
/// For each `[[identity.links]]` entry, resolves or creates the referenced
/// Astrid user and links the platform identity. Logs warnings on failure
/// but does not abort boot.
async fn apply_identity_config(
    store: &Arc<dyn astrid_storage::IdentityStore>,
    workspace_root: &std::path::Path,
) {
    let config = match astrid_config::Config::load(Some(workspace_root)) {
        Ok(resolved) => resolved.config,
        Err(e) => {
            tracing::debug!(error = %e, "No config loaded for identity links");
            return;
        },
    };

    for link_cfg in &config.identity.links {
        let result = apply_single_identity_link(store, link_cfg).await;
        if let Err(e) = result {
            tracing::warn!(
                platform = %link_cfg.platform,
                platform_user_id = %link_cfg.platform_user_id,
                astrid_user = %link_cfg.astrid_user,
                error = %e,
                "Failed to apply identity link from config"
            );
        }
    }
}

/// Apply a single identity link from config.
async fn apply_single_identity_link(
    store: &Arc<dyn astrid_storage::IdentityStore>,
    link_cfg: &astrid_config::types::IdentityLinkConfig,
) -> Result<(), astrid_storage::IdentityError> {
    // Resolve astrid_user: try UUID first, then name lookup, then create.
    let user_id = if let Ok(uuid) = uuid::Uuid::parse_str(&link_cfg.astrid_user) {
        // Ensure user record exists. If the UUID was explicitly specified in
        // config but doesn't exist in the store, that's a configuration error
        // - don't silently create a different user.
        if store.get_user(uuid).await?.is_none() {
            return Err(astrid_storage::IdentityError::UserNotFound(uuid));
        }
        uuid
    } else {
        // Try name lookup.
        if let Some(user) = store.get_user_by_name(&link_cfg.astrid_user).await? {
            user.id
        } else {
            let user = store.create_user(Some(&link_cfg.astrid_user)).await?;
            tracing::info!(
                user_id = %user.id,
                name = %link_cfg.astrid_user,
                "Created user from config identity link"
            );
            user.id
        }
    };

    let method = if link_cfg.method.is_empty() {
        "admin"
    } else {
        &link_cfg.method
    };

    // Check if link already points to the correct user - skip if idempotent.
    if let Some(existing) = store
        .resolve(&link_cfg.platform, &link_cfg.platform_user_id)
        .await?
        && existing.id == user_id
    {
        tracing::debug!(
            platform = %link_cfg.platform,
            platform_user_id = %link_cfg.platform_user_id,
            user_id = %user_id,
            "Identity link from config already exists"
        );
        return Ok(());
    }

    store
        .link(
            &link_cfg.platform,
            &link_cfg.platform_user_id,
            user_id,
            method,
        )
        .await?;

    tracing::info!(
        platform = %link_cfg.platform,
        platform_user_id = %link_cfg.platform_user_id,
        user_id = %user_id,
        "Applied identity link from config"
    );

    Ok(())
}
