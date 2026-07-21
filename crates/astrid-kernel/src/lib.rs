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

/// Kernel implementation of the capsule per-action host-audit sink.
///
/// Native-only: the [`HostAuditSink`](astrid_capsule::HostAuditSink) seam is
/// driven exclusively by the wasmtime host engine, which is itself native-only
/// (the WASM engine never runs on the browser profile). The sink is the last
/// synchronous caller of the now-async audit log, so it carries a native-gated
/// block-on bridge that must not exist on `wasm32-unknown-unknown`.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod audit_sink;
/// Passive event-bus storm diagnostics (publish-rate monitor).
mod bus_monitor;
/// `astrid.v1.capsules_loaded` payload assembly (opaque per-capsule metadata).
mod capsules_loaded;
/// Grant-on-first-use consent handler (issue #998).
///
/// Native-only: reuses the management-API admin grant machinery
/// (`kernel_router::admin`), which is itself native.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod grant_on_use;
/// Persistent invite-token store (issue #756).
pub mod invite;
/// The Management API router listening to the `EventBus`.
///
/// Native-only: it drives the capsule lifecycle (Wasmtime load, disk install,
/// discovery) and the MCP host client, none of which exist on the browser
/// (`wasm32-unknown-unknown`) profile.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod kernel_router;
/// Persistent pair-device token store (issue #756).
pub mod pair_token;
#[cfg(all(test, not(all(target_arch = "wasm32", target_os = "unknown"))))]
mod runtime_policy_tests;
/// The Unix Domain Socket manager. Unix-only: binds the `UnixListener` and
/// acquires the singleton advisory lock.
#[cfg(unix)]
pub mod socket;

use arc_swap::ArcSwap;
use astrid_audit::AuditLog;
use astrid_capabilities::{CapabilityStore, DirHandle};
use astrid_capsule::profile_cache::PrincipalProfileCache;
use astrid_capsule::registry::CapsuleRegistry;
use astrid_capsule_types::CapsuleId;
use astrid_core::SessionId;
use astrid_core::dirs::{WorkspaceLayout, WorkspaceSelection};
use astrid_core::groups::GroupConfig;
use astrid_core::principal::PrincipalId;
use astrid_crypto::KeyPair;
use astrid_events::EventBus;
// MCP client + the cap-std VFS are native-only (the Wasmtime host surface);
// gated out of the browser profile, which supplies its own engine and VFS.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use astrid_mcp::{McpClient, SecureMcpClient, ServerManager, ServersConfig};
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use astrid_vfs::{HostVfs, OverlayVfsRegistry, Vfs};
use dashmap::DashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::{Mutex, RwLock};

const SCOPED_TOPIC_PROBE_SENTINEL: &str = "\0astrid.scoped-topic\0";
const SCOPED_SERVICE_PROBE_SENTINEL: &str = "\0astrid.scoped-service\0";

/// The core Operating System Kernel.
pub struct Kernel {
    /// The unique identifier for this kernel session.
    pub session_id: SessionId,
    /// The global IPC message bus.
    pub event_bus: Arc<EventBus>,
    /// The process manager (loaded WASM capsules).
    pub capsules: Arc<RwLock<CapsuleRegistry>>,
    /// The secure MCP client with capability-based authorization and audit
    /// logging. Native-only: the MCP host surface belongs to the Wasmtime
    /// engine, absent on the browser profile.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub mcp: SecureMcpClient,
    /// The capability store for this session.
    pub capabilities: Arc<CapabilityStore>,
    /// The global Virtual File System mount.
    ///
    /// Points at the unmodified workspace (no overlay). Principal-scoped
    /// overlays live in [`overlay_registry`](Self::overlay_registry) — this
    /// field is kept for kernel-internal paths that do not know a principal
    /// (discovery, capsule load scan). Native-only: `astrid-vfs` is built on
    /// `cap-std`, which does not compile for the browser profile (that host
    /// resolves paths by other means).
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub vfs: Arc<dyn Vfs>,
    /// Per-principal overlay registry (Layer 4, issue #668).
    ///
    /// Each invoking principal resolves their own
    /// [`OverlayVfs`](astrid_vfs::OverlayVfs) from this registry on first
    /// use — lower layer is the shared workspace, upper layer is a
    /// principal-private tempdir. Agent A's uncommitted writes are never
    /// visible to Agent B. Native-only (`astrid-vfs` / `cap-std`).
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub overlay_registry: Arc<OverlayVfsRegistry>,
    /// The global physical root handle for the VFS. On native hosts the
    /// composition root registers it as the cap-std workspace root; the
    /// browser profile keeps the handle (it is engine-agnostic) but gates
    /// out the cap-std-backed `astrid-vfs` machinery behind it.
    pub vfs_root_handle: DirHandle,
    /// The physical path the VFS is mounted to.
    pub workspace_root: PathBuf,
    /// Per-project runtime state layout selected at boot.
    workspace_layout: WorkspaceLayout,
    /// Checked root/state target used to detect later filesystem redirection.
    workspace_selection: WorkspaceSelection,
    /// The principal home resources directory (`~/.astrid/home/{principal}/`).
    /// Capsules declaring `fs_read = ["home://"]` can read files under this
    /// root. Scoped to the principal's home so that keys, databases, and
    /// system config in `~/.astrid/` are NOT accessible.
    ///
    /// Always `Some` in production (boot requires `AstridHome`). Remains
    /// `Option` for compatibility with `CapsuleContext` and test fixtures.
    pub home_root: Option<PathBuf>,
    /// The natively bound Unix Socket for the CLI proxy.
    pub cli_socket_listener: Option<astrid_capsule::context::UplinkListener>,
    /// Exclusive advisory lock enforcing a single kernel instance, held for
    /// the daemon's lifetime (see [`socket::acquire_boot_singleton_lock`],
    /// acquired before the KV/audit stores open). `None` for test kernels that
    /// don't bind a real socket. Never read — the point is that its `Drop` (or
    /// process exit) releases the lock so a restart isn't wedged.
    #[expect(
        dead_code,
        reason = "held for the process lifetime; Drop releases the singleton flock"
    )]
    singleton_lock: Option<std::fs::File>,
    /// Shared KV store backing all capsule-scoped stores and kernel state.
    ///
    /// A trait object (`Arc<dyn KvStore>`) so a portable host can inject its
    /// own backend; the shutdown flush goes through the trait's
    /// [`close`](astrid_storage::KvStore::close).
    pub kv: Arc<dyn astrid_storage::KvStore>,
    /// Chain-linked cryptographic audit log with persistent storage.
    pub audit_log: Arc<AuditLog>,
    /// The runtime ed25519 signing key (issue #929).
    ///
    /// Loaded once at boot from `~/.astrid/keys/runtime.key` and shared
    /// (`Arc`) with [`AuditLog`] — both sign with the exact same key bytes,
    /// never loaded twice. Reachable from the admin token-mint handlers so an
    /// operator can pre-grant `mcp://` tool access by minting a capability
    /// token signed by this key (the same key the approval interceptor's
    /// validator trusts as issuer).
    pub runtime_key: Arc<astrid_crypto::KeyPair>,
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
    /// [`FuelLedger`](astrid_capsule_types::FuelLedger).
    fuel_ledger: astrid_capsule_types::FuelLedger,
    /// Shared per-principal CPU-rate limiter (the deny side of the budget),
    /// cloned into every capsule's `WasmEngine` (via the loader) alongside
    /// `fuel_ledger`. A principal over its `max_cpu_fuel_per_sec` in the rolling
    /// 1-second window is denied at interceptor entry, cross-capsule. See
    /// [`FuelRateLimiter`](astrid_capsule_types::FuelRateLimiter).
    fuel_rate: astrid_capsule_types::FuelRateLimiter,
    /// Shared per-principal peak-memory ledger, the RAM analogue of
    /// `fuel_ledger`: cloned into every capsule's `WasmEngine` (via the loader)
    /// so a principal's linear-memory high-water mark is the max across all
    /// capsules. Telemetry today; fills `ResourceUsage::memory_bytes_peak_total`.
    /// See [`MemoryLedger`](astrid_capsule_types::MemoryLedger).
    memory_ledger: astrid_capsule_types::MemoryLedger,
    /// Host-derived (operator-overridable) concurrency ceilings for capsule
    /// host calls, resolved once by the daemon and forwarded to every
    /// `WasmEngine` via the loader. The kernel only stores and forwards this
    /// `Copy` value — no resolution logic lives here. See
    /// [`CapsuleRuntimeLimits`](astrid_capsule_types::CapsuleRuntimeLimits).
    runtime_limits: astrid_capsule_types::CapsuleRuntimeLimits,
    /// Process-wide persistent network-stream admission budget. One shared
    /// handle is forwarded through every loader and engine so capsule count and
    /// instance-pool size cannot multiply the file-descriptor envelope.
    net_stream_budget: Arc<astrid_capsule_types::NetStreamBudget>,
    /// Operator-approved per-capsule local-egress allowlist
    /// (`[security.capsule_local_egress]`), keyed by capsule id. Resolved
    /// once from config by the daemon; the kernel only stores it and hands
    /// each capsule its own slice at load time so the SSRF airlock can
    /// exempt operator-sanctioned loopback/private endpoints. Empty = no
    /// exemptions (fail-closed).
    local_egress: std::collections::HashMap<String, Vec<String>>,
    /// Resolved `astrid:http` host ceilings (timeouts, redirect/stream caps,
    /// buffered-body limit) from the `[http]` config section. A GLOBAL value —
    /// the same for every capsule (unlike `local_egress`). Resolved once from
    /// config by the daemon; the kernel only stores it and forwards it,
    /// unmodified, to every capsule's `WasmEngine` via the loader. See
    /// [`HttpLimits`](astrid_capsule_types::HttpLimits).
    http_limits: astrid_capsule_types::HttpLimits,
    /// Coalesces full capsule reload requests so the router cannot spawn
    /// overlapping all-principal discovery/load sweeps.
    full_reload_in_flight: AtomicBool,
    /// Serializes per-principal capsule load/warm operations.
    ///
    /// WASM component construction is CPU-heavy and can involve synchronous
    /// host setup. Principal loads are not part of the gateway request fast
    /// path, so queue them instead of letting admin-driven warms stampede the
    /// daemon and starve unrelated HTTP/auth routes.
    capsule_load_lock: Mutex<()>,
    /// Ephemeral mode: shut down immediately when the last client disconnects.
    pub ephemeral: AtomicBool,
    /// Instant when the kernel was booted (for uptime calculation). Crate-
    /// private: the only reader is the router's uptime report, and keeping it
    /// out of the public surface leaves the facade free to swap the concrete
    /// `Instant` type per target.
    pub(crate) boot_time: astrid_runtime::time::Instant,
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

/// Host resources injected into [`Kernel::with_resources`].
///
/// Every field here is a facility whose acquisition is platform-specific — the
/// products of the native side-effects that [`Kernel::new`] performs (resolving
/// the Astrid home, opening the KV/audit stores, loading the runtime key,
/// binding the singleton Unix socket, generating the session token). Bundling
/// them into one value inverts resource acquisition out of the constructor: a
/// native host calls [`Kernel::new`] (which builds this and delegates), while an
/// alternate host (e.g. a browser WebAssembly build) can supply its own
/// resources and call [`Kernel::with_resources`] directly.
pub struct KernelResources {
    /// Resolved Astrid home (FHS layout). Source of the KV/audit/key paths,
    /// the `home://` VFS scheme root, and group/profile config locations.
    pub home: astrid_core::dirs::AstridHome,
    /// Persistent KV store backing the capability store, identity store, and
    /// kernel state. A trait object (`Arc<dyn KvStore>`) so a portable host can
    /// inject its own backend; the shutdown flush routes through the trait's
    /// [`close`](astrid_storage::KvStore::close) rather than an inherent method.
    pub kv: Arc<dyn astrid_storage::KvStore>,
    /// Chain-linked cryptographic audit log, opened over the runtime key.
    pub audit_log: Arc<AuditLog>,
    /// The runtime ed25519 signing key (issue #929) — shared with `audit_log`
    /// and the admin token-mint path; never loaded from disk twice.
    pub runtime_key: Arc<astrid_crypto::KeyPair>,
    /// Session token for socket authentication, generated at boot and written
    /// to `~/.astrid/run/system.token`. The CLI presents it as its first message.
    pub session_token: Arc<astrid_core::session_token::SessionToken>,
    /// Path the session token was written to, retained so shutdown reuses the
    /// exact same path (avoids a fallback mismatch if the environment changes).
    pub token_path: PathBuf,
    /// The natively bound Unix listener for the CLI uplink, or `None` for hosts
    /// (and test kernels) that do not service a real socket.
    pub cli_socket_listener: Option<astrid_capsule::context::UplinkListener>,
    /// Exclusive advisory lock enforcing a single kernel instance, held for the
    /// process lifetime; its `Drop` releases the lock. Independent of
    /// `cli_socket_listener` — the kernel never reads either field, so a host
    /// supplies whichever facilities it actually has (the native daemon: both;
    /// test kernels and hosts with no real socket: neither).
    pub singleton_lock: Option<std::fs::File>,
}

impl KernelResources {
    /// Bundle already-acquired host resources for [`Kernel::with_resources`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        home: astrid_core::dirs::AstridHome,
        kv: Arc<dyn astrid_storage::KvStore>,
        audit_log: Arc<AuditLog>,
        runtime_key: Arc<astrid_crypto::KeyPair>,
        session_token: Arc<astrid_core::session_token::SessionToken>,
        token_path: PathBuf,
        cli_socket_listener: Option<astrid_capsule::context::UplinkListener>,
        singleton_lock: Option<std::fs::File>,
    ) -> Self {
        Self {
            home,
            kv,
            audit_log,
            runtime_key,
            session_token,
            token_path,
            cli_socket_listener,
            singleton_lock,
        }
    }
}

impl Kernel {
    /// Set the process-wide persistent network-stream admission ceiling.
    /// Existing streams remain valid when the ceiling is lowered; new
    /// admissions resume after usage falls below the configured limit.
    pub fn set_net_stream_limit(&self, limit: usize) {
        self.net_stream_budget.set_limit(limit);
        metrics::gauge!("astrid_capsule_net_streams_limit").set(f64::from(
            u32::try_from(self.net_stream_budget.limit()).unwrap_or(u32::MAX),
        ));
        metrics::gauge!("astrid_capsule_net_streams_active").set(f64::from(
            u32::try_from(self.net_stream_budget.active()).unwrap_or(u32::MAX),
        ));
    }

    /// Return `(active, limit)` for capacity reporting and telemetry.
    #[must_use]
    pub fn net_stream_usage(&self) -> (usize, usize) {
        (
            self.net_stream_budget.active(),
            self.net_stream_budget.limit(),
        )
    }

    /// Per-project runtime layout selected at boot.
    #[must_use]
    pub fn workspace_layout(&self) -> &WorkspaceLayout {
        &self.workspace_layout
    }

    /// Checked project state selection captured at boot.
    #[must_use]
    pub fn workspace_selection(&self) -> &WorkspaceSelection {
        &self.workspace_selection
    }

    /// Boot a new Kernel instance mounted at the specified directory.
    ///
    /// The native composition root: resolves the Astrid home, opens the
    /// `SurrealKV` store and audit log, loads the runtime key, binds the singleton
    /// Unix socket, generates the session token, then delegates to the portable
    /// [`Kernel::with_resources`]. Unix-only — the socket bind and singleton
    /// flock have no browser-profile analogue; that host builds its own
    /// [`KernelResources`] and calls `with_resources` directly.
    ///
    /// `runtime_limits` is the resolved per-host capsule concurrency ceiling
    /// pair (blocking vs async-I/O host calls); the daemon resolves it from
    /// config + CLI + host defaults and the kernel forwards it, unmodified, to
    /// every capsule's `WasmEngine`. In tests, pass
    /// [`CapsuleRuntimeLimits::default()`](astrid_capsule_types::CapsuleRuntimeLimits::default).
    ///
    /// `http_limits` is the resolved `astrid:http` host ceilings (a global
    /// value, the same for every capsule), likewise resolved by the daemon from
    /// the `[http]` config section and forwarded unmodified. In tests, pass
    /// [`HttpLimits::default()`](astrid_capsule_types::HttpLimits::default).
    ///
    /// # Panics
    ///
    /// Panics if called on a single-threaded tokio runtime. The capsule
    /// system uses `block_in_place` which requires a multi-threaded runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if any native resource cannot be acquired — the Astrid
    /// home cannot be resolved, the KV store, runtime key, or audit log cannot
    /// be opened, the Unix socket cannot be bound (or the singleton lock is
    /// already held), or the session token cannot be generated — or if the
    /// portable wiring in [`Kernel::with_resources`] fails.
    #[cfg(unix)]
    pub async fn new(
        session_id: SessionId,
        workspace_root: PathBuf,
        runtime_limits: astrid_capsule_types::CapsuleRuntimeLimits,
        local_egress: std::collections::HashMap<String, Vec<String>>,
        http_limits: astrid_capsule_types::HttpLimits,
    ) -> Result<Arc<Self>, std::io::Error> {
        Self::new_with_workspace_layout(
            session_id,
            workspace_root,
            runtime_limits,
            local_egress,
            http_limits,
            WorkspaceLayout::default(),
        )
        .await
    }

    /// Boot a kernel with an explicit per-project runtime layout.
    ///
    /// # Errors
    ///
    /// Returns an error if the Astrid home or native resources cannot be
    /// acquired, or if portable kernel wiring fails.
    #[cfg(unix)]
    pub async fn new_with_workspace_layout(
        session_id: SessionId,
        workspace_root: PathBuf,
        runtime_limits: astrid_capsule_types::CapsuleRuntimeLimits,
        local_egress: std::collections::HashMap<String, Vec<String>>,
        http_limits: astrid_capsule_types::HttpLimits,
        workspace_layout: WorkspaceLayout,
    ) -> Result<Arc<Self>, std::io::Error> {
        use astrid_core::dirs::AstridHome;

        // Resolve the Astrid home directory. Required for persistent KV store
        // and audit log. Fails boot if neither $ASTRID_HOME nor $HOME is set.
        let home = AstridHome::resolve().map_err(|e| {
            std::io::Error::other(format!(
                "Failed to resolve Astrid home (set $ASTRID_HOME or $HOME): {e}"
            ))
        })?;

        // Acquire the singleton advisory lock as the FIRST fallible boot step —
        // BEFORE opening any shared state store. A boot-race loser then fails
        // here with the actionable "already running (singleton lock held)"
        // error and never opens (or even touches) the shared surrealkv KV /
        // audit stores, rather than dying on a raw `LOCK is already locked` from
        // the store layer after having opened one. The listener bind below does
        // NOT re-acquire the lock — it is already held for the process lifetime.
        let singleton_lock = socket::acquire_boot_singleton_lock(&home)?;

        // Open the persistent KV store (needed by the capability store).
        let kv_path = home.state_db_path();
        let kv: Arc<dyn astrid_storage::KvStore> = Arc::new(
            astrid_storage::SurrealKvStore::open(&kv_path)
                .map_err(|e| std::io::Error::other(format!("Failed to open KV store: {e}")))?,
        );
        // TODO: clear ephemeral keys (e: prefix) on boot when the key
        // lifecycle tier convention is established.

        // Load the runtime signing key ONCE and share it (issue #929): the
        // audit log signs chain entries with it, and the admin token-mint path
        // signs capability tokens with the same key. Never load it from disk
        // twice — a second load would still yield the same persisted bytes, but
        // routing one `Arc` makes the single-source-of-truth explicit and lets
        // `kernel.runtime_key` mint tokens the approval interceptor's validator
        // trusts as issuer.
        let runtime_key = Arc::new(load_or_generate_runtime_key(&home.keys_dir())?);
        let audit_log = open_audit_log(&home, Arc::clone(&runtime_key)).await?;

        // Bind the secure Unix socket (the singleton lock is already held). The
        // socket is bound here, but not yet listened on. The token is generated
        // before any capsule can accept connections, preventing a race where a
        // client connects before the token file exists.
        let listener = socket::bind_listener(&home)?;
        // Record our PID immediately after acquiring the singleton lock, so the
        // PID on disk always belongs to the process that holds the state-db
        // lock. The CLI reads this to signal a wedged daemon that is no longer
        // reachable over the socket but still holding the lock (which would
        // otherwise wedge the next `astrid start`). Best-effort: a write
        // failure only degrades `stop`/`restart` to socket-only cleanup.
        if let Err(e) = socket::write_pid_file() {
            tracing::warn!(error = %e, "Failed to write daemon PID file; stop/restart will fall back to socket-only cleanup");
        }
        let (session_token, token_path) = socket::generate_session_token()?;

        let resources = KernelResources::new(
            home,
            kv,
            audit_log,
            runtime_key,
            Arc::new(session_token),
            token_path,
            Some(Arc::new(tokio::sync::Mutex::new(listener))),
            Some(singleton_lock),
        );

        Self::with_resources_and_workspace_layout(
            session_id,
            workspace_root,
            runtime_limits,
            local_egress,
            http_limits,
            resources,
            workspace_layout,
        )
        .await
    }

    /// Construct a Kernel from already-acquired host resources.
    ///
    /// This is the **portable composition root**: it performs the entire
    /// kernel wiring (event bus, registries, capability store, VFS/overlay,
    /// identity/group config, monitors, dispatcher) but performs **no native
    /// side-effects** — every platform-specific facility is injected via
    /// [`KernelResources`]. [`Kernel::new`] is the native composition root that
    /// acquires those resources (resolving the home, opening the KV/audit
    /// stores, loading the runtime key, binding the socket, generating the
    /// token) and delegates here. An alternate host can build its own
    /// [`KernelResources`] and call this directly.
    ///
    /// `runtime_limits` is the resolved per-host capsule concurrency ceiling
    /// pair (blocking vs async-I/O host calls); the daemon resolves it from
    /// config + CLI + host defaults and the kernel forwards it, unmodified, to
    /// every capsule's `WasmEngine`. In tests, pass
    /// [`CapsuleRuntimeLimits::default()`](astrid_capsule_types::CapsuleRuntimeLimits::default).
    ///
    /// `http_limits` is the resolved `astrid:http` host ceilings (a global
    /// value, the same for every capsule), likewise resolved by the daemon from
    /// the `[http]` config section and forwarded unmodified. In tests, pass
    /// [`HttpLimits::default()`](astrid_capsule_types::HttpLimits::default).
    ///
    /// # Panics
    ///
    /// Panics if called on a single-threaded tokio runtime. The capsule
    /// system uses `block_in_place` which requires a multi-threaded runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if any portable wiring step fails: the VFS mount paths
    /// cannot be registered, the capability store cannot be initialized over
    /// the injected KV, the group configuration cannot be loaded, or the CLI
    /// root identity cannot be bootstrapped.
    pub async fn with_resources(
        session_id: SessionId,
        workspace_root: PathBuf,
        runtime_limits: astrid_capsule_types::CapsuleRuntimeLimits,
        local_egress: std::collections::HashMap<String, Vec<String>>,
        http_limits: astrid_capsule_types::HttpLimits,
        resources: KernelResources,
    ) -> Result<Arc<Self>, std::io::Error> {
        Self::with_resources_and_workspace_layout(
            session_id,
            workspace_root,
            runtime_limits,
            local_egress,
            http_limits,
            resources,
            WorkspaceLayout::default(),
        )
        .await
    }

    /// Construct a kernel from injected resources and workspace layout.
    ///
    /// # Panics
    ///
    /// Panics on native targets when called from a single-threaded tokio
    /// runtime because the capsule engine requires `block_in_place`.
    ///
    /// # Errors
    ///
    /// Returns an error if VFS mounts, the capability store, group
    /// configuration, or CLI root bootstrap cannot be initialized.
    #[expect(
        clippy::too_many_lines,
        reason = "boot sequence: sequential setup that does not benefit from splitting"
    )]
    pub async fn with_resources_and_workspace_layout(
        session_id: SessionId,
        workspace_root: PathBuf,
        runtime_limits: astrid_capsule_types::CapsuleRuntimeLimits,
        local_egress: std::collections::HashMap<String, Vec<String>>,
        http_limits: astrid_capsule_types::HttpLimits,
        resources: KernelResources,
        workspace_layout: WorkspaceLayout,
    ) -> Result<Arc<Self>, std::io::Error> {
        // The native capsule engine uses `block_in_place`, which requires a
        // multi-thread runtime. The browser profile has no such runtime (and no
        // `block_in_place`), so the assert is native-only.
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        assert!(
            tokio::runtime::Handle::current().runtime_flavor()
                == tokio::runtime::RuntimeFlavor::MultiThread,
            "Kernel requires a multi-threaded tokio runtime (block_in_place panics on \
             single-threaded). Use #[tokio::main] or Runtime::new() instead of current_thread."
        );

        let KernelResources {
            home,
            kv,
            audit_log,
            runtime_key,
            session_token,
            token_path,
            cli_socket_listener,
            singleton_lock,
        } = resources;

        let workspace_selection = workspace_layout.resolve(&workspace_root).map_err(|error| {
            std::io::Error::new(error.kind(), format!("unsafe workspace selection: {error}"))
        })?;
        let workspace_root = workspace_selection.project_root().to_path_buf();

        let event_bus = Arc::new(EventBus::new());
        let capsules = Arc::new(RwLock::new(CapsuleRegistry::new()));

        // Resolve the home directory for the `home://` VFS scheme.
        // Points to `~/.astrid/home/{principal}/` — NOT the full `~/.astrid/`
        // root — so capsules cannot access keys, databases, or config.
        let default_principal = astrid_core::PrincipalId::default();
        let principal_home = home.principal_home(&default_principal);
        let home_root = Some(principal_home.root().to_path_buf());

        // Bootstrap the capability store (persistent) over the injected KV.
        // Key rotation invalidates persisted tokens (fail-secure by design).
        let capabilities = Arc::new(
            CapabilityStore::with_kv_store(Arc::clone(&kv))
                .await
                .map_err(|e| {
                    std::io::Error::other(format!("Failed to init capability store: {e}"))
                })?,
        );

        // Initialize the MCP process manager with its security layer. Native
        // only — the MCP host surface belongs to the Wasmtime engine, which the
        // browser profile does not build. `workspace_root` is set so sandboxed
        // MCP servers have a writable directory.
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        let mcp = {
            let mcp_config = ServersConfig::load_default().unwrap_or_default();
            let mcp_manager = ServerManager::new(mcp_config)
                .with_workspace_root(workspace_root.clone())
                .with_capsule_log_dir(principal_home.log_dir());
            let mcp_client = McpClient::new(mcp_manager);
            SecureMcpClient::new(
                mcp_client,
                Arc::clone(&capabilities),
                Arc::clone(&audit_log),
                session_id.clone(),
            )
        };

        // Establish the physical security boundary (sandbox handle).
        let root_handle = DirHandle::new();

        // Principal-scoped overlay registry: each invoking principal
        // gets a fresh OverlayVfs on first use (Layer 4, issue #668).
        // The kernel-internal `vfs` field keeps pointing at a plain
        // HostVfs over the workspace for paths that don't yet know a
        // principal (discovery, capsule load scan). Native only — `astrid-vfs`
        // is built on `cap-std`, absent on the browser profile.
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        let vfs = {
            let kernel_host_vfs = HostVfs::new();
            kernel_host_vfs
                .register_dir(root_handle.clone(), workspace_root.clone())
                .await
                .map_err(|_| std::io::Error::other("Failed to register kernel workspace vfs"))?;
            Arc::new(kernel_host_vfs) as Arc<dyn Vfs>
        };
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        let overlay_registry = Arc::new(OverlayVfsRegistry::new(
            workspace_root.clone(),
            root_handle.clone(),
        ));

        let allowance_store = Arc::new(astrid_approval::AllowanceStore::new());
        // Create system-wide identity store backed by the shared KV.
        let identity_kv = astrid_storage::ScopedKvStore::new(Arc::clone(&kv), "system:identity")
            .map_err(|e| std::io::Error::other(format!("Failed to create identity KV: {e}")))?;
        let identity_store: Arc<dyn astrid_storage::IdentityStore> =
            Arc::new(astrid_storage::KvIdentityStore::new(identity_kv));

        // Load group config (issue #670). Boot-loaded once, then swapped
        // atomically by Layer 6 admin topics (issue #672). Missing file
        // → built-ins only; malformed TOML is a hard boot failure
        // (fail-closed). Native-only: `etc/groups.toml` is disk state, and
        // on `wasm32-unknown-unknown` `std::fs` reads fail with
        // `ErrorKind::Unsupported` — which is NOT the `NotFound` the loader
        // maps to built-ins, so an ungated load would hard-fail every
        // browser boot through the fail-closed arm.
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        let groups_loaded = GroupConfig::load(&home)
            .map_err(|e| std::io::Error::other(format!("Failed to load groups config: {e}")))?;
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        let groups_loaded = GroupConfig::builtin_only();
        let groups = Arc::new(ArcSwap::from_pointee(groups_loaded));

        // Bootstrap the CLI root user and apply config-file identity links.
        // Native-only: both are CLI/disk concepts (the root-user seed writes
        // the default principal's profile under `etc/`, and identity links
        // come from on-disk config); the browser host establishes identity
        // through its own uplink instead.
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            // Bootstrap the CLI root user (idempotent). Also seeds the
            // default principal's profile with `groups = ["admin"]` so
            // single-tenant deployments get full management-API access.
            bootstrap_cli_root_user(&identity_store, &home)
                .await
                .map_err(|e| {
                    std::io::Error::other(format!("Failed to bootstrap CLI root user: {e}"))
                })?;

            // Apply pre-configured identity links from config.
            apply_identity_config(&identity_store, &workspace_root, &workspace_layout).await;
        }

        let kernel = Arc::new(Self {
            session_id,
            event_bus,
            capsules,
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            mcp,
            capabilities,
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            vfs,
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            overlay_registry,
            vfs_root_handle: root_handle,
            workspace_root,
            workspace_layout,
            workspace_selection,
            home_root,
            cli_socket_listener,
            singleton_lock,
            kv,
            audit_log,
            runtime_key,
            active_connections: DashMap::new(),
            fuel_ledger: astrid_capsule_types::FuelLedger::default(),
            fuel_rate: astrid_capsule_types::FuelRateLimiter::default(),
            memory_ledger: astrid_capsule_types::MemoryLedger::default(),
            runtime_limits,
            net_stream_budget: Arc::new(astrid_capsule_types::NetStreamBudget::default()),
            local_egress,
            http_limits,
            full_reload_in_flight: AtomicBool::new(false),
            capsule_load_lock: Mutex::new(()),
            ephemeral: AtomicBool::new(false),
            boot_time: astrid_runtime::time::Instant::now(),
            shutdown_tx: tokio::sync::watch::channel(false).0,
            session_token,
            token_path,
            allowance_store,
            identity_store,
            profile_cache: Arc::new(PrincipalProfileCache::with_home(home.clone())),
            groups,
            astrid_home: home,
            admin_write_lock: Mutex::new(()),
        });

        // The management-API router, idle monitor, and capsule health/react
        // monitors drive native-only machinery (capsule lifecycle, disk
        // discovery, `process::exit`). The browser profile runs none of them.
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            drop(kernel_router::spawn_kernel_router(Arc::clone(&kernel)));
            drop(spawn_idle_monitor(Arc::clone(&kernel)));
            drop(spawn_react_watchdog(Arc::clone(&kernel.event_bus)));
            drop(spawn_capsule_health_monitor(Arc::clone(&kernel)));
        }
        // Passive storm diagnostics — subscribes synchronously inside the
        // call (before the debug-assert below) so it counts toward
        // `INTERNAL_SUBSCRIBER_COUNT`.
        drop(bus_monitor::spawn_bus_activity_monitor(&kernel.event_bus));
        // Grant-on-first-use (#998): observe `astrid.v1.approval` for
        // `GrantRequired` signals the dispatcher emits at the access-gate
        // miss, and grant the capsule on an elicited APPROVE. Subscribes
        // synchronously (before the debug-assert below) so its one permanent
        // broadcast subscriber counts toward `INTERNAL_SUBSCRIBER_COUNT`.
        // Native-only: the grant path drives the native admin machinery.
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        drop(grant_on_use::spawn_grant_on_use_handler(Arc::clone(
            &kernel,
        )));

        // Spawn the event dispatcher — routes EventBus events to capsule interceptors.
        // Wire the identity store so auto-provisioning is gated, and the
        // per-principal capsule-access resolver so the user-invocable tool
        // surface (`tool.v1.execute.*`, `cli.v1.command.execute`) is gated
        // at dispatch (admin `*` bypass, fail-closed). The resolver reuses
        // the kernel-owned profile cache + live group config — cloned in
        // the same way the fuel/memory ledgers are.
        let access_resolver = astrid_capsule::CapsuleAccessResolver::new(
            Arc::clone(&kernel.profile_cache),
            Arc::clone(&kernel.groups),
        );
        let dispatcher = astrid_capsule::dispatcher::EventDispatcher::new(
            Arc::clone(&kernel.capsules),
            Arc::clone(&kernel.event_bus),
        )
        .with_identity_store(Arc::clone(&kernel.identity_store))
        .with_access_resolver(access_resolver)
        // Inject the kernel's already-booted home so per-principal
        // auto-provisioning happens under it — the dispatcher never
        // resolves a home from the process environment (#1145).
        .with_home(kernel.astrid_home.clone());
        drop(astrid_runtime::spawn(dispatcher.run()));

        debug_assert_eq!(
            kernel.event_bus.subscriber_count(),
            INTERNAL_SUBSCRIBER_COUNT,
            "INTERNAL_SUBSCRIBER_COUNT is stale; update it when adding permanent subscribers"
        );

        Ok(kernel)
    }

    fn verify_workspace_capsule_tree(&self, dir: &Path) -> anyhow::Result<()> {
        if let Ok(relative) = dir.strip_prefix(self.workspace_selection.state_dir()) {
            self.workspace_selection
                .verify_tree(relative)
                .map_err(|error| {
                    anyhow::anyhow!("workspace capsule tree contains an unsafe redirect: {error}")
                })?;
        }
        Ok(())
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    fn verify_workspace_component_paths(
        &self,
        dir: &Path,
        manifest: &astrid_capsule_types::manifest::CapsuleManifest,
    ) -> anyhow::Result<()> {
        let Ok(capsule_relative) = dir.strip_prefix(self.workspace_selection.state_dir()) else {
            return Ok(());
        };
        for component in &manifest.components {
            if component.path.is_absolute() {
                anyhow::bail!(
                    "workspace capsule component must be relative: {}",
                    component.path.display()
                );
            }
            self.workspace_selection
                .resolve_file(capsule_relative.join(&component.path))
                .map_err(|error| {
                    anyhow::anyhow!(
                        "workspace capsule component path is unsafe ({}): {error}",
                        component.path.display()
                    )
                })?;
        }
        Ok(())
    }

    /// Load a capsule into the Kernel from a directory containing a Capsule.toml
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest cannot be loaded, the capsule cannot be created, or registration fails.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    async fn load_capsule(
        &self,
        dir: PathBuf,
        principal: &PrincipalId,
    ) -> Result<(), anyhow::Error> {
        self.verify_workspace_capsule_tree(&dir)?;
        let manifest_path = dir.join("Capsule.toml");
        let manifest = astrid_capsule::discovery::load_manifest(&manifest_path)
            .map_err(|e| anyhow::anyhow!(e))?;
        self.verify_workspace_component_paths(&dir, &manifest)?;
        let id = astrid_capsule_types::CapsuleId::from_static(&manifest.package.name);
        let wasm_hash = capsule_instance_hash(&manifest, &dir);
        self.verify_workspace_capsule_tree(&dir)?;

        // Dedup by content hash (issue #1069). Runtime instances are shared by
        // hash across principals: a hash referenced by N principals loads ONCE.
        //
        // - Already in THIS principal's view → nothing to do.
        // - A runtime for this hash already exists (loaded by another
        //   principal) → add this principal's VIEW over the shared instance;
        //   no runtime is built.
        //
        // Only when the hash is not yet loaded do we build a runtime (below).
        {
            let mut registry = self.capsules.write().await;
            if registry.get_for(principal, &id).is_some() {
                return Ok(());
            }
            if registry.contains_hash(&wasm_hash) {
                registry
                    .register_existing(&id, &wasm_hash, principal)
                    .map_err(|e| anyhow::anyhow!("Failed to add capsule view: {e}"))?;
                return Ok(());
            }
        }

        // First load of this content hash: build ONE shared runtime under the
        // DEFAULT (system) principal (see `build_shared_capsule`). The installing
        // `principal` receives the dispatch view via `register_owned_by_default`.
        let mut capsule = self.build_shared_capsule(manifest, &dir).await?;

        if !manifest_path.exists() {
            unload_loaded_capsule_after_source_disappeared(capsule, &id, principal, &manifest_path)
                .await;
            return Ok(());
        }

        {
            let mut registry = self.capsules.write().await;
            // A concurrent load may have won the race: either this principal
            // already has a view, or another principal built the shared runtime
            // for this hash while we were loading. In both cases discard the
            // runtime we just built. If the hash now exists but this principal
            // lacks a view, add the view over the winner and drop ours.
            let already_in_view = registry.get_for(principal, &id).is_some();
            let hash_now_loaded = registry.contains_hash(&wasm_hash);
            if already_in_view || hash_now_loaded {
                if hash_now_loaded && !already_in_view {
                    // Attach this principal's view to the runtime that won.
                    if let Err(e) = registry.register_existing(&id, &wasm_hash, principal) {
                        tracing::warn!(
                            capsule_id = %id,
                            principal = %principal,
                            error = %e,
                            "Failed to add view after concurrent shared load"
                        );
                    }
                }
                drop(registry);
                capsule.request_cancel();
                if let Err(e) = capsule.unload().await {
                    tracing::warn!(
                        capsule_id = %id,
                        principal = %principal,
                        error = %e,
                        "Redundant capsule unload failed after concurrent load"
                    );
                }
                return Ok(());
            }
            // First loader of this hash: register the shared runtime (owned by
            // the default/system principal) and give the installing principal
            // its dispatch view.
            registry
                .register_owned_by_default(capsule, wasm_hash, principal)
                .map_err(|e| anyhow::anyhow!("Failed to register capsule: {e}"))?;
        }

        Ok(())
    }

    /// Build and load ONE shared capsule runtime under the DEFAULT (system)
    /// principal.
    ///
    /// A content-addressed runtime is SHARED across every principal that views
    /// the same WASM hash, so it is loaded under no real principal's identity.
    /// The runtime's load-time host state is therefore a NEUTRAL, fail-closed
    /// placeholder: its `kv` is a physically-isolated in-memory store and its
    /// `secret_store` is deny-all — NEVER `default`'s (or anyone's) real KV,
    /// secrets, or home. That placeholder is reached only by principal-less
    /// load-time contexts (e.g. a watchdog tick or `capsules_loaded`), where it
    /// denies rather than exposing any principal's private state.
    ///
    /// EVERY invocation that carries a principal — the owner/`default`
    /// included — installs per-invocation `invocation_*` overlays scoped to the
    /// *invoking* principal (KV / secret store / home / tmp / log), so
    /// per-principal isolation is preserved without a per-principal runtime.
    /// Per-principal config is likewise NOT baked here: it is resolved per
    /// invocation via the `invocation_env_overlay` (read from the invoking
    /// principal's `.config/env/{capsule}.env.json`). The `default` env config
    /// this method pre-loads and `self.config` seed only the real shared KV
    /// backend (`kv_backend`) used to CONSTRUCT overlays and the hash-identical
    /// manifest defaults — never the neutral load-time `kv` fallback.
    ///
    /// # Errors
    ///
    /// Returns an error if the capsule cannot be created, the KV scope cannot be
    /// built, or `capsule.load` fails.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    async fn build_shared_capsule(
        &self,
        manifest: astrid_capsule_types::manifest::CapsuleManifest,
        dir: &std::path::Path,
    ) -> Result<Box<dyn astrid_capsule::capsule::Capsule>, anyhow::Error> {
        self.verify_workspace_capsule_tree(dir)?;
        let load_principal = PrincipalId::default();

        let loader = astrid_capsule::loader::CapsuleLoader::new(
            self.mcp.clone(),
            self.fuel_ledger.clone(),
            self.fuel_rate.clone(),
            self.memory_ledger.clone(),
            self.runtime_limits,
            self.http_limits,
        )
        .with_net_stream_budget(Arc::clone(&self.net_stream_budget));
        let mut capsule = loader.create_capsule(manifest, dir.to_path_buf())?;

        let kv = astrid_storage::ScopedKvStore::new(
            Arc::clone(&self.kv),
            format!("{load_principal}:capsule:{}", capsule.id()),
        )?;

        // Pre-load default/system env config into the KV store. Check the
        // default principal's config first, fall back to the capsule dir's
        // .env.json. (Per-principal overrides come from the per-invocation
        // overlay, not this load-time pre-load.)
        let capsule_name = capsule.id().to_string();
        let env_path = if let Ok(home) = astrid_core::dirs::AstridHome::resolve() {
            let ph = home.principal_home(&load_principal);
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
        self.verify_workspace_capsule_tree(dir)?;

        let ctx = astrid_capsule::context::CapsuleContext::new(
            load_principal,
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
        // Thread the live group config so capsule invocation checks observe
        // runtime group mutations without requiring capsule reloads. Load-time
        // run-loop decisions take their own explicit snapshot.
        .with_live_group_config(Arc::clone(&self.groups))
        // Hand this capsule its operator-approved local-egress allowlist (if
        // any) so the SSRF airlock can exempt sanctioned loopback/private
        // endpoints for it. Absent entry = empty = no exemptions.
        .with_local_egress(self.local_egress.get(&capsule_name).cloned().unwrap_or_default())
        // Hand the engine the signed per-action audit sink so sensitive
        // fs/net/process host calls (allowed, failed, OR denied) land on the
        // kernel's durable, hash-chained audit log — not just the
        // off-by-default observability tracing targets.
        .with_audit_sink(crate::audit_sink::KernelAuditSink::new(
            Arc::clone(&self.audit_log),
            self.session_id.clone(),
        ));

        capsule.load(&ctx).await?;
        Ok(capsule)
    }

    /// Restart a capsule by fully tearing down ONE distinct shared runtime and
    /// re-loading it from source for every principal that was viewing THAT hash.
    ///
    /// A content-addressed runtime is SHARED across principals (issue #1069): a
    /// failed runtime is one instance behind N principal views of the SAME hash.
    /// A restart must rebuild that ONE instance so that no view is left pointing
    /// at a dead runtime — releasing only the requesting principal's view would
    /// decrement the refcount, leave the still-failed runtime alive, and (because
    /// the hash is still loaded) merely re-attach the requester's view to the
    /// failed instance via `register_existing`.
    ///
    /// The restart is scoped to the SPECIFIC hash the requesting `principal`
    /// views. A capsule id can have TWO distinct hashes loaded at once
    /// (per-principal installs of different versions); rebuilding *every* view of
    /// the id — including a viewer pointing at a different, healthy hash — would
    /// wrongly re-home that viewer onto the restarted version. So we resolve the
    /// requester's hash, capture only the views pointing at it, tear that runtime
    /// down, then reload it from its own source and re-attach exactly those views.
    ///
    /// Returns [`RestartOutcome::Clean`] when the old runtime was fully unloaded
    /// before the fresh instance loaded, or [`RestartOutcome::OldInstanceLingering`]
    /// when a still-held `Arc` clone (e.g. a live dispatcher consumer) blocked
    /// the exclusive `unload` — the old run-loop/subprocess are cooperatively
    /// cancelled regardless (no CPU/process leak), but the health monitor must
    /// keep the restart tracker so its retry cap engages instead of thrashing a
    /// persistently-failing capsule every ~10s.
    ///
    /// # Errors
    ///
    /// Returns an error if the capsule has no source directory, cannot be
    /// unregistered, or fails to reload.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    async fn restart_capsule(
        &self,
        id: &astrid_capsule_types::CapsuleId,
        principal: &PrincipalId,
    ) -> Result<RestartOutcome, anyhow::Error> {
        // Capture the failed runtime's own source directory AND every principal
        // viewing THAT hash before we tear it down. The requesting `principal` is
        // restored first so its `handle_lifecycle_restart` fires below.
        let (source_dir, view_principals) = {
            let registry = self.capsules.read().await;
            let capsule = registry
                .get_for(principal, id)
                .ok_or_else(|| anyhow::anyhow!("capsule '{id}' not found in registry"))?;
            let hash = registry
                .hash_for(principal, id)
                .ok_or_else(|| anyhow::anyhow!("capsule '{id}' not found in registry"))?;
            let source_dir = capsule
                .source_dir()
                .map(std::path::Path::to_path_buf)
                .ok_or_else(|| anyhow::anyhow!("capsule '{id}' has no source directory"))?;
            // Requesting principal first, then the rest (dedup), so reload order
            // is deterministic and the requester's lifecycle-restart hook fires.
            // Scoped to the requester's HASH so a viewer of a different hash of
            // the same id is left untouched.
            let mut principals = vec![principal.clone()];
            for p in registry.principals_viewing_hash(id, &hash) {
                if p != *principal {
                    principals.push(p);
                }
            }
            (source_dir, principals)
        };

        // Tear the shared runtime down COMPLETELY: unregister every view so the
        // last release removes the instance and lets us unload it. Doing this for
        // all views (not just the requester's) is what makes this an actual
        // restart of the shared runtime rather than a no-op view re-attach.
        let mut torn_down_runtime: Option<std::sync::Arc<dyn astrid_capsule::capsule::Capsule>> =
            None;
        {
            let mut registry = self.capsules.write().await;
            for p in &view_principals {
                match registry.unregister_for(p, id) {
                    Ok(removed) => {
                        if removed.torn_down {
                            torn_down_runtime = Some(removed.capsule);
                        }
                    },
                    Err(astrid_capsule_types::error::CapsuleError::NotFound(_)) => {
                        // A concurrent unload already released this view; fine.
                    },
                    Err(e) => {
                        return Err(anyhow::anyhow!(
                            "failed to unregister capsule '{id}' view for '{p}': {e}"
                        ));
                    },
                }
            }
        }

        // Explicitly unload the torn-down runtime (there is no async Drop, so we
        // must do it here to avoid leaking MCP subprocesses and engine
        // resources). `Arc::get_mut` requires exclusive ownership.
        //
        // A restart with NO torn-down runtime (a concurrent unload already
        // released it) is Clean by definition — there is no old instance left
        // to leak.
        let mut outcome = RestartOutcome::Clean;
        if let Some(mut old) = torn_down_runtime {
            // Cooperatively stop the old instance FIRST, without needing
            // exclusive ownership. `request_cancel` cancels the instance
            // cancel-token, which (a) unblocks in-flight blocking host calls so
            // their dispatcher-task `Arc` clones drop, (b) stops the run-loop
            // task — its `select!` on the same token preempts even a compute-
            // bound guest now that exempt run-loops cooperatively yield every
            // epoch window (Fix 5) — and (c) wakes the host-process reaper,
            // which reaps subprocesses. So the old run-loop/subprocess are gone
            // even when the exclusive `unload` below cannot run.
            old.request_cancel();
            let mut unloaded = false;
            for retry in 0..20_u32 {
                if let Some(capsule) = std::sync::Arc::get_mut(&mut old) {
                    if let Err(e) = capsule.unload().await {
                        tracing::warn!(
                            capsule_id = %id,
                            error = %e,
                            "Capsule unload failed during restart"
                        );
                    }
                    unloaded = true;
                    break;
                }
                if retry < 19 {
                    astrid_runtime::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
            if !unloaded {
                // Exclusive unload was blocked by a still-held `Arc` clone. The
                // run-loop/subprocess were already cooperatively cancelled
                // above, so this is not a CPU/process leak — the engine's
                // epoch-ticker/pool memory is reclaimed when the last clone
                // (e.g. an idle-evicting dispatcher consumer) drops. But the
                // restart is NOT clean: report it so the health monitor keeps
                // the retry tracker and its cap engages, instead of a
                // persistently-failing capsule thrashing a fresh reload every
                // ~10s forever.
                outcome = RestartOutcome::OldInstanceLingering;
                tracing::warn!(
                    capsule_id = %id,
                    strong_count = std::sync::Arc::strong_count(&old),
                    "Old capsule instance not exclusively unloaded during restart \
                     (Arc still held); run-loop/subprocess were cancelled, memory \
                     reclaims when the last clone drops. Restart tracker retained."
                );
            }
        }

        // Rebuild the shared runtime and re-attach every captured view. The first
        // `load_capsule` builds the fresh runtime (owned by `default`); the rest
        // attach their views over it (same content hash → shared instance).
        for p in &view_principals {
            self.load_capsule(source_dir.clone(), p).await?;
        }

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
            registry.get_for(principal, id)
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

        Ok(outcome)
    }

    /// Auto-discover and load the default principal's boot-critical view.
    ///
    /// Daemon readiness depends on the default view because it owns system
    /// service capsules such as the CLI proxy. Other profile principals are
    /// warmed after boot so persisted tenant state cannot make restart
    /// health depend on loading every agent's tool set.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub async fn load_boot_capsules(&self) {
        self.load_default_capsule_view().await;
        self.publish_capsules_loaded().await;
    }

    /// Schedule background warm-up for known non-default profile principals.
    ///
    /// The actual load work is serialized by
    /// [`Kernel::capsule_load_lock`], so this can run behind a ready daemon
    /// without racing other admin-driven warm/reload paths.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub fn schedule_profile_principal_warm(self: &Arc<Self>) {
        let kernel = Arc::clone(self);
        astrid_runtime::spawn(async move {
            let principals: Vec<_> = kernel
                .enumerate_profile_principals()
                .into_iter()
                .filter(|principal| *principal != PrincipalId::default())
                .collect();

            for principal in &principals {
                kernel.ensure_principal_uplinks_loaded(principal).await;
                kernel.publish_capsules_loaded().await;
            }

            for principal in principals {
                if principal != PrincipalId::default() {
                    kernel.ensure_principal_loaded(&principal).await;
                    kernel.publish_capsules_loaded().await;
                }
            }
        });
    }

    /// Auto-discover and load capsule views for known principals.
    ///
    /// The default principal is loaded eagerly, then every principal with a
    /// profile on disk gets its own view. Content-identical capsules reuse the
    /// same installed artifact on disk, but loaded runtime instances remain
    /// principal-scoped; default's capsule set is never copied into another
    /// principal's view.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub async fn load_all_capsules(&self) {
        self.load_default_capsule_view().await;
        for principal in self.enumerate_profile_principals() {
            if principal != PrincipalId::default() {
                self.ensure_principal_loaded(&principal).await;
            }
        }

        // Signal that all capsules have been loaded so uplink capsules
        // (like the registry) can proceed with discovery instead of
        // polling with arbitrary timeouts.
        self.publish_capsules_loaded().await;
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    async fn load_default_capsule_view(&self) {
        self.ensure_principal_loaded(&PrincipalId::default()).await;

        // Warn loudly if the loaded set can't actually serve an agent chat
        // turn. Computed from the live registry *after* load completes (not the
        // pre-load discovered set) so a manifest that failed to load is not
        // mistaken for a working capability. Without this a fresh daemon
        // (socket uplink only) boots clean yet silently drops every prompt —
        // name-agnostic introspection turns that into one actionable warning.
        {
            let reg = self.capsules.read().await;
            let loaded: Vec<&astrid_capsule_types::manifest::CapsuleManifest> = reg
                .values()
                .map(astrid_capsule::capsule::Capsule::manifest)
                .collect();
            warn_agent_loop_readiness(&loaded);
        }
    }

    /// Build or refresh one principal's capsule view from its own install set.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub async fn ensure_principal_loaded(&self, principal: &PrincipalId) {
        let _load_guard = self.capsule_load_lock.lock().await;
        let sorted = self.sorted_principal_capsules(principal);
        validate_principal_capsules(principal, &sorted);

        let (uplinks, others): (Vec<_>, Vec<_>) =
            sorted.into_iter().partition(|(m, _)| m.capabilities.uplink);
        let uplink_names: Vec<String> = uplinks
            .iter()
            .map(|(m, _)| m.package.name.clone())
            .collect();
        for (manifest, dir) in &uplinks {
            if let Err(e) = self.load_capsule(dir.clone(), principal).await {
                tracing::warn!(
                    %principal,
                    capsule = %manifest.package.name,
                    error = %e,
                    "Failed to load uplink capsule during discovery"
                );
            }
        }
        self.await_capsule_readiness_for(principal, &uplink_names)
            .await;

        for (manifest, dir) in &others {
            if let Err(e) = self.load_capsule(dir.clone(), principal).await {
                tracing::warn!(
                    %principal,
                    capsule = %manifest.package.name,
                    error = %e,
                    "Failed to load capsule during discovery"
                );
            }
        }
        let other_names: Vec<String> = others.iter().map(|(m, _)| m.package.name.clone()).collect();
        self.await_capsule_readiness_for(principal, &other_names)
            .await;
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    async fn ensure_principal_uplinks_loaded(&self, principal: &PrincipalId) {
        let _load_guard = self.capsule_load_lock.lock().await;
        let sorted = self.sorted_principal_capsules(principal);
        validate_principal_capsules(principal, &sorted);

        let uplinks: Vec<_> = sorted
            .into_iter()
            .filter(|(manifest, _)| manifest.capabilities.uplink)
            .collect();
        let uplink_names: Vec<String> = uplinks
            .iter()
            .map(|(manifest, _)| manifest.package.name.clone())
            .collect();
        for (manifest, dir) in &uplinks {
            if let Err(e) = self.load_capsule(dir.clone(), principal).await {
                tracing::warn!(
                    %principal,
                    capsule = %manifest.package.name,
                    error = %e,
                    "Failed to load uplink capsule during background warm"
                );
            }
        }
        self.await_capsule_readiness_for(principal, &uplink_names)
            .await;
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    fn sorted_principal_capsules(
        &self,
        principal: &PrincipalId,
    ) -> Vec<(astrid_capsule_types::manifest::CapsuleManifest, PathBuf)> {
        use astrid_capsule::toposort::toposort_manifests;

        let paths = capsule_discovery_paths_for(
            &self.astrid_home,
            &self.workspace_root,
            principal,
            &self.workspace_layout,
        );
        let discovered = astrid_capsule::discovery::discover_manifests_in_workspace(
            Some(&paths),
            Some(&self.workspace_root),
            &self.workspace_layout,
        );
        match toposort_manifests(discovered) {
            Ok(sorted) => sorted,
            Err((e, original)) => {
                tracing::error!(
                    %principal,
                    cycle = %e,
                    "Dependency cycle in capsules, falling back to discovery order"
                );
                original
            },
        }
    }

    fn enumerate_profile_principals(&self) -> Vec<PrincipalId> {
        let profiles_dir = self.astrid_home.profiles_dir();
        let Ok(entries) = std::fs::read_dir(profiles_dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|entry| {
                if !entry.file_type().is_ok_and(|ty| ty.is_file()) {
                    return None;
                }
                let name = entry.file_name();
                let stem = name.to_str()?.strip_suffix(".toml")?;
                PrincipalId::new(stem).ok()
            })
            .collect()
    }

    /// Build an in-process agent-loop readiness probe over the live registry.
    ///
    /// Handed to the co-located gateway so its prompt fail-fast can ask whether
    /// the loaded set can serve a chat turn directly — agent-loop serviceability
    /// is global daemon health, not per-principal authorization, so it needs no
    /// capability check and no socket round-trip (unlike the capability-gated
    /// `GetAgentReadiness` request, which exists for the detailed, ops-facing
    /// `/api/sys/readiness` view and `astrid doctor`). The closure clones the
    /// registry `Arc`, so each call reflects the current loaded set.
    #[must_use]
    pub fn agent_readiness_probe(&self) -> astrid_core::kernel_api::AgentReadinessProbe {
        let registry = Arc::clone(&self.capsules);
        astrid_core::kernel_api::AgentReadinessProbe::new(move || {
            let registry = Arc::clone(&registry);
            Box::pin(async move {
                let reg = registry.read().await;
                let manifests: Vec<&astrid_capsule_types::manifest::CapsuleManifest> = reg
                    .values()
                    .map(astrid_capsule::capsule::Capsule::manifest)
                    .collect();
                astrid_capsule::readiness::agent_loop_readiness(&manifests)
            })
        })
    }

    /// Evaluate one capability against the current principal and device policy.
    #[doc(hidden)]
    #[must_use]
    pub fn runtime_capability_allows(
        &self,
        principal: &PrincipalId,
        device_key_id: Option<&str>,
        capability: &str,
    ) -> bool {
        let Ok(profile) = self.profile_cache.resolve(principal) else {
            return false;
        };
        if !profile.enabled {
            return false;
        }

        let device_scope = match device_key_id {
            Some(key_id) => {
                let Ok(key_id) = astrid_core::profile::DeviceKeyId::new(key_id) else {
                    return false;
                };
                let Some(device) = profile.auth.device_by_typed_key_id(&key_id) else {
                    return false;
                };
                Some(&device.scope)
            },
            None => None,
        };

        let groups = self.groups.load_full();
        let mut check = astrid_capabilities::CapabilityCheck::new_borrowed(
            profile.as_ref(),
            groups.as_ref(),
            principal,
        );
        if let Some(scope) = device_scope {
            check = check.with_device_scope(scope);
        }
        check.has(capability)
    }

    /// In-process probe for "does a loaded capsule subscribe to this topic",
    /// computed from the live registry without a capability check. Mirrors
    /// [`Self::agent_readiness_probe`]; the co-located gateway uses it to
    /// gracefully degrade a route whose backing verb a pre-upgrade capsule
    /// may not handle (e.g. answer `501` instead of waiting out a bus timeout),
    /// and lets routes wait for a caller's async-warmed capsule view without
    /// going through capability-gated inventory APIs.
    #[must_use]
    pub fn capsule_topic_probe(&self) -> astrid_core::kernel_api::CapsuleTopicProbe {
        let passive_registry = Arc::clone(&self.capsules);
        let ensure_registry = Arc::clone(&self.capsules);
        let source_registry = Arc::clone(&self.capsules);
        astrid_core::kernel_api::CapsuleTopicProbe::new_with_ensure_and_sources(
            move |topic: String| {
                let registry = Arc::clone(&passive_registry);
                Box::pin(async move { Self::topic_has_subscriber(registry, topic).await })
            },
            move |topic: String| {
                let registry = Arc::clone(&ensure_registry);
                Box::pin(async move { Self::topic_has_subscriber(registry, topic).await })
            },
            move |topic: String| {
                let registry = Arc::clone(&source_registry);
                Box::pin(async move { Self::topic_subscriber_source_ids(registry, topic).await })
            },
        )
    }

    /// Build a topic probe that can actively warm the caller's uplink capsules
    /// before answering a scoped readiness read.
    ///
    /// The daemon-spawned gateway uses this for registry-backed model routes:
    /// after restart, the route must not publish request IPC until the caller's
    /// registry subscription exists. The plain [`Self::capsule_topic_probe`]
    /// remains passive for compatibility with existing callers.
    #[must_use]
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub fn capsule_topic_probe_with_warm(
        self: &Arc<Self>,
    ) -> astrid_core::kernel_api::CapsuleTopicProbe {
        let passive = self.capsule_topic_probe();
        let passive_read = passive.clone();
        let passive_sources = passive.clone();
        let warm_kernel = Arc::clone(self);
        astrid_core::kernel_api::CapsuleTopicProbe::new_with_ensure_and_sources(
            move |topic: String| {
                let passive = passive_read.clone();
                Box::pin(async move { passive.is_subscribed(&topic).await })
            },
            move |topic: String| {
                let kernel = Arc::clone(&warm_kernel);
                Box::pin(async move {
                    if let Some(principal) = Self::scoped_probe_principal(&topic) {
                        kernel.ensure_principal_uplinks_loaded(&principal).await;
                        kernel.publish_capsules_loaded().await;
                        if Self::topic_has_subscriber(Arc::clone(&kernel.capsules), topic.clone())
                            .await
                        {
                            return true;
                        }
                        kernel.ensure_principal_loaded(&principal).await;
                        kernel.publish_capsules_loaded().await;
                    }
                    Self::topic_has_subscriber(Arc::clone(&kernel.capsules), topic).await
                })
            },
            move |topic: String| {
                let passive = passive_sources.clone();
                Box::pin(async move { passive.subscriber_source_ids(&topic).await })
            },
        )
    }

    async fn topic_has_subscriber(registry: Arc<RwLock<CapsuleRegistry>>, topic: String) -> bool {
        if let Some((principal, namespace, interface, requirement, scoped_topic)) =
            Self::split_scoped_service_probe_key(&topic)
        {
            let reg = registry.read().await;
            let mut providers = reg
                .cloned_values_for(&principal)
                .into_iter()
                .filter(|capsule| {
                    Self::capsule_provides_service(
                        capsule.manifest(),
                        &namespace,
                        &interface,
                        &requirement,
                        &scoped_topic,
                    )
                });
            return providers.next().is_some() && providers.next().is_none();
        }
        if let Some((principal, capsule_id, scoped_topic)) =
            Self::split_scoped_topic_probe_key(&topic)
        {
            let reg = registry.read().await;
            if let Some(capsule_id) = capsule_id {
                return reg.get_for(&principal, &capsule_id).is_some_and(|capsule| {
                    astrid_capsule::readiness::manifest_subscribes_topic(
                        capsule.manifest(),
                        &scoped_topic,
                    )
                });
            }
            return reg.cloned_values_for(&principal).iter().any(|capsule| {
                astrid_capsule::readiness::manifest_subscribes_topic(
                    capsule.manifest(),
                    &scoped_topic,
                )
            });
        }

        let reg = registry.read().await;
        // Short-circuit on the first loaded capsule that subscribes the
        // topic — no need to materialise the manifest list or the full
        // subscriber set just to answer a boolean.
        reg.values().any(|c| {
            astrid_capsule::readiness::manifest_subscribes_topic(
                astrid_capsule::capsule::Capsule::manifest(c),
                &topic,
            )
        })
    }

    async fn topic_subscriber_source_ids(
        registry: Arc<RwLock<CapsuleRegistry>>,
        topic: String,
    ) -> Vec<uuid::Uuid> {
        if let Some((principal, namespace, interface, requirement, scoped_topic)) =
            Self::split_scoped_service_probe_key(&topic)
        {
            let reg = registry.read().await;
            let providers: Vec<_> = reg
                .cloned_values_for(&principal)
                .into_iter()
                .filter(|capsule| {
                    Self::capsule_provides_service(
                        capsule.manifest(),
                        &namespace,
                        &interface,
                        &requirement,
                        &scoped_topic,
                    )
                })
                .collect();
            if providers.len() != 1 {
                return Vec::new();
            }
            return providers
                .first()
                .and_then(|capsule| reg.source_id_for(&principal, capsule.id()))
                .into_iter()
                .collect();
        }
        let (principal, capsule_id, topic) = Self::split_scoped_topic_probe_key(&topic)
            .unwrap_or_else(|| (PrincipalId::default(), None, topic));
        let reg = registry.read().await;
        let capsules = match capsule_id {
            Some(capsule_id) => reg.get_for(&principal, &capsule_id).into_iter().collect(),
            None => reg.cloned_values_for(&principal),
        };
        let mut source_ids: Vec<uuid::Uuid> = capsules
            .into_iter()
            .filter(|capsule| {
                astrid_capsule::readiness::manifest_subscribes_topic(capsule.manifest(), &topic)
            })
            .filter_map(|capsule| reg.source_id_for(&principal, capsule.id()))
            .collect();
        source_ids.sort_unstable();
        source_ids.dedup();
        source_ids
    }

    fn capsule_provides_service(
        manifest: &astrid_capsule_types::manifest::CapsuleManifest,
        namespace: &str,
        interface: &str,
        requirement: &semver::VersionReq,
        topic: &str,
    ) -> bool {
        manifest
            .exports
            .get(namespace)
            .and_then(|interfaces| interfaces.get(interface))
            .is_some_and(|export| requirement.matches(&export.version))
            && astrid_capsule::readiness::manifest_subscribes_topic(manifest, topic)
    }

    fn scoped_probe_principal(raw: &str) -> Option<PrincipalId> {
        Self::split_scoped_service_probe_key(raw)
            .map(|(principal, _, _, _, _)| principal)
            .or_else(|| Self::split_scoped_topic_probe_key(raw).map(|(principal, _, _)| principal))
    }

    fn split_scoped_service_probe_key(
        raw: &str,
    ) -> Option<(PrincipalId, String, String, semver::VersionReq, String)> {
        let rest = raw.strip_prefix(SCOPED_SERVICE_PROBE_SENTINEL)?;
        let mut parts = rest.splitn(5, '\0');
        let principal = PrincipalId::new(parts.next()?).ok()?;
        let namespace = parts.next()?;
        let interface = parts.next()?;
        let requirement = semver::VersionReq::parse(parts.next()?).ok()?;
        let topic = parts.next()?;
        if namespace.is_empty() || interface.is_empty() || topic.is_empty() {
            return None;
        }
        Some((
            principal,
            namespace.to_string(),
            interface.to_string(),
            requirement,
            topic.to_string(),
        ))
    }

    fn split_scoped_topic_probe_key(raw: &str) -> Option<(PrincipalId, Option<CapsuleId>, String)> {
        let rest = raw.strip_prefix(SCOPED_TOPIC_PROBE_SENTINEL)?;
        let mut parts = rest.splitn(3, '\0');
        let principal = parts.next()?;
        let second = parts.next()?;
        let third = parts.next();
        let principal = PrincipalId::new(principal).ok()?;
        match third {
            Some(topic) => {
                let capsule_id = CapsuleId::new(second).ok()?;
                Some((principal, Some(capsule_id), topic.to_string()))
            },
            None => Some((principal, None, second.to_string())),
        }
    }

    /// Publish `astrid.v1.capsules_loaded` so subscribers re-read the current
    /// capsule/tool set after the loaded set changes — the registry, and the
    /// `astrid mcp serve` shim, which turns this into an MCP
    /// `notifications/tools/list_changed` for connected clients.
    ///
    /// The payload carries, per loaded capsule, its installed `meta.json` under
    /// `capsules[].meta` with the capsule's tool surface injected. The kernel
    /// probes each loaded capsule once — invoking its `tool_describe`
    /// interceptor (the same hook the dispatcher already routes) and injecting
    /// the captured descriptors — so a consumer (e.g. the sage-mcp broker) gets
    /// a deterministic, complete tool surface from this signal **without the
    /// capsule having been rebuilt**. The kernel invokes-and-forwards: it never
    /// interprets the descriptors (the broker owns all policy). A describe
    /// failure leaves `tools` absent for that capsule this cycle (the consumer
    /// falls back to its fan-out). The legacy `status: "ready"` field is
    /// retained so bare-signal subscribers (the shim, the TUI) keep working; the
    /// `capsules` field is additive. The signal is emitted once per principal
    /// and bus-stamped with that principal so socket consumers only receive
    /// their own inventory view.
    pub(crate) async fn publish_capsules_loaded(&self) {
        // Clone the loaded-capsule handles under a brief read lock, then release
        // it before any filesystem I/O or `tool_describe` invocation (which can
        // `block_in_place` and must never run while holding the registry lock).
        let capsules = {
            let reg = self.capsules.read().await;
            reg.cloned_values_with_principal()
        };

        let mut by_principal = std::collections::BTreeMap::<
            String,
            Vec<(String, String, Option<serde_json::Value>)>,
        >::new();
        for (principal, capsule) in &capsules {
            let principal = principal.to_string();
            let name = capsule.id().to_string();
            let mut meta = capsule.source_dir().and_then(|source_dir| {
                self.verify_workspace_capsule_tree(source_dir).ok()?;
                let meta = capsules_loaded::read_capsule_meta_opaque(source_dir);
                self.verify_workspace_capsule_tree(source_dir).ok()?;
                meta
            });

            // Probe the live instance for its tool surface and inject it. Best-
            // effort: a describe (or serialize) failure leaves `tools` absent
            // and the consumer falls back to its fan-out for this cycle.
            match astrid_capsule::describe_loaded_capsule(capsule.as_ref()).await {
                Ok(tools) => {
                    // A tool advertises straight from its `#[astrid::tool]`
                    // annotation, but only EXECUTES if the manifest `[subscribe]`s
                    // its `tool.v1.execute.<name>` topic (the dispatcher routes
                    // solely from `[subscribe]` handlers). When they drift the tool
                    // appears in tools/list yet silently never runs — no dispatch,
                    // no capsule log, no error. Surface that at load, naming the
                    // exact missing line, so authors don't lose hours to it.
                    // Skip the manifest lookup entirely for a capsule with no
                    // tools (most non-tool capsules) — nothing to cross-check.
                    if !tools.is_empty() {
                        let interceptors = capsule.manifest().effective_interceptors();
                        for tool in
                            astrid_capsule::tools_missing_execute_route(&tools, &interceptors)
                        {
                            tracing::warn!(
                                capsule_id = %name,
                                "capsule advertises tool '{tool}' but no `tool.v1.execute.{tool}` \
                                 subscription routes it — it appears in tools/list but will never \
                                 execute. Add to Capsule.toml: [subscribe] \
                                 \"tool.v1.execute.{tool}\" = {{ wit = \
                                 \"@unicity-astrid/wit/types/tool-call\", handler = \
                                 \"tool_execute_{tool}\" }}"
                            );
                        }
                    }
                    match serde_json::to_value(&tools) {
                        Ok(tools_json) => {
                            meta = Some(capsules_loaded::inject_tools(meta, tools_json));
                        },
                        Err(e) => tracing::debug!(
                            capsule_id = %name, error = %e,
                            "failed to serialize live-described tools; capsule left uncaptured this cycle"
                        ),
                    }
                },
                Err(e) => tracing::debug!(
                    capsule_id = %name, error = %e,
                    "live tool_describe failed; capsule left uncaptured this cycle"
                ),
            }
            by_principal
                .entry(principal.clone())
                .or_default()
                .push((principal, name, meta));
        }
        if by_principal.is_empty() {
            by_principal.insert(PrincipalId::default().to_string(), Vec::new());
        }

        for (principal, entries) in by_principal {
            let payload = capsules_loaded::build_capsules_loaded_payload(entries);

            let msg = astrid_events::ipc::IpcMessage::new(
                astrid_events::ipc::Topic::from_raw("astrid.v1.capsules_loaded"),
                astrid_events::ipc::IpcPayload::RawJson(payload),
                self.session_id.0,
            )
            .with_principal(principal);
            let _ = self.event_bus.publish(astrid_events::AstridEvent::Ipc {
                metadata: astrid_events::EventMetadata::new("kernel"),
                message: msg,
            });
        }
    }

    /// Reload a single capsule by id without a daemon restart.
    ///
    /// If the capsule is already registered, [`Self::restart_capsule`] re-reads
    /// its source directory — picking up the new content-addressed bytes a
    /// reinstall wrote (a live upgrade / hot-swap). If it isn't registered yet,
    /// the currently-installed set is discovered and loaded (a fresh add;
    /// already-loaded capsules are skipped by `load_capsule`'s guard). Either
    /// way `astrid.v1.capsules_loaded` is published so the tool surface
    /// refreshes. Backs [`astrid_core::kernel_api::KernelRequest::ReloadCapsule`].
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(crate) async fn reload_one_capsule(
        &self,
        id: &astrid_capsule_types::CapsuleId,
        principal: &PrincipalId,
    ) -> Result<(), anyhow::Error> {
        let registered = { self.capsules.read().await.get_for(principal, id).is_some() };
        if registered {
            self.restart_capsule(id, principal).await?;
            self.publish_capsules_loaded().await;
        } else {
            // Build or refresh this principal's view from its installed set.
            self.ensure_principal_loaded(principal).await;
            if self.capsules.read().await.get_for(principal, id).is_none() {
                return Err(anyhow::anyhow!(
                    "capsule '{id}' was not found in the install directories or failed to load"
                ));
            }
            self.publish_capsules_loaded().await;
        }
        Ok(())
    }

    /// Unload a single capsule by id without a daemon restart.
    ///
    /// Mirrors the unregister half of [`Self::restart_capsule`]: it removes the
    /// capsule from the running registry and explicitly unloads it (there is no
    /// async `Drop`, so we must do it here to avoid leaking MCP subprocesses and
    /// other engine resources), then publishes `astrid.v1.capsules_loaded` so the
    /// tool surface refreshes — the departed capsule self-excludes from the next
    /// fan-out. Backs [`astrid_core::kernel_api::KernelRequest::UnloadCapsule`].
    ///
    /// Returns `Ok(true)` if the capsule was loaded and is now unregistered, or
    /// `Ok(false)` if it was not loaded (a no-op — nothing to unload, no signal
    /// published). The on-disk removal that precedes this call is authoritative;
    /// a capsule absent from the running registry is not an error here.
    ///
    /// # Errors
    ///
    /// Returns an error only if the registry fails to unregister a capsule it
    /// reported as present.
    pub(crate) async fn unload_one_capsule(
        &self,
        id: &astrid_capsule_types::CapsuleId,
        principal: &PrincipalId,
    ) -> Result<bool, anyhow::Error> {
        // Unregister only this principal's view. The runtime is shared by
        // content hash across principals; `unregister_for` decrements the
        // refcount and reports whether this was the last view. The runtime is
        // cancelled/unloaded ONLY on the last release — tearing it down while
        // other principals still reference the shared instance would break them.
        let removed = {
            let mut registry = self.capsules.write().await;
            match registry.unregister_for(principal, id) {
                Ok(removed) => removed,
                Err(astrid_capsule_types::error::CapsuleError::NotFound(_)) => return Ok(false),
                Err(e) => {
                    return Err(anyhow::anyhow!("failed to unregister capsule '{id}': {e}"));
                },
            }
        };

        // Explicitly unload the old capsule only when this was the last view.
        // There is no Drop impl that calls unload() (it's async), so we must do
        // it here to avoid leaking MCP subprocesses and other engine resources.
        // Arc::get_mut requires exclusive ownership (strong_count == 1).
        if removed.torn_down {
            let mut old = removed.capsule;
            old.request_cancel();
            let mut unloaded = false;
            for retry in 0..20_u32 {
                if let Some(capsule) = std::sync::Arc::get_mut(&mut old) {
                    if let Err(e) = capsule.unload().await {
                        tracing::warn!(
                            capsule_id = %id,
                            error = %e,
                            "Capsule unload failed during unload request"
                        );
                    }
                    unloaded = true;
                    break;
                }
                if retry < 19 {
                    astrid_runtime::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
            if !unloaded {
                tracing::warn!(
                    capsule_id = %id,
                    strong_count = std::sync::Arc::strong_count(&old),
                    "Cannot call unload - Arc still held by in-flight task"
                );
            }
        } else {
            // The shared runtime survives — but the DEPARTING principal's
            // in-flight blocking host calls (approval/elicit waits, net/io/ipc
            // waits) would otherwise keep running inside it with nothing left
            // to answer them, wedging the shared instance for every remaining
            // principal. Cancel exactly that principal's waits; everyone
            // else's work is untouched (per-principal child tokens, not the
            // instance-wide `request_cancel`).
            //
            // Accepted race: an invocation dispatched before the unregister
            // above but installing its per-principal context after this cancel
            // mints a fresh token and survives until its own timeout. New
            // invocations cannot dispatch (the view is gone), so the window is
            // bounded; closing it would take cross-component locking between
            // the registry and every engine, which is not worth it.
            removed.capsule.request_cancel_for(principal);
            tracing::debug!(
                capsule_id = %id,
                principal = %principal,
                "Unloaded one view of a shared runtime; other principals still \
                 reference it, so the runtime is left running and only the \
                 departing principal's in-flight host calls were cancelled"
            );
        }

        self.publish_capsules_loaded().await;
        Ok(true)
    }

    /// Promote (`commit == true`) or roll back (`commit == false`) a capsule's
    /// OS-level copy-on-write workspace changes — the gate's approve/reject for
    /// a non-git workspace (Fix #2).
    ///
    /// Returns `Ok(None)` if the capsule is not loaded in `principal`'s view;
    /// `Ok(Some(true))` if a copy-on-write workspace was committed/rolled back;
    /// `Ok(Some(false))` if the capsule has no copy-on-write workspace
    /// (git-managed or No-CoW — nothing to do).
    pub(crate) async fn commit_workspace_for(
        &self,
        id: &astrid_capsule_types::CapsuleId,
        principal: &PrincipalId,
        commit: bool,
    ) -> Result<Option<bool>, anyhow::Error> {
        let capsule = { self.capsules.read().await.get_for(principal, id) };
        let Some(capsule) = capsule else {
            return Ok(None);
        };
        let outcome = if commit {
            capsule.promote_workspace().await
        } else {
            capsule.rollback_workspace().await
        };
        outcome
            .map(Some)
            .map_err(|e| anyhow::anyhow!("workspace commit for capsule '{id}' failed: {e}"))
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

        // 2. Release the persistent-store locks FIRST — BEFORE the best-effort
        // capsule drain. The audit/KV surrealkv `LOCK` MUST be freed on the
        // graceful path regardless of how long the drain takes: each capsule's
        // unload is bounded (~1s of `Arc::get_mut` retries) but a large fleet
        // draining sequentially could exceed the OS-thread watchdog's force-exit
        // grace, and a force-exit with the audit `LOCK` still held is the exact
        // wedge this whole change closes. Nothing in the drain below reads
        // KV/audit (WASM unload = cancel/abort/drop; MCP unload = subprocess
        // disconnect), and `clear_session()` above was the last KV writer, so
        // closing the stores ahead of the drain is safe and makes the lock
        // release independent of drain time.
        if let Err(e) = self.kv.close().await {
            tracing::warn!(error = %e, "Failed to flush KV store during shutdown");
        }
        // Closes through the shared `Arc<AuditLog>` (no `&mut` needed). Without
        // this the audit lock outlived a terminating daemon — why a wedge forced
        // a `SIGKILL`, which then raced the next boot on the still-held lock.
        if let Err(e) = self.audit_log.close().await {
            tracing::warn!(error = %e, "Failed to close audit log during shutdown");
        }

        // 3. Drain the registry so the dispatcher cannot hand out new Arc clones,
        // then unload each capsule CONCURRENTLY. MCP engine unload is critical —
        // it calls `mcp_client.disconnect()` to gracefully terminate child
        // processes; without explicit unload they orphan. `drain()` returns one
        // Arc per DISTINCT runtime (views are cleared first), so no two unload
        // tasks contend on the same runtime's `Arc::get_mut`. Concurrency bounds
        // the whole drain to ~one retry budget instead of N×, keeping the
        // graceful path well under the watchdog grace so even a large fleet's
        // subprocesses are actually disconnected rather than force-exited
        // mid-drain (which would re-introduce the orphan class).
        //
        // The `EventDispatcher` temporarily clones `Arc<dyn Capsule>` into
        // spawned interceptor tasks. After draining, no new clones can be
        // created, but in-flight tasks may still hold one; each unload task
        // `request_cancel`s to unblock them, then retries `Arc::get_mut` with
        // brief yields.
        let capsules = {
            let mut reg = self.capsules.write().await;
            reg.drain()
        };
        let mut drain_set = tokio::task::JoinSet::new();
        for mut arc in capsules {
            drain_set.spawn(async move {
                let id = arc.id().clone();
                let mut unloaded = false;

                arc.request_cancel();
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
                        astrid_runtime::time::sleep(std::time::Duration::from_millis(50)).await;
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
            });
        }
        // Await every unload task. A task that panicked or was cancelled would
        // otherwise be swallowed silently, leaving its capsule un-unloaded (and
        // its MCP subprocess possibly orphaned) with no diagnostic — so log the
        // join failure. Shutdown still proceeds: a stuck unload must not block
        // the graceful path (the OS-thread watchdog is the hard backstop).
        while let Some(res) = drain_set.join_next().await {
            if let Err(err) = res {
                if err.is_panic() {
                    tracing::error!("A capsule unload task panicked during shutdown");
                } else {
                    tracing::error!(error = %err, "A capsule unload task failed to join during shutdown");
                }
            }
        }

        // 4. Remove the socket and token files so stale-socket detection works
        // on next boot and the auth token doesn't persist on disk after shutdown.
        // This runs AFTER the capsule drain, which is the correct order: MCP
        // child processes communicate via stdio pipes (not this Unix socket), so
        // they are already terminated by step 3. The socket is only used for
        // CLI-to-kernel IPC. Unix-only: the `socket` module (and the on-disk
        // socket/PID/readiness files it manages) exist only on that profile.
        #[cfg(unix)]
        {
            let socket_path = crate::socket::kernel_socket_path();
            let _ = std::fs::remove_file(&socket_path);
            let _ = std::fs::remove_file(&self.token_path);
            crate::socket::remove_readiness_file();
            crate::socket::remove_pid_file();
        }

        tracing::info!("Kernel shutdown complete");
    }

    /// Wait for a set of capsules to signal readiness, in parallel.
    ///
    /// Collects `Arc<dyn Capsule>` handles under a short-lived read lock,
    /// then drops the lock before awaiting. Capsules without a run loop
    /// return `Ready` immediately and don't contribute to wait time.
    async fn await_capsule_readiness_for(&self, principal: &PrincipalId, names: &[String]) {
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
                    |name| match astrid_capsule_types::CapsuleId::new(name.clone()) {
                        Ok(capsule_id) => registry
                            .get_for(principal, &capsule_id)
                            .map(|c| (name.clone(), c)),
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

async fn unload_loaded_capsule_after_source_disappeared(
    mut capsule: Box<dyn astrid_capsule::capsule::Capsule>,
    id: &astrid_capsule_types::CapsuleId,
    principal: &PrincipalId,
    manifest_path: &Path,
) {
    capsule.request_cancel();
    if let Err(e) = capsule.unload().await {
        tracing::warn!(
            capsule_id = %id,
            principal = %principal,
            path = %manifest_path.display(),
            error = %e,
            "Capsule unload failed after source disappeared before registration"
        );
    }
    tracing::warn!(
        capsule_id = %id,
        principal = %principal,
        path = %manifest_path.display(),
        "Skipping capsule registration because the source disappeared during load"
    );
}

/// Test-only lightweight constructor (issue #672) that builds a
/// [`Kernel`] with just the fields the admin handlers touch:
/// `event_bus`, `session_id`, `audit_log`, `profile_cache`,
/// `identity_store`, `groups`, `astrid_home`, `admin_write_lock`, plus
/// the shared allowance / capability / kv store handles. Skips the
/// heavy boot bits (socket bind, MCP init, token generation, capsule
/// discovery) that aren't load-bearing for admin-topic tests.
///
/// It deliberately does **not** route through [`Kernel::with_resources`]: that
/// path asserts a multi-threaded tokio runtime (it wires the `block_in_place`
/// dispatcher and the full monitor set), whereas these admin-topic tests run on
/// the default current-thread `#[tokio::test]` runtime and only need the admin
/// router. It fakes the native bits directly (`None` socket listener + lock).
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
    let kv: Arc<dyn astrid_storage::KvStore> = Arc::new(
        astrid_storage::SurrealKvStore::open(home.state_db_path()).expect("test kernel: open kv"),
    );
    let capabilities = Arc::new(
        CapabilityStore::with_kv_store(Arc::clone(&kv))
            .await
            .expect("test kernel: capability store"),
    );

    // Audit log at the tempdir — chain verification is trivially Ok on a
    // fresh log, no historical entries.
    let runtime_key =
        Arc::new(load_or_generate_runtime_key(&home.keys_dir()).expect("test kernel: runtime key"));
    let default_principal = astrid_core::PrincipalId::default();
    let principal_home = home.principal_home(&default_principal);
    principal_home
        .ensure()
        .expect("test kernel: ensure principal home");
    let audit_log = Arc::new(
        AuditLog::open(principal_home.audit_dir(), Arc::clone(&runtime_key))
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
    let identity_kv = astrid_storage::ScopedKvStore::new(Arc::clone(&kv), "system:identity")
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
        workspace_layout: WorkspaceLayout::default(),
        workspace_selection: WorkspaceLayout::default()
            .resolve(home.root())
            .expect("test workspace selection"),
        home_root: Some(principal_home.root().to_path_buf()),
        cli_socket_listener: None,
        singleton_lock: None,
        kv,
        audit_log,
        runtime_key,
        active_connections: DashMap::new(),
        fuel_ledger: astrid_capsule_types::FuelLedger::default(),
        fuel_rate: astrid_capsule_types::FuelRateLimiter::default(),
        memory_ledger: astrid_capsule_types::MemoryLedger::default(),
        runtime_limits: astrid_capsule_types::CapsuleRuntimeLimits::default(),
        net_stream_budget: Arc::new(astrid_capsule_types::NetStreamBudget::default()),
        local_egress: std::collections::HashMap::new(),
        http_limits: astrid_capsule_types::HttpLimits::default(),
        full_reload_in_flight: AtomicBool::new(false),
        capsule_load_lock: Mutex::new(()),
        ephemeral: AtomicBool::new(false),
        boot_time: astrid_runtime::time::Instant::now(),
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
/// Takes the caller's already-resolved [`AstridHome`](astrid_core::dirs::AstridHome)
/// so every resource acquired by the native composition root is rooted in the
/// same home — re-resolving from the environment here could split the audit
/// log from the KV/socket paths if `$ASTRID_HOME` changed between calls.
#[cfg(unix)]
async fn open_audit_log(
    home: &astrid_core::dirs::AstridHome,
    runtime_key: Arc<astrid_crypto::KeyPair>,
) -> std::io::Result<Arc<AuditLog>> {
    home.ensure()
        .map_err(|e| std::io::Error::other(format!("cannot create Astrid home dirs: {e}")))?;

    let default_principal = astrid_core::PrincipalId::default();
    let principal_home = home.principal_home(&default_principal);
    principal_home
        .ensure()
        .map_err(|e| std::io::Error::other(format!("cannot create principal home dirs: {e}")))?;
    // Share the kernel's single runtime key — never load it from disk twice
    // (issue #929). The audit log and the admin token-mint path sign with the
    // exact same key bytes.
    let audit_log = AuditLog::open(principal_home.audit_dir(), runtime_key)
        .map_err(|e| std::io::Error::other(format!("cannot open audit log: {e}")))?;

    // Verify all historical chains on boot.
    match audit_log.verify_all().await {
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
/// `EventDispatcher` (all events), the bus activity monitor (all events,
/// storm diagnostics — see [`bus_monitor::spawn_bus_activity_monitor`]), and
/// the grant-on-first-use observer (`astrid.v1.approval` — see
/// [`grant_on_use::spawn_grant_on_use_handler`]).
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
const INTERNAL_SUBSCRIBER_COUNT: usize = 6;
/// Browser-profile count: only the `EventDispatcher` and the bus activity
/// monitor subscribe at boot — the router pair, `ConnectionTracker`, and
/// the grant-on-first-use observer are native-gated machinery.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
const INTERNAL_SUBSCRIBER_COUNT: usize = 2;

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
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn spawn_idle_monitor(kernel: Arc<Kernel>) -> astrid_runtime::JoinHandle<()> {
    astrid_runtime::spawn(async move {
        // Initial grace period — wait for capsules to boot and first client
        // to connect before checking idle status.
        astrid_runtime::time::sleep(IDLE_INITIAL_GRACE).await;

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
            astrid_runtime::time::sleep(IDLE_NON_EPHEMERAL_GRACE).await;
        }
        let mut idle_since: Option<astrid_runtime::time::Instant> = None;

        loop {
            astrid_runtime::time::sleep(check_interval).await;
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
                let now = astrid_runtime::time::Instant::now();
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
    last_attempt: astrid_runtime::time::Instant,
    backoff: std::time::Duration,
}

impl RestartTracker {
    const MAX_ATTEMPTS: u32 = 5;
    const INITIAL_BACKOFF: std::time::Duration = std::time::Duration::from_secs(2);
    const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_mins(2);

    fn new() -> Self {
        Self {
            attempts: 0,
            last_attempt: astrid_runtime::time::Instant::now(),
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
        self.last_attempt = astrid_runtime::time::Instant::now();
        self.backoff = self.backoff.saturating_mul(2).min(Self::MAX_BACKOFF);
    }

    /// Returns `true` if all retry attempts have been exhausted.
    fn exhausted(&self) -> bool {
        self.attempts >= Self::MAX_ATTEMPTS
    }
}

/// Whether [`Kernel::restart_capsule`] fully tore the old instance down.
///
/// A restart reloads a fresh instance either way; this is a DIAGNOSTIC of what
/// happened to the OLD one. It deliberately does NOT drive the retry cap: the
/// cap counts consecutive HEALTH failures (a lingering old instance is a normal,
/// harmless state for a busy capsule whose dispatcher consumer still holds a
/// clone — it is NOT a restart failure), and the health monitor prunes a
/// tracker when the capsule RECOVERS, not on the restart-call outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
enum RestartOutcome {
    /// The old runtime was exclusively unloaded before the fresh instance
    /// loaded — a genuinely clean restart.
    Clean,
    /// The old runtime's exclusive `unload` was skipped because an `Arc` clone
    /// (e.g. a live dispatcher consumer holding a clone for up to its idle
    /// grace) was still held. Its run-loop and subprocesses were cooperatively
    /// cancelled — no CPU/process leak — and its memory reclaims when the last
    /// clone drops. This is common for a capsule under load and is NOT counted
    /// as a restart failure.
    OldInstanceLingering,
}

/// Attempts to restart a failed capsule, respecting backoff and max retries.
///
/// Records ONE restart attempt (advancing backoff and the retry count) per call
/// when eligible. The count is a measure of CONSECUTIVE health failures: a busy
/// capsule whose restart legitimately leaves a lingering old instance is NOT
/// treated as a failure here — the tracker is pruned by the health monitor the
/// moment the capsule RECOVERS (see the retain in [`spawn_capsule_health_monitor`]),
/// so only a capsule that keeps failing across ticks accumulates toward the cap.
/// This deliberately does not key off the [`RestartOutcome`], which is diagnostic
/// only: keying the cap off "lingering" would let a busy-but-healthy capsule
/// (whose consumer holds a clone for up to its 60s idle grace) exhaust the cap
/// and be permanently disabled.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
async fn attempt_capsule_restart(
    kernel: &Kernel,
    id_str: &str,
    principal: &PrincipalId,
    tracker: &mut RestartTracker,
) {
    if tracker.exhausted() {
        return;
    }

    if !tracker.should_restart() {
        tracing::debug!(
            capsule_id = %id_str,
            next_attempt_in = ?tracker.backoff.saturating_sub(tracker.last_attempt.elapsed()),
            "Waiting for backoff before next restart attempt"
        );
        return;
    }

    tracker.record_attempt();
    let attempt = tracker.attempts;

    tracing::warn!(
        capsule_id = %id_str,
        principal = %principal,
        attempt,
        max_attempts = RestartTracker::MAX_ATTEMPTS,
        "Attempting capsule restart"
    );

    let capsule_id = astrid_capsule_types::CapsuleId::from_static(id_str);
    match kernel.restart_capsule(&capsule_id, principal).await {
        Ok(RestartOutcome::Clean) => {
            tracing::info!(
                capsule_id = %id_str,
                principal = %principal,
                attempt,
                "Capsule restarted (old instance fully unloaded)"
            );
        },
        Ok(RestartOutcome::OldInstanceLingering) => {
            // Fresh instance loaded; the old one could not be exclusively
            // unloaded (an Arc clone was still held) but its run-loop/subprocess
            // were cancelled, so this is not a leak and NOT a restart failure.
            // The tracker is pruned on recovery, so a busy capsule that stays
            // healthy will not accumulate toward the cap.
            tracing::info!(
                capsule_id = %id_str,
                principal = %principal,
                attempt,
                "Capsule restarted (old instance lingering behind a held Arc; cancelled, \
                 memory reclaims when the last clone drops)"
            );
        },
        Err(e) => {
            tracing::error!(
                capsule_id = %id_str,
                principal = %principal,
                attempt,
                error = %e,
                "Capsule restart failed"
            );
        },
    }

    if tracker.exhausted() {
        tracing::error!(
            capsule_id = %id_str,
            principal = %principal,
            "All restart attempts exhausted after {} consecutive failing health checks - \
             capsule will remain down until it recovers or the daemon restarts",
            RestartTracker::MAX_ATTEMPTS
        );
    }
}

/// Spawns a background task that periodically probes capsule health.
///
/// Every 10 seconds, reads the capsule registry and calls `check_health()` on
/// each capsule that is currently in `Ready` state. If a capsule reports
/// `Failed`, attempts to restart it with exponential backoff (max 5 attempts).
/// Publishes `astrid.v1.health.failed` IPC events for each detected failure.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn spawn_capsule_health_monitor(kernel: Arc<Kernel>) -> astrid_runtime::JoinHandle<()> {
    astrid_runtime::spawn(async move {
        let mut interval = astrid_runtime::time::interval(std::time::Duration::from_secs(10));
        interval.tick().await; // Skip the first immediate tick.

        let mut restart_trackers: std::collections::HashMap<String, RestartTracker> =
            std::collections::HashMap::new();

        loop {
            interval.tick().await;
            metrics::counter!(METRIC_BACKGROUND_TICKS_TOTAL, "loop" => "capsule_health")
                .increment(1);

            // Collect ready capsules under a brief read lock, then drop
            // the lock before calling check_health() or publishing events.
            let ready_capsules: Vec<(
                PrincipalId,
                astrid_capsule::registry::WasmHash,
                std::sync::Arc<dyn astrid_capsule::capsule::Capsule>,
            )> = {
                let registry = kernel.capsules.read().await;
                registry
                    .cloned_values_with_principal_and_hash()
                    .into_iter()
                    .filter_map(|(principal, hash, capsule)| {
                        if capsule.state() == astrid_capsule::capsule::CapsuleState::Ready {
                            Some((principal, hash, capsule))
                        } else {
                            None
                        }
                    })
                    .collect()
            };

            // Probe health once per DISTINCT runtime, collect failures, then drop
            // the Arc Vec before restarting. This ensures restart_capsule's
            // Arc::get_mut can succeed (no other strong references held).
            //
            // A content-addressed runtime is SHARED across principals (issue
            // #1069): `cloned_values_with_principal_and_hash()` yields one
            // `(principal, hash, Arc)` triple PER VIEW, so a runtime referenced by
            // N views of the same hash appears N times, all sharing one `Arc` and
            // reporting the same `check_health`. `collect_failed_runtimes_deduped`
            // DEDUPS by `(id, hash)` so that runtime is restarted exactly ONCE —
            // yet a capsule id with two DISTINCT loaded hashes (per-principal
            // installs of different versions) yields two entries, each restarted
            // independently. `restart_capsule` rebuilds every view of that hash.
            let failures = collect_failed_runtimes_deduped(&ready_capsules);
            for (principal, id_str, _hash, reason) in &failures {
                tracing::error!(
                    capsule_id = %id_str,
                    principal = %principal,
                    reason = %reason,
                    "Capsule health check failed"
                );
                let msg = astrid_events::ipc::IpcMessage::new(
                    astrid_events::ipc::Topic::from_raw("astrid.v1.health.failed"),
                    astrid_events::ipc::IpcPayload::Custom {
                        data: serde_json::json!({
                            "capsule_id": id_str,
                            "principal": principal.as_str(),
                            "reason": reason,
                        }),
                    },
                    uuid::Uuid::new_v4(),
                );
                let _ = kernel.event_bus.publish(astrid_events::AstridEvent::Ipc {
                    metadata: astrid_events::EventMetadata::new("kernel"),
                    message: msg,
                });
            }

            // Drop all Arc clones so restart_capsule's Arc::get_mut can
            // obtain exclusive access for calling unload().
            drop(ready_capsules);

            let failed_this_tick: std::collections::HashSet<String> = failures
                .iter()
                .map(|(_principal, id, hash, _)| restart_tracker_key(id, hash))
                .collect();

            for (principal, id_str, hash, _reason) in &failures {
                let tracker_key = restart_tracker_key(id_str, hash);
                let tracker = restart_trackers
                    .entry(tracker_key.clone())
                    .or_insert_with(RestartTracker::new);

                attempt_capsule_restart(&kernel, id_str, principal, tracker).await;
            }

            // Prune trackers on RECOVERY — the sole tracker-removal path. A
            // tracker is dropped only when its capsule is healthy again (absent
            // from `failed_this_tick`) AND past its backoff window. This is what
            // decouples the retry cap from the restart-call outcome: a restart is
            // never treated as "success" that resets the budget; instead the
            // budget resets only when the capsule genuinely recovers. So a
            // transient hiccup (one failing tick, then healthy) prunes cleanly
            // and never approaches the cap, while a capsule that keeps failing
            // across ticks accumulates attempts until the cap engages — for both
            // clean and lingering restarts alike. Exhausted trackers are kept so
            // an exhausted capsule stays down; within-backoff trackers are kept
            // because a failed reload can drop the capsule from the registry so
            // it won't appear in `ready_capsules` next tick.
            restart_trackers.retain(|tracker_key, tracker| {
                tracker_should_be_retained(tracker, failed_this_tick.contains(tracker_key))
            });
        }
    })
}

/// The health monitor's per-tick tracker-retention predicate.
///
/// Keep a restart tracker across ticks only while it is still relevant; pruning
/// it (returning `false`) is the SOLE path that resets a capsule's retry budget,
/// and it happens only on genuine RECOVERY — healthy this tick
/// (`!failed_this_tick`) AND past the backoff window. Exhausted trackers are
/// kept so an exhausted capsule stays down; a within-backoff tracker is kept
/// because a failed reload can drop the capsule from the registry so it is
/// absent from `ready_capsules` (hence `!failed_this_tick`) for a tick without
/// having recovered. Decoupling the budget reset from the restart-call outcome
/// (a lingering old instance is not a failure) is what stops a busy capsule from
/// exhausting the cap on transient hiccups.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn tracker_should_be_retained(tracker: &RestartTracker, failed_this_tick: bool) -> bool {
    if tracker.exhausted() {
        return true;
    }
    if tracker.last_attempt.elapsed() < tracker.backoff {
        return true;
    }
    failed_this_tick
}

/// Restart-tracker key for a DISTINCT shared runtime: `(capsule id, content
/// hash)`.
///
/// A content-addressed runtime is shared across principals (issue #1069) — one
/// instance behind N views of the SAME hash. Including the hash (not the capsule
/// id alone, and not `principal/capsule_id`) makes the health monitor track ONE
/// restart budget per DISTINCT runtime: a failed shared instance is not restarted
/// N times (once per viewing principal), yet two distinct hashes of one capsule
/// id (per-principal installs of different versions) get INDEPENDENT budgets so a
/// crash-looping v1 cannot exhaust v2's restart allowance or vice versa.
fn restart_tracker_key(capsule_id: &str, hash: &astrid_capsule::registry::WasmHash) -> String {
    format!("{capsule_id}\0{hash}")
}

/// Collect the FAILED runtimes from the health-monitor's view snapshot,
/// deduplicated by `(capsule id, content hash)`.
///
/// `cloned_values_with_principal_and_hash()` yields one `(principal, hash, Arc)`
/// triple PER VIEW, so a SHARED failed runtime (issue #1069) referenced by N
/// views of the SAME hash appears N times — all sharing one `Arc` and reporting
/// the same `check_health`. This dedups by `(id, hash)` so that shared runtime
/// yields exactly ONE failure entry (and therefore exactly one restart), while
/// still surfacing TWO entries when one capsule id has two DISTINCT hashes loaded
/// at once (e.g. `default` on `foo@1.0` and `alice` on `foo@2.0` — installs are
/// per-principal, so each derives its own content hash). Each distinct runtime is
/// then restarted independently rather than one being collapsed into the other.
///
/// The retained entry keeps the first-seen viewing principal as the restart
/// requester; `restart_capsule` rebuilds every view pointing at that exact hash.
///
/// Returns `(requesting principal, capsule id, content hash, failure reason)`.
fn collect_failed_runtimes_deduped(
    ready_capsules: &[(
        PrincipalId,
        astrid_capsule::registry::WasmHash,
        std::sync::Arc<dyn astrid_capsule::capsule::Capsule>,
    )],
) -> Vec<(
    PrincipalId,
    String,
    astrid_capsule::registry::WasmHash,
    String,
)> {
    let mut failures = Vec::new();
    let mut seen: std::collections::HashSet<(String, astrid_capsule::registry::WasmHash)> =
        std::collections::HashSet::new();
    for (principal, hash, capsule) in ready_capsules {
        // Probe health FIRST — it borrows and does not allocate, and the common
        // case (a healthy runtime) short-circuits before any `String` / key
        // allocation. Only an actually-failed runtime pays for the `(id, hash)`
        // dedup key; `HashSet::insert` returning `false` means this exact
        // `(id, hash)` was already recorded this tick, so we skip the duplicate.
        let astrid_capsule::capsule::CapsuleState::Failed(reason) = capsule.check_health() else {
            continue;
        };
        let id_str = capsule.id().to_string();
        if seen.insert((id_str.clone(), hash.clone())) {
            failures.push((principal.clone(), id_str, hash.clone(), reason));
        }
    }
    failures
}

/// Spawns a periodic watchdog that publishes `astrid.v1.watchdog.tick` events every 5 seconds.
///
/// The `ReAct` capsule (WASM guest) cannot use async timers, so this kernel-side task
/// drives timeout enforcement by waking the capsule on a fixed interval. Each tick
/// causes the capsule's `handle_watchdog_tick` interceptor to run `check_phase_timeout`.
fn spawn_react_watchdog(event_bus: Arc<EventBus>) -> astrid_runtime::JoinHandle<()> {
    astrid_runtime::spawn(async move {
        let mut interval = astrid_runtime::time::interval(std::time::Duration::from_secs(5));
        // The first tick fires immediately - skip it to give capsules time to load.
        interval.tick().await;

        loop {
            interval.tick().await;
            metrics::counter!(METRIC_BACKGROUND_TICKS_TOTAL, "loop" => "react_watchdog")
                .increment(1);

            let msg = astrid_events::ipc::IpcMessage::new(
                astrid_events::ipc::Topic::from_raw("astrid.v1.watchdog.tick"),
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
fn capsule_discovery_paths(
    home: &astrid_core::dirs::AstridHome,
    workspace_root: &Path,
) -> Vec<PathBuf> {
    capsule_discovery_paths_for(
        home,
        workspace_root,
        &PrincipalId::default(),
        &WorkspaceLayout::default(),
    )
}

fn capsule_discovery_paths_for(
    home: &astrid_core::dirs::AstridHome,
    workspace_root: &Path,
    principal: &PrincipalId,
    workspace_layout: &WorkspaceLayout,
) -> Vec<PathBuf> {
    let _ = (workspace_root, workspace_layout);
    vec![home.principal_home(principal).capsules_dir()]
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn capsule_instance_hash(
    manifest: &astrid_capsule_types::manifest::CapsuleManifest,
    dir: &Path,
) -> astrid_capsule::registry::WasmHash {
    astrid_capsule_install::read_meta(dir)
        .and_then(|meta| meta.wasm_hash)
        .map_or_else(
            || {
                astrid_capsule::registry::WasmHash::synthetic(
                    &manifest.package.name,
                    &manifest.package.version,
                )
            },
            astrid_capsule::registry::WasmHash::from_raw,
        )
}

// ---------------------------------------------------------------------------
// Boot validation
// ---------------------------------------------------------------------------

fn validate_principal_capsules(
    principal: &PrincipalId,
    sorted: &[(
        astrid_capsule_types::manifest::CapsuleManifest,
        std::path::PathBuf,
    )],
) {
    for (manifest, _) in sorted {
        if manifest.capabilities.uplink && manifest.has_imports() {
            tracing::warn!(
                %principal,
                capsule = %manifest.package.name,
                "Uplink capsule has [imports] - this should have been rejected at manifest load time"
            );
        }
    }
    validate_imports_exports(sorted);
}

/// Validate that every capsule's required imports have a matching export
/// from another loaded capsule. Logs errors for unsatisfied required imports
/// and info messages for unsatisfied optional imports. Also warns about
/// duplicate exports of the same interface from multiple capsules.
///
/// The set of unsatisfied *required* imports is sourced from
/// [`astrid_capsule::readiness::unsatisfied_required_imports`] so this boot
/// validator and the agent-loop readiness report share a single source of
/// truth — they can never disagree on whether a required dependency is met.
/// Optional-import info, the satisfied count, and duplicate-export warnings
/// stay local since the shared fn only covers required imports.
fn validate_imports_exports(
    manifests: &[(
        astrid_capsule_types::manifest::CapsuleManifest,
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

    // Single source of truth for unsatisfied imports — both the required and
    // the optional sets come from the shared readiness helpers, which apply the
    // SAME cross-capsule self-exclusion rule (a capsule cannot self-satisfy its
    // own import). Keying on (capsule, namespace, interface) lets the per-import
    // loop below decide each branch by membership, so the required-error and
    // optional-info diagnostics can never disagree on what "satisfied" means.
    let plain: Vec<&astrid_capsule_types::manifest::CapsuleManifest> =
        manifests.iter().map(|(m, _)| m).collect();
    let key_set = |missing: Vec<astrid_core::kernel_api::MissingImport>| {
        missing
            .into_iter()
            .map(|m| (m.capsule, m.namespace, m.interface))
            .collect::<std::collections::HashSet<(String, String, String)>>()
    };
    let unsatisfied_required = key_set(astrid_capsule::readiness::unsatisfied_required_imports(
        &plain,
    ));
    let unsatisfied_optional = key_set(astrid_capsule::readiness::unsatisfied_optional_imports(
        &plain,
    ));

    let mut satisfied_count: u32 = 0;
    let mut warning_count: u32 = 0;

    for (manifest, _) in manifests {
        for (ns, name, req, optional) in manifest.import_tuples() {
            let key = (
                manifest.package.name.clone(),
                ns.to_string(),
                name.to_string(),
            );
            if optional {
                if unsatisfied_optional.contains(&key) {
                    tracing::info!(
                        capsule = %manifest.package.name,
                        import = %format!("{ns}/{name} {req}"),
                        "Optional import not satisfied — capsule will boot with reduced functionality"
                    );
                    warning_count = warning_count.saturating_add(1);
                } else {
                    satisfied_count = satisfied_count.saturating_add(1);
                }
            } else if unsatisfied_required.contains(&key) {
                tracing::error!(
                    capsule = %manifest.package.name,
                    import = %format!("{ns}/{name} {req}"),
                    "Required import not satisfied — no loaded capsule exports this interface"
                );
                warning_count = warning_count.saturating_add(1);
            } else {
                satisfied_count = satisfied_count.saturating_add(1);
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

/// Emit a single concise WARN when the loaded capsule set can't serve an
/// agent chat turn, naming the missing piece(s). Summarized — never a
/// per-import flood. Reuses the shared
/// [`astrid_capsule::readiness::agent_loop_readiness`] so the boot signal,
/// the `/api/sys/readiness` route, and `astrid doctor` all agree.
///
/// Takes the manifests of the capsules that are actually **loaded** (read from
/// the live registry after load completes), not the pre-load discovered set —
/// a manifest can be discovered but fail to load (missing env, WASM error), so
/// only the loaded registry reflects what can really serve a turn.
fn warn_agent_loop_readiness(manifests: &[&astrid_capsule_types::manifest::CapsuleManifest]) {
    let readiness = astrid_capsule::readiness::agent_loop_readiness(manifests);
    if readiness.ready {
        tracing::info!(
            capsules = readiness.loaded_capsules.len(),
            "Agent loop ready — a capsule subscribes the prompt topic and publishes the response topic"
        );
        return;
    }

    let mut missing: Vec<String> = Vec::new();
    if readiness.prompt_subscribers.is_empty() {
        missing.push(format!(
            "no capsule subscribes to {}",
            astrid_capsule::readiness::AGENT_PROMPT_TOPIC
        ));
    }
    if readiness.response_publishers.is_empty() {
        missing.push(format!(
            "no capsule publishes {}",
            astrid_capsule::readiness::AGENT_RESPONSE_TOPIC
        ));
    }
    if !readiness.unsatisfied_required_imports.is_empty() {
        let ifaces: Vec<String> = readiness
            .unsatisfied_required_imports
            .iter()
            .map(|m| format!("{}:{}", m.namespace, m.interface))
            .collect();
        missing.push(format!(
            "required interface(s) unsatisfied: {}",
            ifaces.join(" ")
        ));
    }

    tracing::warn!(
        reasons = %missing.join("; "),
        "Agent chat is not configured — POST /api/agent/prompt will return an immediate error. \
         Install the capsules that complete the loop (run `astrid doctor` for details)."
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
    seed_default_principal_admin_profile(home).map_err(|error| {
        astrid_storage::IdentityError::Storage(format!(
            "default admin profile bootstrap failed: {error}"
        ))
    })?;

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
        remove_legacy_profile_file(&legacy_path)?;
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

fn remove_legacy_profile_file(path: &Path) -> Result<(), std::io::Error> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
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
    migrate_legacy_profile_path(home, &default_principal)?;

    let path = PrincipalProfile::path_for(home, &default_principal);
    let mut profile = PrincipalProfile::load_from_path(&path)?;

    // Two independent idempotent steps that may each mutate the profile:
    //   1. seed the built-in `admin` group on a fresh-default profile, and
    //   2. mint `default`'s per-principal keypair if it has none.
    // `mutated` tracks whether either ran so we save at most once.
    let mut mutated = false;

    // 1. Admin-group seeding. Only on a truly fresh default (no groups,
    // grants, or revokes) — an operator-configured profile is left intact.
    if profile.groups.is_empty() && profile.grants.is_empty() && profile.revokes.is_empty() {
        let admin_group =
            astrid_core::GroupName::new(astrid_core::groups::BUILTIN_ADMIN).map_err(|e| {
                astrid_core::ProfileError::Invalid(format!("built-in admin group rejected: {e}"))
            })?;
        profile.groups.push(admin_group.as_str().to_string());
        mutated = true;
        tracing::info!(
            principal = %default_principal,
            "Seeded default principal with built-in `admin` group"
        );
    } else {
        tracing::debug!(
            principal = %default_principal,
            "Default principal profile already has group/grant/revoke entries — leaving groups intact"
        );
    }

    // 2. Per-principal keypair (issue #45/#852). Mint only if `default` has no
    // ed25519 key yet, so the operator can authenticate as `default` over the
    // socket. Independent of the admin-group step above: an operator-configured
    // default still gets a key.
    if mint_default_principal_keypair(home, &default_principal, &mut profile)? {
        mutated = true;
    }

    if mutated {
        profile.save_to_path(&path)?;
    }
    Ok(())
}

/// Mint `default`'s per-principal ed25519 keypair if it has none, writing the
/// private key to `keys/default.key` (0600) and registering the public key on
/// `profile` (issue #45/#852). Mirrors
/// [`mint_principal_keypair`](crate::kernel_router::admin::handlers) but takes
/// only `home` + the profile, since the boot path has no `Kernel` yet.
///
/// Returns `Ok(true)` if the profile's auth config was mutated (so the caller
/// saves it), `Ok(false)` if a key was already registered (no-op).
fn mint_default_principal_keypair(
    home: &astrid_core::dirs::AstridHome,
    principal: &astrid_core::PrincipalId,
    profile: &mut astrid_core::PrincipalProfile,
) -> Result<bool, astrid_core::ProfileError> {
    use astrid_core::profile::AuthMethod;

    // Already has a key registered → nothing to do. (Re-minting would orphan
    // the on-disk key the operator may already be signing with.)
    let has_key = !profile.auth.public_keys.is_empty();
    if has_key {
        return Ok(false);
    }

    let keypair = astrid_crypto::KeyPair::generate();
    let keys_dir = home.keys_dir();
    std::fs::create_dir_all(&keys_dir)?;
    let key_path = keys_dir.join(format!("{principal}.key"));
    // Create the file 0600 atomically (via `OpenOptions::mode`) BEFORE writing
    // the secret bytes, so the private key is never momentarily group/world
    // readable between a `write` and a follow-up `set_permissions` chmod.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&key_path)?;
        f.write_all(&keypair.secret_key_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&key_path, keypair.secret_key_bytes())?;
    }

    // Register Full-scope: the default principal's bootstrap keypair acts
    // with the principal's full authority. Dedup by canonical pubkey.
    let pubkey_hex = keypair.export_public_key().to_hex();
    if profile.auth.device_by_pubkey(&pubkey_hex).is_none() {
        profile
            .auth
            .public_keys
            .push(astrid_core::profile::DeviceKey::new(
                pubkey_hex,
                astrid_core::profile::DeviceScope::Full,
                None,
                // Stamp the real mint epoch — `0` is the migrated-legacy-key
                // sentinel, so using it for a freshly minted key would show a
                // 1970 timestamp in `pair-device list` / audit.
                i64::try_from(crate::invite::now_epoch()).unwrap_or(0),
            ));
    }
    if !profile.auth.methods.contains(&AuthMethod::Keypair) {
        profile.auth.methods.push(AuthMethod::Keypair);
    }
    tracing::info!(
        principal = %principal,
        "Minted per-principal keypair for default principal"
    );
    Ok(true)
}

/// Apply pre-configured identity links from the config file.
///
/// For each `[[identity.links]]` entry, resolves or creates the referenced
/// Astrid user and links the platform identity. Logs warnings on failure
/// but does not abort boot.
async fn apply_identity_config(
    store: &Arc<dyn astrid_storage::IdentityStore>,
    workspace_root: &std::path::Path,
    workspace_layout: &WorkspaceLayout,
) {
    let config =
        match astrid_config::Config::load_with_layout(Some(workspace_root), workspace_layout) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    use astrid_capsule::capsule::{Capsule, CapsuleState};
    use astrid_capsule::context::CapsuleContext;
    use astrid_capsule_types::CapsuleId;
    use astrid_capsule_types::error::CapsuleResult;
    use astrid_capsule_types::manifest::CapsuleManifest;

    struct CancellableTestCapsule {
        id: CapsuleId,
        manifest: CapsuleManifest,
        cancelled: Arc<AtomicBool>,
        unloaded: Arc<AtomicBool>,
        /// Records every `request_cancel_for` call, in order, so tests can
        /// assert the per-principal cancel fires for exactly the releasing
        /// principal (and never as a substitute for the full instance cancel).
        cancelled_for: Arc<std::sync::Mutex<Vec<PrincipalId>>>,
    }

    #[async_trait::async_trait]
    impl Capsule for CancellableTestCapsule {
        fn id(&self) -> &CapsuleId {
            &self.id
        }

        fn manifest(&self) -> &CapsuleManifest {
            &self.manifest
        }

        fn state(&self) -> CapsuleState {
            CapsuleState::Ready
        }

        async fn load(&mut self, _ctx: &CapsuleContext) -> CapsuleResult<()> {
            Ok(())
        }

        async fn unload(&mut self) -> CapsuleResult<()> {
            self.unloaded.store(true, Ordering::Relaxed);
            Ok(())
        }

        fn request_cancel(&self) {
            self.cancelled.store(true, Ordering::Relaxed);
        }

        fn request_cancel_for(&self, principal: &PrincipalId) {
            self.cancelled_for
                .lock()
                .expect("cancelled_for mutex")
                .push(principal.clone());
        }
    }

    #[test]
    fn capsule_discovery_extra_paths_include_principal_capsules_only() {
        let (_d, home) = scratch_home();
        let workspace = tempfile::tempdir().unwrap();
        let paths = capsule_discovery_paths(&home, workspace.path());
        let default = astrid_core::PrincipalId::default();

        assert_eq!(paths, vec![home.principal_home(&default).capsules_dir()]);
    }

    #[test]
    fn workspace_capsules_are_not_flattened_into_unchecked_extra_paths() {
        let (_d, home) = scratch_home();
        let workspace = tempfile::tempdir().unwrap();
        let layout = WorkspaceLayout::new(".alternate-runtime").unwrap();
        let paths =
            capsule_discovery_paths_for(&home, workspace.path(), &PrincipalId::default(), &layout);

        assert_eq!(paths.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unload_requests_cancel_before_waiting_for_exclusive_capsule() {
        let (_d, home) = scratch_home();
        let kernel = test_kernel_with_home(home).await;
        let id = CapsuleId::new("cancellable-test").unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let unloaded = Arc::new(AtomicBool::new(false));

        {
            let mut registry = kernel.capsules.write().await;
            registry
                .register(Box::new(CancellableTestCapsule {
                    id: id.clone(),
                    manifest: CapsuleManifest::default(),
                    cancelled: Arc::clone(&cancelled),
                    unloaded: Arc::clone(&unloaded),
                    cancelled_for: Arc::default(),
                }))
                .unwrap();
        }

        let held = {
            let registry = kernel.capsules.read().await;
            registry.get(&id).expect("registered capsule")
        };
        let release_after_cancel = {
            let cancelled = Arc::clone(&cancelled);
            astrid_runtime::spawn(async move {
                while !cancelled.load(Ordering::Relaxed) {
                    astrid_runtime::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                drop(held);
            })
        };

        let removed = kernel
            .unload_one_capsule(&id, &PrincipalId::default())
            .await
            .unwrap();
        release_after_cancel.await.unwrap();

        assert!(removed);
        assert!(
            cancelled.load(Ordering::Relaxed),
            "unload must request cancellation before exclusive unload is available"
        );
        assert!(
            unloaded.load(Ordering::Relaxed),
            "unload should complete once the in-flight holder releases its Arc"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unload_one_principal_retains_shared_runtime_for_others() {
        // Shared-by-hash (#1069): alice and bob view ONE runtime for the same
        // content hash. Unloading alice's view must NOT cancel or unload the
        // shared runtime while bob still references it — the runtime survives
        // and bob's view is intact. (The pre-#1069 model built one runtime per
        // principal; this asserts the shared model.)
        let (_d, home) = scratch_home();
        let kernel = test_kernel_with_home(home).await;
        let id = CapsuleId::new("shared-test").unwrap();
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        let hash = astrid_capsule::registry::WasmHash::from_raw("shared-test-hash");
        let cancelled = Arc::new(AtomicBool::new(false));
        let unloaded = Arc::new(AtomicBool::new(false));
        let cancelled_for: Arc<std::sync::Mutex<Vec<PrincipalId>>> = Arc::default();

        {
            let mut registry = kernel.capsules.write().await;
            // First loader builds the shared runtime via the PRODUCTION path:
            // owned by `default`, with alice's dispatch view. Using
            // `register_owned_by_default` (not `register_for(.., &alice)`) means
            // the shared instance's load-time owner is `default`, never a real
            // non-default principal whose host-state fields would be a
            // cross-principal fallback.
            registry
                .register_owned_by_default(
                    Box::new(CancellableTestCapsule {
                        id: id.clone(),
                        manifest: CapsuleManifest::default(),
                        cancelled: Arc::clone(&cancelled),
                        unloaded: Arc::clone(&unloaded),
                        cancelled_for: Arc::clone(&cancelled_for),
                    }),
                    hash.clone(),
                    &alice,
                )
                .unwrap();
            // Bob shares the SAME runtime (no second build).
            registry.register_existing(&id, &hash, &bob).unwrap();
        }

        let removed = kernel.unload_one_capsule(&id, &alice).await.unwrap();
        assert!(removed);
        assert!(
            !cancelled.load(Ordering::Relaxed),
            "releasing one view of a shared runtime must NOT cancel it while bob references it"
        );
        assert!(
            !unloaded.load(Ordering::Relaxed),
            "releasing one view of a shared runtime must NOT unload it while bob references it"
        );
        assert_eq!(
            cancelled_for.lock().expect("cancelled_for mutex").clone(),
            vec![alice.clone()],
            "the non-last release must cancel exactly the releasing principal's \
             in-flight host calls — no one else's"
        );

        {
            let registry = kernel.capsules.read().await;
            assert!(
                registry.get_for(&alice, &id).is_none(),
                "alice's view should no longer contain the capsule"
            );
            assert!(
                registry.get_for(&bob, &id).is_some(),
                "bob's view should retain the shared runtime"
            );
            assert_eq!(
                registry.refcount_for_hash(&hash),
                Some(1),
                "shared runtime refcount drops to bob's single remaining view"
            );
        }

        // Bob's release is the LAST view: the full instance-scoped
        // `request_cancel` + `unload` path runs, and no additional
        // per-principal cancel substitutes for it.
        let removed = kernel.unload_one_capsule(&id, &bob).await.unwrap();
        assert!(removed);
        assert!(
            cancelled.load(Ordering::Relaxed),
            "the last release must use the full instance-scoped request_cancel"
        );
        assert!(
            unloaded.load(Ordering::Relaxed),
            "the last release must unload the runtime"
        );
        assert_eq!(
            cancelled_for.lock().expect("cancelled_for mutex").clone(),
            vec![alice],
            "the last release goes through the instance-scoped path, not \
             request_cancel_for"
        );
    }

    /// A test capsule that reports `Failed` from `check_health`, for the health
    /// monitor dedup test.
    struct FailingTestCapsule {
        id: CapsuleId,
        manifest: CapsuleManifest,
    }

    #[async_trait::async_trait]
    impl Capsule for FailingTestCapsule {
        fn id(&self) -> &CapsuleId {
            &self.id
        }
        fn manifest(&self) -> &CapsuleManifest {
            &self.manifest
        }
        fn state(&self) -> CapsuleState {
            CapsuleState::Ready
        }
        fn check_health(&self) -> CapsuleState {
            CapsuleState::Failed("simulated failure".to_string())
        }
        async fn load(&mut self, _ctx: &CapsuleContext) -> CapsuleResult<()> {
            Ok(())
        }
        async fn unload(&mut self) -> CapsuleResult<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn health_monitor_dedups_shared_failed_runtime_to_one_restart() {
        // Bleed #3: a shared failed runtime with N views must be collected as
        // exactly ONE failure (hence restarted once), not once per viewing
        // principal. `cloned_values_with_principal()` yields one pair per view
        // (N), all sharing one `Arc`; the dedup must collapse them to one.
        let (_d, home) = scratch_home();
        let kernel = test_kernel_with_home(home).await;
        let id = CapsuleId::new("failing-shared").unwrap();
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        let carol = PrincipalId::new("carol").unwrap();
        let hash = astrid_capsule::registry::WasmHash::from_raw("failing-shared-hash");

        {
            let mut registry = kernel.capsules.write().await;
            // Production path: owned by default, three principal views over ONE
            // shared runtime.
            registry
                .register_owned_by_default(
                    Box::new(FailingTestCapsule {
                        id: id.clone(),
                        manifest: CapsuleManifest::default(),
                    }),
                    hash.clone(),
                    &alice,
                )
                .unwrap();
            registry.register_existing(&id, &hash, &bob).unwrap();
            registry.register_existing(&id, &hash, &carol).unwrap();
        }

        let ready = {
            let registry = kernel.capsules.read().await;
            registry.cloned_values_with_principal_and_hash()
        };
        // Three views of one shared runtime → three triples.
        assert_eq!(
            ready.len(),
            3,
            "three views must produce three (principal, hash, Arc) triples (shared runtime)"
        );

        let failures = collect_failed_runtimes_deduped(&ready);
        assert_eq!(
            failures.len(),
            1,
            "a shared failed runtime with N views must dedup to exactly ONE restart, got {}",
            failures.len()
        );
        assert_eq!(failures[0].1, id.as_str());
        assert_eq!(failures[0].2, hash);
        // The tracker key is `(id, hash)` — one budget for the DISTINCT shared
        // runtime, not one per principal.
        assert_eq!(
            restart_tracker_key(&failures[0].1, &failures[0].2),
            restart_tracker_key(id.as_str(), &hash)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn health_monitor_keeps_two_distinct_hashes_of_one_id_separate() {
        // Two principals on DIFFERENT versions of the same capsule id resolve to
        // two DISTINCT content hashes (per-principal installs). Dedup is by
        // `(id, hash)`, so two failed runtimes for one id must surface as TWO
        // failures (two independent restarts), never collapsed into one.
        let (_d, home) = scratch_home();
        let kernel = test_kernel_with_home(home).await;
        let id = CapsuleId::new("two-versions").unwrap();
        let default_p = PrincipalId::default();
        let alice = PrincipalId::new("alice").unwrap();
        let hash_v1 = astrid_capsule::registry::WasmHash::from_raw("two-versions-v1");
        let hash_v2 = astrid_capsule::registry::WasmHash::from_raw("two-versions-v2");

        {
            let mut registry = kernel.capsules.write().await;
            // `default` on v1, `alice` on v2 — two distinct runtimes, one id.
            registry
                .register_owned_by_default(
                    Box::new(FailingTestCapsule {
                        id: id.clone(),
                        manifest: CapsuleManifest::default(),
                    }),
                    hash_v1.clone(),
                    &default_p,
                )
                .unwrap();
            registry
                .register_owned_by_default(
                    Box::new(FailingTestCapsule {
                        id: id.clone(),
                        manifest: CapsuleManifest::default(),
                    }),
                    hash_v2.clone(),
                    &alice,
                )
                .unwrap();
        }

        let ready = {
            let registry = kernel.capsules.read().await;
            registry.cloned_values_with_principal_and_hash()
        };
        assert_eq!(ready.len(), 2, "two distinct hashes → two view triples");

        let failures = collect_failed_runtimes_deduped(&ready);
        assert_eq!(
            failures.len(),
            2,
            "two distinct failed hashes for one id must NOT be collapsed; got {}",
            failures.len()
        );
        let mut seen_hashes: Vec<_> = failures.iter().map(|(_, _, h, _)| h.clone()).collect();
        seen_hashes.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        assert_eq!(seen_hashes, vec![hash_v1.clone(), hash_v2.clone()]);
        // Distinct tracker keys → independent restart budgets per version.
        assert_ne!(
            restart_tracker_key(id.as_str(), &hash_v1),
            restart_tracker_key(id.as_str(), &hash_v2),
            "each distinct runtime must get its own restart budget"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn register_owned_by_default_then_register_for_alice_is_rejected() {
        // Bleed #5 guard, kernel level: once a hash is loaded under `default`
        // (the production owner), a `register_for` under a real principal must be
        // REJECTED — no code path may create a shared instance owned by a real
        // non-default principal whose load-time fields would be a fallback.
        let (_d, home) = scratch_home();
        let kernel = test_kernel_with_home(home).await;
        let id = CapsuleId::new("guarded").unwrap();
        let alice = PrincipalId::new("alice").unwrap();
        let hash = astrid_capsule::registry::WasmHash::from_raw("guarded-hash");

        let mut registry = kernel.capsules.write().await;
        registry
            .register_owned_by_default(
                Box::new(CancellableTestCapsule {
                    id: id.clone(),
                    manifest: CapsuleManifest::default(),
                    cancelled: Arc::new(AtomicBool::new(false)),
                    unloaded: Arc::new(AtomicBool::new(false)),
                    cancelled_for: Arc::default(),
                }),
                hash.clone(),
                &PrincipalId::default(),
            )
            .unwrap();
        // A `register_for` under alice targets owner=alice ≠ existing owner
        // (default) → rejected.
        let rejected = registry.register_for(
            Box::new(CancellableTestCapsule {
                id: id.clone(),
                manifest: CapsuleManifest::default(),
                cancelled: Arc::new(AtomicBool::new(false)),
                unloaded: Arc::new(AtomicBool::new(false)),
                cancelled_for: Arc::default(),
            }),
            hash.clone(),
            &alice,
        );
        assert!(
            rejected.is_err(),
            "register_for under a real principal must be rejected when the hash is default-owned"
        );
        // The sanctioned share path (register_existing) still works.
        registry.register_existing(&id, &hash, &alice).unwrap();
        assert_eq!(registry.refcount_for_hash(&hash), Some(2));
    }

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
        tracker.last_attempt = astrid_runtime::time::Instant::now()
            .checked_sub(RestartTracker::INITIAL_BACKOFF)
            .unwrap()
            .checked_sub(std::time::Duration::from_millis(1))
            .unwrap();
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
        tracker.last_attempt = astrid_runtime::time::Instant::now()
            .checked_sub(RestartTracker::MAX_BACKOFF)
            .unwrap();
        assert!(!tracker.should_restart());
    }

    /// Simulate the health monitor's per-tick tracker bookkeeping over a
    /// sequence of health states (`true` = failing this tick). Drives the exact
    /// production primitives: `attempt` mirrors the record-attempt on a failing
    /// eligible tick, and `tracker_should_be_retained` is the real retain
    /// predicate. `sim_elapsed` back-dates the tracker so backoff is treated as
    /// elapsed by the next tick (real ticks are 10s apart; the test can't sleep).
    ///
    /// Returns `(total restart attempts recorded, capsule permanently disabled)`.
    #[cfg(test)]
    fn simulate_health_ticks(failing_by_tick: &[bool]) -> (u32, bool) {
        use std::collections::HashMap;
        const KEY: &str = "cap\0hash";

        let mut trackers: HashMap<&str, RestartTracker> = HashMap::new();
        let mut attempts: u32 = 0;

        for &failing in failing_by_tick {
            if failing {
                let tracker = trackers.entry(KEY).or_insert_with(RestartTracker::new);
                // Back-date so `should_restart`'s backoff gate is satisfied,
                // modelling ticks spaced past the (short, early) backoff.
                tracker.last_attempt = astrid_runtime::time::Instant::now()
                    .checked_sub(RestartTracker::MAX_BACKOFF)
                    .unwrap_or_else(astrid_runtime::time::Instant::now);
                if !tracker.exhausted() && tracker.should_restart() {
                    tracker.record_attempt();
                    attempts = attempts.saturating_add(1);
                }
            }
            // Retain/prune exactly as the monitor does. Back-date first so a
            // recovered (non-failing) tracker is past its backoff and prunes.
            if let Some(t) = trackers.get_mut(KEY) {
                t.last_attempt = astrid_runtime::time::Instant::now()
                    .checked_sub(RestartTracker::MAX_BACKOFF)
                    .unwrap_or_else(astrid_runtime::time::Instant::now);
            }
            trackers.retain(|_, tracker| tracker_should_be_retained(tracker, failing));
        }

        let disabled = trackers.get(KEY).is_some_and(RestartTracker::exhausted);
        (attempts, disabled)
    }

    #[test]
    fn persistent_health_failures_engage_the_retry_cap() {
        // A capsule that fails health on every tick must stop restarting at the
        // cap (no infinite thrash / leak). This holds regardless of restart
        // outcome — the cap counts consecutive health failures, not clean-vs-
        // lingering. Pre-fix, a "successful" restart cleared the tracker every
        // tick so attempts reset to 0 and the cap NEVER engaged.
        let (attempts, disabled) = simulate_health_ticks(&[true; 20]);
        assert_eq!(
            attempts,
            RestartTracker::MAX_ATTEMPTS,
            "persistent failures must stop at the cap, not thrash forever"
        );
        assert!(disabled, "a persistently-failing capsule ends up capped");
    }

    #[test]
    fn transient_failure_on_busy_capsule_does_not_permanently_disable_it() {
        // Important-#1 regression: a busy capsule (dispatcher consumer holds an
        // Arc for up to its 60s idle grace, so its restart reports "lingering")
        // hits ONE transient health failure, restarts, then stabilizes. It must
        // NOT be counted toward the cap across the healthy ticks — the tracker is
        // pruned on recovery, so the capsule is never permanently disabled.
        //
        // Pre-hardening, a lingering restart was counted toward the cap; a busy
        // capsule that flapped a few times within its backoff could exhaust the
        // 5-attempt budget and `should_restart` would then refuse forever.
        let mut pattern = vec![true]; // one transient failure
        pattern.extend(std::iter::repeat_n(false, 10)); // then healthy
        let (attempts, disabled) = simulate_health_ticks(&pattern);
        assert_eq!(attempts, 1, "exactly one restart for the single hiccup");
        assert!(
            !disabled,
            "a capsule that recovers must never be permanently disabled"
        );

        // Even several NON-consecutive hiccups (recovering between each) stay
        // well under the cap — each recovery prunes the accumulated budget.
        let flapping = [true, false, false, true, false, false, true, false, false];
        let (flap_attempts, flap_disabled) = simulate_health_ticks(&flapping);
        assert!(
            flap_attempts <= 3 && !flap_disabled,
            "recovering between failures resets the budget; got {flap_attempts} attempts, \
             disabled={flap_disabled}"
        );
    }

    #[test]
    fn restart_outcome_is_diagnostic_only_not_a_cap_signal() {
        // The outcome enum is retained for diagnostics but must not itself gate
        // the cap; both variants exist and are distinct.
        assert_ne!(RestartOutcome::Clean, RestartOutcome::OldInstanceLingering);
    }

    // ── Bootstrap admin-group seeding (issue #670) ───────────────────

    fn scratch_home() -> (tempfile::TempDir, astrid_core::dirs::AstridHome) {
        let dir = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(dir.path());
        (dir, home)
    }

    fn injected_kernel_resources(home: &astrid_core::dirs::AstridHome) -> KernelResources {
        home.ensure().expect("ensure test home");
        let kv: Arc<dyn astrid_storage::KvStore> = Arc::new(astrid_storage::MemoryKvStore::new());
        let runtime_key = Arc::new(astrid_crypto::KeyPair::generate());
        let principal_home = home.principal_home(&astrid_core::PrincipalId::default());
        principal_home.ensure().expect("ensure default home");
        let audit_log = Arc::new(
            AuditLog::open(principal_home.audit_dir(), Arc::clone(&runtime_key))
                .expect("open test audit log"),
        );
        KernelResources::new(
            home.clone(),
            kv,
            audit_log,
            runtime_key,
            Arc::new(astrid_core::session_token::SessionToken::generate()),
            home.token_path(),
            None,
            None,
        )
    }

    async fn boot_with_injected_resources(
        home: &astrid_core::dirs::AstridHome,
        resources: KernelResources,
    ) -> std::io::Result<Arc<Kernel>> {
        Kernel::with_resources(
            SessionId::SYSTEM,
            home.root().to_path_buf(),
            astrid_capsule_types::CapsuleRuntimeLimits::default(),
            std::collections::HashMap::new(),
            astrid_capsule_types::HttpLimits::default(),
            resources,
        )
        .await
    }

    fn assert_bootstrap_error(error: &std::io::Error) {
        let message = error.to_string();
        assert!(
            message.contains("Failed to bootstrap CLI root user")
                && message.contains("default admin profile bootstrap failed"),
            "unexpected boot error: {message}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn with_resources_aborts_when_legacy_profile_migration_fails() {
        let (_dir, home) = scratch_home();
        let resources = injected_kernel_resources(&home);
        let default = astrid_core::PrincipalId::default();
        let legacy_path = home
            .principal_home(&default)
            .config_dir()
            .join("profile.toml");
        astrid_core::PrincipalProfile {
            groups: vec![astrid_core::groups::BUILTIN_ADMIN.to_string()],
            ..Default::default()
        }
        .save_to_path(&legacy_path)
        .expect("seed legacy profile");
        std::fs::write(home.profiles_dir(), b"blocks profile directory")
            .expect("create deterministic migration obstacle");

        let Err(error) = boot_with_injected_resources(&home, resources).await else {
            panic!("kernel boot must fail when policy migration fails");
        };
        assert_bootstrap_error(&error);
        assert!(
            legacy_path.exists(),
            "failed migration must preserve source policy"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn with_resources_aborts_when_default_key_seeding_fails() {
        let (_dir, home) = scratch_home();
        let resources = injected_kernel_resources(&home);
        std::fs::create_dir(home.keys_dir().join("default.key"))
            .expect("create deterministic key-write obstacle");

        let Err(error) = boot_with_injected_resources(&home, resources).await else {
            panic!("kernel boot must fail when bootstrap key seeding fails");
        };
        assert_bootstrap_error(&error);
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

        // Default now carries a per-principal ed25519 key + the Keypair
        // method, and the private key is on disk 0600 (issue #45/#852).
        assert!(
            !profile.auth.public_keys.is_empty(),
            "default must have an ed25519 key registered"
        );
        assert!(
            profile
                .auth
                .public_keys
                .iter()
                .all(|k| matches!(k.scope, astrid_core::profile::DeviceScope::Full)),
            "bootstrap key must be Full-scope"
        );
        assert!(
            profile
                .auth
                .methods
                .contains(&astrid_core::profile::AuthMethod::Keypair),
            "default must record the Keypair auth method"
        );
        let key_path = home.keys_dir().join("default.key");
        assert!(key_path.exists(), "default.key must be written to disk");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "default.key must be owner-only");
        }
    }

    #[test]
    fn seed_admin_keypair_is_idempotent() {
        // A second seed must NOT mint a fresh key — the registered key and the
        // on-disk private key are stable across reboots so an operator who has
        // started signing with it keeps working (issue #45/#852).
        let (_d, home) = scratch_home();
        let default = astrid_core::PrincipalId::default();
        let path = astrid_core::PrincipalProfile::path_for(&home, &default);

        seed_default_principal_admin_profile(&home).unwrap();
        let first = astrid_core::PrincipalProfile::load_from_path(&path).unwrap();
        let first_keys = first.auth.public_keys.clone();
        let first_bytes = std::fs::read(home.keys_dir().join("default.key")).unwrap();

        seed_default_principal_admin_profile(&home).unwrap();
        let second = astrid_core::PrincipalProfile::load_from_path(&path).unwrap();
        let second_bytes = std::fs::read(home.keys_dir().join("default.key")).unwrap();

        assert_eq!(
            first_keys, second.auth.public_keys,
            "key must not be re-minted"
        );
        assert_eq!(
            first_bytes, second_bytes,
            "private key bytes must be stable"
        );
        assert_eq!(
            second.auth.public_keys.len(),
            1,
            "exactly one ed25519 key — no duplication across reboots"
        );
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
        let existing = astrid_core::PrincipalProfile {
            groups: vec!["agent".to_string()],
            ..Default::default()
        };
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

        let existing = astrid_core::PrincipalProfile {
            grants: vec!["system:status".to_string()],
            ..Default::default()
        };
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

        let existing = astrid_core::PrincipalProfile {
            revokes: vec!["system:shutdown".to_string()],
            ..Default::default()
        };
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
        let existing = astrid_core::PrincipalProfile {
            groups: vec!["operator-configured".to_string()],
            ..Default::default()
        };
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
        let stale = astrid_core::PrincipalProfile {
            groups: vec!["stale".to_string()],
            ..Default::default()
        };
        stale.save_to_path(&legacy_path).unwrap();

        // Fresh new-path content (migrated already).
        let new_path = astrid_core::PrincipalProfile::path_for(&home, &default);
        std::fs::create_dir_all(new_path.parent().unwrap()).unwrap();
        let canonical = astrid_core::PrincipalProfile {
            groups: vec!["canonical".to_string()],
            ..Default::default()
        };
        canonical.save_to_path(&new_path).unwrap();

        seed_default_principal_admin_profile(&home).unwrap();

        // Legacy removed, canonical preserved.
        assert!(!legacy_path.exists());
        let result = astrid_core::PrincipalProfile::load_from_path(&new_path).unwrap();
        assert_eq!(result.groups, vec!["canonical".to_string()]);
    }

    #[test]
    fn missing_legacy_profile_cleanup_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        remove_legacy_profile_file(&dir.path().join("already-removed.toml")).unwrap();
    }
}
