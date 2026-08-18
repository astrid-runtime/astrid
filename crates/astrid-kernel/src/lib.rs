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

#[cfg(all(test, unix))]
#[path = "audit_retirement_tests.rs"]
mod audit_retirement_tests;
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
#[cfg(test)]
mod capsules_loaded_tests;
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
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod legacy_migration_barrier;
/// Persistent pair-device token store (issue #756).
pub mod pair_token;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod principal_distro_migration;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod principal_home_migration;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod principal_log_migration;
#[cfg(all(test, not(all(target_arch = "wasm32", target_os = "unknown"))))]
mod runtime_policy_tests;
/// The Unix Domain Socket manager. Unix-only: binds the `UnixListener` and
/// acquires the singleton advisory lock.
#[cfg(unix)]
pub mod socket;
/// Authenticated native filesystem lease and callback service.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod storage_mount;

use arc_swap::ArcSwap;
use astrid_audit::AuditLog;
#[cfg(unix)]
use astrid_audit::{AuditCapacityProvider, AuditError};
use astrid_capabilities::{CapabilityStore, DirHandle};
use astrid_capsule::profile_cache::PrincipalProfileCache;
use astrid_capsule::registry::CapsuleRegistry;
use astrid_capsule_types::CapsuleId;
use astrid_core::SessionId;
use astrid_core::dirs::{WorkspaceLayout, WorkspaceSelection};
use astrid_core::groups::GroupConfig;
use astrid_core::principal::PrincipalId;
#[cfg(unix)]
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
#[cfg(not(target_family = "wasm"))]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use tokio::sync::{Mutex, RwLock};

const SCOPED_TOPIC_PROBE_SENTINEL: &str = "\0astrid.scoped-topic\0";
const SCOPED_SERVICE_PROBE_SENTINEL: &str = "\0astrid.scoped-service\0";
pub(crate) const REACT_WATCHDOG_TOPIC: &str = "astrid.v1.watchdog.tick";
const WATCHDOG_PUBLISH_BATCH: usize = 32;
const WATCHDOG_PUBLISH_PAUSE: std::time::Duration = std::time::Duration::from_millis(1);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CapsuleViewKey {
    principal: PrincipalId,
    capsule: CapsuleId,
}

struct CapsuleViewLease {
    key: CapsuleViewKey,
    lock: Weak<Mutex<()>>,
    locks: Arc<DashMap<CapsuleViewKey, Weak<Mutex<()>>>>,
}

impl Drop for CapsuleViewLease {
    fn drop(&mut self) {
        self.locks.remove_if(&self.key, |_, stored| {
            stored.ptr_eq(&self.lock) && stored.strong_count() == 0
        });
    }
}

struct CapsuleViewGuard {
    held: Option<tokio::sync::OwnedMutexGuard<()>>,
    _lease: CapsuleViewLease,
}

impl Drop for CapsuleViewGuard {
    fn drop(&mut self) {
        drop(self.held.take());
    }
}

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
    /// Legacy native home root retained for lifecycle/compatibility contexts.
    /// Steady-state capsule `home://` authority is the UID-bound
    /// `principal_store` projection, never this host path.
    ///
    /// Always `Some` in production (boot requires `AstridHome`). Remains
    /// `Option` for compatibility with `CapsuleContext` and test fixtures.
    pub home_root: Option<PathBuf>,
    /// The natively bound Unix Socket for the CLI proxy.
    pub cli_socket_listener: Option<astrid_capsule::context::UplinkListener>,
    /// Set once the Astrid-owned native uplink claims the canonical listener.
    /// Capsules then receive no handle to that endpoint, preventing competing
    /// accept loops from randomly splitting client connections.
    native_uplink_owns_listener: AtomicBool,
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
    /// Live alias-to-immutable-UID directory used to scope executable capsule
    /// runtimes. Runtime authority is never keyed by a reusable alias.
    pub(crate) principal_directory: astrid_storage::PrincipalDirectory,
    /// Native principal projections sharing the same engine as [`Self::kv`].
    ///
    /// Portable hosts may inject only a [`KvStore`](astrid_storage::KvStore),
    /// so management diagnostics fail closed when this native composition
    /// resource is absent.
    #[cfg(not(target_family = "wasm"))]
    pub(crate) principal_store: Option<astrid_storage::RuntimePrincipalStore>,
    /// Kernel-wide canonical workspace branch service shared by all capsule
    /// engines. Branch bindings are keyed by immutable principal UID.
    #[cfg(not(target_family = "wasm"))]
    pub(crate) workspace_branches: Option<Arc<astrid_capsule::context::WorkspaceBranchService>>,
    /// Kernel-private native provider broker for spawned process projections.
    #[cfg(not(target_family = "wasm"))]
    pub(crate) process_storage_mount_broker:
        OnceLock<Arc<dyn astrid_capsule::context::ProcessStorageMountBroker>>,
    /// Chain-linked cryptographic audit log with persistent storage.
    pub audit_log: Arc<AuditLog>,
    /// Shared bounded host-audit writer and operator health surface.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub audit_sink: Arc<crate::audit_sink::KernelAuditSink>,
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
    /// Immutable verified WASM compilation cache shared by all
    /// authority-scoped capsule runtimes in this kernel.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    compiled_wasm: astrid_capsule::engine::wasm::CompiledWasmCache,
    /// Host-derived (operator-overridable) concurrency ceilings for capsule
    /// host calls, resolved once by the daemon and forwarded to every
    /// `WasmEngine` via the loader. The kernel only stores and forwards this
    /// `Copy` value — no resolution logic lives here. See
    /// [`CapsuleRuntimeLimits`](astrid_capsule_types::CapsuleRuntimeLimits).
    runtime_limits: astrid_capsule_types::CapsuleRuntimeLimits,
    /// Operator-approved per-capsule local-egress allowlist
    /// (`[security.capsule_local_egress]`), keyed by capsule id. Resolved
    /// once from config by the daemon; the kernel only stores it and hands
    /// each capsule its own slice at load time so the SSRF airlock can
    /// exempt operator-sanctioned loopback/private endpoints. Empty = no
    /// exemptions (fail-closed).
    local_egress: std::collections::HashMap<String, Vec<String>>,
    /// Operator-declared capsule IDs permitted to run as explicit system
    /// singletons. Manifest fields can request uplink behavior but cannot grant
    /// this cross-principal authority themselves.
    system_capsules: RwLock<std::collections::HashSet<String>>,
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
    /// Serializes lifecycle transitions for one `(principal, capsule)` view.
    ///
    /// The global load lock protects short publication and retirement edges;
    /// this narrower lock remains held while an old view quiesces so an
    /// identical view cannot resume it mid-drain. Weak values make idle keys
    /// self-evicting without an unbounded fleet-history map.
    capsule_view_locks: Arc<DashMap<CapsuleViewKey, Weak<Mutex<()>>>>,
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
    #[cfg(unix)]
    token_path: PathBuf,
    /// Shared allowance store for capsule-level approval decisions.
    ///
    /// Capsules can check existing allowances and create new ones when
    /// users approve actions with session/always scope.
    pub allowance_store: Arc<astrid_approval::AllowanceStore>,
    /// System-wide identity store for platform user resolution.
    identity_store: Arc<dyn astrid_storage::IdentityStore>,
    /// Durable human, fleet, and exclusive principal ownership graph.
    ownership_store: Arc<astrid_storage::OwnershipStore>,
    /// Live native filesystem leases, each fixed to one authenticated caller
    /// and one typed storage owner.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(crate) storage_mounts: Arc<
        DashMap<
            astrid_core::storage_provider::StorageMountId,
            Arc<storage_mount::StorageMountLeaseState>,
        >,
    >,
    /// Linearizes read-modify-publish filesystem mutations across all native
    /// mounts so concurrent views cannot lose non-overlapping writes.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(crate) storage_mount_mutations: tokio::sync::Mutex<()>,
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
    /// Native layout origin captured before `AstridHome::ensure`. `None`
    /// denotes an injected/portable composition root, which does not own the
    /// host-home migration lifecycle.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(crate) layout_origin: Option<legacy_migration_barrier::LayoutOrigin>,
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
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            layout_origin: None,
        }
    }

    #[cfg(unix)]
    fn with_layout_origin(mut self, origin: legacy_migration_barrier::LayoutOrigin) -> Self {
        self.layout_origin = Some(origin);
        self
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
struct PreparedRuntimeReplacement {
    capsule: Box<dyn astrid_capsule::capsule::Capsule>,
    runtime_id: astrid_capsule::registry::RuntimeId,
    principal_uid: Option<astrid_core::identity::PrincipalUid>,
    system_runtime: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeResidency {
    Principal,
    SystemResident,
}

impl RuntimeResidency {
    const fn is_system(self) -> bool {
        matches!(self, Self::SystemResident)
    }
}

fn classify_runtime_residency(
    manifest: &astrid_capsule_types::manifest::CapsuleManifest,
    id: &astrid_capsule_types::CapsuleId,
    system_allowed: bool,
) -> Result<RuntimeResidency, anyhow::Error> {
    let provides_uplink = !manifest.uplinks.is_empty();
    if provides_uplink && !system_allowed {
        anyhow::bail!(
            "capsule '{id}' provides an uplink but is absent from the \
             operator-owned [[uplinks]] allowlist"
        );
    }
    if system_allowed && (manifest.capabilities.uplink || provides_uplink) {
        Ok(RuntimeResidency::SystemResident)
    } else {
        Ok(RuntimeResidency::Principal)
    }
}

impl Kernel {
    async fn lock_capsule_view(
        &self,
        principal: &PrincipalId,
        capsule: &CapsuleId,
    ) -> CapsuleViewGuard {
        let key = CapsuleViewKey {
            principal: principal.clone(),
            capsule: capsule.clone(),
        };
        let lock = match self.capsule_view_locks.entry(key.clone()) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                if let Some(lock) = entry.get().upgrade() {
                    lock
                } else {
                    let lock = Arc::new(Mutex::new(()));
                    entry.insert(Arc::downgrade(&lock));
                    lock
                }
            },
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                let lock = Arc::new(Mutex::new(()));
                entry.insert(Arc::downgrade(&lock));
                lock
            },
        };
        let lease = CapsuleViewLease {
            key,
            lock: Arc::downgrade(&lock),
            locks: Arc::clone(&self.capsule_view_locks),
        };
        CapsuleViewGuard {
            held: Some(lock.lock_owned().await),
            _lease: lease,
        }
    }

    /// Install the operator-owned allowlist for explicit system-resident
    /// capsules. Capsule manifests cannot mutate or widen this policy.
    pub async fn set_system_capsules(&self, capsules: impl IntoIterator<Item = String>) {
        *self.system_capsules.write().await = capsules.into_iter().collect();
    }
    /// Claim the canonical local listener for Astrid's built-in uplink.
    ///
    /// The first caller receives the shared listener. Once claimed, capsule
    /// contexts no longer receive it; optional distribution frontends may
    /// expose other transports but cannot replace or race the base control
    /// plane.
    #[must_use]
    pub fn claim_native_uplink_listener(&self) -> Option<astrid_capsule::context::UplinkListener> {
        if self
            .native_uplink_owns_listener
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return None;
        }
        self.cli_socket_listener.clone()
    }

    /// Astrid's authoritative human-to-fleet ownership store.
    #[must_use]
    pub fn ownership_store(&self) -> &Arc<astrid_storage::OwnershipStore> {
        &self.ownership_store
    }

    /// Return the durable UID-scoped principal store used by trusted daemon
    /// composition paths. Capsule and gateway callers must use authenticated
    /// admin requests instead of receiving this storage handle.
    #[cfg(not(target_family = "wasm"))]
    #[must_use]
    pub fn principal_store(&self) -> Option<&astrid_storage::RuntimePrincipalStore> {
        self.principal_store.as_ref()
    }

    /// Return the live alias-to-immutable-UID directory for trusted daemon
    /// composition paths. The directory is never a storage authority; it only
    /// resolves a principal alias before selecting its UID-owned store view.
    #[must_use]
    pub fn principal_directory(&self) -> &astrid_storage::PrincipalDirectory {
        &self.principal_directory
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
    /// The native composition root: resolves the Astrid home, opens the durable
    /// principal store and audit log, loads the runtime key, binds the singleton
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
        let layout_origin = legacy_migration_barrier::capture_layout_origin(&home)?;
        // A layout-two sentinel is only authoritative together with the
        // component migration ledger.  Check this before `AstridHome::ensure`
        // can retire any released source on behalf of an incomplete cutover.
        legacy_migration_barrier::reject_incomplete_layout_v2(&home)?;
        home.ensure().map_err(|error| {
            std::io::Error::other(format!("Failed to validate Astrid home layout: {error}"))
        })?;

        // Acquire the singleton advisory lock as the FIRST fallible boot step —
        // BEFORE opening any shared state store. A boot-race loser then fails
        // here with the actionable "already running (singleton lock held)"
        // error and never opens (or even touches) the shared principal or audit
        // stores, rather than dying on a raw `LOCK is already locked` from
        // the store layer after having opened one. The listener bind below does
        // NOT re-acquire the lock — it is already held for the process lifetime.
        let singleton_lock = socket::acquire_boot_singleton_lock(&home)?;
        home.clear_runtime_principal_scratch().map_err(|error| {
            std::io::Error::other(format!(
                "Failed to clear stale principal runtime scratch: {error}"
            ))
        })?;
        if home.layout_version()?.as_deref() == Some(astrid_core::dirs::LEGACY_LAYOUT_VERSION) {
            let migration_target =
                astrid_core::dirs::LayoutMigrationTarget::for_current_executable(
                    astrid_storage::RUNTIME_STORE_FORMAT_ID,
                )?;
            home.begin_layout_v2_migration(&migration_target)?;
        }

        // Resolve quota policy before opening state so the durable adapter and
        // capsule engine share exactly one invalidatable profile cache.
        let profile_cache = Arc::new(PrincipalProfileCache::with_home(home.clone()));
        let principal_directory = astrid_storage::PrincipalDirectory::default();
        let quota_cache = Arc::clone(&profile_cache);
        let quota_principals = principal_directory.clone();
        let quota: Arc<dyn astrid_storage::KvQuotaResolver<astrid_storage::StateOwner>> =
            Arc::new(move |owner: &astrid_storage::StateOwner| {
                match owner {
                    astrid_storage::StateOwner::System => Ok(None),
                    astrid_storage::StateOwner::Principal(owner) => {
                        quota_principals.alias_for(*owner).and_then(|principal| {
                            quota_cache
                                .resolve(&principal)
                                .map(|profile| Some(profile.quotas.max_storage_bytes))
                                .map_err(|error| {
                                    astrid_storage::StorageError::Internal(format!(
                                        "resolve storage quota for {principal}: {error}"
                                    ))
                                })
                        })
                    },
                    // A fleet is a real writable owner. Until the allocation-policy
                    // capsule admits a tighter fleet budget, retain the same hard
                    // storage ceiling used by an unconfigured principal. Accounting
                    // and enforcement remain in the kernel; policy does not run in
                    // the storage transaction.
                    astrid_storage::StateOwner::Fleet(_) => {
                        Ok(Some(astrid_core::profile::DEFAULT_MAX_STORAGE_BYTES))
                    },
                }
            });

        // Open the authoritative state store. First cutover imports and
        // verifies legacy SurrealKV under the singleton lock before serving.
        let principal_store = astrid_storage::open_runtime_principal_store_with_directory(
            &home,
            quota,
            principal_directory.clone(),
        )
        .await
        .map_err(|e| std::io::Error::other(format!("Failed to open principal store: {e}")))?;
        let kv = principal_store.kv();
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
        let audit_store = principal_store
            .system_control_kv("audit")
            .map_err(|e| std::io::Error::other(format!("Failed to open audit projection: {e}")))?
            .backend();
        let audit_log = open_audit_log(
            &home,
            audit_store,
            &principal_store,
            Arc::clone(&runtime_key),
        )
        .await?;

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
        )
        .with_layout_origin(layout_origin);

        Self::with_resources_and_workspace_layout_with_profile_cache_and_directory(
            session_id,
            workspace_root,
            runtime_limits,
            local_egress,
            http_limits,
            resources,
            workspace_layout,
            Some(profile_cache),
            principal_directory,
            Some(principal_store),
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
    pub async fn with_resources_and_workspace_layout(
        session_id: SessionId,
        workspace_root: PathBuf,
        runtime_limits: astrid_capsule_types::CapsuleRuntimeLimits,
        local_egress: std::collections::HashMap<String, Vec<String>>,
        http_limits: astrid_capsule_types::HttpLimits,
        resources: KernelResources,
        workspace_layout: WorkspaceLayout,
    ) -> Result<Arc<Self>, std::io::Error> {
        Self::with_resources_and_workspace_layout_with_profile_cache(
            session_id,
            workspace_root,
            runtime_limits,
            local_egress,
            http_limits,
            resources,
            workspace_layout,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn with_resources_and_workspace_layout_with_profile_cache(
        session_id: SessionId,
        workspace_root: PathBuf,
        runtime_limits: astrid_capsule_types::CapsuleRuntimeLimits,
        local_egress: std::collections::HashMap<String, Vec<String>>,
        http_limits: astrid_capsule_types::HttpLimits,
        resources: KernelResources,
        workspace_layout: WorkspaceLayout,
        profile_cache: Option<Arc<PrincipalProfileCache>>,
    ) -> Result<Arc<Self>, std::io::Error> {
        Self::with_resources_and_workspace_layout_with_profile_cache_and_directory(
            session_id,
            workspace_root,
            runtime_limits,
            local_egress,
            http_limits,
            resources,
            workspace_layout,
            profile_cache,
            astrid_storage::PrincipalDirectory::default(),
            #[cfg(not(target_family = "wasm"))]
            None,
        )
        .await
    }

    #[expect(
        clippy::too_many_lines,
        reason = "boot sequence: sequential setup that does not benefit from splitting"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn with_resources_and_workspace_layout_with_profile_cache_and_directory(
        session_id: SessionId,
        workspace_root: PathBuf,
        runtime_limits: astrid_capsule_types::CapsuleRuntimeLimits,
        local_egress: std::collections::HashMap<String, Vec<String>>,
        http_limits: astrid_capsule_types::HttpLimits,
        resources: KernelResources,
        workspace_layout: WorkspaceLayout,
        profile_cache: Option<Arc<PrincipalProfileCache>>,
        principal_directory: astrid_storage::PrincipalDirectory,
        #[cfg(not(target_family = "wasm"))] principal_store: Option<
            astrid_storage::RuntimePrincipalStore,
        >,
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
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            layout_origin,
        } = resources;
        #[cfg(not(unix))]
        let _ = token_path;

        home.clear_runtime_principal_scratch().map_err(|error| {
            std::io::Error::other(format!(
                "Failed to clear stale principal runtime scratch: {error}"
            ))
        })?;

        let workspace_selection = workspace_layout.resolve(&workspace_root).map_err(|error| {
            std::io::Error::new(error.kind(), format!("unsafe workspace selection: {error}"))
        })?;
        let workspace_root = workspace_selection.project_root().to_path_buf();

        let event_bus = Arc::new(EventBus::new());
        let capsules = Arc::new(RwLock::new(CapsuleRegistry::new()));

        // The canonical runtime has no native principal-home authority. Home
        // and workspace mounts are bound from the durable storage provider;
        // lifecycle compatibility callers receive an explicit `None` and
        // must not recreate a host `principal_home` tree.
        let home_root = None;

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
                // MCP is a system service, not a principal-home projection.
                // Keep native operational logs under the top-level log tree
                // so boot never recreates `home/<alias>/.local/log`.
                .with_capsule_log_dir(home.log_dir().join("system").join("mcp"));
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
            Arc::new(astrid_storage::KvIdentityStore::with_principal_directory(
                identity_kv,
                principal_directory.clone(),
            ));
        identity_store
            .load_principal_directory()
            .await
            .map_err(|error| {
                std::io::Error::other(format!(
                    "Failed to load durable principal identities: {error}"
                ))
            })?;
        let ownership_store = Arc::new(
            astrid_storage::OwnershipStore::new(Arc::clone(&kv), principal_directory.clone())
                .map_err(|error| {
                    std::io::Error::other(format!("Failed to create ownership store: {error}"))
                })?,
        );
        ownership_store.load().await.map_err(|error| {
            std::io::Error::other(format!("Failed to load ownership graph: {error}"))
        })?;

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
        // Native-only: both are CLI/disk concepts; the browser host
        // establishes identity through its own uplink instead.
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            let adopt_released_layout_principals = matches!(
                layout_origin,
                Some(legacy_migration_barrier::LayoutOrigin::Legacy)
            );
            if adopt_released_layout_principals && singleton_lock.is_none() {
                return Err(std::io::Error::other(
                    "layout-one migration requires the daemon singleton lock",
                ));
            }
            // All released native state crosses the same singleton-protected
            // barrier before identity bootstrap can mutate the default
            // profile. The durable directory loaded above already contains
            // every released principal needed by the importers.
            if let Some(layout_origin) = layout_origin {
                legacy_migration_barrier::run(
                    &home,
                    principal_store.as_ref().ok_or_else(|| {
                        std::io::Error::other(
                            "legacy migration barrier requires an authoritative principal store",
                        )
                    })?,
                    &principal_directory,
                    &audit_log,
                    layout_origin,
                    &workspace_root,
                    &workspace_layout,
                )
                .await?;
            }

            // The released profile, when present, is now represented by the
            // completed migration ledger. Apply the normal idempotent admin
            // seed before deriving the root principal identity from its key.
            seed_default_principal_admin_profile(&home).map_err(|error| {
                std::io::Error::other(format!("default admin profile bootstrap failed: {error}"))
            })?;

            // Bootstrap the CLI root user (idempotent).
            let (root_user, root_principal_identity) =
                bootstrap_cli_root_user(&identity_store, &home)
                    .await
                    .map_err(|e| {
                        std::io::Error::other(format!("Failed to bootstrap CLI root user: {e}"))
                    })?;
            bootstrap_cli_root_ownership(
                &ownership_store,
                &principal_directory,
                root_user,
                root_principal_identity,
                adopt_released_layout_principals,
            )
            .await
            .map_err(|error| {
                std::io::Error::other(format!("Failed to bootstrap CLI root ownership: {error}"))
            })?;

            // Apply pre-configured identity links from config.
            apply_identity_config(&identity_store, &workspace_root, &workspace_layout).await;

            // Import ordinary user files from the released principal-home
            // tree before the layout receipt allows the daemon to serve the
            // logical `home://` projection. Dedicated policy, capsule,
            // environment, audit, token, tmp, and operator-log migrations
            // retain their own authorities and are deliberately excluded.
            // Finish receipt-bound layout retirement after the global barrier
            // on both first cutover and restart. Existing-v2 homes may be the
            // post-sentinel/pre-unlink crash shape; `complete_layout_v2` is
            // idempotent and a fresh-layout ledger has no legacy source.
            let layout_result = if layout_origin.is_some() {
                astrid_core::dirs::LayoutMigrationTarget::for_current_executable(
                    astrid_storage::RUNTIME_STORE_FORMAT_ID,
                )
                .and_then(|target| home.complete_layout_v2(&target))
            } else {
                Ok(())
            };
            layout_result.map_err(|error| {
                std::io::Error::other(format!(
                    "Failed to commit Astrid home layout migration: {error}"
                ))
            })?;
        }

        #[cfg(not(target_family = "wasm"))]
        let workspace_branches = principal_store.clone().map(|store| {
            Arc::new(
                astrid_capsule::context::WorkspaceBranchService::new_with_ownership(
                    store,
                    principal_directory.clone(),
                    Some(Arc::clone(&ownership_store)),
                ),
            )
        });
        #[cfg(not(target_family = "wasm"))]
        if let Some(service) = workspace_branches.as_ref() {
            service.cleanup_orphaned().await.map_err(|error| {
                std::io::Error::other(format!(
                    "Failed to clean unfinished workspace branches: {error}"
                ))
            })?;
        }

        let kernel = Arc::new(Self {
            session_id: session_id.clone(),
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
            native_uplink_owns_listener: AtomicBool::new(false),
            singleton_lock,
            kv,
            principal_directory: principal_directory.clone(),
            #[cfg(not(target_family = "wasm"))]
            principal_store: principal_store.clone(),
            #[cfg(not(target_family = "wasm"))]
            workspace_branches,
            #[cfg(not(target_family = "wasm"))]
            process_storage_mount_broker: OnceLock::new(),
            audit_log: Arc::clone(&audit_log),
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            audit_sink: Arc::new(crate::audit_sink::KernelAuditSink::new(
                Arc::clone(&audit_log),
                session_id.clone(),
            )),
            runtime_key,
            active_connections: DashMap::new(),
            fuel_ledger: astrid_capsule_types::FuelLedger::default(),
            fuel_rate: astrid_capsule_types::FuelRateLimiter::default(),
            memory_ledger: astrid_capsule_types::MemoryLedger::default(),
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            compiled_wasm: astrid_capsule::engine::wasm::CompiledWasmCache::default(),
            runtime_limits,
            local_egress,
            system_capsules: RwLock::new(std::collections::HashSet::new()),
            http_limits,
            full_reload_in_flight: AtomicBool::new(false),
            capsule_load_lock: Mutex::new(()),
            capsule_view_locks: Arc::new(DashMap::new()),
            ephemeral: AtomicBool::new(false),
            boot_time: astrid_runtime::time::Instant::now(),
            shutdown_tx: tokio::sync::watch::channel(false).0,
            session_token,
            #[cfg(unix)]
            token_path,
            allowance_store,
            identity_store,
            ownership_store,
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            storage_mounts: Arc::new(DashMap::new()),
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            storage_mount_mutations: tokio::sync::Mutex::new(()),
            profile_cache: profile_cache
                .unwrap_or_else(|| Arc::new(PrincipalProfileCache::with_home(home.clone()))),
            groups,
            astrid_home: home,
            admin_write_lock: Mutex::new(()),
        });

        #[cfg(not(target_family = "wasm"))]
        let _ = kernel.process_storage_mount_broker.set(Arc::new(
            storage_mount::KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel)),
        ));

        // The management-API router, idle monitor, and capsule health/react
        // monitors drive native-only machinery (capsule lifecycle, disk
        // discovery, `process::exit`). The browser profile runs none of them.
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            drop(kernel_router::spawn_kernel_router(Arc::clone(&kernel)));
            drop(spawn_idle_monitor(Arc::clone(&kernel)));
            drop(spawn_react_watchdog(Arc::clone(&kernel)));
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
        // Wire the identity store so the dispatch admission gate remains
        // single-tenant aware, and the per-principal capsule-access resolver
        // so the user-invocable tool
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
        .with_access_resolver(access_resolver);
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

    /// Verify a path-only capsule cache against the durable package registry.
    ///
    /// The extracted directory is disposable projection state; its owner,
    /// capsule id, and archive digest are accepted only when they exactly
    /// match the authenticated immutable-UID registry snapshot. `false`
    /// means this is an explicit workspace/project portal and must use its
    /// separate installation receipt policy.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    fn verify_registry_materialization(
        &self,
        dir: &Path,
        principal: &PrincipalId,
        manifest: &astrid_capsule_types::manifest::CapsuleManifest,
    ) -> anyhow::Result<bool> {
        let cache_root = self.astrid_home.run_dir().join("capsules");
        let Ok(relative) = dir.strip_prefix(&cache_root) else {
            return Ok(false);
        };
        astrid_core::platform_fs::verify_no_redirects(dir)
            .map_err(|error| anyhow::anyhow!("capsule cache path is redirected: {error}"))?;
        let components: Vec<String> = relative
            .components()
            .map(|component| match component {
                std::path::Component::Normal(value) => Ok(value.to_string_lossy().into_owned()),
                _ => Err(anyhow::anyhow!(
                    "capsule cache path contains unsafe components"
                )),
            })
            .collect::<anyhow::Result<_>>()?;
        if components.len() != 3 {
            anyhow::bail!("capsule cache path does not contain owner/id/digest components");
        }
        let uid = self
            .principal_directory
            .uid_for(principal)
            .map_err(|error| anyhow::anyhow!("resolve capsule cache owner UID: {error}"))?;
        if components[0] != uid.to_string() || components[1] != manifest.package.name {
            anyhow::bail!("capsule cache owner or id does not match authenticated registry scope");
        }
        let capsule_id = astrid_capsule_types::CapsuleId::new(manifest.package.name.clone())
            .map_err(|error| anyhow::anyhow!("invalid materialized capsule id: {error}"))?;
        let store = self
            .principal_store
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("durable capsule registry is unavailable"))?;
        let owner = astrid_storage::StateOwner::Principal(uid);
        let verified = astrid_capsule_install::read_verified_durable_package_for_owner(
            store,
            &owner,
            capsule_id.as_str(),
        )?
        .ok_or_else(|| anyhow::anyhow!("materialized capsule is absent from durable registry"))?;
        let digest = blake3::hash(verified.archive()).to_hex().to_string();
        if components[2] != digest {
            anyhow::bail!("materialized capsule digest does not match durable registry");
        }
        if verified.manifest().package.name != manifest.package.name
            || verified.manifest().package.version != manifest.package.version
        {
            anyhow::bail!("materialized capsule manifest differs from durable registry");
        }
        let manifest_bytes = std::fs::read(dir.join("Capsule.toml"))
            .map_err(|error| anyhow::anyhow!("read materialized capsule manifest: {error}"))?;
        if manifest_bytes != verified.manifest_bytes() {
            anyhow::bail!("durable capsule manifest bytes do not match materialization");
        }
        let expansions = manifest
            .capabilities
            .expansions_from(&verified.authority().approved_capabilities);
        if !expansions.is_empty() {
            anyhow::bail!("materialized capsule manifest exceeds durable authority approval");
        }
        Ok(true)
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
        if !self.verify_registry_materialization(&dir, principal, &manifest)? {
            if self.principal_store.is_some()
                && !dir.starts_with(self.workspace_selection.state_dir())
            {
                anyhow::bail!(
                    "capsule '{}' is outside the explicit workspace portal and has no durable registry authority",
                    manifest.package.name
                );
            }
            astrid_capsule_install::verify_installed_authority(&self.astrid_home, &dir, &manifest)
                .map_err(|error| {
                    anyhow::anyhow!(
                        "capsule '{}' exceeds or cannot prove its installed authority: {error:#}",
                        manifest.package.name
                    )
                })?;
        }
        self.verify_workspace_component_paths(&dir, &manifest)?;
        let id = astrid_capsule_types::CapsuleId::from_static(&manifest.package.name);
        let _view_guard = self.lock_capsule_view(principal, &id).await;
        let _load_guard = self.capsule_load_lock.lock().await;
        if *principal != PrincipalId::default()
            && self.capabilities.is_principal_retiring(principal).await
        {
            anyhow::bail!("cannot load capsule '{id}' for retiring principal '{principal}'");
        }
        let wasm_hash = capsule_instance_hash(&manifest, &dir);
        // `capabilities.uplink` alone remains a principal-scoped daemon/host
        // grant unless the operator explicitly promotes it. A manifest that
        // actually provides an uplink must be operator-approved.
        let system_allowed = self.system_capsules.read().await.contains(id.as_str());
        let system_runtime =
            classify_runtime_residency(&manifest, &id, system_allowed)?.is_system();
        if system_runtime && !manifest.mcp_servers.is_empty() {
            anyhow::bail!(
                "system-resident capsule '{id}' cannot host principal-bearing stdio MCP servers"
            );
        }
        self.verify_workspace_capsule_tree(&dir)?;

        // Mutable runtimes are authority-scoped. A principal always receives a
        // fresh runtime for its immutable UID; only an explicitly classified
        // SystemResident service may attach another view to one runtime.
        {
            let mut registry = self.capsules.write().await;
            if registry.get_for(principal, &id).is_some() {
                return Ok(());
            }
            if system_runtime && registry.contains_system_runtime(&id, &wasm_hash) {
                registry
                    .register_existing(&id, &wasm_hash, principal)
                    .map_err(|e| anyhow::anyhow!("Failed to add capsule view: {e}"))?;
                if let Some(capsule) = registry.get_for(principal, &id) {
                    capsule.resume_for(principal);
                }
                return Ok(());
            }
        }
        if system_runtime && principal != &PrincipalId::default() {
            anyhow::bail!(
                "system-resident capsule '{id}' must be created by the operator/default view before dependents attach"
            );
        }
        // System residency is an operator/admin classification, not a host
        // path ancestry claim. The source directory is a disposable
        // materialization of the durable package registry; `system_capsules`
        // is the authenticated admission set and the installed authority
        // receipt was verified above.

        let principal_uid = self.runtime_principal_uid(system_runtime, principal, &id)?;
        let scope = principal_uid.map_or(
            astrid_capsule::registry::RuntimeScope::SystemResident,
            astrid_capsule::registry::RuntimeScope::Principal,
        );
        let runtime_id =
            self.capsules
                .write()
                .await
                .reserve_runtime_id(id.clone(), wasm_hash.clone(), scope)?;
        let mut capsule = self
            .build_capsule_runtime(
                manifest,
                &dir,
                (!system_runtime).then_some(principal),
                runtime_id.clone(),
            )
            .await?;

        if let Err(error) = activate_and_wait_ready(&id, capsule.as_mut()).await {
            capsule.request_cancel();
            if let Err(cleanup) = capsule.unload().await {
                tracing::warn!(capsule_id = %id, error = %cleanup, "Failed to unload rejected runtime candidate");
            }
            return Err(error);
        }

        if !manifest_path.exists() {
            unload_loaded_capsule_after_source_disappeared(capsule, &id, principal, &manifest_path)
                .await;
            return Ok(());
        }

        self.publish_initial_runtime(capsule, runtime_id, &wasm_hash, system_runtime, principal)
            .await
    }

    async fn publish_initial_runtime(
        &self,
        mut candidate: Box<dyn astrid_capsule::capsule::Capsule>,
        runtime_id: astrid_capsule::registry::RuntimeId,
        artifact: &astrid_capsule::registry::WasmHash,
        system_runtime: bool,
        principal: &PrincipalId,
    ) -> Result<(), anyhow::Error> {
        let id = candidate.id().clone();
        let mut registry = self.capsules.write().await;
        let already_in_view = registry.get_for(principal, &id).is_some();
        let system_winner = system_runtime && registry.contains_system_runtime(&id, artifact);
        if already_in_view || system_winner {
            if system_winner && !already_in_view {
                registry.register_existing(&id, artifact, principal)?;
                if let Some(capsule) = registry.get_for(principal, &id) {
                    capsule.resume_for(principal);
                }
            }
            drop(registry);
            candidate.request_cancel();
            if let Err(error) = candidate.unload().await {
                tracing::warn!(capsule_id = %id, %principal, %error, "Redundant capsule candidate failed to unload");
            }
            return Ok(());
        }

        let owner = Some(principal.clone());
        if let Err(publication) =
            registry.try_register_reserved_runtime(candidate, runtime_id, principal, owner)
        {
            drop(registry);
            let mut candidate = publication.capsule;
            candidate.retire();
            candidate.request_cancel();
            if let Err(cleanup) = candidate.unload().await {
                tracing::warn!(capsule_id = %id, %cleanup, "Failed to unload rejected publication candidate");
            }
            return Err(anyhow::anyhow!(publication.error));
        }
        if let Some(capsule) = registry.get_for(principal, &id) {
            capsule.resume_for(principal);
            capsule.publish();
        }
        Ok(())
    }

    fn runtime_principal_uid(
        &self,
        system_runtime: bool,
        principal: &PrincipalId,
        id: &astrid_capsule_types::CapsuleId,
    ) -> Result<Option<astrid_core::identity::PrincipalUid>, anyhow::Error> {
        if system_runtime {
            return Ok(None);
        }
        self.principal_directory
            .uid_for(principal)
            .map(Some)
            .map_err(|error| {
                anyhow::anyhow!(
                    "cannot load capsule '{id}' for unadmitted principal '{principal}': {error}"
                )
            })
    }

    /// Build and load one mutable runtime. `Some(principal)` installs that
    /// principal's concrete KV/home/env authority from construction onward.
    /// `None` is reserved for an explicitly classified `SystemResident` service
    /// and receives a neutral system namespace rather than `default` authority.
    ///
    /// # Errors
    ///
    /// Returns an error if the capsule cannot be created, the KV scope cannot be
    /// built, or `capsule.load` fails.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    async fn build_capsule_runtime(
        &self,
        manifest: astrid_capsule_types::manifest::CapsuleManifest,
        dir: &std::path::Path,
        principal: Option<&PrincipalId>,
        runtime_id: astrid_capsule::registry::RuntimeId,
    ) -> Result<Box<dyn astrid_capsule::capsule::Capsule>, anyhow::Error> {
        self.verify_workspace_capsule_tree(dir)?;
        let load_principal = principal.cloned().unwrap_or_default();

        let loader = astrid_capsule::loader::CapsuleLoader::new(
            self.mcp.clone(),
            self.fuel_ledger.clone(),
            self.fuel_rate.clone(),
            self.memory_ledger.clone(),
            self.runtime_limits,
            self.http_limits,
        )
        .with_compiled_wasm_cache(self.compiled_wasm.clone())
        .with_runtime_id(runtime_id)
        .with_deferred_background_activation();
        let mut capsule = loader.create_capsule(manifest, dir.to_path_buf())?;
        let capsule_name = capsule.id().to_string();

        let kv = astrid_storage::ScopedKvStore::new(
            Arc::clone(&self.kv),
            principal.map_or_else(
                || format!("system:capsule:{}", capsule.id()),
                |principal| format!("{principal}:capsule:{}", capsule.id()),
            ),
        )?;

        // Environment configuration is loaded from the host-only typed
        // control namespace during invocation setup. Never read a capsule
        // directory `.env.json` or a principal-home env file here: those paths
        // are legacy import sources only and are not authoritative runtime
        // state.
        self.verify_workspace_capsule_tree(dir)?;

        let capsule_listener = (!self.native_uplink_owns_listener.load(Ordering::Acquire))
            .then(|| self.cli_socket_listener.clone())
            .flatten();
        let ctx = astrid_capsule::context::CapsuleContext::new(
            load_principal,
            self.workspace_root.clone(),
            // Durable home VFS authority is threaded separately through the
            // UID-bound principal store. Do not pass a native PrincipalHome
            // path into the steady-state capsule context.
            None,
            kv,
            Arc::clone(&self.event_bus),
            capsule_listener,
        )
        .with_astrid_workspace()
        .with_principal_storage(
            self.principal_store.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "native capsule runtime requires the authoritative principal store"
                )
            })?,
            self.principal_directory.clone(),
        )
        .with_workspace_branches(self.workspace_branches.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "canonical Astrid workspace requires the kernel workspace branch service"
            )
        })?)
        .with_process_storage_mount_broker(
            self.process_storage_mount_broker
                .get()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("native process storage mount broker unavailable"))?,
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
        .with_audit_sink(self.audit_sink.as_ref().clone());
        capsule.load(&ctx).await?;
        Ok(capsule)
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    async fn prepare_runtime_replacement(
        &self,
        id: &astrid_capsule_types::CapsuleId,
        source_dir: &Path,
        principal: &PrincipalId,
        expected_scope: astrid_capsule::registry::RuntimeScope,
    ) -> Result<PreparedRuntimeReplacement, anyhow::Error> {
        self.verify_workspace_capsule_tree(source_dir)?;
        let manifest_path = source_dir.join("Capsule.toml");
        let manifest = astrid_capsule::discovery::load_manifest(&manifest_path)
            .map_err(|error| anyhow::anyhow!(error))?;
        if manifest.package.name != id.as_str() {
            anyhow::bail!(
                "replacement manifest id '{}' does not match running capsule '{id}'",
                manifest.package.name
            );
        }
        if !self.verify_registry_materialization(source_dir, principal, &manifest)? {
            if self.principal_store.is_some()
                && !source_dir.starts_with(self.workspace_selection.state_dir())
            {
                anyhow::bail!(
                    "capsule replacement source is outside the explicit workspace portal and has no durable registry authority"
                );
            }
            astrid_capsule_install::verify_installed_authority(
                &self.astrid_home,
                source_dir,
                &manifest,
            )?;
        }
        self.verify_workspace_component_paths(source_dir, &manifest)?;
        if !manifest.mcp_servers.is_empty() {
            anyhow::bail!(
                "live replacement of stdio MCP capsule '{id}' is not yet atomic; restart the daemon to activate these process changes"
            );
        }
        let artifact = capsule_instance_hash(&manifest, source_dir);
        let system_allowed = self.system_capsules.read().await.contains(id.as_str());
        let system_runtime = classify_runtime_residency(&manifest, id, system_allowed)?.is_system();
        if system_runtime && !manifest.mcp_servers.is_empty() {
            anyhow::bail!(
                "system-resident capsule '{id}' cannot host principal-bearing stdio MCP servers"
            );
        }
        // Replacement authority is the authenticated operator classification
        // and installed receipt, never the ancestry of `source_dir`.
        let actual_scope = if system_runtime {
            astrid_capsule::registry::RuntimeScope::SystemResident
        } else {
            astrid_capsule::registry::RuntimeScope::Principal(
                self.principal_directory.uid_for(principal)?,
            )
        };
        if actual_scope != expected_scope {
            anyhow::bail!(
                "capsule '{id}' cannot change runtime scope during live replacement: \
                 running={expected_scope:?}, installed={actual_scope:?}"
            );
        }
        let principal_uid = self.runtime_principal_uid(system_runtime, principal, id)?;
        let runtime_id =
            self.capsules
                .write()
                .await
                .reserve_runtime_id(id.clone(), artifact, actual_scope)?;
        let mut capsule = self
            .build_capsule_runtime(
                manifest,
                source_dir,
                (!system_runtime).then_some(principal),
                runtime_id.clone(),
            )
            .await?;
        if !manifest_path.exists() {
            anyhow::bail!(
                "capsule source disappeared while preparing replacement: {}",
                manifest_path.display()
            );
        }
        if let Err(error) = activate_and_wait_ready(id, capsule.as_mut()).await {
            capsule.request_cancel();
            if let Err(cleanup) = capsule.unload().await {
                tracing::warn!(capsule_id = %id, error = %cleanup, "Failed to unload rejected replacement candidate");
            }
            return Err(error);
        }
        Ok(PreparedRuntimeReplacement {
            capsule,
            runtime_id,
            principal_uid,
            system_runtime,
        })
    }

    /// Restart the exact runtime generation visible to `principal`. Principal
    /// failures affect only that immutable UID. A `SystemResident` failure
    /// rebuilds its explicit singleton and restores its dependent views.
    ///
    /// The replacement is activated behind a closed route-admission gate and
    /// must become ready before it is atomically published. Returns
    /// [`RestartOutcome::Clean`] when the old runtime was then fully unloaded,
    /// or [`RestartOutcome::OldInstanceLingering`] when another `Arc` still
    /// holds its already-cancelled resources.
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
        expected_runtime: Option<&astrid_capsule::registry::RuntimeId>,
    ) -> Result<RestartOutcome, anyhow::Error> {
        let (source_dir, current_runtime) = {
            let registry = self.capsules.read().await;
            let capsule = registry
                .get_for(principal, id)
                .ok_or_else(|| anyhow::anyhow!("capsule '{id}' not found in registry"))?;
            let runtime_id = registry
                .runtime_id_for(principal, id)
                .ok_or_else(|| anyhow::anyhow!("capsule '{id}' not found in registry"))?;
            if expected_runtime.is_some_and(|expected| expected != &runtime_id) {
                return Ok(RestartOutcome::Superseded);
            }
            let source_dir = capsule
                .source_dir()
                .map(std::path::Path::to_path_buf)
                .ok_or_else(|| anyhow::anyhow!("capsule '{id}' has no source directory"))?;
            (source_dir, runtime_id)
        };

        // Prepare and prove a route-gated replacement while the current
        // generation remains visible and healthy. A preparation or readiness
        // failure leaves the running view untouched.
        let mut prepared = self
            .prepare_runtime_replacement(id, &source_dir, principal, current_runtime.key().scope())
            .await?;

        let load_guard = self.capsule_load_lock.lock().await;
        if self.capabilities.is_principal_retiring(principal).await {
            drop(load_guard);
            prepared.capsule.retire();
            prepared.capsule.request_cancel();
            if let Err(cleanup) = prepared.capsule.unload().await {
                tracing::warn!(capsule_id = %id, %cleanup, "Failed to unload replacement rejected by principal retirement");
            }
            anyhow::bail!("cannot replace capsule '{id}' for retiring principal '{principal}'");
        }
        let (mut previous, replacement) = {
            let mut registry = self.capsules.write().await;
            if registry.runtime_id_for(principal, id).as_ref() != Some(&current_runtime) {
                drop(registry);
                drop(load_guard);
                prepared.capsule.request_cancel();
                prepared.capsule.unload().await?;
                return Ok(RestartOutcome::Superseded);
            }
            if prepared.system_runtime
                && let Err(error) = registry.validate_system_runtime_replacement(
                    &current_runtime,
                    prepared.capsule.as_ref(),
                    &prepared.runtime_id,
                )
            {
                drop(registry);
                drop(load_guard);
                prepared.capsule.retire();
                prepared.capsule.request_cancel();
                if let Err(cleanup) = prepared.capsule.unload().await {
                    tracing::warn!(capsule_id = %id, %cleanup, "Failed to unload rejected replacement publication");
                }
                return Err(anyhow::anyhow!(error));
            }
            let replaced = if prepared.system_runtime {
                registry.replace_system_runtime_reserved(
                    &current_runtime,
                    prepared.capsule,
                    prepared.runtime_id,
                )?
            } else {
                registry.replace_principal_runtime_reserved(
                    &current_runtime,
                    prepared.capsule,
                    prepared.runtime_id,
                    principal,
                    prepared
                        .principal_uid
                        .expect("principal replacement resolved durable uid"),
                )?
            };
            let replacement = registry
                .get_for(principal, id)
                .expect("replacement generation was atomically published");

            // Close the old generation before publishing the candidate's
            // already-ready routes. Dispatcher lookups already resolve the new
            // view, so no interval admits fresh work to both generations.
            replaced.previous.retire();
            replaced.previous.request_cancel();
            for viewer in registry.principals_viewing_runtime(&replaced.runtime_id) {
                replacement.resume_for(&viewer);
            }
            replacement.publish();
            (replaced.previous, replacement)
        };
        drop(load_guard);

        let outcome = unload_replaced_runtime(id, &mut previous).await;
        if let Err(error) = replacement
            .invoke_interceptor("handle_lifecycle_restart", &[], None)
            .await
        {
            tracing::debug!(
                capsule_id = %id,
                error = %error,
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
                kernel.publish_capsules_loaded_for(principal).await;
            }

            for principal in principals {
                if principal != PrincipalId::default() {
                    kernel.ensure_principal_loaded(&principal).await;
                    kernel.publish_capsules_loaded_for(&principal).await;
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
        // (native control plane only) boots clean yet silently drops every prompt —
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
        if *principal != PrincipalId::default() {
            // The retirement fence is authoritative while deletion retains the
            // profile long enough for quota-aware state reclamation. Check it
            // under the same load lock used by unload so a queued loader cannot
            // re-attach a view after retirement begins.
            if self.capabilities.is_principal_retiring(principal).await {
                tracing::debug!(%principal, "Skipping capsule load for retiring principal");
                return;
            }
            if !astrid_core::profile::PrincipalProfile::path_for(&self.astrid_home, principal)
                .exists()
            {
                tracing::debug!(%principal, "Skipping capsule load for principal without a profile");
                return;
            }
        }
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

    /// Load a principal's capsule view and prove that every explicitly required
    /// capsule reached readiness before returning.
    ///
    /// The ordinary background warm path remains best-effort for compatibility;
    /// derived sessions use this checked edge because returning a principal that
    /// cannot run its selected harness would violate the atomic derive contract.
    pub(crate) async fn ensure_principal_capsules_ready(
        &self,
        principal: &PrincipalId,
        required: &[String],
    ) -> Result<(), String> {
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            let _ = (principal, required);
            return Err("capsule loading is unavailable in the portable kernel build".to_string());
        }

        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            use astrid_capsule::capsule::ReadyStatus;

            self.ensure_principal_loaded(principal).await;
            let capsules = {
                let registry = self.capsules.read().await;
                let mut capsules = Vec::with_capacity(required.len());
                for name in required {
                    let id = astrid_capsule_types::CapsuleId::new(name.clone())
                        .map_err(|error| format!("invalid required capsule '{name}': {error}"))?;
                    let capsule = registry.get_for(principal, &id).ok_or_else(|| {
                        format!(
                            "required capsule '{name}' failed to load for principal '{principal}'"
                        )
                    })?;
                    capsules.push((name.clone(), capsule));
                }
                capsules
            };

            let timeout = std::time::Duration::from_millis(500);
            let mut waits = tokio::task::JoinSet::new();
            for (name, capsule) in capsules {
                waits.spawn(async move { (name, capsule.wait_ready(timeout).await) });
            }
            while let Some(result) = waits.join_next().await {
                let (name, status) = result
                    .map_err(|error| format!("required capsule readiness task failed: {error}"))?;
                match status {
                    ReadyStatus::Ready => {},
                    ReadyStatus::Timeout => {
                        return Err(format!(
                            "required capsule '{name}' did not signal ready within {}ms",
                            timeout.as_millis()
                        ));
                    },
                    ReadyStatus::Crashed => {
                        return Err(format!(
                            "required capsule '{name}' exited before signaling ready"
                        ));
                    },
                }
            }
            Ok(())
        }
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    async fn ensure_principal_uplinks_loaded(&self, principal: &PrincipalId) {
        if *principal != PrincipalId::default()
            && self.capabilities.is_principal_retiring(principal).await
        {
            tracing::debug!(%principal, "Skipping uplink load for retiring principal");
            return;
        }
        if *principal != PrincipalId::default()
            && !astrid_core::profile::PrincipalProfile::path_for(&self.astrid_home, principal)
                .exists()
        {
            tracing::debug!(%principal, "Skipping uplink load for principal without a profile");
            return;
        }
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

        let mut paths = self.durable_principal_capsule_paths(principal);
        // Workspace capsules are an explicit project portal and remain the
        // lowest-priority discovery source. They never establish authority
        // for an Astrid principal package.
        let workspace_paths = capsule_discovery_paths_for(
            &self.astrid_home,
            &self.workspace_root,
            principal,
            &self.workspace_layout,
        );
        paths.extend(workspace_paths);
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

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    fn durable_principal_capsule_paths(&self, principal: &PrincipalId) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(store) = self.principal_store.as_ref() {
            match self.principal_directory.uid_for(principal) {
                Ok(uid) => {
                    let owner = astrid_storage::StateOwner::Principal(uid);
                    match store.capsules().list(&owner) {
                        Ok(packages) => {
                            for summary in packages {
                                let id = summary.id().to_owned();
                                let Ok(Some(snapshot)) = store.capsules().get_snapshot(&owner, &id)
                                else {
                                    tracing::warn!(
                                        %principal,
                                        capsule = %id,
                                        "Skipping durable capsule whose package disappeared"
                                    );
                                    continue;
                                };
                                let digest = blake3::hash(&snapshot.package().archive)
                                    .to_hex()
                                    .to_string();
                                let target = match astrid_capsule_install::resolve_cache_target_dir(
                                    &self.astrid_home,
                                    uid,
                                    &id,
                                    &digest,
                                    false,
                                    None,
                                    &self.workspace_layout,
                                ) {
                                    Ok(target) => target,
                                    Err(error) => {
                                        tracing::warn!(
                                            %principal,
                                            capsule = %id,
                                            error = %error,
                                            "Skipping durable capsule with unsafe materialization target"
                                        );
                                        continue;
                                    },
                                };
                                if !target.exists()
                                    && let Err(error) =
                                        astrid_capsule_install::materialize_capsule_package(
                                            snapshot.package(),
                                            &target,
                                        )
                                {
                                    tracing::warn!(
                                        %principal,
                                        capsule = %id,
                                        error = %error,
                                        "Skipping durable capsule that failed materialization"
                                    );
                                    continue;
                                }
                                paths.push(target);
                            }
                        },
                        Err(error) => {
                            tracing::warn!(
                                %principal,
                                error = %error,
                                "Durable capsule registry unavailable during discovery"
                            );
                        },
                    }
                },
                Err(error) => {
                    tracing::warn!(
                        %principal,
                        error = %error,
                        "Skipping durable capsule discovery without immutable principal UID"
                    );
                },
            }
        }
        paths
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
                        kernel.publish_capsules_loaded_for(&principal).await;
                        if Self::topic_has_subscriber(Arc::clone(&kernel.capsules), topic.clone())
                            .await
                        {
                            return true;
                        }
                        kernel.ensure_principal_loaded(&principal).await;
                        kernel.publish_capsules_loaded_for(&principal).await;
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

        self.publish_capsules_loaded_snapshot(capsules, &PrincipalId::default())
            .await;
    }

    /// Publish the current capsule inventory for exactly one principal view.
    ///
    /// Provisioning and profile mutation already carry the affected principal;
    /// re-describing every other live view in those paths turns one local
    /// mutation into fleet-wide work. Snapshot the target view while holding the
    /// registry lock, then perform all filesystem and guest calls after release.
    /// An empty view still emits an empty inventory so consumers can discard a
    /// previously cached tool surface for this principal.
    pub(crate) async fn publish_capsules_loaded_for(&self, principal: &PrincipalId) {
        let capsules = {
            let reg = self.capsules.read().await;
            reg.cloned_values_for(principal)
                .into_iter()
                .map(|capsule| (principal.clone(), capsule))
                .collect()
        };

        self.publish_capsules_loaded_snapshot(capsules, principal)
            .await;
    }

    async fn publish_capsules_loaded_snapshot(
        &self,
        capsules: Vec<(PrincipalId, Arc<dyn astrid_capsule::capsule::Capsule>)>,
        empty_principal: &PrincipalId,
    ) {
        let mut by_principal = std::collections::BTreeMap::<
            String,
            Vec<(String, String, Option<serde_json::Value>)>,
        >::new();
        for (principal, capsule) in &capsules {
            let name = capsule.id().to_string();
            let mut meta = capsule.source_dir().and_then(|source_dir| {
                self.verify_workspace_capsule_tree(source_dir).ok()?;
                let meta = capsules_loaded::read_capsule_meta_opaque(source_dir);
                self.verify_workspace_capsule_tree(source_dir).ok()?;
                meta
            });
            // `tools` is live-owned data. Strip surfaces persisted by older
            // Astrid releases before probing so an unavailable/failed probe
            // leaves the field genuinely absent and consumer fan-out can run.
            meta = capsules_loaded::without_tools(meta);

            // Probe the live instance for its tool surface and inject it. Best-
            // effort: a describe (or serialize) failure leaves `tools` absent
            // and the consumer falls back to its fan-out for this cycle.
            match astrid_capsule::describe_loaded_capsule_status_for(capsule.as_ref(), principal)
                .await
            {
                Ok(Some(tools)) => {
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
                Ok(None) => {
                    // Pool-less / run-loop capsule: the interceptor describe
                    // can't run, so leave `tools` ABSENT (not `[]`). The
                    // consumer's describe fan-out then fires and the capsule's
                    // own `tool.v1.request.describe` responder supplies its
                    // surface. Injecting `[]` reads as "0 tools" and suppresses
                    // the fan-out (#1198).
                    tracing::debug!(
                        capsule_id = %name,
                        "pool-less/run-loop capsule: leaving tools absent so the describe fan-out fires (#1198)"
                    );
                },
                Err(e) => tracing::debug!(
                    capsule_id = %name, error = %e,
                    "live tool_describe failed; capsule left uncaptured this cycle"
                ),
            }
            by_principal
                .entry(principal.to_string())
                .or_default()
                .push((principal.to_string(), name, meta));
        }
        if by_principal.is_empty() {
            by_principal.insert(empty_principal.to_string(), Vec::new());
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
        let view_guard = self.lock_capsule_view(principal, id).await;
        let registered = { self.capsules.read().await.get_for(principal, id).is_some() };
        if registered {
            if self.capabilities.is_principal_retiring(principal).await {
                anyhow::bail!("cannot reload capsule '{id}' for retiring principal '{principal}'");
            }
            self.restart_capsule(id, principal, None).await?;
            self.publish_capsules_loaded().await;
        } else {
            drop(view_guard);
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
        let _view_guard = self.lock_capsule_view(principal, id).await;
        let load_guard = self.capsule_load_lock.lock().await;
        // A principal runtime is always torn down. An operator-owned
        // `SystemResident` runtime survives until its final view is released.
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
        // Registration/reload is serialized by `capsule_load_lock`, so the
        // registry map lock can be released before awaiting the old runtime's
        // drain. This avoids a lock cycle with admitted host calls that perform
        // generation-scoped registry reads.
        if removed.torn_down {
            // The generation is no longer reachable from the registry. Close
            // every admission path before releasing the global publication
            // lock, then let generation-owned teardown drain independently.
            // This preserves hard MCP process-tree cleanup without allowing a
            // wedged child to block unrelated principals' lifecycle work.
            removed.capsule.retire();
            removed.capsule.request_cancel();
            drop(load_guard);
            removed.capsule.quiesce_for(principal).await;
        } else {
            // The keyed view guard prevents this exact view from reattaching
            // while its retirement tombstone drains. The old generation is
            // still reachable by peer views, so only principal-scoped work is
            // quiesced; unrelated lifecycle work need not wait behind it.
            drop(load_guard);
            removed.capsule.quiesce_for(principal).await;
        }

        // Explicitly unload the old capsule only when this was the last view.
        // There is no Drop impl that calls unload() (it's async), so we must do
        // it here to avoid leaking MCP subprocesses and other engine resources.
        // Arc::get_mut requires exclusive ownership (strong_count == 1).
        if removed.torn_down {
            let mut old = removed.capsule;
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
            // The SystemResident runtime survives — but the departing view's
            // in-flight blocking host calls (approval/elicit waits, net/io/ipc
            // waits) would otherwise keep running inside it with nothing left
            // to answer them, wedging the system runtime for every remaining
            // principal. Cancel exactly that principal's waits; everyone
            // else's work is untouched (per-principal child tokens, not the
            // instance-wide `request_cancel`).
            // The lifecycle fence rejects late admissions, cancels blocking
            // host work, and waits for interceptor calls admitted before
            // unregister to return. The cancelled token remains as a tombstone
            // until an explicit future view registration reopens the identity.
            tracing::debug!(
                capsule_id = %id,
                principal = %principal,
                "Unloaded one view of a SystemResident runtime; other principals still \
                 reference it, so the runtime is left running and only the \
                 departing principal's in-flight host calls were cancelled"
            );
        }

        self.publish_capsules_loaded().await;
        Ok(true)
    }

    /// Atomically remove one capsule package from the authenticated owner's
    /// durable registry, then tear down the corresponding live view. Native
    /// install directories are never consulted or deleted by this path.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable store or owner mapping is unavailable,
    /// the registry mutation fails, or the live view cannot be unloaded.
    #[cfg(not(target_family = "wasm"))]
    pub(crate) async fn remove_one_capsule(
        &self,
        id: &astrid_capsule_types::CapsuleId,
        principal: &PrincipalId,
    ) -> Result<bool, anyhow::Error> {
        let store = self
            .principal_store
            .clone()
            .ok_or_else(|| anyhow::anyhow!("authoritative principal store is unavailable"))?;
        let uid = self
            .principal_directory
            .uid_for(principal)
            .map_err(|error| anyhow::anyhow!("resolve durable owner for {principal}: {error}"))?;
        let owner = astrid_storage::StateOwner::Principal(uid);
        let snapshot = store
            .capsules()
            .get_snapshot(&owner, id.as_str())
            .map_err(|error| anyhow::anyhow!("read durable capsule package '{id}': {error}"))?;
        if snapshot.is_none() {
            return Ok(false);
        }
        // Quiesce and unload before deleting the durable package. If unload
        // fails, the package remains authoritative and can be retried on the
        // next request; no live runtime is left without its registry source.
        let _ = self.unload_one_capsule(id, principal).await?;
        let removed = match store.capsules().remove(&owner, id.as_str()) {
            Ok(removed) => removed,
            Err(error) => {
                self.ensure_principal_loaded(principal).await;
                return Err(anyhow::anyhow!(
                    "remove durable capsule package '{id}': {error}"
                ));
            },
        };
        if !removed {
            // A concurrent administrative writer won the generation race. The
            // durable package is still authoritative; restore the just-closed
            // runtime view before surfacing the conflict.
            self.ensure_principal_loaded(principal).await;
            return Err(anyhow::anyhow!(
                "durable capsule package '{id}' disappeared during removal"
            ));
        }
        Ok(true)
    }

    #[cfg(target_family = "wasm")]
    pub(crate) async fn remove_one_capsule(
        &self,
        _id: &astrid_capsule_types::CapsuleId,
        _principal: &PrincipalId,
    ) -> Result<bool, anyhow::Error> {
        Err(anyhow::anyhow!(
            "durable capsule removal is unavailable on portable hosts"
        ))
    }

    /// Remove every capsule view owned by `principal` before that principal's
    /// persistent state is reclaimed.
    ///
    /// The load lock closes the race with background warm/install discovery:
    /// once the profile/identity fence has closed new authorization, no loader
    /// can re-attach a view between the snapshot and the last unload. Each
    /// release uses [`Self::unload_one_capsule`]. Principal runtimes are always
    /// removed; dependent `SystemResident` views survive only while their
    /// explicit owner remains installed.
    pub(crate) async fn unload_principal_capsules(
        &self,
        principal: &PrincipalId,
    ) -> Result<Vec<astrid_capsule_types::CapsuleId>, anyhow::Error> {
        let mut ids: Vec<_> = {
            let registry = self.capsules.read().await;
            registry.list_for(principal).into_iter().cloned().collect()
        };
        ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));

        let mut unloaded = Vec::with_capacity(ids.len());
        for id in ids {
            if self.unload_one_capsule(&id, principal).await? {
                unloaded.push(id);
            }
        }
        Ok(unloaded)
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
            capsule.promote_workspace(principal).await
        } else {
            capsule.rollback_workspace(principal).await
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

        if result.is_ok() {
            self.request_ephemeral_shutdown_if_idle();
        }
    }

    /// Enable or disable ephemeral mode (immediate shutdown on last disconnect).
    pub fn set_ephemeral(&self, val: bool) {
        self.ephemeral.store(val, Ordering::Relaxed);
    }

    /// Arm the never-connected fallback after the daemon has published
    /// readiness and clients are able to establish lifecycle leases.
    pub fn arm_ephemeral_startup_fallback(self: &Arc<Self>) {
        drop(spawn_ephemeral_startup_fallback(
            Arc::clone(self),
            EPHEMERAL_STARTUP_GRACE,
        ));
    }

    fn request_ephemeral_shutdown_if_idle(&self) {
        if !self.ephemeral.load(Ordering::Relaxed) || self.total_connection_count() != 0 {
            return;
        }
        tracing::info!("Last client disconnected, shutting down ephemeral kernel");
        self.shutdown_tx.send_replace(true);
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

        // 2. Release persistent resources FIRST — BEFORE the best-effort
        // capsule drain. The audit SurrealKV `LOCK` and principal-store file
        // handles MUST be freed on the graceful path regardless of how long
        // the drain takes: each capsule's
        // unload is bounded (~1s of `Arc::get_mut` retries) but a large fleet
        // draining sequentially could exceed the OS-thread watchdog's force-exit
        // grace, and a force-exit with the audit `LOCK` still held is the exact
        // wedge this whole change closes. Nothing in the drain below reads
        // KV/audit (WASM unload = cancel/abort/drop; MCP unload = subprocess
        // disconnect), and `clear_session()` above was the last KV writer, so
        // closing the stores ahead of the drain is safe and makes the lock
        // release independent of drain time.
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        self.audit_sink.shutdown();
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
            let _ = astrid_core::local_transport::remove_endpoint(&socket_path);
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
async fn open_test_runtime_kv(
    home: &astrid_core::dirs::AstridHome,
) -> (
    Arc<dyn astrid_storage::KvStore>,
    astrid_storage::PrincipalDirectory,
    astrid_storage::RuntimePrincipalStore,
) {
    let directory = astrid_storage::PrincipalDirectory::default();
    let quota_home = home.clone();
    let quota_directory = directory.clone();
    let quota: Arc<dyn astrid_storage::KvQuotaResolver<astrid_storage::StateOwner>> =
        Arc::new(move |owner: &astrid_storage::StateOwner| match owner {
            astrid_storage::StateOwner::System => Ok(None),
            astrid_storage::StateOwner::Principal(uid) => {
                quota_directory
                    .alias_for(*uid)
                    .map_or(Ok(None), |principal| {
                        astrid_core::profile::PrincipalProfile::load_required(
                            &quota_home,
                            &principal,
                        )
                        .map(|profile| Some(profile.quotas.max_storage_bytes))
                        .map_err(|error| {
                            astrid_storage::StorageError::Internal(format!(
                                "resolve storage quota for {principal}: {error}"
                            ))
                        })
                    })
            },
            astrid_storage::StateOwner::Fleet(_) => {
                Ok(Some(astrid_core::profile::DEFAULT_MAX_STORAGE_BYTES))
            },
        });
    let store =
        astrid_storage::open_runtime_principal_store_with_directory(home, quota, directory.clone())
            .await
            .expect("test kernel: open authoritative principal store");
    let kv = store.kv();
    (kv, directory, store)
}

#[cfg(test)]
fn open_test_identity_stores(
    kv: &Arc<dyn astrid_storage::KvStore>,
    principal_directory: astrid_storage::PrincipalDirectory,
) -> (
    Arc<dyn astrid_storage::IdentityStore>,
    Arc<astrid_storage::OwnershipStore>,
) {
    let identity_kv = astrid_storage::ScopedKvStore::new(Arc::clone(kv), "system:identity")
        .expect("test kernel: identity kv scope");
    let identity_store = Arc::new(astrid_storage::KvIdentityStore::with_principal_directory(
        identity_kv,
        principal_directory.clone(),
    ));
    let ownership_store = Arc::new(
        astrid_storage::OwnershipStore::new(Arc::clone(kv), principal_directory)
            .expect("test kernel: ownership store"),
    );
    (identity_store, ownership_store)
}

#[cfg(test)]
fn test_workspace_selection(home: &astrid_core::dirs::AstridHome) -> WorkspaceSelection {
    WorkspaceLayout::default()
        .resolve(home.root())
        .expect("test workspace selection")
}

#[cfg(test)]
#[expect(
    clippy::too_many_lines,
    reason = "the complete kernel test fixture keeps every security-relevant dependency explicit"
)]
pub(crate) async fn test_kernel_with_home(home: astrid_core::dirs::AstridHome) -> Arc<Kernel> {
    use astrid_capsule::profile_cache::PrincipalProfileCache;

    home.ensure()
        .expect("test kernel: ensure astrid home dir tree");

    let session_id = SessionId::SYSTEM;
    let event_bus = Arc::new(EventBus::new());
    let capsules = Arc::new(RwLock::new(CapsuleRegistry::new()));

    // Use the same authoritative principal-store composition as native boot.
    // A test helper opening the legacy import source directly would let kernel
    // tests pass against a runtime topology that production cannot select.
    let (kv, principal_directory, principal_store) = open_test_runtime_kv(&home).await;
    let capabilities = Arc::new(
        CapabilityStore::with_kv_store(Arc::clone(&kv))
            .await
            .expect("test kernel: capability store"),
    );

    // Audit log uses the same system-owned principal-store projection as
    // production; no principal-home directory is authoritative.
    let runtime_key = Arc::new(astrid_crypto::KeyPair::generate());
    let audit_store = principal_store
        .system_control_kv("audit")
        .expect("test kernel: audit control projection")
        .backend();
    let audit_log = Arc::new(
        AuditLog::open_with_kv_store(audit_store, Arc::clone(&runtime_key))
            .expect("test kernel: open audit log"),
    );

    // Admin tests exercise the real UID-bound storage path. Seed the default
    // principal through the authoritative identity store rather than merely
    // writing a profile; handlers must be able to resolve its immutable UID.
    let (identity_store, ownership_store) =
        open_test_identity_stores(&kv, principal_directory.clone());
    identity_store
        .create_principal(PrincipalId::default(), [7; 32])
        .await
        .expect("test kernel: seed default principal identity");

    // `AstridHome::ensure` has already written the v2 sentinel. Complete the
    // fresh-home barrier receipt in the fixture so delete/reclaim tests model
    // an admitted runtime rather than bypassing the production gate. The
    // fixture writes the exact canonical empty-home ledger shape; production
    // still obtains it only through `legacy_migration_barrier::run`.
    seed_test_migration_ledger(&home);

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

    let groups = Arc::new(ArcSwap::from_pointee(
        GroupConfig::load(&home).expect("test kernel: load groups"),
    ));

    let kernel = Arc::new(Kernel {
        session_id: session_id.clone(),
        event_bus,
        capsules,
        mcp,
        capabilities,
        vfs: Arc::new(kernel_host_vfs) as Arc<dyn Vfs>,
        overlay_registry,
        vfs_root_handle: root_handle,
        workspace_root: home.root().to_path_buf(),
        workspace_layout: WorkspaceLayout::default(),
        workspace_selection: test_workspace_selection(&home),
        home_root: None,
        cli_socket_listener: None,
        native_uplink_owns_listener: AtomicBool::new(false),
        singleton_lock: None,
        kv,
        principal_directory: principal_directory.clone(),
        #[cfg(not(target_family = "wasm"))]
        principal_store: Some(principal_store.clone()),
        #[cfg(not(target_family = "wasm"))]
        workspace_branches: Some(Arc::new(
            astrid_capsule::context::WorkspaceBranchService::new_with_ownership(
                principal_store,
                principal_directory,
                Some(Arc::clone(&ownership_store)),
            ),
        )),
        #[cfg(not(target_family = "wasm"))]
        process_storage_mount_broker: OnceLock::new(),
        audit_log: Arc::clone(&audit_log),
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        audit_sink: Arc::new(crate::audit_sink::KernelAuditSink::new(
            Arc::clone(&audit_log),
            session_id.clone(),
        )),
        runtime_key,
        active_connections: DashMap::new(),
        fuel_ledger: astrid_capsule_types::FuelLedger::default(),
        fuel_rate: astrid_capsule_types::FuelRateLimiter::default(),
        memory_ledger: astrid_capsule_types::MemoryLedger::default(),
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        compiled_wasm: astrid_capsule::engine::wasm::CompiledWasmCache::default(),
        runtime_limits: astrid_capsule_types::CapsuleRuntimeLimits::default(),
        local_egress: std::collections::HashMap::new(),
        system_capsules: RwLock::new(std::collections::HashSet::new()),
        http_limits: astrid_capsule_types::HttpLimits::default(),
        full_reload_in_flight: AtomicBool::new(false),
        capsule_load_lock: Mutex::new(()),
        capsule_view_locks: Arc::new(DashMap::new()),
        ephemeral: AtomicBool::new(false),
        boot_time: astrid_runtime::time::Instant::now(),
        shutdown_tx: tokio::sync::watch::channel(false).0,
        session_token: Arc::new(astrid_core::session_token::SessionToken::generate()),
        #[cfg(unix)]
        token_path: home.token_path(),
        allowance_store,
        identity_store,
        ownership_store,
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        storage_mounts: Arc::new(DashMap::new()),
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        storage_mount_mutations: tokio::sync::Mutex::new(()),
        profile_cache: Arc::new(PrincipalProfileCache::with_home(home.clone())),
        groups,
        astrid_home: home,
        admin_write_lock: Mutex::new(()),
    });
    #[cfg(not(target_family = "wasm"))]
    let _ = kernel.process_storage_mount_broker.set(Arc::new(
        storage_mount::KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel)),
    ));
    // Spawn the Layer 6 admin dispatcher so IPC-driven tests can drive
    // the full publish → response loop. State-mutating tests that call
    // `handlers::dispatch` directly are unaffected — those messages
    // never hit the bus.
    drop(kernel_router::admin::spawn_admin_router(Arc::clone(
        &kernel,
    )));
    kernel
}

#[cfg(test)]
fn seed_test_migration_ledger(home: &astrid_core::dirs::AstridHome) {
    #[derive(serde::Serialize)]
    struct Source {
        digest: &'static str,
        entries: u64,
        bytes: u64,
        present: bool,
    }
    #[derive(serde::Serialize)]
    struct Component {
        name: &'static str,
        source: Source,
        destination_proof: &'static str,
    }
    #[derive(serde::Serialize)]
    struct Ledger {
        schema: u32,
        complete: bool,
        components: Vec<Component>,
    }

    let component = |name: &'static str, destination_proof: &'static str| Component {
        name,
        source: Source {
            digest: "absent",
            entries: 0,
            bytes: 0,
            present: false,
        },
        destination_proof,
    };
    let ledger = Ledger {
        schema: 1,
        complete: true,
        components: vec![
            component("system:capsule-authority", "absent"),
            component(
                "system:cow",
                "verified-discard-v1:source-digest=absent:layout-receipt=layout-v1-to-v2.complete",
            ),
            component(
                "system:fresh-layout",
                "fresh-layout-v1:initialized-without-legacy-sources",
            ),
            component("system:gateway-revocations", "absent"),
            component("system:host-secrets", "absent"),
            component("system:invites", "absent"),
            component("system:pair-tokens", "absent"),
            component("system:state-db", "absent"),
        ],
    };
    let mut bytes = serde_json::to_vec(&ledger).expect("test kernel: encode migration ledger");
    bytes.push(b'\n');
    astrid_core::platform_fs::atomic_write_private_file(
        &home.migrations_dir().join("layout-v2-components.complete"),
        &bytes,
    )
    .expect("test kernel: write migration ledger");
}

#[cfg(unix)]
struct RuntimeAuditCapacityProvider {
    store: astrid_storage::RuntimePrincipalStore,
}

#[cfg(unix)]
impl AuditCapacityProvider for RuntimeAuditCapacityProvider {
    fn available_bytes(&self) -> astrid_audit::AuditResult<Option<u64>> {
        self.store
            .compaction_capacity()
            .map(|capacity| capacity.map(|(available, _)| available))
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }
}

/// Opens the system-owned audit projection over the runtime principal store and
/// verifies already-published destination chains before serving. Released
/// native sources are migrated by [`legacy_migration_barrier::run`] so audit
/// retirement is covered by the same completion ledger as every other legacy
/// component. Any integrity failure blocks boot.
/// Takes the caller's already-resolved [`AstridHome`](astrid_core::dirs::AstridHome)
/// so every resource acquired by the native composition root is rooted in the
/// same home — re-resolving from the environment here could split the audit
/// log from the KV/socket paths if `$ASTRID_HOME` changed between calls.
#[cfg(unix)]
async fn open_audit_log(
    home: &astrid_core::dirs::AstridHome,
    audit_store: Arc<dyn astrid_storage::KvStore>,
    principal_store: &astrid_storage::RuntimePrincipalStore,
    runtime_key: Arc<astrid_crypto::KeyPair>,
) -> std::io::Result<Arc<AuditLog>> {
    home.ensure()
        .map_err(|e| std::io::Error::other(format!("cannot create Astrid home dirs: {e}")))?;

    // Share the kernel's single runtime key — never load it from disk twice
    // (issue #929). The audit log and the admin token-mint path sign with the
    // exact same key bytes.
    let capacity = Arc::new(RuntimeAuditCapacityProvider {
        store: principal_store.clone(),
    });
    let audit_log =
        AuditLog::open_with_kv_store_and_capacity(audit_store, runtime_key, Some(capacity))
            .map_err(|e| std::io::Error::other(format!("cannot open audit log: {e}")))?;

    // Verify all historical chains on boot. Audit is authoritative compliance
    // state: serving with a tampered or unverifiable chain would silently
    // bless an untrusted history.
    let results = audit_log.verify_all().await.map_err(|error| {
        std::io::Error::other(format!("audit chain verification failed: {error}"))
    })?;
    require_audit_integrity(&results)?;

    Ok(Arc::new(audit_log))
}

/// Enforce the released audit-source contract before opening any native
/// database. The first released layout had one system audit directory under
/// the `default` principal; ordinary principal-home migration deliberately
/// excludes every `.local/audit` subtree. An additional non-default source is
/// therefore a hard migration conflict rather than something that may be
/// silently left mounted or copied as ordinary home data.
#[cfg(unix)]
pub(crate) fn preflight_legacy_audit_sources(
    home: &astrid_core::dirs::AstridHome,
    default_source: &Path,
) -> std::io::Result<bool> {
    let root = home.home_dir();
    let metadata = match std::fs::symlink_metadata(&root) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "legacy principal-home root is not a directory: {}",
                    root.display()
                ),
            ));
        },
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let root_device = audit_tree_device(&metadata);
    let mut default_source_present = false;
    astrid_core::platform_fs::verify_no_redirects(&root)?;
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        let principal_root = entry.path();
        let principal_metadata = std::fs::symlink_metadata(&principal_root)?;
        if principal_metadata.file_type().is_symlink() || !principal_metadata.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "legacy principal-home entry is not a regular directory: {}",
                    principal_root.display()
                ),
            ));
        }
        if audit_tree_device(&principal_metadata) != root_device {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "legacy principal-home entry crosses a filesystem boundary: {}",
                    principal_root.display()
                ),
            ));
        }
        astrid_core::platform_fs::verify_no_redirects(&principal_root)?;
        let local_root = principal_root.join(".local");
        match std::fs::symlink_metadata(&local_root) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "legacy principal .local path is not a directory: {}",
                        local_root.display()
                    ),
                ));
            },
            Ok(_) => astrid_core::platform_fs::verify_no_redirects(&local_root)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
        let audit_source = local_root.join("audit");
        let audit_metadata = match std::fs::symlink_metadata(&audit_source) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if audit_source == default_source {
            default_source_present = true;
            validate_audit_tree(&audit_source, audit_tree_device(&audit_metadata))?;
            continue;
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "unsupported legacy audit source {}; only the default principal source is admitted",
                audit_source.display()
            ),
        ));
    }
    Ok(default_source_present)
}

pub(crate) fn require_audit_integrity(
    results: &[(
        astrid_core::SessionId,
        astrid_audit::ChainVerificationResult,
    )],
) -> std::io::Result<()> {
    let mut tampered_sessions = 0_usize;
    for (session_id, result) in results {
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
    if tampered_sessions != 0 {
        return Err(std::io::Error::other(format!(
            "audit chain integrity verification rejected {tampered_sessions} session(s); repair or restore the system audit projection before retrying boot"
        )));
    }
    if !results.is_empty() {
        tracing::info!(
            total_sessions = results.len(),
            "Audit chain verification passed for all sessions"
        );
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn retire_legacy_audit_dir(
    home: &astrid_core::dirs::AstridHome,
    source: &Path,
) -> std::io::Result<()> {
    let retired = home.migrations_dir().join("audit-principal-home.retired");
    let expected = home
        .principal_home(&astrid_core::PrincipalId::default())
        .audit_dir();
    if source != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "legacy audit retirement source is outside the default principal audit path",
        ));
    }
    astrid_core::platform_fs::verify_no_redirects(source.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "legacy audit source has no parent",
        )
    })?)?;
    astrid_core::platform_fs::ensure_private_directory(&home.migrations_dir())?;
    astrid_core::platform_fs::verify_no_redirects(&home.migrations_dir())?;
    match std::fs::symlink_metadata(source) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "legacy audit source is not a regular directory: {}",
                    source.display()
                ),
            ));
        },
        Ok(_) => {
            if std::fs::symlink_metadata(&retired).is_ok() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "legacy audit retirement is ambiguous: {}",
                        retired.display()
                    ),
                ));
            }
            let root_device = audit_tree_device(&std::fs::symlink_metadata(source)?);
            validate_audit_tree(source, root_device)?;
            astrid_core::platform_fs::rename_with_write_through(source, &retired)?;
            sync_audit_directory(source.parent().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "legacy audit source has no parent",
                )
            })?)?;
            sync_audit_directory(&home.migrations_dir())?;
            validate_audit_tree(&retired, root_device)?;
            delete_audit_tree(&retired, root_device)?;
            sync_audit_directory(&home.migrations_dir())?;
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if std::fs::symlink_metadata(&retired).is_ok() {
                let root_device = audit_tree_device(&std::fs::symlink_metadata(&retired)?);
                validate_audit_tree(&retired, root_device)?;
                delete_audit_tree(&retired, root_device)?;
                sync_audit_directory(&home.migrations_dir())?;
            }
        },
        Err(error) => return Err(error),
    }
    Ok(())
}

#[cfg(unix)]
fn audit_tree_device(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt as _;

    metadata.dev()
}

#[cfg(unix)]
fn validate_audit_tree(path: &Path, root_device: u64) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "legacy audit tree is redirected or not a directory: {}",
                path.display()
            ),
        ));
    }
    if audit_tree_device(&metadata) != root_device || audit_mountpoint(path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "legacy audit tree crosses a filesystem or mount boundary: {}",
                path.display()
            ),
        ));
    }
    astrid_core::platform_fs::verify_no_redirects(path)?;
    for entry in std::fs::read_dir(path)? {
        let child = entry?.path();
        let child_metadata = std::fs::symlink_metadata(&child)?;
        if child_metadata.file_type().is_symlink()
            || audit_tree_device(&child_metadata) != root_device
            || audit_mountpoint(&child)?
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "legacy audit tree contains a redirect or boundary: {}",
                    child.display()
                ),
            ));
        }
        if child_metadata.is_dir() {
            validate_audit_tree(&child, root_device)?;
        } else if child_metadata.is_file() {
            astrid_core::platform_fs::verify_no_redirects(&child)?;
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "legacy audit tree contains a special file: {}",
                    child.display()
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn delete_audit_tree(path: &Path, root_device: u64) -> std::io::Result<()> {
    validate_audit_tree(path, root_device)?;
    for entry in std::fs::read_dir(path)? {
        let child = entry?.path();
        let metadata = std::fs::symlink_metadata(&child)?;
        if metadata.is_dir() {
            delete_audit_tree(&child, root_device)?;
        } else {
            astrid_core::platform_fs::verify_no_redirects(&child)?;
            std::fs::remove_file(&child)?;
        }
    }
    sync_audit_directory(path)?;
    std::fs::remove_dir(path)
}

#[cfg(unix)]
fn sync_audit_directory(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(target_os = "linux")]
fn audit_mountpoint(path: &Path) -> std::io::Result<bool> {
    use std::os::unix::ffi::OsStringExt as _;

    let canonical = std::fs::canonicalize(path)?;
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
    for line in mountinfo.lines() {
        let Some(encoded) = line.split_whitespace().nth(4) else {
            continue;
        };
        let mut decoded = Vec::with_capacity(encoded.len());
        let bytes = encoded.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            let escape_end = index.checked_add(4).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "mount path overflow")
            })?;
            let escape_start = index.checked_add(1).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "mount path overflow")
            })?;
            if bytes[index] == b'\\' && escape_end <= bytes.len() {
                let digits = bytes.get(escape_start..escape_end).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid mount escape")
                })?;
                if digits.iter().all(|digit| (b'0'..=b'7').contains(digit)) {
                    let value = u8::from_str_radix(
                        std::str::from_utf8(digits).map_err(std::io::Error::other)?,
                        8,
                    )
                    .map_err(std::io::Error::other)?;
                    decoded.push(value);
                    index = escape_end;
                    continue;
                }
            }
            decoded.push(bytes[index]);
            index = index.checked_add(1).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "mount path overflow")
            })?;
        }
        if std::ffi::OsString::from_vec(decoded) == canonical.as_os_str() {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(all(unix, not(target_os = "linux")))]
#[allow(clippy::unnecessary_wraps)]
fn audit_mountpoint(_path: &Path) -> std::io::Result<bool> {
    Ok(false)
}

/// Load the runtime ed25519 signing key from disk, or generate and persist a new one.
///
/// The key file is 32 bytes of raw secret key material at `{keys_dir}/runtime.key`.
#[cfg(unix)]
fn load_or_generate_runtime_key(keys_dir: &Path) -> std::io::Result<KeyPair> {
    astrid_core::platform_fs::ensure_private_directory(keys_dir)?;
    let key_path = keys_dir.join("runtime.key");
    if key_path.exists() {
        astrid_core::platform_fs::validate_private_file(&key_path)?;
    }
    let keypair = astrid_crypto::load_or_generate_keypair(&key_path).map_err(|error| {
        let message = error
            .to_string()
            .replacen("invalid signing key", "invalid runtime key", 1);
        std::io::Error::new(error.kind(), message)
    })?;
    astrid_core::platform_fs::restrict_private_file(&key_path)?;
    Ok(keypair)
}

/// Spawns the persistent-daemon idle monitor.
///
/// Ephemeral shutdown is driven by reliable connection lifecycle accounting;
/// its never-connected fallback is armed by the daemon only after readiness.
/// Persistent mode remains idle-shutdown-free unless
/// `ASTRID_IDLE_TIMEOUT_SECS` is set.
/// Number of permanent internal event bus subscribers that are not client
/// connections: `KernelRouter` (`kernel.request.*`), `AdminRouter`
/// (`kernel.admin.*`), the synchronous `ConnectionTracker` (`client.*`),
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

/// Post-readiness grace for an ephemeral daemon whose spawning client never
/// establishes a connection.
const EPHEMERAL_STARTUP_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
/// Initial grace before checking the persistent-daemon idle policy.
const IDLE_INITIAL_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
/// Additional grace for non-ephemeral daemons to let capsules fully initialize.
const IDLE_NON_EPHEMERAL_GRACE: std::time::Duration = std::time::Duration::from_secs(25);
/// How often the idle monitor polls when running in persistent mode.
const IDLE_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);
fn persistent_idle_monitor_enabled(ephemeral: &AtomicBool) -> bool {
    !ephemeral.load(Ordering::Relaxed)
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn spawn_idle_monitor(kernel: Arc<Kernel>) -> astrid_runtime::JoinHandle<()> {
    astrid_runtime::spawn(async move {
        // The daemon sets ephemeral mode after Kernel construction. Once set,
        // its lifecycle is handled by connection closes plus the explicitly
        // post-readiness fallback, never by this construction-time monitor.
        astrid_runtime::time::sleep(IDLE_INITIAL_GRACE).await;
        if !persistent_idle_monitor_enabled(&kernel.ephemeral) {
            return;
        }

        // Persistent (`astrid start`) mode: idle shutdown is opt-in.
        // The operator explicitly chose persistent — honour that.
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
        let idle_timeout = std::time::Duration::from_secs(secs);

        // Give capsules time to initialize before applying an explicitly
        // configured persistent-daemon idle timeout.
        astrid_runtime::time::sleep(IDLE_NON_EPHEMERAL_GRACE).await;
        if !persistent_idle_monitor_enabled(&kernel.ephemeral) {
            return;
        }
        let mut idle_since: Option<astrid_runtime::time::Instant> = None;

        loop {
            astrid_runtime::time::sleep(IDLE_CHECK_INTERVAL).await;
            if !persistent_idle_monitor_enabled(&kernel.ephemeral) {
                return;
            }
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

fn spawn_ephemeral_startup_fallback(
    kernel: Arc<Kernel>,
    grace: std::time::Duration,
) -> astrid_runtime::JoinHandle<()> {
    astrid_runtime::spawn(async move {
        astrid_runtime::time::sleep(grace).await;
        kernel.request_ephemeral_shutdown_if_idle();
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
/// A restart publishes a fresh generation either way; this is a diagnostic of what
/// happened to the OLD one. It deliberately does NOT drive the retry cap: the
/// cap counts consecutive HEALTH failures (a lingering old instance is a normal,
/// harmless state for a busy capsule whose dispatcher consumer still holds a
/// clone — it is NOT a restart failure), and the health monitor prunes a
/// tracker when the capsule RECOVERS, not on the restart-call outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
enum RestartOutcome {
    /// The old runtime was exclusively unloaded after the fresh generation was
    /// atomically published.
    Clean,
    /// The old runtime's exclusive `unload` was skipped because an `Arc` clone
    /// (e.g. a live dispatcher consumer holding a clone for up to its idle
    /// grace) was still held. Its run-loop and subprocesses were cooperatively
    /// cancelled — no CPU/process leak — and its memory reclaims when the last
    /// clone drops. This is common for a capsule under load and is NOT counted
    /// as a restart failure.
    OldInstanceLingering,
    /// The observed failed generation was already replaced before restart.
    Superseded,
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
async fn unload_replaced_runtime(
    id: &astrid_capsule_types::CapsuleId,
    previous: &mut Arc<dyn astrid_capsule::capsule::Capsule>,
) -> RestartOutcome {
    for retry in 0..20_u32 {
        if let Some(capsule) = Arc::get_mut(previous) {
            if let Err(error) = capsule.unload().await {
                tracing::warn!(
                    capsule_id = %id,
                    error = %error,
                    "Capsule unload failed after generation replacement"
                );
            }
            return RestartOutcome::Clean;
        }
        if retry < 19 {
            astrid_runtime::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
    tracing::warn!(
        capsule_id = %id,
        strong_count = Arc::strong_count(previous),
        "Old capsule generation remains referenced after replacement; autonomous \
         work was cancelled and memory reclaims when the last reference drops"
    );
    RestartOutcome::OldInstanceLingering
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
async fn activate_and_wait_ready(
    id: &astrid_capsule_types::CapsuleId,
    candidate: &mut dyn astrid_capsule::capsule::Capsule,
) -> Result<(), anyhow::Error> {
    use astrid_capsule::capsule::ReadyStatus;

    let activation_timeout = std::time::Duration::from_secs(30);
    let readiness_timeout = std::time::Duration::from_millis(500);
    match astrid_runtime::time::timeout(activation_timeout, candidate.activate()).await {
        Ok(result) => result?,
        Err(_) => anyhow::bail!(
            "candidate generation for '{id}' did not activate within {}ms",
            activation_timeout.as_millis()
        ),
    }
    match candidate.wait_ready(readiness_timeout).await {
        ReadyStatus::Ready => Ok(()),
        ReadyStatus::Timeout => anyhow::bail!(
            "candidate generation for '{id}' did not signal ready within {}ms",
            readiness_timeout.as_millis()
        ),
        ReadyStatus::Crashed => {
            anyhow::bail!("candidate generation for '{id}' exited before signaling ready")
        },
    }
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
    expected_runtime: &astrid_capsule::registry::RuntimeId,
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
    let _view_guard = kernel.lock_capsule_view(principal, &capsule_id).await;
    if kernel.capabilities.is_principal_retiring(principal).await {
        tracing::debug!(capsule_id = %id_str, %principal, "Skipping health restart for retiring principal");
        return;
    }
    match kernel
        .restart_capsule(&capsule_id, principal, Some(expected_runtime))
        .await
    {
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
        Ok(RestartOutcome::Superseded) => {
            tracing::debug!(
                capsule_id = %id_str,
                principal = %principal,
                "Skipping restart because the failed runtime generation was already replaced"
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

        let mut restart_trackers: std::collections::HashMap<
            astrid_capsule::registry::RuntimeId,
            RestartTracker,
        > = std::collections::HashMap::new();

        loop {
            interval.tick().await;
            metrics::counter!(METRIC_BACKGROUND_TICKS_TOTAL, "loop" => "capsule_health")
                .increment(1);

            // Collect ready capsules under a brief read lock, then drop
            // the lock before calling check_health() or publishing events.
            let ready_capsules: Vec<(
                PrincipalId,
                astrid_capsule::registry::RuntimeId,
                std::sync::Arc<dyn astrid_capsule::capsule::Capsule>,
            )> = {
                let registry = kernel.capsules.read().await;
                registry
                    .cloned_runtimes_with_principal()
                    .into_iter()
                    .filter_map(|(principal, runtime_id, capsule)| {
                        if capsule.state() == astrid_capsule::capsule::CapsuleState::Ready {
                            Some((principal, runtime_id, capsule))
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
            // RuntimeId already carries authority scope and generation, so each
            // mutable runtime is probed exactly once. A SystemResident runtime
            // likewise appears once regardless of its number of views.
            let failures = collect_failed_runtimes(&ready_capsules);
            for (principal, id_str, _runtime_id, reason) in &failures {
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

            let failed_this_tick: std::collections::HashSet<astrid_capsule::registry::RuntimeId> =
                failures
                    .iter()
                    .map(|(_principal, _id, runtime_id, _)| runtime_id.clone())
                    .collect();

            for (principal, id_str, runtime_id, _reason) in &failures {
                let tracker = restart_trackers
                    .entry(runtime_id.clone())
                    .or_insert_with(RestartTracker::new);

                attempt_capsule_restart(&kernel, id_str, principal, runtime_id, tracker).await;
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

/// Collect failed runtime generations from the health-monitor snapshot.
/// Returns `(requesting principal, capsule id, RuntimeId, failure reason)`.
fn collect_failed_runtimes(
    ready_capsules: &[(
        PrincipalId,
        astrid_capsule::registry::RuntimeId,
        std::sync::Arc<dyn astrid_capsule::capsule::Capsule>,
    )],
) -> Vec<(
    PrincipalId,
    String,
    astrid_capsule::registry::RuntimeId,
    String,
)> {
    let mut failures = Vec::new();
    for (principal, runtime_id, capsule) in ready_capsules {
        // The registry snapshot is already unique by RuntimeId generation.
        // Probe health before allocating the diagnostic capsule-id String so
        // healthy runtimes remain allocation-free on the common path.
        let astrid_capsule::capsule::CapsuleState::Failed(reason) = capsule.check_health() else {
            continue;
        };
        let id_str = capsule.id().to_string();
        failures.push((principal.clone(), id_str, runtime_id.clone(), reason));
    }
    failures
}

fn watchdog_principals(registry: &astrid_capsule::registry::CapsuleRegistry) -> Vec<PrincipalId> {
    let unique: std::collections::HashSet<_> = registry
        .cloned_values_with_principal()
        .into_iter()
        .map(|(principal, _)| principal)
        .collect();
    let mut principals: Vec<_> = unique.into_iter().collect();
    principals.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
    principals
}

async fn publish_watchdog_ticks(
    event_bus: &EventBus,
    principals: impl IntoIterator<Item = PrincipalId>,
) {
    for (index, principal) in principals.into_iter().enumerate() {
        let msg = astrid_events::ipc::IpcMessage::new(
            astrid_events::ipc::Topic::from_raw(REACT_WATCHDOG_TOPIC),
            astrid_events::ipc::IpcPayload::Custom {
                data: serde_json::json!({}),
            },
            uuid::Uuid::new_v4(),
        )
        .with_principal(principal.to_string());
        let _ = event_bus.publish(astrid_events::AstridEvent::Ipc {
            metadata: astrid_events::EventMetadata::new("kernel"),
            message: msg,
        });
        if index != 0 && index.is_multiple_of(WATCHDOG_PUBLISH_BATCH) {
            // `broadcast` has no receiver acknowledgement or async send. A
            // cooperative yield may immediately reschedule this producer, so
            // it is not backpressure and can still overrun every receiver on
            // a busy runner. Give consumers one bounded scheduler interval
            // between sub-capacity batches instead.
            tokio::time::sleep(WATCHDOG_PUBLISH_PAUSE).await;
        }
    }
}

/// Spawns a periodic watchdog that publishes `astrid.v1.watchdog.tick` events every 5 seconds.
///
/// The `ReAct` capsule (WASM guest) cannot use async timers, so this kernel-side task
/// drives timeout enforcement by waking the capsule on a fixed interval. Each tick
/// causes the capsule's `handle_watchdog_tick` interceptor to run `check_phase_timeout`.
fn spawn_react_watchdog(kernel: Arc<Kernel>) -> astrid_runtime::JoinHandle<()> {
    astrid_runtime::spawn(async move {
        let mut interval = astrid_runtime::time::interval(std::time::Duration::from_secs(5));
        // The first tick fires immediately - skip it to give capsules time to load.
        interval.tick().await;

        loop {
            interval.tick().await;
            metrics::counter!(METRIC_BACKGROUND_TICKS_TOTAL, "loop" => "react_watchdog")
                .increment(1);

            // A watchdog tick is per admitted principal, not an anonymous
            // user event. Stamp one event for every live principal view so the
            // dispatcher selects that principal's isolated runtimes plus any
            // explicitly shared SystemResident services. An unstamped global
            // fan-out would either drop principal runtimes or expose the same
            // event indiscriminately across authority scopes.
            let principals = {
                let registry = kernel.capsules.read().await;
                watchdog_principals(&registry)
            };
            publish_watchdog_ticks(&kernel.event_bus, principals).await;
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
    _home: &astrid_core::dirs::AstridHome,
    workspace_root: &Path,
    principal: &PrincipalId,
    workspace_layout: &WorkspaceLayout,
) -> Vec<PathBuf> {
    // Principal packages are discovered from the UID-keyed durable registry
    // by `sorted_principal_capsules`. This helper intentionally returns no
    // native principal-home path; only explicit project/workspace portals are
    // allowed to enter generic path discovery.
    let _ = (workspace_root, principal, workspace_layout);
    Vec::new()
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
/// Idempotent: skips creation if the root user already exists.
async fn bootstrap_cli_root_user(
    store: &Arc<dyn astrid_storage::IdentityStore>,
    home: &astrid_core::dirs::AstridHome,
) -> Result<
    (astrid_core::AstridUserId, astrid_core::PrincipalIdentity),
    astrid_storage::IdentityError,
> {
    let principal = astrid_core::PrincipalId::default();
    let initial_public_key = principal_initial_public_key(home, &principal)?;

    // Check if root user already exists by trying to resolve the CLI link.
    if let Some(user) = store.resolve("cli", "local").await? {
        let identity = store
            .bind_principal_identity(user.id, principal, initial_public_key)
            .await?;
        tracing::debug!("CLI root user already linked");
        return Ok((user, identity));
    }

    // No CLI link exists. Recover a durable principal left by an interrupted
    // first boot, or create it when no such record exists yet.
    let mut recovered = None;
    for user in store.list_users().await? {
        if user.principal != principal {
            continue;
        }
        let Some(identity) = store.get_principal_identity(user.id).await? else {
            continue;
        };
        if recovered.is_some() {
            return Err(astrid_storage::IdentityError::InvalidInput(
                "multiple durable CLI root principals exist".to_owned(),
            ));
        }
        recovered = Some((user, identity));
    }

    let (user, identity) = if let Some(existing) = recovered {
        tracing::info!(user_id = %existing.0.id, "Recovered unlinked CLI root user");
        existing
    } else {
        let user = store
            .create_principal(principal, initial_public_key)
            .await?;
        let identity = store
            .get_principal_identity(user.id)
            .await?
            .ok_or_else(|| {
                astrid_storage::IdentityError::InvalidInput(
                    "new CLI root principal is missing immutable identity".to_owned(),
                )
            })?;
        tracing::info!(user_id = %user.id, "Created CLI root user");
        (user, identity)
    };

    // Link the CLI platform identity.
    store.link("cli", "local", user.id, "system").await?;
    tracing::info!(user_id = %user.id, "Linked CLI root user (cli/local)");

    Ok((user, identity))
}

async fn bootstrap_cli_root_ownership(
    store: &astrid_storage::OwnershipStore,
    principal_directory: &astrid_storage::PrincipalDirectory,
    root_user: astrid_core::AstridUserId,
    root_principal_identity: astrid_core::PrincipalIdentity,
    adopt_unowned_principals: bool,
) -> Result<(), astrid_storage::OwnershipError> {
    let user = astrid_core::UserIdentity::from_genesis(astrid_core::UserGenesis::from_parts(
        root_user.id,
        root_user.created_at,
        root_principal_identity.genesis.initial_public_key,
    ))?;
    store.create_user(user.clone()).await?;

    // Reuse the legacy root UUID and timestamp as deterministic fleet genesis
    // inputs. User/fleet UID derivation is domain-separated, so their durable
    // identifiers remain distinct while every boot derives the same records.
    let fleet = astrid_core::FleetIdentity::from_genesis(astrid_core::FleetGenesis::from_parts(
        root_user.id,
        root_user.created_at,
        user.uid,
    ))?;
    store.create_fleet(fleet.clone()).await?;

    let principal_uid = principal_directory
        .uid_for(&astrid_core::PrincipalId::default())
        .map_err(astrid_storage::OwnershipError::Storage)?;
    if store.load().await?.principal_owner(principal_uid).is_none() {
        store
            .assign_principal(astrid_core::PrincipalOwnership {
                principal_uid,
                fleet_uid: fleet.uid,
                assigned_by: user.uid,
            })
            .await?;
    }
    if adopt_unowned_principals {
        for (_, candidate) in principal_directory.bindings() {
            if store.load().await?.principal_owner(candidate).is_none() {
                store
                    .assign_principal(astrid_core::PrincipalOwnership {
                        principal_uid: candidate,
                        fleet_uid: fleet.uid,
                        assigned_by: user.uid,
                    })
                    .await?;
            }
        }
    }
    Ok(())
}

fn principal_initial_public_key(
    home: &astrid_core::dirs::AstridHome,
    principal: &astrid_core::PrincipalId,
) -> Result<[u8; 32], astrid_storage::IdentityError> {
    let profile = astrid_core::PrincipalProfile::load(home, principal).map_err(|error| {
        astrid_storage::IdentityError::Storage(format!(
            "load profile for principal identity {principal}: {error}"
        ))
    })?;
    let device = profile
        .auth
        .public_keys
        .iter()
        .min_by_key(|device| (device.created_at, device.key_id.as_str()))
        .ok_or_else(|| {
            astrid_storage::IdentityError::InvalidInput(format!(
                "principal {principal} has no Ed25519 key for genesis identity"
            ))
        })?;
    let public_key = astrid_crypto::PublicKey::from_hex(&device.pubkey).map_err(|error| {
        astrid_storage::IdentityError::InvalidInput(format!(
            "principal {principal} has an invalid genesis public key: {error}"
        ))
    })?;
    Ok(public_key.into())
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
pub(crate) fn migrate_legacy_profile_path(
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

    let keys_dir = home.keys_dir();
    std::fs::create_dir_all(&keys_dir)?;
    let key_path = keys_dir.join(format!("{principal}.key"));
    // Reuse a key left by an interrupted prior boot. The crypto helper creates
    // and syncs an owner-only key without ever replacing a winner.
    let keypair = astrid_crypto::load_or_generate_keypair(&key_path)?;

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

    use astrid_capsule::capsule::{Capsule, CapsuleState, ReadyStatus};
    use astrid_capsule::context::CapsuleContext;
    use astrid_capsule_types::CapsuleId;
    use astrid_capsule_types::error::CapsuleResult;
    use astrid_capsule_types::manifest::CapsuleManifest;

    #[tokio::test]
    async fn cli_root_bootstrap_recovers_a_durable_principal_without_its_link() {
        let (_dir, home) = scratch_home();
        seed_default_principal_admin_profile(&home).unwrap();
        let principal = astrid_core::PrincipalId::default();
        let initial_public_key = principal_initial_public_key(&home, &principal).unwrap();
        let backend: Arc<dyn astrid_storage::KvStore> =
            Arc::new(astrid_storage::MemoryKvStore::new());
        let directory = astrid_storage::PrincipalDirectory::default();
        let identity_store: Arc<dyn astrid_storage::IdentityStore> =
            Arc::new(astrid_storage::KvIdentityStore::with_principal_directory(
                astrid_storage::ScopedKvStore::new(backend, "system:identity").unwrap(),
                directory,
            ));
        let stranded = identity_store
            .create_principal(principal, initial_public_key)
            .await
            .unwrap();
        assert!(
            identity_store
                .resolve("cli", "local")
                .await
                .unwrap()
                .is_none()
        );

        let (recovered, recovered_identity) = bootstrap_cli_root_user(&identity_store, &home)
            .await
            .unwrap();

        assert_eq!(recovered.id, stranded.id);
        assert_eq!(
            identity_store
                .resolve("cli", "local")
                .await
                .unwrap()
                .unwrap()
                .id,
            stranded.id
        );
        assert_eq!(identity_store.list_users().await.unwrap().len(), 1);
        assert_eq!(
            identity_store
                .get_principal_identity(stranded.id)
                .await
                .unwrap()
                .unwrap(),
            recovered_identity
        );
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one ownership-bootstrap scenario must retain the same store across initial \
                  adoption, idempotent replay, transfer, and non-legacy restart"
    )]
    async fn legacy_root_ownership_bootstrap_is_deterministic_and_idempotent() {
        let backend: Arc<dyn astrid_storage::KvStore> =
            Arc::new(astrid_storage::MemoryKvStore::new());
        let directory = astrid_storage::PrincipalDirectory::default();
        let ownership_store =
            astrid_storage::OwnershipStore::new(backend, directory.clone()).unwrap();
        let principal_identity = astrid_core::PrincipalIdentity::from_genesis(
            astrid_core::PrincipalGenesis::from_parts(
                uuid::Uuid::from_u128(2),
                chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                [2; 32],
            ),
        )
        .unwrap();
        directory
            .register(astrid_core::PrincipalId::default(), principal_identity.uid)
            .unwrap();
        let legacy_principal_identity = astrid_core::PrincipalIdentity::from_genesis(
            astrid_core::PrincipalGenesis::from_parts(
                uuid::Uuid::from_u128(4),
                chrono::DateTime::from_timestamp(1_700_000_002, 0).unwrap(),
                [4; 32],
            ),
        )
        .unwrap();
        directory
            .register(
                astrid_core::PrincipalId::new("legacy-agent").unwrap(),
                legacy_principal_identity.uid,
            )
            .unwrap();
        let root_user = astrid_core::AstridUserId {
            id: uuid::Uuid::from_u128(1),
            principal: astrid_core::PrincipalId::default(),
            public_key: None,
            display_name: None,
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        };

        bootstrap_cli_root_ownership(
            &ownership_store,
            &directory,
            root_user.clone(),
            principal_identity.clone(),
            true,
        )
        .await
        .unwrap();
        let first = ownership_store.load().await.unwrap();
        bootstrap_cli_root_ownership(
            &ownership_store,
            &directory,
            root_user.clone(),
            principal_identity.clone(),
            true,
        )
        .await
        .unwrap();
        let second = ownership_store.load().await.unwrap();

        assert_eq!(first, second);
        let principal_owner = second.principal_owner(principal_identity.uid).unwrap();
        let root_user_uid = principal_owner.assigned_by;
        let initial_fleet_uid = principal_owner.fleet_uid;
        let expected_user =
            astrid_core::UserIdentity::from_genesis(astrid_core::UserGenesis::from_parts(
                root_user.id,
                root_user.created_at,
                principal_identity.genesis.initial_public_key,
            ))
            .unwrap();
        assert_eq!(root_user_uid, expected_user.uid);
        assert_eq!(second.fleets().count(), 1);
        assert!(second.fleet(principal_owner.fleet_uid).is_some());
        assert_eq!(
            second
                .principal_owner(legacy_principal_identity.uid)
                .unwrap()
                .fleet_uid,
            initial_fleet_uid
        );

        let destination =
            astrid_core::FleetIdentity::from_genesis(astrid_core::FleetGenesis::from_parts(
                uuid::Uuid::from_u128(3),
                chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
                root_user_uid,
            ))
            .unwrap();
        ownership_store
            .create_fleet(destination.clone())
            .await
            .unwrap();
        ownership_store
            .transfer_principal(
                principal_identity.uid,
                initial_fleet_uid,
                destination.uid,
                root_user_uid,
            )
            .await
            .unwrap();

        bootstrap_cli_root_ownership(
            &ownership_store,
            &directory,
            root_user,
            principal_identity.clone(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            ownership_store
                .load()
                .await
                .unwrap()
                .principal_owner(principal_identity.uid)
                .unwrap()
                .fleet_uid,
            destination.uid
        );
    }

    #[test]
    fn persistent_idle_monitor_stops_after_ephemeral_mode_is_enabled() {
        let ephemeral = AtomicBool::new(false);
        assert!(persistent_idle_monitor_enabled(&ephemeral));

        ephemeral.store(true, Ordering::Relaxed);
        assert!(
            !persistent_idle_monitor_enabled(&ephemeral),
            "every post-grace and polling-loop check must observe ephemeral mode"
        );
    }

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

    struct BlockingQuiesceCapsule {
        id: CapsuleId,
        manifest: CapsuleManifest,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    struct RegistryReadingQuiesceCapsule {
        id: CapsuleId,
        manifest: CapsuleManifest,
        registry: Arc<RwLock<astrid_capsule::registry::CapsuleRegistry>>,
    }

    struct NeverReadyCapsule {
        id: CapsuleId,
        manifest: CapsuleManifest,
        activated: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl Capsule for NeverReadyCapsule {
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
            Ok(())
        }

        async fn activate(&mut self) -> CapsuleResult<()> {
            self.activated.store(true, Ordering::Release);
            Ok(())
        }

        async fn wait_ready(&self, _timeout: std::time::Duration) -> ReadyStatus {
            ReadyStatus::Timeout
        }
    }

    #[async_trait::async_trait]
    impl Capsule for RegistryReadingQuiesceCapsule {
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
            Ok(())
        }

        async fn quiesce_for(&self, _principal: &PrincipalId) {
            let _registry = self.registry.read().await;
        }
    }

    #[async_trait::async_trait]
    impl Capsule for BlockingQuiesceCapsule {
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
            Ok(())
        }

        async fn quiesce_for(&self, _principal: &PrincipalId) {
            self.entered.notify_one();
            self.release.notified().await;
        }
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
    fn runtime_residency_policy_distinguishes_grants_from_providers() {
        let id = CapsuleId::new("uplink-policy").unwrap();
        let mut capability_only = CapsuleManifest::default();
        capability_only.capabilities.uplink = true;

        assert_eq!(
            classify_runtime_residency(&capability_only, &id, false).unwrap(),
            RuntimeResidency::Principal
        );
        assert_eq!(
            classify_runtime_residency(&capability_only, &id, true).unwrap(),
            RuntimeResidency::SystemResident
        );

        let mut provider = CapsuleManifest::default();
        provider
            .uplinks
            .push(astrid_capsule_types::manifest::UplinkDef {
                name: "test".to_string(),
                platform: "test".to_string(),
                profile: astrid_core::UplinkProfile::Chat,
            });
        assert!(classify_runtime_residency(&provider, &id, false).is_err());
        assert_eq!(
            classify_runtime_residency(&provider, &id, true).unwrap(),
            RuntimeResidency::SystemResident
        );
    }

    #[test]
    fn capsule_discovery_extra_paths_include_principal_capsules_only() {
        let (_d, home) = scratch_home();
        let workspace = tempfile::tempdir().unwrap();
        let paths = capsule_discovery_paths(&home, workspace.path());

        assert!(
            paths.is_empty(),
            "native principal-home paths are not authority"
        );
    }

    #[test]
    fn workspace_capsules_are_not_flattened_into_unchecked_extra_paths() {
        let (_d, home) = scratch_home();
        let workspace = tempfile::tempdir().unwrap();
        let layout = WorkspaceLayout::new(".alternate-runtime").unwrap();
        let paths =
            capsule_discovery_paths_for(&home, workspace.path(), &PrincipalId::default(), &layout);

        assert!(paths.is_empty());
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unload_releases_registry_write_lock_before_quiescence() {
        let (_d, home) = scratch_home();
        let kernel = test_kernel_with_home(home).await;
        let id = CapsuleId::new("registry-reading-quiesce").unwrap();
        kernel
            .capsules
            .write()
            .await
            .register(Box::new(RegistryReadingQuiesceCapsule {
                id: id.clone(),
                manifest: CapsuleManifest::default(),
                registry: Arc::clone(&kernel.capsules),
            }))
            .unwrap();

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            kernel.unload_one_capsule(&id, &PrincipalId::default()),
        )
        .await
        .expect("unload deadlocked registry write against admitted registry read")
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retired_generation_drain_does_not_hold_global_lifecycle_lock() {
        let (_d, home) = scratch_home();
        let kernel = test_kernel_with_home(home).await;
        let id = CapsuleId::new("blocking-retired-drain").unwrap();
        let alice = PrincipalId::new("alice").unwrap();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());

        kernel
            .capsules
            .write()
            .await
            .register_principal_runtime(
                Box::new(BlockingQuiesceCapsule {
                    id: id.clone(),
                    manifest: CapsuleManifest::default(),
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                }),
                astrid_capsule::registry::WasmHash::from_raw("blocking-retired-drain"),
                &alice,
                astrid_core::PrincipalUid::from_bytes([7; 32]),
            )
            .unwrap();

        let unloading = {
            let kernel = Arc::clone(&kernel);
            let id = id.clone();
            let alice = alice.clone();
            tokio::spawn(async move { kernel.unload_one_capsule(&id, &alice).await })
        };
        entered.notified().await;

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            drop(kernel.capsule_load_lock.lock().await);
        })
        .await
        .expect("an unrelated lifecycle must proceed while a retired generation drains");

        release.notify_one();
        assert!(unloading.await.unwrap().unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capsule_view_lock_serializes_waiters_and_evicts_idle_key() {
        let (_d, home) = scratch_home();
        let kernel = test_kernel_with_home(home).await;
        let principal = PrincipalId::new("lock-churn").unwrap();
        let id = CapsuleId::new("lock-churn").unwrap();
        let first = kernel.lock_capsule_view(&principal, &id).await;
        assert_eq!(kernel.capsule_view_locks.len(), 1);

        let waiting = {
            let kernel = Arc::clone(&kernel);
            let principal = principal.clone();
            let id = id.clone();
            tokio::spawn(async move { kernel.lock_capsule_view(&principal, &id).await })
        };
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished(), "the same typed view must serialize");

        drop(first);
        let second = waiting.await.expect("view-lock waiter");
        assert_eq!(kernel.capsule_view_locks.len(), 1);
        drop(second);
        assert!(
            kernel.capsule_view_locks.is_empty(),
            "the final guard must evict its exact dead weak entry"
        );
    }

    #[tokio::test]
    async fn cancelled_capsule_view_waiter_evicts_dead_key() {
        let (_d, home) = scratch_home();
        let kernel = test_kernel_with_home(home).await;
        let principal = PrincipalId::new("cancelled-lock").unwrap();
        let id = CapsuleId::new("cancelled-lock").unwrap();
        let first = kernel.lock_capsule_view(&principal, &id).await;
        let waiting = {
            let kernel = Arc::clone(&kernel);
            let principal = principal.clone();
            let id = id.clone();
            tokio::spawn(async move { kernel.lock_capsule_view(&principal, &id).await })
        };
        let key = CapsuleViewKey {
            principal: principal.clone(),
            capsule: id.clone(),
        };
        loop {
            let strong = kernel
                .capsule_view_locks
                .get(&key)
                .map_or(0, |weak| weak.strong_count());
            if strong >= 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(kernel.capsule_view_locks.len(), 1);

        drop(first);
        waiting.abort();
        let result = waiting.await;
        assert!(matches!(result, Err(error) if error.is_cancelled()));
        assert!(
            kernel.capsule_view_locks.is_empty(),
            "a cancelled pre-acquisition lease must evict its dead weak key"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unready_candidate_cannot_replace_current_generation() {
        let id = CapsuleId::new("never-ready").unwrap();
        let principal = PrincipalId::default();
        let mut registry = astrid_capsule::registry::CapsuleRegistry::new();
        registry
            .register(Box::new(CancellableTestCapsule {
                id: id.clone(),
                manifest: CapsuleManifest::default(),
                cancelled: Arc::new(AtomicBool::new(false)),
                unloaded: Arc::new(AtomicBool::new(false)),
                cancelled_for: Arc::default(),
            }))
            .unwrap();
        let current = registry.runtime_id_for(&principal, &id).unwrap();
        let activated = Arc::new(AtomicBool::new(false));
        let mut candidate = NeverReadyCapsule {
            id: id.clone(),
            manifest: CapsuleManifest::default(),
            activated: Arc::clone(&activated),
        };

        assert!(activate_and_wait_ready(&id, &mut candidate).await.is_err());
        assert!(activated.load(Ordering::Acquire));
        assert_eq!(registry.runtime_id_for(&principal, &id), Some(current));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unload_one_principal_retains_system_runtime_for_others() {
        // Alice and Bob deliberately view one explicit system singleton.
        // Releasing Alice's view must cancel only her in-flight work while the
        // service and Bob's view remain intact.
        let (_d, home) = scratch_home();
        let kernel = test_kernel_with_home(home).await;
        let id = CapsuleId::new("shared-test").unwrap();
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        let operator = PrincipalId::default();
        let hash = astrid_capsule::registry::WasmHash::from_raw("shared-test-hash");
        let cancelled = Arc::new(AtomicBool::new(false));
        let unloaded = Arc::new(AtomicBool::new(false));
        let cancelled_for: Arc<std::sync::Mutex<Vec<PrincipalId>>> = Arc::default();

        {
            let mut registry = kernel.capsules.write().await;
            // Register the explicit system singleton under operator policy;
            // Alice and Bob are dependent views, never implicit owners.
            registry
                .register_system_runtime(
                    Box::new(CancellableTestCapsule {
                        id: id.clone(),
                        manifest: CapsuleManifest::default(),
                        cancelled: Arc::clone(&cancelled),
                        unloaded: Arc::clone(&unloaded),
                        cancelled_for: Arc::clone(&cancelled_for),
                    }),
                    hash.clone(),
                    &operator,
                )
                .unwrap();
            registry.register_existing(&id, &hash, &bob).unwrap();
            registry.register_existing(&id, &hash, &alice).unwrap();
        }

        let removed = kernel.unload_one_capsule(&id, &alice).await.unwrap();
        assert!(removed);
        assert!(
            !cancelled.load(Ordering::Relaxed),
            "releasing one system view must NOT cancel the singleton while bob references it"
        );
        assert!(
            !unloaded.load(Ordering::Relaxed),
            "releasing one system view must NOT unload it while bob references it"
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
                "bob's view should retain the system runtime"
            );
            assert_eq!(
                registry.refcount_for_hash(&hash),
                Some(2),
                "system runtime retains the operator and bob views"
            );
        }

        // Bob can also detach without tearing down the operator-owned service.
        let removed = kernel.unload_one_capsule(&id, &bob).await.unwrap();
        assert!(removed);
        assert!(!cancelled.load(Ordering::Relaxed));
        assert!(!unloaded.load(Ordering::Relaxed));

        // Removing the operator-owned view revokes the singleton itself.
        let removed = kernel.unload_one_capsule(&id, &operator).await.unwrap();
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
            vec![alice, bob, operator],
            "every releasing principal must cross its lifecycle fence, including \
             the last view before instance teardown"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn registration_cannot_resume_principal_until_old_view_finishes_quiescing() {
        let (_d, home) = scratch_home();
        let kernel = test_kernel_with_home(home).await;
        let id = CapsuleId::new("serialized-lifecycle").unwrap();
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        let operator = PrincipalId::default();
        let hash = astrid_capsule::registry::WasmHash::from_raw("serialized-lifecycle-hash");
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());

        {
            let mut registry = kernel.capsules.write().await;
            registry
                .register_system_runtime(
                    Box::new(BlockingQuiesceCapsule {
                        id: id.clone(),
                        manifest: CapsuleManifest::default(),
                        entered: Arc::clone(&entered),
                        release: Arc::clone(&release),
                    }),
                    hash.clone(),
                    &operator,
                )
                .unwrap();
            registry.register_existing(&id, &hash, &alice).unwrap();
            registry.register_existing(&id, &hash, &bob).unwrap();
        }

        let unloading = {
            let kernel = Arc::clone(&kernel);
            let id = id.clone();
            let alice = alice.clone();
            tokio::spawn(async move { kernel.unload_one_capsule(&id, &alice).await })
        };
        entered.notified().await;

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            drop(kernel.capsule_load_lock.lock().await);
        })
        .await
        .expect("an unrelated lifecycle must proceed while one system view drains");

        let registering = {
            let kernel = Arc::clone(&kernel);
            let id = id.clone();
            let hash = hash.clone();
            let alice = alice.clone();
            tokio::spawn(async move {
                let _view = kernel.lock_capsule_view(&alice, &id).await;
                let _lifecycle = kernel.capsule_load_lock.lock().await;
                let mut registry = kernel.capsules.write().await;
                registry.register_existing(&id, &hash, &alice)
            })
        };
        tokio::task::yield_now().await;
        assert!(
            !registering.is_finished(),
            "registration/resume must wait behind the old view's quiescence"
        );

        release.notify_one();
        assert!(unloading.await.unwrap().unwrap());
        registering.await.unwrap().unwrap();
        assert!(kernel.capsules.read().await.get_for(&alice, &id).is_some());
        assert!(kernel.capsules.read().await.get_for(&bob, &id).is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unload_principal_capsules_retires_every_view_without_harming_shared_peers() {
        let (_d, home) = scratch_home();
        let kernel = test_kernel_with_home(home).await;
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        let operator = PrincipalId::default();
        let shared_id = CapsuleId::new("shared").unwrap();
        let private_id = CapsuleId::new("private").unwrap();
        let shared_hash = astrid_capsule::registry::WasmHash::from_raw("shared-hash");
        let private_hash = astrid_capsule::registry::WasmHash::from_raw("private-hash");

        let shared_cancelled = Arc::new(AtomicBool::new(false));
        let shared_unloaded = Arc::new(AtomicBool::new(false));
        let shared_cancelled_for: Arc<std::sync::Mutex<Vec<PrincipalId>>> = Arc::default();
        let private_cancelled = Arc::new(AtomicBool::new(false));
        let private_unloaded = Arc::new(AtomicBool::new(false));

        {
            let mut registry = kernel.capsules.write().await;
            registry
                .register_system_runtime(
                    Box::new(CancellableTestCapsule {
                        id: shared_id.clone(),
                        manifest: CapsuleManifest::default(),
                        cancelled: Arc::clone(&shared_cancelled),
                        unloaded: Arc::clone(&shared_unloaded),
                        cancelled_for: Arc::clone(&shared_cancelled_for),
                    }),
                    shared_hash.clone(),
                    &operator,
                )
                .unwrap();
            registry
                .register_existing(&shared_id, &shared_hash, &alice)
                .unwrap();
            registry
                .register_existing(&shared_id, &shared_hash, &bob)
                .unwrap();
            registry
                .register_for(
                    Box::new(CancellableTestCapsule {
                        id: private_id.clone(),
                        manifest: CapsuleManifest::default(),
                        cancelled: Arc::clone(&private_cancelled),
                        unloaded: Arc::clone(&private_unloaded),
                        cancelled_for: Arc::default(),
                    }),
                    private_hash,
                    &alice,
                )
                .unwrap();
        }

        let retired = kernel.unload_principal_capsules(&alice).await.unwrap();
        assert_eq!(retired, vec![private_id.clone(), shared_id.clone()]);
        assert_eq!(
            shared_cancelled_for.lock().unwrap().as_slice(),
            std::slice::from_ref(&alice)
        );
        assert!(!shared_cancelled.load(Ordering::Relaxed));
        assert!(!shared_unloaded.load(Ordering::Relaxed));
        assert!(private_cancelled.load(Ordering::Relaxed));
        assert!(private_unloaded.load(Ordering::Relaxed));

        let registry = kernel.capsules.read().await;
        assert!(registry.list_for(&alice).is_empty());
        assert!(registry.get_for(&bob, &shared_id).is_some());
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
    async fn watchdog_targets_every_live_principal_view_once() {
        let (_d, home) = scratch_home();
        let kernel = test_kernel_with_home(home).await;
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();

        {
            let mut registry = kernel.capsules.write().await;
            registry
                .register_principal_runtime(
                    Box::new(FailingTestCapsule {
                        id: CapsuleId::new("alice-react").unwrap(),
                        manifest: CapsuleManifest::default(),
                    }),
                    astrid_capsule::registry::WasmHash::from_raw("alice-react"),
                    &alice,
                    astrid_core::PrincipalUid::from_bytes([1; 32]),
                )
                .unwrap();
            let system_id = CapsuleId::new("system-watchdog").unwrap();
            let system_hash = astrid_capsule::registry::WasmHash::from_raw("system-watchdog");
            registry
                .register_system_runtime(
                    Box::new(FailingTestCapsule {
                        id: system_id.clone(),
                        manifest: CapsuleManifest::default(),
                    }),
                    system_hash.clone(),
                    &PrincipalId::default(),
                )
                .unwrap();
            registry
                .register_existing(&system_id, &system_hash, &bob)
                .unwrap();
        }

        let principals = {
            let registry = kernel.capsules.read().await;
            watchdog_principals(&registry)
        };
        assert_eq!(principals.len(), 3);
        assert!(principals.contains(&PrincipalId::default()));
        assert!(principals.contains(&alice));
        assert!(principals.contains(&bob));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watchdog_batching_yields_to_bounded_bus_receivers() {
        const PRINCIPALS: usize = 500;
        let bus = Arc::new(EventBus::with_capacity(64));
        let mut subscriber = bus.subscribe_as("test");
        let collecting = tokio::spawn(async move {
            let mut event_count = 0;
            while event_count < PRINCIPALS {
                if subscriber.recv().await.is_some() {
                    event_count += 1;
                }
            }
            (event_count, subscriber.drain_lagged())
        });
        tokio::task::yield_now().await;

        let principals = (0..PRINCIPALS).map(|index| {
            PrincipalId::new(format!("watchdog-{index}")).expect("generated principal is valid")
        });
        publish_watchdog_ticks(&bus, principals).await;

        let (event_count, lagged) =
            tokio::time::timeout(std::time::Duration::from_secs(2), collecting)
                .await
                .expect("receiver should drain the yielded watchdog batches")
                .expect("collector task");
        assert_eq!(event_count, PRINCIPALS);
        assert_eq!(lagged, 0, "watchdog fan-out must not overrun the bus");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn health_monitor_tracks_one_explicit_system_runtime_generation() {
        let (_d, home) = scratch_home();
        let kernel = test_kernel_with_home(home).await;
        let id = CapsuleId::new("failing-shared").unwrap();
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        let carol = PrincipalId::new("carol").unwrap();
        let hash = astrid_capsule::registry::WasmHash::from_raw("failing-shared-hash");

        {
            let mut registry = kernel.capsules.write().await;
            // Three principal views over one explicit operator-owned system
            // runtime generation.
            registry
                .register_system_runtime(
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
            registry.cloned_runtimes_with_principal()
        };
        assert_eq!(
            ready.len(),
            1,
            "system runtime health is represented once regardless of view count"
        );

        let failures = collect_failed_runtimes(&ready);
        assert_eq!(
            failures.len(),
            1,
            "a shared failed runtime with N views must dedup to exactly ONE restart, got {}",
            failures.len()
        );
        assert_eq!(failures[0].1, id.as_str());
        assert_eq!(failures[0].2.key().artifact(), &hash);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn health_monitor_keeps_two_distinct_hashes_of_one_id_separate() {
        // Two principals on DIFFERENT versions of the same capsule id resolve to
        // two DISTINCT content hashes and immutable authority scopes. Two failed
        // runtime generations for one id must surface as TWO independent
        // restart identities, never collapse by capsule name.
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
                .register_principal_runtime(
                    Box::new(FailingTestCapsule {
                        id: id.clone(),
                        manifest: CapsuleManifest::default(),
                    }),
                    hash_v1.clone(),
                    &default_p,
                    astrid_core::PrincipalUid::from_bytes([1; 32]),
                )
                .unwrap();
            registry
                .register_principal_runtime(
                    Box::new(FailingTestCapsule {
                        id: id.clone(),
                        manifest: CapsuleManifest::default(),
                    }),
                    hash_v2.clone(),
                    &alice,
                    astrid_core::PrincipalUid::from_bytes([2; 32]),
                )
                .unwrap();
        }

        let ready = {
            let registry = kernel.capsules.read().await;
            registry.cloned_runtimes_with_principal()
        };
        assert_eq!(ready.len(), 2, "two distinct hashes → two view triples");

        let failures = collect_failed_runtimes(&ready);
        assert_eq!(
            failures.len(),
            2,
            "two distinct failed hashes for one id must NOT be collapsed; got {}",
            failures.len()
        );
        let mut seen_hashes: Vec<_> = failures
            .iter()
            .map(|(_, _, runtime_id, _)| runtime_id.key().artifact().clone())
            .collect();
        seen_hashes.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        assert_eq!(seen_hashes, vec![hash_v1, hash_v2]);
        assert_ne!(failures[0].2, failures[1].2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn system_and_principal_runtimes_with_same_artifact_remain_distinct() {
        let (_d, home) = scratch_home();
        let kernel = test_kernel_with_home(home).await;
        let id = CapsuleId::new("guarded").unwrap();
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        let hash = astrid_capsule::registry::WasmHash::from_raw("guarded-hash");

        let mut registry = kernel.capsules.write().await;
        registry
            .register_system_runtime(
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
        registry
            .register_for(
                Box::new(CancellableTestCapsule {
                    id: id.clone(),
                    manifest: CapsuleManifest::default(),
                    cancelled: Arc::new(AtomicBool::new(false)),
                    unloaded: Arc::new(AtomicBool::new(false)),
                    cancelled_for: Arc::default(),
                }),
                hash.clone(),
                &alice,
            )
            .expect("alice receives a separate authority-scoped runtime");

        let system = registry
            .get_for(&PrincipalId::default(), &id)
            .expect("system runtime");
        let alice_runtime = registry.get_for(&alice, &id).expect("alice runtime");
        assert!(!Arc::ptr_eq(&system, &alice_runtime));
        assert_eq!(registry.refcount_for_hash(&hash), Some(2));

        registry.register_existing(&id, &hash, &bob).unwrap();
        let bob_runtime = registry.get_for(&bob, &id).expect("bob system view");
        assert!(Arc::ptr_eq(&system, &bob_runtime));
        assert_eq!(registry.refcount_for_hash(&hash), Some(3));
    }

    #[cfg(unix)]
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

    #[cfg(unix)]
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

    #[cfg(unix)]
    #[test]
    fn test_load_or_generate_rejects_bad_key_length() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let keys_dir = dir.path().join("keys");
        std::fs::create_dir_all(&keys_dir).unwrap();

        // Write a key file with wrong length.
        std::fs::write(keys_dir.join("runtime.key"), [0u8; 16]).unwrap();
        std::fs::set_permissions(
            keys_dir.join("runtime.key"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

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

    #[tokio::test]
    async fn ephemeral_shutdown_waits_for_the_final_client_disconnect() {
        let root = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(root.path());
        let kernel = super::test_kernel_with_home(home).await;
        let alice = astrid_core::PrincipalId::new("alice").unwrap();
        let bob = astrid_core::PrincipalId::new("bob").unwrap();
        let shutdown = kernel.shutdown_tx.subscribe();

        kernel.set_ephemeral(true);
        kernel.connection_opened(&alice);
        kernel.connection_opened(&bob);
        kernel.connection_closed(&alice);
        assert!(!*shutdown.borrow());

        kernel.connection_closed(&bob);
        assert!(*shutdown.borrow());
    }

    #[tokio::test]
    async fn persistent_kernel_does_not_shutdown_on_last_disconnect() {
        let root = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(root.path());
        let kernel = super::test_kernel_with_home(home).await;
        let alice = astrid_core::PrincipalId::new("alice").unwrap();
        let shutdown = kernel.shutdown_tx.subscribe();

        kernel.connection_opened(&alice);
        kernel.connection_closed(&alice);

        assert!(!*shutdown.borrow());
    }

    #[tokio::test]
    async fn never_connected_fallback_starts_only_when_explicitly_armed() {
        let root = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(root.path());
        let kernel = super::test_kernel_with_home(home).await;
        let shutdown = kernel.shutdown_tx.subscribe();

        kernel.set_ephemeral(true);
        astrid_runtime::time::sleep(std::time::Duration::from_millis(10)).await;
        assert!(
            !*shutdown.borrow(),
            "Kernel construction must not consume the daemon's startup grace"
        );

        drop(spawn_ephemeral_startup_fallback(
            Arc::clone(&kernel),
            std::time::Duration::from_millis(1),
        ));
        astrid_runtime::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(*shutdown.borrow());
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
        let audit_log = Arc::new(
            AuditLog::open_with_kv_store(Arc::clone(&kv), Arc::clone(&runtime_key))
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
            message.contains("default admin profile bootstrap failed"),
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
