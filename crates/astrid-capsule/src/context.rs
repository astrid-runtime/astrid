//! Capsule context types.
//!
//! Provides the execution context for capsule lifecycle and tool invocations.

use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, Weak};

use arc_swap::ArcSwap;
use astrid_core::GroupConfig;
use astrid_core::principal::PrincipalId;
use astrid_events::EventBus;
use astrid_storage::ScopedKvStore;

use astrid_core::session_token::SessionToken;

use crate::profile_cache::PrincipalProfileCache;
use crate::registry::CapsuleRegistry;
use crate::schema_catalog::SchemaCatalog;

/// Handle to the kernel-bound uplink (CLI) Unix socket listener.
///
/// On native this is exactly the concrete type the kernel binds and hands into
/// the capsule execution context.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub type UplinkListener = std::sync::Arc<tokio::sync::Mutex<tokio::net::UnixListener>>;
/// No uplink socket exists on the browser target; this uninhabited type
/// makes `Option<UplinkListener>` necessarily `None` there.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub enum UplinkListener {}

/// Handle to the per-principal overlay VFS registry (Layer 4, issue #668).
///
/// On native this is exactly the concrete `astrid-vfs` registry the kernel
/// threads through the capsule context. `astrid-vfs` is native-only (it uses
/// `cap-std` and `tokio`'s filesystem surface), so on the browser target the
/// alias is an uninhabited type — an alternate host resolves per-principal
/// overlays by other means, and `Option<OverlayRegistry>` is necessarily
/// `None` there.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub type OverlayRegistry = std::sync::Arc<astrid_vfs::OverlayVfsRegistry>;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub enum OverlayRegistry {}

static LIVE_GROUP_CONFIGS: LazyLock<Mutex<Vec<LiveGroupConfigEntry>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

struct LiveGroupConfigEntry {
    snapshot: Weak<GroupConfig>,
    live: Weak<ArcSwap<GroupConfig>>,
}

pub(crate) fn live_group_config_for(
    snapshot: &Option<Arc<GroupConfig>>,
) -> Option<Arc<ArcSwap<GroupConfig>>> {
    let snapshot = snapshot.as_ref()?;
    let mut entries = LIVE_GROUP_CONFIGS.lock().ok()?;
    entries.retain(|entry| entry.snapshot.strong_count() > 0 && entry.live.strong_count() > 0);
    entries.iter().find_map(|entry| {
        let registered_snapshot = entry.snapshot.upgrade()?;
        if Arc::ptr_eq(&registered_snapshot, snapshot) {
            entry.live.upgrade()
        } else {
            None
        }
    })
}

fn register_live_group_config(snapshot: &Arc<GroupConfig>, live: &Arc<ArcSwap<GroupConfig>>) {
    if let Ok(mut entries) = LIVE_GROUP_CONFIGS.lock() {
        entries.retain(|entry| entry.snapshot.strong_count() > 0 && entry.live.strong_count() > 0);
        entries.push(LiveGroupConfigEntry {
            snapshot: Arc::downgrade(snapshot),
            live: Arc::downgrade(live),
        });
    }
}

/// Context provided to a capsule during lifecycle operations (load/unload).
///
/// Not `Clone` by design - `session_token` holds secret bytes that should
/// not be accidentally duplicated. Use `Arc<SessionToken>` for cheap sharing.
/// Constructed via `new()` + builder methods (`with_session_token`, etc.).
pub struct CapsuleContext {
    /// The principal this capsule is running on behalf of.
    pub principal: PrincipalId,
    pub workspace_root: PathBuf,
    /// Home resources directory (`~/.astrid/home/{principal}/`).
    /// When set, capsules declaring `fs_read = ["home://"]` can read files
    /// under this root via the `home://` path prefix. This is scoped to the
    /// principal's home — keys, databases, and system config in `~/.astrid/`
    /// are NOT accessible through this path.
    pub home_root: Option<PathBuf>,
    pub kv: ScopedKvStore,
    pub event_bus: Arc<EventBus>,
    pub cli_socket_listener: Option<UplinkListener>,
    /// Shared capsule registry for `hooks::trigger` fan-out.
    ///
    /// When set, WASM capsules can dispatch hooks to other capsules via
    /// the `astrid_trigger_hook` host function (the kernel mechanism).
    pub capsule_registry: Option<Arc<tokio::sync::RwLock<CapsuleRegistry>>>,
    /// Session token for authenticating CLI socket connections. Only set for
    /// capsules with `net_bind` capability (the CLI proxy capsule).
    pub session_token: Option<Arc<SessionToken>>,
    /// Shared allowance store for capsule-level approval requests.
    pub allowance_store: Option<Arc<astrid_approval::AllowanceStore>>,
    /// Shared identity store for resolving platform users to `AstridUserId`.
    pub identity_store: Option<Arc<dyn astrid_storage::IdentityStore>>,
    /// Shared schema catalog for topic→schema mappings (A2UI Track 2).
    ///
    /// Updated on capsule load/unload. The A2UI bridge reads this to generate
    /// schema context for the LLM system prompt.
    pub schema_catalog: Arc<SchemaCatalog>,
    /// Shared per-principal quota profile cache (Layer 3, issue #666).
    ///
    /// One instance per kernel boot, backing [`WasmEngine::invoke_interceptor`](
    /// crate::engine::wasm::WasmEngine::invoke_interceptor)'s per-invocation
    /// quota resolution. Tests and single-tenant deployments may leave this
    /// `None` — the engine falls back to the process-global default profile.
    pub profile_cache: Option<Arc<PrincipalProfileCache>>,
    /// Shared per-principal overlay VFS registry (Layer 4, issue #668).
    ///
    /// One instance per kernel boot. The engine resolves the invoking
    /// principal's overlay on each invocation so Agent A's workspace writes
    /// never reach Agent B's view of the same tree. Tests and single-tenant
    /// deployments may leave this `None`.
    pub overlay_registry: Option<OverlayRegistry>,
    /// Snapshot group → capability mapping.
    ///
    /// This field remains the public compatibility surface for callers that
    /// construct capsule contexts outside the kernel. The kernel threads live
    /// updates through `with_live_group_config`.
    pub group_config: Option<Arc<GroupConfig>>,
    /// Operator-approved local-egress allowlist for THIS capsule, as
    /// `host:port` / `host:*` patterns. Resolved by the kernel from
    /// `[security.capsule_local_egress]` keyed by capsule id and snapshotted
    /// onto every pooled instance's `HostState` at load. Endpoints listed
    /// here are exempt from the `astrid:http` SSRF airlock for this capsule
    /// only. Empty = no exemptions (fail-closed). Operator config — never
    /// settable by the capsule's own (untrusted) manifest.
    pub local_egress: Vec<String>,
    /// Synchronous per-action audit sink for sensitive host calls (fs
    /// read/write/delete, net connect/bind, process spawn). One instance per
    /// kernel boot, holding the kernel's signed audit log + session id. The
    /// engine snapshots it onto every pooled `HostState` at load; the fs/net/
    /// process host fns report every allowed, failed, OR denied call to it.
    /// `None` in tests / single-tenant boot that did not thread it — the host
    /// fns then only emit the observability `tracing` lines.
    pub audit_sink: Option<Arc<dyn crate::audit_sink::HostAuditSink>>,
}

impl CapsuleContext {
    #[must_use]
    pub fn new(
        principal: PrincipalId,
        workspace_root: PathBuf,
        home_root: Option<PathBuf>,
        kv: ScopedKvStore,
        event_bus: Arc<EventBus>,
        cli_socket_listener: Option<UplinkListener>,
    ) -> Self {
        Self {
            principal,
            workspace_root,
            home_root,
            kv,
            event_bus,
            cli_socket_listener,
            capsule_registry: None,
            session_token: None,
            allowance_store: None,
            identity_store: None,
            schema_catalog: Arc::new(SchemaCatalog::new()),
            profile_cache: None,
            overlay_registry: None,
            group_config: None,
            local_egress: Vec::new(),
            audit_sink: None,
        }
    }

    /// Set the session token for socket authentication.
    #[must_use]
    pub fn with_session_token(mut self, token: Arc<SessionToken>) -> Self {
        self.session_token = Some(token);
        self
    }

    /// Set the capsule registry for hook dispatch.
    #[must_use]
    pub fn with_registry(mut self, registry: Arc<tokio::sync::RwLock<CapsuleRegistry>>) -> Self {
        self.capsule_registry = Some(registry);
        self
    }

    /// Set the shared allowance store for capsule-level approval.
    #[must_use]
    pub fn with_allowance_store(mut self, store: Arc<astrid_approval::AllowanceStore>) -> Self {
        self.allowance_store = Some(store);
        self
    }

    /// Set the shared identity store for platform user resolution.
    #[must_use]
    pub fn with_identity_store(mut self, store: Arc<dyn astrid_storage::IdentityStore>) -> Self {
        self.identity_store = Some(store);
        self
    }

    /// Set the shared per-principal profile cache (Layer 3 quota enforcement).
    #[must_use]
    pub fn with_profile_cache(mut self, cache: Arc<PrincipalProfileCache>) -> Self {
        self.profile_cache = Some(cache);
        self
    }

    /// Set the shared per-principal overlay VFS registry (Layer 4, issue #668).
    ///
    /// Native-only: `astrid-vfs` (its `OverlayVfsRegistry`) does not compile for
    /// the browser target, so this builder is absent there. On native the
    /// parameter type is exactly [`OverlayRegistry`].
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[must_use]
    pub fn with_overlay_registry(mut self, registry: Arc<astrid_vfs::OverlayVfsRegistry>) -> Self {
        self.overlay_registry = Some(registry);
        self
    }

    /// Set a snapshot group → capability config used to resolve
    /// capability-driven resource exemptions.
    #[must_use]
    pub fn with_group_config(mut self, groups: Arc<GroupConfig>) -> Self {
        self.group_config = Some(groups);
        self
    }

    /// Set the live group → capability config used to resolve capability-driven
    /// resource exemptions.
    #[must_use]
    pub fn with_live_group_config(mut self, groups: Arc<ArcSwap<GroupConfig>>) -> Self {
        let snapshot = groups.load_full();
        register_live_group_config(&snapshot, &groups);
        self.group_config = Some(snapshot);
        self
    }

    /// Set this capsule's operator-approved local-egress allowlist
    /// (`host:port` / `host:*` patterns) used to exempt sanctioned
    /// loopback/private endpoints from the SSRF airlock.
    #[must_use]
    pub fn with_local_egress(mut self, allowlist: Vec<String>) -> Self {
        self.local_egress = allowlist;
        self
    }

    /// Set the synchronous per-action audit sink (fs/net/process). The
    /// kernel passes its signed audit sink so sensitive host calls land on
    /// the durable, hash-chained audit log.
    ///
    /// Generic over the concrete sink type so callers hand over an owned
    /// implementation without wrapping it in an `Arc<dyn …>` themselves; the
    /// builder erases it to the trait object the engine stores.
    #[must_use]
    pub fn with_audit_sink<S>(mut self, sink: S) -> Self
    where
        S: crate::audit_sink::HostAuditSink + 'static,
    {
        let sink: Arc<dyn crate::audit_sink::HostAuditSink> = Arc::new(sink);
        self.audit_sink = Some(sink);
        self
    }
}
