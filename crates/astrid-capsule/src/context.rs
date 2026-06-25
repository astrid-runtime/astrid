//! Capsule context types.
//!
//! Provides the execution context for capsule lifecycle and tool invocations.

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use astrid_core::GroupConfig;
use astrid_core::principal::PrincipalId;
use astrid_events::EventBus;
use astrid_storage::ScopedKvStore;

use astrid_core::session_token::SessionToken;

use crate::profile_cache::PrincipalProfileCache;
use crate::registry::CapsuleRegistry;
use crate::schema_catalog::SchemaCatalog;

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
    pub cli_socket_listener: Option<Arc<tokio::sync::Mutex<tokio::net::UnixListener>>>,
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
    pub overlay_registry: Option<Arc<astrid_vfs::OverlayVfsRegistry>>,
    /// Live group → capability mapping from the kernel's `ArcSwap<GroupConfig>`.
    ///
    /// The capsule load path resolves the owner principal's
    /// [`CAP_RESOURCES_UNBOUNDED`](astrid_core::CAP_RESOURCES_UNBOUNDED)
    /// capability against this config (groups → grants/revokes → capability
    /// set) to decide whether the capsule's run-loop is exempt from the
    /// per-principal CPU + memory bound. Per-invocation checks load from the
    /// same live handle so runtime group mutations are observed without
    /// reloading capsules. **Fail-secure**: `None` (tests, single-tenant boot
    /// that did not thread it, or an unthreaded call site) means *not exempt*.
    pub group_config: Option<Arc<ArcSwap<GroupConfig>>>,
    /// Operator-approved local-egress allowlist for THIS capsule, as
    /// `host:port` / `host:*` patterns. Resolved by the kernel from
    /// `[security.capsule_local_egress]` keyed by capsule id and snapshotted
    /// onto every pooled instance's `HostState` at load. Endpoints listed
    /// here are exempt from the `astrid:http` SSRF airlock for this capsule
    /// only. Empty = no exemptions (fail-closed). Operator config — never
    /// settable by the capsule's own (untrusted) manifest.
    pub local_egress: Vec<String>,
}

impl CapsuleContext {
    #[must_use]
    pub fn new(
        principal: PrincipalId,
        workspace_root: PathBuf,
        home_root: Option<PathBuf>,
        kv: ScopedKvStore,
        event_bus: Arc<EventBus>,
        cli_socket_listener: Option<Arc<tokio::sync::Mutex<tokio::net::UnixListener>>>,
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
    #[must_use]
    pub fn with_overlay_registry(mut self, registry: Arc<astrid_vfs::OverlayVfsRegistry>) -> Self {
        self.overlay_registry = Some(registry);
        self
    }

    /// Set the live group → capability config used to resolve capability-driven
    /// resource exemptions.
    #[must_use]
    pub fn with_group_config(mut self, groups: Arc<ArcSwap<GroupConfig>>) -> Self {
        self.group_config = Some(groups);
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
}
