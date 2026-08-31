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

#[cfg(not(target_family = "wasm"))]
/// Awaitable process-projection teardown callback.
pub type ProcessStorageMountCleanupFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
#[cfg(not(target_family = "wasm"))]
/// Owned process-projection teardown callback.
pub type ProcessStorageMountCleanup = Box<dyn FnOnce() -> ProcessStorageMountCleanupFuture + Send>;

/// Handle to the kernel-bound uplink (CLI) local-transport listener.
///
/// On native this is exactly the concrete type the kernel binds and hands into
/// the capsule execution context.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub type UplinkListener =
    std::sync::Arc<tokio::sync::Mutex<astrid_core::local_transport::LocalListener>>;
/// No uplink socket exists on the browser target; this uninhabited type
/// makes `Option<UplinkListener>` necessarily `None` there.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[derive(Clone)]
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

/// Authority source for the capsule's workspace namespace.
///
/// `Astrid` is the canonical path-free content workspace. A native project
/// directory is available only when the caller explicitly selects the
/// `HostedPortal` variant.
#[derive(Clone, Debug)]
pub enum WorkspaceSource {
    /// Owner-internal Astrid content workspace. Branches are selected by the
    /// authenticated principal at invocation time.
    Astrid,
    /// Explicit native project portal used by compatibility and host flows.
    HostedPortal(PathBuf),
}

/// Native filesystem projection held by a spawned child process.
///
/// The paths are private run-time mountpoints issued by the kernel.  They are
/// never selected by a capsule or serialized over the public provider wire;
/// the broker fixes their owner/branch targets before returning this value.
#[cfg(not(target_family = "wasm"))]
pub struct ProcessStorageMount {
    /// Native path containing the caller's workspace attachment.
    pub workspace_root: PathBuf,
    /// Native path containing the caller's owner-local home projection.
    pub home_root: PathBuf,
    /// Optional explicitly-authorized Fleet `shared/` attachment.
    /// This is never the acting principal's HOME and is only populated when
    /// Fleet ownership grants the process a separate shared view.
    pub fleet_shared_root: Option<PathBuf>,
    cleanup: Option<ProcessStorageMountCleanup>,
}

#[cfg(not(target_family = "wasm"))]
impl ProcessStorageMount {
    /// Construct a projection with an optional teardown callback.
    pub fn new(
        workspace_root: PathBuf,
        home_root: PathBuf,
        cleanup: impl FnOnce() + Send + 'static,
    ) -> Self {
        Self::new_async(workspace_root, home_root, move || {
            Box::pin(async move { cleanup() })
        })
    }

    /// Construct a projection with an awaitable teardown. Callers that own a
    /// process lifecycle should invoke [`Self::close_async`] before dropping
    /// the guard; `Drop` remains only the emergency fallback for abandoned
    /// handles or runtime shutdown.
    pub fn new_async(
        workspace_root: PathBuf,
        home_root: PathBuf,
        cleanup: impl FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + 'static,
    ) -> Self {
        Self {
            workspace_root,
            home_root,
            fleet_shared_root: None,
            cleanup: Some(Box::new(cleanup)),
        }
    }

    /// Explicitly await provider unmount, lease revocation, and projection
    /// cleanup. This consumes the guard so its `Drop` fallback is not run a
    /// second time.
    pub async fn close_async(mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup().await;
        }
    }
}

#[cfg(not(target_family = "wasm"))]
impl Drop for ProcessStorageMount {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(cleanup());
            } else {
                // A synchronous drop during runtime shutdown still gets an
                // emergency drain. Explicit lifecycle paths should use
                // `close_async` so this detached fallback is not needed.
                let _ = std::thread::Builder::new()
                    .name("astrid-storage-mount-cleanup".to_owned())
                    .spawn(move || {
                        if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                        {
                            runtime.block_on(cleanup());
                        }
                    });
            }
        }
    }
}

/// Kernel-provided native projection broker used by process host calls.
///
/// Capsule code sees only the neutral mount/teardown contract.  The kernel
/// implementation issues private owner-root and workspace-branch leases and
/// launches the platform provider; no owner or branch selector crosses this
/// boundary.
#[cfg(not(target_family = "wasm"))]
#[async_trait::async_trait]
pub trait ProcessStorageMountBroker: Send + Sync {
    /// Mount the authenticated principal's process view.
    async fn mount(&self, principal: &PrincipalId) -> Result<ProcessStorageMount, String>;
}

/// One immutable principal binding to the canonical workspace attachment.
///
/// The alias is deliberately absent from this value.  Callers resolve an
/// alias through the live directory once and retain the immutable UID for the
/// lifetime of the mount; alias retirement or reuse therefore cannot retarget
/// an existing branch.
#[cfg(not(target_family = "wasm"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkspaceBranchBinding {
    /// Immutable principal owner selected by the kernel.
    pub uid: astrid_core::PrincipalUid,
    /// Typed storage owner for the branch.
    pub owner: astrid_storage::StateOwner,
    /// Opaque durable branch identifier.
    pub branch: astrid_core::WorkspaceUid,
}

/// Operation applied to one authenticated workspace branch.
#[cfg(not(target_family = "wasm"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceCommitOp {
    /// Publish the branch's selected attachment into the owner catalog.
    Promote,
    /// Discard the branch's selected attachment.
    Rollback,
}

/// Kernel-owned workspace branch service shared by every capsule engine.
///
/// Branches are keyed by immutable [`PrincipalUid`] rather than a mutable
/// alias.  The service is placed in [`CapsuleContext`] as one `Arc` owned by
/// the kernel, so two capsules serving the same principal observe one branch
/// and one attachment prefix.  The branch manager itself remains in
/// `astrid-storage`; this type only binds authenticated aliases and enforces
/// lifecycle/authority checks at the capsule boundary.
#[cfg(not(target_family = "wasm"))]
pub struct WorkspaceBranchService {
    store: astrid_storage::RuntimePrincipalStore,
    directory: astrid_storage::PrincipalDirectory,
    ownership: Option<Arc<astrid_storage::OwnershipStore>>,
    branches: astrid_storage::RuntimeWorkspaceBranchStore,
    /// Serializes the check/lookup/begin/insert sequence. The separate async
    /// gate keeps the synchronous binding map lock out of await points while
    /// still ensuring concurrent capsule loads cannot create two branches.
    bind_lock: tokio::sync::Mutex<()>,
    bindings: Mutex<std::collections::HashMap<astrid_core::PrincipalUid, WorkspaceBranchBinding>>,
}

#[cfg(not(target_family = "wasm"))]
impl WorkspaceBranchService {
    /// Stable attachment selector used by the canonical Astrid workspace.
    ///
    /// `home/<principal>/` and other owner-catalog names remain outside this
    /// attachment.  A future explicit attachment selector can replace this
    /// constant without changing branch authority or lease semantics.
    pub const ATTACHMENT_PREFIX: &'static str = "workspace/default";

    /// Construct a service over the kernel's authoritative principal store.
    #[must_use]
    pub fn new(
        store: astrid_storage::RuntimePrincipalStore,
        directory: astrid_storage::PrincipalDirectory,
    ) -> Self {
        Self::new_with_ownership(store, directory, None)
    }

    /// Construct a service with the authoritative principal-to-fleet graph.
    ///
    /// A principal assigned to a fleet receives an independent branch under
    /// that fleet owner, so all fleet principals share one base catalog while
    /// retaining independent working views. The graph is re-read at bind and
    /// commit boundaries; ownership moves therefore cannot promote an old
    /// owner branch.
    #[must_use]
    pub fn new_with_ownership(
        store: astrid_storage::RuntimePrincipalStore,
        directory: astrid_storage::PrincipalDirectory,
        ownership: Option<Arc<astrid_storage::OwnershipStore>>,
    ) -> Self {
        let branches = astrid_storage::WorkspaceBranchStore::new(store.content());
        Self {
            store,
            directory,
            ownership,
            branches,
            bind_lock: tokio::sync::Mutex::new(()),
            bindings: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Return the authoritative store used to construct a branch filesystem.
    #[must_use]
    pub fn store(&self) -> astrid_storage::RuntimePrincipalStore {
        self.store.clone()
    }

    /// Bind one live alias to its immutable principal branch.
    ///
    /// Existing bindings are returned unchanged.  New bindings begin a
    /// selected `workspace/default` attachment and never expose the complete
    /// owner catalog.
    pub async fn bind(&self, principal: &PrincipalId) -> Result<WorkspaceBranchBinding, String> {
        let _bind_guard = self.bind_lock.lock().await;
        let uid = self
            .directory
            .uid_for(principal)
            .map_err(|error| format!("resolve principal workspace identity: {error}"))?;
        let owner = self.owner_for(uid).await?;
        let existing = self
            .bindings
            .lock()
            .map_err(|_| "workspace branch binding lock poisoned".to_owned())?
            .get(&uid)
            .copied();
        if let Some(binding) = existing {
            if binding.owner != owner {
                return Err(
                    "principal workspace ownership changed; old branch is no longer valid"
                        .to_owned(),
                );
            }
            return Ok(binding);
        }
        let prefix = astrid_storage::ContentName::new(Self::ATTACHMENT_PREFIX)
            .map_err(|error| format!("invalid workspace attachment prefix: {error}"))?;
        // Durable records are authoritative across daemon/capsule restarts.
        // Reuse a live UID-bound branch instead of creating a divergent view;
        // terminal promotion receipts intentionally do not become a new live
        // binding and therefore fall through to a fresh branch.
        if let Some(durable) = self
            .branches
            .binding_for_uid(&owner, uid, &prefix)
            .map_err(|error| format!("recover durable workspace binding: {error}"))?
            && durable.lifecycle() == astrid_storage::WorkspaceBindingLifecycle::Live
        {
            let binding = WorkspaceBranchBinding {
                uid,
                owner,
                branch: durable.branch_id(),
            };
            self.bindings
                .lock()
                .map_err(|_| "workspace branch binding lock poisoned".to_owned())?
                .insert(uid, binding);
            return Ok(binding);
        }
        let descriptor = self
            .branches
            .begin_for_uid_at(&owner, uid, astrid_storage::WorkspaceUid::random(), prefix)
            .map_err(|error| format!("begin workspace branch: {error}"))?;
        // Ownership can change while the synchronous branch begin is in
        // progress. Re-read before publishing the binding and discard the
        // just-created branch if the owner moved.
        if self.owner_for(uid).await? != owner {
            let _ = self.branches.rollback(&owner, descriptor.id());
            return Err("principal workspace ownership changed during branch bind".to_owned());
        }
        let binding = WorkspaceBranchBinding {
            uid,
            owner,
            branch: descriptor.id(),
        };
        self.bindings
            .lock()
            .map_err(|_| "workspace branch binding lock poisoned".to_owned())?
            .insert(uid, binding);
        Ok(binding)
    }

    async fn owner_for(
        &self,
        uid: astrid_core::PrincipalUid,
    ) -> Result<astrid_storage::StateOwner, String> {
        let Some(ownership) = self.ownership.as_ref() else {
            return Ok(astrid_storage::StateOwner::Principal(uid));
        };
        let snapshot = ownership
            .load()
            .await
            .map_err(|error| format!("resolve principal fleet ownership: {error}"))?;
        Ok(snapshot
            .principal_owner(uid)
            .map_or(astrid_storage::StateOwner::Principal(uid), |assignment| {
                astrid_storage::StateOwner::Fleet(assignment.fleet_uid)
            }))
    }

    /// Construct a filesystem view for an already-authorized binding.
    #[must_use]
    pub fn filesystem(
        &self,
        binding: WorkspaceBranchBinding,
    ) -> astrid_storage::RuntimeWorkspaceFilesystem {
        self.branches.filesystem(binding.owner, binding.branch)
    }

    /// Return an existing binding for an authenticated alias without creating
    /// a new branch.  Commit/rollback paths use this lookup so an alias that
    /// was retired and later reused cannot acquire authority over the old
    /// runtime's branch as a side effect of a lifecycle request.
    pub async fn binding_for(
        &self,
        principal: &PrincipalId,
    ) -> Result<WorkspaceBranchBinding, String> {
        let uid = self
            .directory
            .uid_for(principal)
            .map_err(|error| format!("resolve current principal identity: {error}"))?;
        let owner = self.owner_for(uid).await?;
        let prefix = astrid_storage::ContentName::new(Self::ATTACHMENT_PREFIX)
            .map_err(|error| format!("invalid workspace attachment prefix: {error}"))?;
        let cached = self
            .bindings
            .lock()
            .map_err(|_| "workspace branch binding lock poisoned".to_owned())?
            .get(&uid)
            .copied();
        let binding = if let Some(binding) = cached {
            binding
        } else {
            let durable = self
                .branches
                .binding_for_uid(&owner, uid, &prefix)
                .map_err(|error| format!("recover durable workspace binding: {error}"))?
                .ok_or_else(|| "no workspace branch is bound to this principal".to_owned())?;
            if durable.lifecycle() != astrid_storage::WorkspaceBindingLifecycle::Live
                || durable.binding_uid() != Some(uid)
            {
                return Err("durable workspace binding is not a live UID-bound branch".to_owned());
            }
            let binding = WorkspaceBranchBinding {
                uid,
                owner,
                branch: durable.branch_id(),
            };
            self.bindings
                .lock()
                .map_err(|_| "workspace branch binding lock poisoned".to_owned())?
                .insert(uid, binding);
            binding
        };
        if binding.owner != owner {
            return Err(
                "principal workspace ownership changed; old branch is no longer valid".to_owned(),
            );
        }
        let durable = self
            .branches
            .binding(&binding.owner, binding.branch)
            .map_err(|error| format!("read durable workspace binding: {error}"))?;
        if durable.lifecycle() != astrid_storage::WorkspaceBindingLifecycle::Live
            || durable.binding_uid() != Some(uid)
            || durable.target_prefix() != Some(&prefix)
        {
            return Err("durable workspace binding no longer matches this principal".to_owned());
        }
        Ok(binding)
    }

    /// Promote or roll back a branch, verifying the alias still names the
    /// immutable UID that originally received the binding.
    pub async fn finish(
        &self,
        principal: &PrincipalId,
        binding: WorkspaceBranchBinding,
        operation: WorkspaceCommitOp,
    ) -> Result<(), String> {
        let current_uid = self
            .directory
            .uid_for(principal)
            .map_err(|error| format!("resolve current principal identity: {error}"))?;
        if current_uid != binding.uid {
            return Err(format!(
                "principal alias {principal} no longer names workspace owner {}",
                binding.uid
            ));
        }
        let current_owner = self.owner_for(binding.uid).await?;
        if current_owner != binding.owner {
            return Err("principal workspace ownership changed; refusing branch commit".to_owned());
        }
        let stored = self
            .bindings
            .lock()
            .map_err(|_| "workspace branch binding lock poisoned".to_owned())?
            .get(&binding.uid)
            .copied()
            .ok_or_else(|| "no workspace branch is bound to this principal".to_owned())?;
        if stored != binding {
            return Err("workspace branch binding does not match the kernel lease".to_owned());
        }
        let prefix = astrid_storage::ContentName::new(Self::ATTACHMENT_PREFIX)
            .map_err(|error| format!("invalid workspace attachment prefix: {error}"))?;
        let durable = self
            .branches
            .binding(&binding.owner, binding.branch)
            .map_err(|error| format!("read durable workspace binding: {error}"))?;
        if durable.lifecycle() != astrid_storage::WorkspaceBindingLifecycle::Live
            || durable.binding_uid() != Some(binding.uid)
            || durable.target_prefix() != Some(&prefix)
        {
            return Err("durable workspace binding no longer matches this principal".to_owned());
        }
        match operation {
            WorkspaceCommitOp::Promote => self
                .branches
                .promote(&binding.owner, binding.branch)
                .map(|_| ())
                .map_err(|error| format!("promote workspace branch: {error}"))?,
            WorkspaceCommitOp::Rollback => {
                self.branches
                    .rollback(&binding.owner, binding.branch)
                    .map_err(|error| format!("rollback workspace branch: {error}"))?
            },
        }
        self.bindings
            .lock()
            .map_err(|_| "workspace branch binding lock poisoned".to_owned())?
            .remove(&binding.uid);
        Ok(())
    }

    /// Roll back all live branches during engine/kernel teardown.
    pub fn rollback_all(&self) {
        let bindings = match self.bindings.lock() {
            Ok(mut bindings) => std::mem::take(&mut *bindings),
            Err(_) => return,
        };
        for binding in bindings.into_values() {
            if let Err(error) = self.branches.rollback(&binding.owner, binding.branch) {
                tracing::warn!(%error, "failed to roll back unloaded Astrid workspace branch");
            }
        }
    }

    /// Remove unfinished durable branches left by a crashed kernel boot.
    ///
    /// Promotion receipts are not returned by `list_branches` and therefore
    /// survive this cleanup; a completed promotion remains retryable and
    /// idempotent while only disposable live branches are discarded.
    pub async fn cleanup_orphaned(&self) -> Result<(), String> {
        let mut owners = std::collections::BTreeSet::new();
        for (_, uid) in self.directory.bindings() {
            owners.insert(astrid_storage::StateOwner::Principal(uid));
        }
        if let Some(ownership) = self.ownership.as_ref() {
            let snapshot = ownership
                .load()
                .await
                .map_err(|error| format!("load ownership graph for branch cleanup: {error}"))?;
            for assignment in snapshot.principal_owners() {
                owners.insert(astrid_storage::StateOwner::Fleet(assignment.fleet_uid));
            }
            for fleet in snapshot.fleets() {
                owners.insert(astrid_storage::StateOwner::Fleet(fleet.identity().uid));
            }
        }
        for owner in owners {
            let branches = self
                .branches
                .list_branches(&owner)
                .map_err(|error| format!("list orphaned workspace branches: {error}"))?;
            for branch in branches {
                let Some(binding_uid) = branch.binding_uid() else {
                    // Legacy uid-less records cannot be attributed safely;
                    // they are disposable crash residue and are rolled back.
                    self.branches
                        .rollback(&owner, branch.id())
                        .map_err(|error| format!("roll back unbound workspace branch: {error}"))?;
                    continue;
                };
                let owner_now = self.owner_for(binding_uid).await?;
                if owner_now != owner
                    || branch.target_prefix().map(ToString::to_string)
                        != Some(Self::ATTACHMENT_PREFIX.to_owned())
                {
                    // A moved/retired principal's durable branch is retained
                    // but remains inaccessible until explicit administrative
                    // rollback/export. Never delete valid uncommitted state at
                    // boot merely because the in-memory binding is absent.
                    tracing::warn!(
                        %binding_uid,
                        branch = %branch.id(),
                        "retaining inaccessible workspace branch after ownership change"
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(not(target_family = "wasm"))]
impl Drop for WorkspaceBranchService {
    fn drop(&mut self) {}
}

#[cfg(all(test, not(target_family = "wasm")))]
mod workspace_branch_tests;

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
    /// Typed workspace authority. `workspace_root` is ignored for
    /// [`WorkspaceSource::Astrid`].
    pub workspace_source: WorkspaceSource,
    /// Legacy native home root retained for lifecycle/compatibility callers.
    /// Normal native runtimes bind `home://` to `principal_store` through the
    /// immutable UID in `principal_directory`; this field is not the authority
    /// for steady-state home VFS operations.
    pub home_root: Option<PathBuf>,
    /// Live alias-to-UID directory used to bind durable principal-owned
    /// filesystem views.  The alias is never used as a storage owner.
    pub principal_directory: astrid_storage::PrincipalDirectory,
    /// Authoritative principal store used for `home://` on native hosts.
    /// `None` is retained for compatibility/lifecycle contexts that do not
    /// have a kernel-owned durable store.
    #[cfg(not(target_family = "wasm"))]
    pub principal_store: Option<astrid_storage::RuntimePrincipalStore>,
    /// Kernel-owned branch service shared by every capsule engine in this
    /// runtime. `None` is retained for hosted-portal and browser contexts.
    #[cfg(not(target_family = "wasm"))]
    pub workspace_branches: Option<Arc<WorkspaceBranchService>>,
    /// Kernel-owned broker for native process projections over path-free
    /// Astrid storage. Hosted portals leave this unset.
    #[cfg(not(target_family = "wasm"))]
    pub process_storage_mount_broker: Option<Arc<dyn ProcessStorageMountBroker>>,
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
    /// quota resolution. Unstamped compatibility callers may leave this `None`
    /// and retain the process-global default profile. A typed principal runtime
    /// with an autonomous `run` export requires it so owner authority and
    /// sub-budgets cannot silently fall back to another context.
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
            workspace_source: WorkspaceSource::HostedPortal(workspace_root.clone()),
            workspace_root,
            home_root,
            principal_directory: astrid_storage::PrincipalDirectory::default(),
            #[cfg(not(target_family = "wasm"))]
            principal_store: None,
            #[cfg(not(target_family = "wasm"))]
            workspace_branches: None,
            #[cfg(not(target_family = "wasm"))]
            process_storage_mount_broker: None,
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

    /// Select the canonical path-free Astrid workspace for this runtime.
    #[must_use]
    pub fn with_astrid_workspace(mut self) -> Self {
        self.workspace_source = WorkspaceSource::Astrid;
        self
    }

    /// Select an explicit native project portal.
    #[must_use]
    pub fn with_hosted_portal(mut self, root: PathBuf) -> Self {
        self.workspace_root = root.clone();
        self.workspace_source = WorkspaceSource::HostedPortal(root);
        self
    }

    /// Attach the kernel's authoritative principal store and alias directory.
    ///
    /// The store is cloned into the context so pooled capsule instances can
    /// bind each invocation to its immutable [`PrincipalUid`](astrid_core::PrincipalUid)
    /// without consulting host home directories.
    #[cfg(not(target_family = "wasm"))]
    #[must_use]
    pub fn with_principal_storage(
        mut self,
        store: astrid_storage::RuntimePrincipalStore,
        directory: astrid_storage::PrincipalDirectory,
    ) -> Self {
        self.principal_store = Some(store);
        self.principal_directory = directory;
        self
    }

    /// Attach the kernel-wide canonical workspace branch service.
    #[cfg(not(target_family = "wasm"))]
    #[must_use]
    pub fn with_workspace_branches(mut self, service: Arc<WorkspaceBranchService>) -> Self {
        self.workspace_branches = Some(service);
        self
    }

    /// Attach the kernel's private native process projection broker.
    #[cfg(not(target_family = "wasm"))]
    #[must_use]
    pub fn with_process_storage_mount_broker(
        mut self,
        broker: Arc<dyn ProcessStorageMountBroker>,
    ) -> Self {
        self.process_storage_mount_broker = Some(broker);
        self
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
    pub fn with_overlay_registry(mut self, registry: OverlayRegistry) -> Self {
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
