//! Singleton-owned native admission before resolving immutable capsule policy.
//!
//! An admitted stage owns the one open store and the restored operator
//! snapshot. Consuming it wires the kernel; it cannot reopen or substitute
//! the home after callers resolve their CLI overrides.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use astrid_capsule::profile_cache::PrincipalProfileCache;
use astrid_capsule_types::{CapsuleRuntimeLimits, HttpLimits};
use astrid_core::SessionId;
use astrid_core::dirs::{AstridHome, WorkspaceLayout};
use astrid_storage::{PrincipalDirectory, RuntimePrincipalStore};

use crate::legacy_migration_barrier::LayoutOrigin;
use crate::{
    Kernel, KernelResources, boot_policy, home_admission, legacy_migration_barrier,
    load_or_generate_runtime_key, open_audit_log, socket,
};

/// Admitted native resources and one restored, validated configuration snapshot.
///
/// No capsule is loaded and no management dispatcher runs until [`Self::start`]
/// consumes this stage with the caller's final immutable capsule limits.
pub struct AdmittedNativeBoot {
    native: NativeResources,
    workspace_root: PathBuf,
    workspace_layout: WorkspaceLayout,
    config: Arc<astrid_config::ResolvedConfig>,
}

impl AdmittedNativeBoot {
    /// Admit and restore a captured home under the existing boot singleton.
    ///
    /// # Errors
    /// Fails on unsafe homes, storage/recovery errors, invalid operator policy,
    /// or failure to acquire native audit/socket/key resources. Storage opens
    /// once; configuration is read only after authenticated restoration.
    pub async fn admit(
        home: AstridHome,
        workspace_root: PathBuf,
        workspace_layout: WorkspaceLayout,
    ) -> io::Result<Self> {
        let admitted = AdmittedStore::open(home).await?;
        let config = Arc::new(boot_policy::load(
            &admitted.home,
            &workspace_root,
            &workspace_layout,
        )?);
        let native = admitted.acquire_resources().await?;
        Ok(Self {
            native,
            workspace_root,
            workspace_layout,
            config,
        })
    }

    /// Share the restored snapshot used by every kernel boot-policy consumer.
    #[must_use]
    pub fn config(&self) -> Arc<astrid_config::ResolvedConfig> {
        Arc::clone(&self.config)
    }

    /// Consume admission with the caller's resolved immutable capsule policy.
    ///
    /// # Errors
    /// Returns any portable kernel wiring or migration failure. No capsule
    /// policy is rebound after construction.
    pub async fn start(
        self,
        session_id: SessionId,
        runtime_limits: CapsuleRuntimeLimits,
        local_egress: HashMap<String, Vec<String>>,
        http_limits: HttpLimits,
    ) -> io::Result<Arc<Kernel>> {
        let NativeResources {
            mut resources,
            profile_cache,
            principal_directory,
            principal_store,
        } = self.native;
        resources.boot_config = Some(self.config);
        Kernel::with_resources_and_workspace_layout_with_profile_cache_and_directory(
            session_id,
            self.workspace_root,
            runtime_limits,
            local_egress,
            http_limits,
            resources,
            self.workspace_layout,
            Some(profile_cache),
            principal_directory,
            Some(principal_store),
        )
        .await
    }
}

struct NativeResources {
    resources: KernelResources,
    profile_cache: Arc<PrincipalProfileCache>,
    principal_directory: PrincipalDirectory,
    principal_store: RuntimePrincipalStore,
}

struct AdmittedStore {
    home: AstridHome,
    layout_origin: LayoutOrigin,
    singleton_lock: std::fs::File,
    profile_cache: Arc<PrincipalProfileCache>,
    principal_directory: PrincipalDirectory,
    principal_store: RuntimePrincipalStore,
}

impl AdmittedStore {
    async fn open(home: AstridHome) -> io::Result<Self> {
        // A layout-two sentinel is only authoritative together with the
        // component migration ledger.  Check this before `AstridHome::ensure`
        // can retire any released source on behalf of an incomplete cutover.
        home_admission::validate_boot(&home)?;

        // Acquire the singleton advisory lock as the FIRST fallible boot step —
        // BEFORE opening any shared state store. A boot-race loser then fails
        // here with the actionable "already running (singleton lock held)"
        // error and never opens (or even touches) the shared principal or audit
        // stores, rather than dying on a raw `LOCK is already locked` from
        // the store layer after having opened one. The listener bind below does
        // NOT re-acquire the lock — it is already held for the process lifetime.
        let singleton_lock = socket::acquire_boot_singleton_lock(&home)?;
        // A competing owner may have completed admission while we waited for
        // the singleton. Reclassify the captured home before opening media.
        let mut layout_origin = legacy_migration_barrier::capture_layout_origin(&home)?;
        let home_admission = home_admission::validate_boot(&home)?;
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
        let quota = quota_resolver(&profile_cache, &principal_directory);

        // Open the authoritative state store. First cutover imports and
        // verifies legacy SurrealKV under the singleton lock before serving.
        let (principal_store, recovered_origin) = home_admission
            .open_store(&home, quota, principal_directory.clone())
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to open principal store: {e}")))?;
        if let Some(origin) = recovered_origin {
            // Storage returned the origin proved before restoring host bytes.
            // Missing sentinels alone never authorize fresh initialization.
            layout_origin = origin;
        }
        home.clear_runtime_principal_scratch().map_err(|error| {
            std::io::Error::other(format!(
                "Failed to clear stale principal runtime scratch: {error}"
            ))
        })?;
        Ok(Self {
            home,
            layout_origin,
            singleton_lock,
            profile_cache,
            principal_directory,
            principal_store,
        })
    }

    async fn acquire_resources(self) -> io::Result<NativeResources> {
        let Self {
            home,
            layout_origin,
            singleton_lock,
            profile_cache,
            principal_directory,
            principal_store,
        } = self;
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
        if let Err(e) = socket::write_pid_file_for_home(&home) {
            tracing::warn!(error = %e, "Failed to write daemon PID file; stop/restart will fall back to socket-only cleanup");
        }
        let (session_token, token_path) = socket::generate_session_token(&home)?;

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
        Ok(NativeResources {
            resources,
            profile_cache,
            principal_directory,
            principal_store,
        })
    }
}

fn quota_resolver(
    profile_cache: &Arc<PrincipalProfileCache>,
    principal_directory: &PrincipalDirectory,
) -> Arc<dyn astrid_storage::KvQuotaResolver<astrid_storage::StateOwner>> {
    let quota_cache = Arc::clone(profile_cache);
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

    quota
}

#[cfg(test)]
mod tests;
