//! Native resource acquisition feeding the single portable composition path.
use crate::{Kernel, KernelResources, load_or_generate_runtime_key, open_audit_log};
use crate::{native_boot, socket};
use astrid_capsule::profile_cache::PrincipalProfileCache;
use astrid_core::{SessionId, dirs::WorkspaceLayout};
use std::{path::PathBuf, sync::Arc};

impl Kernel {
    /// Resolve host-call limits from the restored, admitted boot configuration.
    ///
    /// The resolver runs once after native migration, runtime-tree admission
    /// and layout publication, before configured identity links and capsule
    /// engines consume policy. It may initialize logging for identity-link
    /// diagnostics without writing into an unadmitted home. The returned
    /// configuration is the same validated snapshot used for audit and resources.
    ///
    /// # Errors
    /// Returns native admission, configuration, resolver or kernel wiring errors.
    pub async fn new_configured_with_workspace_layout(
        session_id: SessionId,
        workspace_root: PathBuf,
        local_egress: std::collections::HashMap<String, Vec<String>>,
        workspace_layout: WorkspaceLayout,
        configure: impl FnOnce(
            &astrid_config::Config,
        ) -> std::io::Result<(
            astrid_capsule_types::CapsuleRuntimeLimits,
            astrid_capsule_types::HttpLimits,
        )>,
    ) -> std::io::Result<(Arc<Self>, astrid_config::Config)> {
        use astrid_core::dirs::AstridHome;

        // Resolve the Astrid home directory. Required for persistent KV store
        // and audit log. Fails boot if neither $ASTRID_HOME nor $HOME is set.
        let home = AstridHome::resolve().map_err(|e| {
            std::io::Error::other(format!(
                "Failed to resolve Astrid home (set $ASTRID_HOME or $HOME): {e}"
            ))
        })?;
        // Home-bound custody acquires the singleton before opening stores.
        // Interrupted projection subsets must authenticate their durable
        // RETIRING authority before ordinary home admission or amendments.
        let boot_admission = native_boot::NativeBootAdmission::acquire(&home)?;

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
        let (principal_store, singleton_lock, layout_origin) = boot_admission
            .open(quota, principal_directory.clone())
            .await?;
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
            local_egress,
            resources,
            workspace_layout,
            Some(profile_cache),
            principal_directory,
            Some(principal_store),
            |config| {
                configure(config.ok_or_else(|| {
                    std::io::Error::other("native boot policy snapshot is missing")
                })?)
            },
        )
        .await
        .and_then(|(kernel, config)| {
            config
                .map(|config| (kernel, config))
                .ok_or_else(|| std::io::Error::other("native boot policy snapshot is missing"))
        })
    }
}
