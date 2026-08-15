//! Durable engine construction and policy entry points.

use super::{
    Arc, ArenaReader, BTreeMap, CommitGroup, DurableEngine, DurableEnginePolicy, DurableError,
    DurableInner, EngineOpenOptions, FaultInjector, FileExt, GroupCommitPolicy, LIFECYCLE_USABLE,
    LOCK_FILE, Mutex, NoFaults, ObjectCache, ObjectCacheConfig, Path, PersistentObjectIdentity,
    PrincipalCodec, RecoveryLimits, RecoveryRetryPolicy, RwLock, io, io_error, open_rw_capability,
    recover_store,
};

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Open or create a durable store with no injected faults.
    ///
    /// # Errors
    ///
    /// Returns an I/O, lock, frame, identity, principal-codec, or model
    /// recovery error. An incomplete or physically invalid final frame is
    /// treated as an uncommitted tail only when no valid frame follows it;
    /// semantic invalidity and interior corruption remain fatal.
    pub fn open(
        path: impl AsRef<Path>,
        identity: I,
        principal_codec: C,
        limits: RecoveryLimits,
    ) -> Result<Self, DurableError> {
        Self::open_with_options(
            path,
            identity,
            principal_codec,
            limits,
            EngineOpenOptions {
                policy: DurableEnginePolicy::default(),
                faults: Arc::new(NoFaults),
            },
        )
    }

    /// Open or create a durable store with an explicit group-commit policy.
    ///
    /// Setting both delays to zero disables intentional waiting while still
    /// allowing callers queued behind an active flush to share that caller's
    /// next durability group.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open`].
    pub fn open_with_group_commit_policy(
        path: impl AsRef<Path>,
        identity: I,
        principal_codec: C,
        limits: RecoveryLimits,
        group_policy: GroupCommitPolicy,
    ) -> Result<Self, DurableError> {
        Self::open_with_options(
            path,
            identity,
            principal_codec,
            limits,
            EngineOpenOptions {
                policy: DurableEnginePolicy::new(
                    group_policy,
                    RecoveryRetryPolicy::default(),
                    ObjectCacheConfig::disabled(),
                ),
                faults: Arc::new(NoFaults),
            },
        )
    }

    /// Open or create a durable store with an explicitly governed decoded
    /// object cache.
    ///
    /// The engine never selects a hidden default cache ceiling. The embedding
    /// runtime owns both the live total controller and per-principal budget.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open`].
    pub fn open_with_object_cache(
        path: impl AsRef<Path>,
        identity: I,
        principal_codec: C,
        limits: RecoveryLimits,
        object_cache: ObjectCacheConfig<P>,
    ) -> Result<Self, DurableError> {
        Self::open_with_options(
            path,
            identity,
            principal_codec,
            limits,
            EngineOpenOptions {
                policy: DurableEnginePolicy::new(
                    GroupCommitPolicy::default(),
                    RecoveryRetryPolicy::default(),
                    object_cache,
                ),
                faults: Arc::new(NoFaults),
            },
        )
    }

    /// Open or create a durable store with an explicit in-process recovery
    /// policy.
    ///
    /// The recovery policy bounds work performed by one foreground operation.
    /// It does not cap future recovery attempts: a later operation starts a
    /// fresh bounded attempt after an operator resolves a persistent I/O
    /// incident.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open`].
    pub fn open_with_recovery_policy(
        path: impl AsRef<Path>,
        identity: I,
        principal_codec: C,
        limits: RecoveryLimits,
        recovery_policy: RecoveryRetryPolicy,
    ) -> Result<Self, DurableError> {
        Self::open_with_options(
            path,
            identity,
            principal_codec,
            limits,
            EngineOpenOptions {
                policy: DurableEnginePolicy::new(
                    GroupCommitPolicy::default(),
                    recovery_policy,
                    ObjectCacheConfig::disabled(),
                ),
                faults: Arc::new(NoFaults),
            },
        )
    }

    /// Open or create a durable store with one complete operating policy.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open`].
    pub fn open_with_policy(
        path: impl AsRef<Path>,
        identity: I,
        principal_codec: C,
        limits: RecoveryLimits,
        policy: DurableEnginePolicy<P>,
    ) -> Result<Self, DurableError> {
        Self::open_with_options(
            path,
            identity,
            principal_codec,
            limits,
            EngineOpenOptions {
                policy,
                faults: Arc::new(NoFaults),
            },
        )
    }

    /// Open or create a durable store with an explicit fault injector.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open`].
    pub fn open_with_faults(
        path: impl AsRef<Path>,
        identity: I,
        principal_codec: C,
        limits: RecoveryLimits,
        faults: Arc<dyn FaultInjector>,
    ) -> Result<Self, DurableError> {
        Self::open_with_options(
            path,
            identity,
            principal_codec,
            limits,
            EngineOpenOptions {
                policy: DurableEnginePolicy::default(),
                faults,
            },
        )
    }

    pub(super) fn open_with_options(
        path: impl AsRef<Path>,
        identity: I,
        principal_codec: C,
        limits: RecoveryLimits,
        options: EngineOpenOptions<P>,
    ) -> Result<Self, DurableError> {
        let path = path.as_ref().to_path_buf();
        std::fs::create_dir_all(&path)
            .map_err(|source| io_error("create principal-store directory", source))?;
        let directory_capability = Arc::new(super::representations::open_store_root(&path)?);
        let lock_path = path.join(LOCK_FILE);
        let lock = open_rw_capability(&directory_capability, Path::new(LOCK_FILE), true)?;
        if let Err(source) = lock.try_lock_exclusive() {
            if source.kind() == io::ErrorKind::WouldBlock {
                return Err(DurableError::LockHeld(lock_path));
            }
            return Err(io_error("lock principal store", source));
        }

        let recovered = recover_store(
            &path,
            &directory_capability,
            &principal_codec,
            &identity,
            limits,
        )?;

        Ok(Self {
            directory: path,
            directory_capability,
            identity,
            principal_codec,
            limits,
            faults: options.faults,
            lifecycle: std::sync::atomic::AtomicU8::new(LIFECYCLE_USABLE),
            arena_reader: RwLock::new(Some(ArenaReader {
                file: recovered.arena_reader,
                generation: 0,
            })),
            object_cache: ObjectCache::new(options.policy.object_cache),
            recovery_policy: options.policy.recovery,
            preparation_authority: Arc::new(()),
            group_policy: options.policy.group_commit,
            commit_group: Mutex::new(CommitGroup::default()),
            inner: Mutex::new(DurableInner {
                roots_by_principal: recovered.roots_by_principal,
                index: recovered.index,
                pending_index_locations: Vec::new(),
                pending_direct_objects: BTreeMap::new(),
                validated: recovered.validated,
                files: Some(recovered.files),
                representations: recovered.representations,
                lock: Some(lock),
                poisoned: false,
                arena_generation: 0,
            }),
        })
    }
}
