//! Authoritative startup and in-process recovery for the durable engine.

use super::wal::{durable_error as wal_durable_error, recover_wal};
use super::{
    ARENA_FILE, ArenaReader, DurableEngine, DurableError, DurableFiles, DurableInner, DurableWal,
    FaultInjector, FaultPoint, INDEX_FILE, IndexState, LIFECYCLE_CLOSED, LIFECYCLE_USABLE,
    MutexGuard, PersistentObjectIdentity, PrincipalCodec, ROOT_FILE, RecoveredStore,
    RecoveryLimits, Seek, SeekFrom, SharedIdentity, SharedPrincipalCodec, WAL_FILE, io, io_error,
    open_rw_capability, recover_arena, recover_index, recover_interrupted_compaction,
    recover_root_history, recover_startup_roots, replace_index, sync_store_directory_capability,
};
use crate::volume::AstridVolume;
use std::collections::BTreeSet;

type RecoveredWal<P, I, C> = (RecoveredStore<P>, Option<DurableWal<P, I, C>>);
use std::path::Path;
use std::sync::Arc;

#[derive(Default)]
pub(super) struct RecoveryScope {
    entered: bool,
}

impl RecoveryScope {
    fn enter(&mut self) -> Result<(), DurableError> {
        if self.entered {
            return Err(DurableError::RequiresRecovery);
        }
        self.entered = true;
        Ok(())
    }
}

pub(super) fn recover_store<P, I, C>(
    store_root: &cap_std::fs::Dir,
    principal_codec: &SharedPrincipalCodec<C>,
    identity: &SharedIdentity<I>,
    limits: RecoveryLimits,
    create_wal: bool,
) -> Result<RecoveredWal<P, I, C>, DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    recover_interrupted_compaction(store_root, principal_codec, identity, limits)?;
    let mut representations =
        super::representations::RepresentationStore::open(store_root, limits)?;
    let protected_arena_len = representations.as_ref().map_or(
        Ok(0),
        super::representations::RepresentationStore::generation_zero_protected_len,
    )?;
    let mut arena = open_rw_capability(store_root, Path::new(ARENA_FILE), true)?;
    let mut roots = open_rw_capability(store_root, Path::new(ROOT_FILE), true)?;
    let mut index_cache = open_rw_capability(store_root, Path::new(INDEX_FILE), true).ok();
    sync_store_directory_capability(store_root)?;
    let wal_file = open_optional_native_wal(store_root, create_wal)?;
    if wal_file.is_some() {
        sync_store_directory_capability(store_root)?;
    }
    let scheme = identity.scheme();
    let arena_len = arena
        .metadata()
        .map_err(|source| io_error("read object-arena metadata", source))?
        .len();
    let cached = index_cache
        .as_mut()
        .and_then(|file| recover_index(file, &mut arena, scheme, limits, arena_len));
    let (index, arena_tail) = if let Some(state) = cached {
        (state.objects, state.arena_tail)
    } else {
        let (index, arena_tail) = recover_arena(&mut arena, identity, limits, protected_arena_len)?;
        let state = IndexState {
            arena_len: arena
                .metadata()
                .map_err(|source| io_error("read recovered arena metadata", source))?
                .len(),
            arena_tail,
            objects: index,
        };
        drop(index_cache.take());
        index_cache = replace_index(store_root, &state, scheme);
        (state.objects, state.arena_tail)
    };
    if let Some(representations) = &mut representations {
        representations.validate_generation_zero_index(&index)?;
    }
    let mut index = index;
    let wal_writer = if let Some(wal_file) = wal_file {
        Some(replay_transaction_wal(
            wal_file,
            &mut arena,
            &mut roots,
            &mut index,
            representations.as_mut(),
            identity,
            principal_codec,
            limits,
        )?)
    } else {
        None
    };
    let (roots_by_principal, journal_heads, validated, rejected_roots) = recover_startup_roots(
        &mut roots,
        &mut arena,
        &index,
        principal_codec,
        identity,
        limits,
    )?;
    let arena_len = arena
        .metadata()
        .map_err(|source| io_error("read recovered arena metadata", source))?
        .len();
    arena
        .seek(SeekFrom::End(0))
        .map_err(|source| io_error("seek object arena", source))?;
    roots
        .seek(SeekFrom::End(0))
        .map_err(|source| io_error("seek root journal", source))?;
    let arena_reader = arena
        .try_clone()
        .map_err(|source| io_error("clone object arena for positional reads", source))?;
    Ok((
        RecoveredStore {
            roots_by_principal,
            journal_heads,
            rejected_roots,
            index,
            validated,
            files: DurableFiles {
                arena,
                roots,
                index_cache,
                arena_len,
                arena_tail,
            },
            representations,
            arena_reader,
        },
        wal_writer,
    ))
}

pub(super) fn recover_volume<P, I, C>(
    volume: &Arc<dyn AstridVolume>,
    principal_codec: &SharedPrincipalCodec<C>,
    identity: &SharedIdentity<I>,
    limits: RecoveryLimits,
    create_wal: bool,
) -> Result<RecoveredWal<P, I, C>, DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    let mut arena = super::File::volume(Arc::clone(volume), ARENA_FILE, true)?;
    let mut roots = super::File::volume(Arc::clone(volume), ROOT_FILE, true)?;
    let mut index_cache = super::File::volume(Arc::clone(volume), INDEX_FILE, true).ok();
    let wal_file = open_optional_volume_wal(volume, create_wal)?;
    volume
        .sync()
        .map_err(|source| io_error("flush Astrid volume namespace", source))?;
    let scheme = identity.scheme();
    let arena_len = arena
        .metadata()
        .map_err(|source| io_error("read object-arena metadata", source))?
        .len();
    let mut representations =
        super::representations::RepresentationStore::open_volume(volume, limits)?;
    let protected_arena_len = representations.as_ref().map_or(
        Ok(0),
        super::representations::RepresentationStore::generation_zero_protected_len,
    )?;
    let cached = index_cache
        .as_mut()
        .and_then(|file| recover_index(file, &mut arena, scheme, limits, arena_len));
    let (index, arena_tail) = if let Some(state) = cached {
        (state.objects, state.arena_tail)
    } else {
        drop(index_cache.take());
        recover_arena(&mut arena, identity, limits, protected_arena_len)?
    };
    if let Some(store) = &mut representations {
        store.validate_generation_zero_index(&index)?;
    }
    let mut index = index;
    let wal_writer = if let Some(wal_file) = wal_file {
        Some(replay_transaction_wal(
            wal_file,
            &mut arena,
            &mut roots,
            &mut index,
            representations.as_mut(),
            identity,
            principal_codec,
            limits,
        )?)
    } else {
        None
    };
    let (roots_by_principal, journal_heads, validated, rejected_roots) = recover_startup_roots(
        &mut roots,
        &mut arena,
        &index,
        principal_codec,
        identity,
        limits,
    )?;
    let arena_len = arena
        .metadata()
        .map_err(|source| io_error("read recovered arena metadata", source))?
        .len();
    arena
        .seek(SeekFrom::End(0))
        .map_err(|source| io_error("seek object arena", source))?;
    roots
        .seek(SeekFrom::End(0))
        .map_err(|source| io_error("seek root journal", source))?;
    let arena_reader = arena
        .try_clone()
        .map_err(|source| io_error("clone object arena for positional reads", source))?;
    Ok((
        RecoveredStore {
            roots_by_principal,
            journal_heads,
            rejected_roots,
            index,
            validated,
            files: DurableFiles {
                arena,
                roots,
                index_cache,
                arena_len,
                arena_tail,
            },
            representations,
            arena_reader,
        },
        wal_writer,
    ))
}

fn open_optional_native_wal(
    store_root: &cap_std::fs::Dir,
    create_wal: bool,
) -> Result<Option<super::File>, DurableError> {
    if create_wal {
        return open_rw_capability(store_root, Path::new(WAL_FILE), true).map(Some);
    }
    match open_rw_capability(store_root, Path::new(WAL_FILE), false) {
        Ok(file) => Ok(Some(file)),
        Err(DurableError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(None)
        },
        Err(error) => Err(error),
    }
}

fn open_optional_volume_wal(
    volume: &Arc<dyn AstridVolume>,
    create_wal: bool,
) -> Result<Option<super::File>, DurableError> {
    let region = crate::volume::VolumeRegion::new(WAL_FILE)
        .map_err(|source| io_error("validate WAL volume region", source))?;
    let exists = volume
        .region_exists(&region)
        .map_err(|source| io_error("probe WAL volume region", source))?;
    if !exists && !create_wal {
        return Ok(None);
    }
    super::File::volume(Arc::clone(volume), WAL_FILE, true).map(Some)
}

#[allow(clippy::too_many_arguments)]
fn replay_transaction_wal<P, I, C>(
    wal_file: super::File,
    arena: &mut super::File,
    roots: &mut super::File,
    index: &mut std::collections::BTreeMap<crate::storage_model::ObjectId, super::ArenaLocation>,
    representations: Option<&mut super::representations::RepresentationStore>,
    identity: &SharedIdentity<I>,
    codec: &SharedPrincipalCodec<C>,
    limits: RecoveryLimits,
) -> Result<DurableWal<P, I, C>, DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    let mut wal_validated = BTreeSet::new();
    let mut root_history =
        recover_root_history::<P, _, _>(roots, codec, identity.scheme(), limits)?;
    let mut wal_writer = recover_wal(
        wal_file,
        arena,
        roots,
        index,
        &mut wal_validated,
        &mut root_history,
        representations,
        identity.clone(),
        codec.clone(),
        limits,
    )?;
    wal_writer.checkpoint().map_err(wal_durable_error)?;
    Ok(wal_writer)
}

fn stabilize_recovered_store<P: Ord>(
    recovered: &mut RecoveredStore<P>,
    faults: &dyn FaultInjector,
) -> Result<(), DurableError> {
    if faults.should_fail(FaultPoint::BeforeInProcessRecoveryArenaFlush) {
        return Err(io_error(
            "flush recovered object arena",
            io::Error::other("injected recovery arena-flush I/O failure"),
        ));
    }
    recovered
        .files
        .arena
        .sync_data()
        .map_err(|source| io_error("flush recovered object arena", source))?;
    if faults.should_fail(FaultPoint::BeforeInProcessRecoveryRootFlush) {
        return Err(io_error(
            "flush recovered root journal",
            io::Error::other("injected recovery root-flush I/O failure"),
        ));
    }
    recovered
        .files
        .roots
        .sync_data()
        .map_err(|source| io_error("flush recovered root journal", source))?;
    if let Some(representations) = &mut recovered.representations {
        representations.flush()?;
    }
    Ok(())
}

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Recover a poisoned engine in place while retaining its singleton lock.
    ///
    /// Healthy engines return `Ok(false)` without taking the mutation mutex.
    /// A poisoned engine drops its stale data-file handles, replays the same
    /// authoritative recovery path used at process startup, clears disposable
    /// caches, and returns `Ok(true)`. Only I/O failures are retried according
    /// to the configured bounded policy; corruption and model failures fail
    /// immediately. A later operation may try again after the external fault
    /// is repaired.
    ///
    /// # Errors
    ///
    /// Returns [`DurableError::Closed`] after explicit close, or the last
    /// recovery error while leaving the engine poisoned and retryable.
    pub fn recover_if_required(&self) -> Result<bool, DurableError> {
        match self.lifecycle.load(std::sync::atomic::Ordering::Acquire) {
            LIFECYCLE_USABLE => return Ok(false),
            LIFECYCLE_CLOSED => return Err(DurableError::Closed),
            _ => {},
        }

        let mut inner = self.inner.lock();
        self.recover_locked(&mut inner)
    }

    fn recover_locked(&self, inner: &mut DurableInner<P>) -> Result<bool, DurableError> {
        if !inner.poisoned {
            return if inner.files.is_some() {
                Ok(false)
            } else {
                Err(DurableError::Closed)
            };
        }
        if inner.lock.is_none() {
            return Err(DurableError::Closed);
        }

        drop(self.wal.lock().take());
        drop(inner.files.take());
        drop(inner.representations.take());
        drop(self.arena_reader.write().take());
        self.object_cache.clear();
        let next_generation = inner.arena_generation.wrapping_add(1);
        let attempts = self.recovery_policy.attempts().get();
        let mut last_error = None;
        for attempt in 0..attempts {
            let recovered = if self
                .faults
                .should_fail(FaultPoint::BeforeInProcessRecoveryOpen)
            {
                Err(io_error(
                    "reopen durable engine after failed write",
                    io::Error::other("injected recovery I/O failure"),
                ))
            } else {
                self.recover_media().and_then(|(mut recovered, wal)| {
                    stabilize_recovered_store(&mut recovered, self.faults.as_ref())?;
                    Ok((recovered, wal))
                })
            };
            match recovered {
                Ok((recovered, wal)) => {
                    inner.roots_by_principal = recovered.roots_by_principal;
                    inner.journal_heads = recovered.journal_heads;
                    inner.rejected_roots = recovered.rejected_roots;
                    self.published_roots.replace(&inner.roots_by_principal);
                    inner.index = recovered.index;
                    inner.pending_index_locations.clear();
                    inner.pending_direct_objects.clear();
                    inner.pending_wal = super::wal::PendingWalOverlay::default();
                    inner.validated = recovered.validated;
                    inner.files = Some(recovered.files);
                    inner.representations = recovered.representations;
                    *self.wal.lock() = wal;
                    inner.poisoned = false;
                    inner.arena_generation = next_generation;
                    *self.arena_reader.write() = Some(ArenaReader {
                        file: recovered.arena_reader,
                        generation: next_generation,
                    });
                    self.lifecycle
                        .store(LIFECYCLE_USABLE, std::sync::atomic::Ordering::Release);
                    return Ok(true);
                },
                Err(error) => {
                    let retryable = matches!(error, DurableError::Io { .. });
                    last_error = Some(error);
                    if !retryable || attempt.saturating_add(1) == attempts {
                        break;
                    }
                    if !self.recovery_policy.backoff().is_zero() {
                        std::thread::sleep(self.recovery_policy.backoff());
                    }
                },
            }
        }
        Err(last_error.unwrap_or(DurableError::RequiresRecovery))
    }

    fn recover_media(&self) -> Result<RecoveredWal<P, I, C>, DurableError> {
        let volume = self.volume.read();
        match (
            self.directory.as_deref(),
            self.directory_capability.as_deref(),
            volume.as_ref(),
        ) {
            (Some(_), Some(directory), None) => recover_store(
                directory,
                &self.principal_codec,
                &self.identity,
                self.limits,
                self.transaction_wal.is_enabled(),
            ),
            (None, None, Some(volume)) => recover_volume(
                volume,
                &self.principal_codec,
                &self.identity,
                self.limits,
                self.transaction_wal.is_enabled(),
            ),
            _ => Err(DurableError::InvalidRepresentationState(
                "durable engine media configuration is inconsistent",
            )),
        }
    }

    pub(super) fn lock_usable(&self) -> Result<MutexGuard<'_, DurableInner<P>>, DurableError> {
        self.lock_usable_with(&mut RecoveryScope::default())
    }

    pub(super) fn lock_usable_with(
        &self,
        recovery: &mut RecoveryScope,
    ) -> Result<MutexGuard<'_, DurableInner<P>>, DurableError> {
        let mut inner = self.inner.lock();
        if inner.poisoned {
            recovery.enter()?;
            self.recover_locked(&mut inner)?;
        }
        super::ensure_usable(&inner)?;
        Ok(inner)
    }
}
