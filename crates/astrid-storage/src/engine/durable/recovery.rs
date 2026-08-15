//! Authoritative startup and in-process recovery for the durable engine.

use super::{
    ARENA_FILE, ArenaReader, DurableEngine, DurableError, DurableFiles, DurableInner,
    FaultInjector, FaultPoint, INDEX_FILE, IndexState, LIFECYCLE_CLOSED, LIFECYCLE_USABLE,
    MutexGuard, PersistentObjectIdentity, PrincipalCodec, ROOT_FILE, RecoveredStore,
    RecoveryLimits, Seek, SeekFrom, io, io_error, open_rw_capability, recover_arena, recover_index,
    recover_interrupted_compaction, recover_roots, replace_index, sync_store_directory_capability,
};
use crate::volume::AstridVolume;
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
    path: &Path,
    store_root: &cap_std::fs::Dir,
    principal_codec: &C,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<RecoveredStore<P>, DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    recover_interrupted_compaction(path, store_root, principal_codec, identity, limits)?;
    let mut representations =
        super::representations::RepresentationStore::open(path, store_root, limits)?;
    let protected_arena_len = representations.as_ref().map_or(
        Ok(0),
        super::representations::RepresentationStore::generation_zero_protected_len,
    )?;
    let mut arena = open_rw_capability(store_root, Path::new(ARENA_FILE), true)?;
    let mut roots = open_rw_capability(store_root, Path::new(ROOT_FILE), true)?;
    let mut index_cache = open_rw_capability(store_root, Path::new(INDEX_FILE), true).ok();
    sync_store_directory_capability(store_root)?;
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
        representations.rebuild_contiguous_index(&mut arena, &index, identity, limits)?;
    }
    let (roots_by_principal, validated) = recover_roots(
        &mut roots,
        &mut arena,
        &index,
        representations.as_ref(),
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
    Ok(RecoveredStore {
        roots_by_principal,
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
    })
}

pub(super) fn recover_volume<P, I, C>(
    volume: &Arc<dyn AstridVolume>,
    principal_codec: &C,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<RecoveredStore<P>, DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    let mut arena = super::File::volume(Arc::clone(volume), ARENA_FILE, true)?;
    let mut roots = super::File::volume(Arc::clone(volume), ROOT_FILE, true)?;
    let mut index_cache = super::File::volume(Arc::clone(volume), INDEX_FILE, true).ok();
    volume
        .sync()
        .map_err(|source| io_error("flush Astrid volume namespace", source))?;
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
        // The index is disposable. Rebuild authority from the arena and allow
        // ordinary future admissions to repopulate the cache region.
        drop(index_cache.take());
        recover_arena(&mut arena, identity, limits, 0)?
    };
    let (roots_by_principal, validated) = recover_roots(
        &mut roots,
        &mut arena,
        &index,
        None,
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
    Ok(RecoveredStore {
        roots_by_principal,
        index,
        validated,
        files: DurableFiles {
            arena,
            roots,
            index_cache,
            arena_len,
            arena_tail,
        },
        representations: None,
        arena_reader,
    })
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
                self.recover_media().and_then(|mut recovered| {
                    stabilize_recovered_store(&mut recovered, self.faults.as_ref())?;
                    Ok(recovered)
                })
            };
            match recovered {
                Ok(recovered) => {
                    inner.roots_by_principal = recovered.roots_by_principal;
                    inner.index = recovered.index;
                    inner.pending_index_locations.clear();
                    inner.pending_direct_objects.clear();
                    inner.validated = recovered.validated;
                    inner.files = Some(recovered.files);
                    inner.representations = recovered.representations;
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

    fn recover_media(&self) -> Result<RecoveredStore<P>, DurableError> {
        let volume = self.volume.read();
        match (
            self.directory.as_deref(),
            self.directory_capability.as_deref(),
            volume.as_ref(),
        ) {
            (Some(path), Some(directory), None) => recover_store(
                path,
                directory,
                &self.principal_codec,
                &self.identity,
                self.limits,
            ),
            (None, None, Some(volume)) => {
                recover_volume(volume, &self.principal_codec, &self.identity, self.limits)
            },
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
