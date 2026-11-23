//! Explicit flush and close lifecycle for the durable engine.

use crate::storage_model::{ObjectId, RootState};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::wal::durable_error as wal_durable_error;
use super::{
    ARENA_MAGIC, DurableEngine, DurableError, DurableInner, FRAME_HEADER_LEN,
    FRAME_HEADER_LEN_USIZE, File, IndexState, LIFECYCLE_CLOSED, PersistentObjectIdentity,
    PrincipalCodec, ROOT_MAGIC, StoreLock, append_frames, io_error, live_files_mut,
    read_indexed_object_with_payload,
};

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Flush both authoritative files.
    ///
    /// # Errors
    ///
    /// Returns an authoritative recovery error or the underlying filesystem
    /// error.
    pub fn flush(&self) -> Result<(), DurableError> {
        let mut inner = self.lock_usable()?;
        self.flush_for_retirement(&mut inner)
    }

    /// Flush, unlock, and close the authoritative store files.
    ///
    /// Closing is idempotent. Every other operation returns
    /// [`DurableError::Closed`] after the first close, even while other
    /// [`Arc`](std::sync::Arc) references keep this engine value alive.
    ///
    /// # Errors
    ///
    /// Returns a recovery-required, flush, or unlock error after still
    /// releasing every owned file handle.
    pub fn close(&self) -> Result<(), DurableError> {
        // Arbiter then inner. Drain/join happens while holding both and without
        // the physical representation mutex so the worker can return Prepared.
        let mut arbiter = self.checkpoint_arbiter.lock();
        let mut inner = self.inner.lock();
        if inner.files.is_none() && inner.lock.is_none() {
            // Idempotent close: absorb any stray slot, then leave the engine closed.
            if let Ok(super::checkpoint_worker::DrainedWorker::Prepared { checkpoint, .. }) =
                super::checkpoint_worker::drain_join_slot(&mut arbiter, self.lifecycle.as_ref())
            {
                drop(checkpoint);
            }
            return arbiter.bump_custody();
        }

        let mut result = match super::checkpoint_worker::drain_join_slot(
            &mut arbiter,
            self.lifecycle.as_ref(),
        ) {
            Ok(joined) => self.finish_drained_checkpoint(&arbiter, &mut inner, joined),
            Err(error) => Err(error),
        };

        let lifecycle = self.lifecycle.load(std::sync::atomic::Ordering::Acquire);
        let poisoned = inner.poisoned || lifecycle == super::LIFECYCLE_REQUIRES_RECOVERY;
        if poisoned {
            inner.poisoned = true;
        }
        if result.is_ok() && poisoned {
            result = Err(DurableError::RequiresRecovery);
        }

        let bump = arbiter.bump_custody();
        if result.is_ok()
            && let Err(error) = bump
        {
            result = Err(error);
        }
        if result.is_ok()
            && inner.files.is_some()
            && let Err(error) =
                self.checkpoint_index(&mut inner, VolumeIndexPersist::CompactSnapshot)
        {
            self.mark_requires_recovery(&mut inner);
            result = Err(error);
        }
        // Common teardown always runs: prepare failure, publish uncertainty, and
        // every other close error still release owned handles.
        drop(self.wal.lock().take());
        drop(inner.representations.take());
        drop(inner.files.take());
        drop(self.arena_reader.write().take());
        self.lifecycle
            .store(LIFECYCLE_CLOSED, std::sync::atomic::Ordering::Release);
        let retired_metadata = self.retire_closed_metadata(&mut inner);
        let unlock = match inner.lock.take() {
            Some(StoreLock::Native(lock)) => fs2::FileExt::unlock(&lock)
                .map_err(|source| io_error("unlock principal store while closing", source)),
            Some(StoreLock::Volume) | None => Ok(()),
        };
        drop(self.volume.write().take());
        // Principal keys may have destructors that query the closed engine.
        // Release both guards before freeing the retired metadata containers.
        drop(inner);
        drop(arbiter);
        drop(retired_metadata);
        self.object_cache.clear();
        result.and(unlock)
    }

    fn retire_closed_metadata(&self, inner: &mut DurableInner<P>) -> RetiredMetadata<P> {
        // Close is terminal even after a flush error: only a fresh engine may
        // reconstruct from the unchanged arena/WAL. Swap out the disposable
        // views now, but defer their destructors until the writer is released.
        RetiredMetadata {
            _index: std::mem::take(&mut inner.index),
            _validated: std::mem::take(&mut inner.validated),
            _roots: std::mem::take(&mut inner.roots_by_principal),
            _direct_objects: std::mem::take(&mut inner.pending_direct_objects),
            _locations: std::mem::take(&mut inner.pending_index_locations),
            _wal: inner.pending_wal.take(),
            _published_roots: self.published_roots.entries.swap(Arc::new(BTreeMap::new())),
        }
    }

    fn finish_drained_checkpoint(
        &self,
        arbiter: &super::checkpoint_worker::CheckpointArbiterState,
        inner: &mut DurableInner<P>,
        joined: super::checkpoint_worker::DrainedWorker,
    ) -> Result<(), DurableError> {
        use super::checkpoint_worker::{DrainedWorker, PublicationPoison};
        if let DrainedWorker::Prepared {
            custody_generation, ..
        } = &joined
            && *custody_generation != arbiter.custody_generation
        {
            drop(joined);
            self.mark_requires_recovery(inner);
            return Err(DurableError::RequiresRecovery);
        }
        if inner.poisoned
            || self.lifecycle.load(std::sync::atomic::Ordering::Acquire)
                == super::LIFECYCLE_REQUIRES_RECOVERY
        {
            drop(joined);
            inner.poisoned = true;
            return Err(DurableError::RequiresRecovery);
        }
        if inner.files.is_none() {
            return Err(DurableError::Closed);
        }
        // Exactly one authoritative flush for every close. If a prepared job
        // was drained, this may append source updates it must still catch up.
        if let Err(error) = self.flush_authority(inner) {
            drop(joined);
            self.mark_requires_recovery(inner);
            return Err(error);
        }
        let DrainedWorker::Prepared {
            control,
            checkpoint,
            ..
        } = joined
        else {
            return Ok(());
        };
        let Some(shared) = inner.representations.clone() else {
            drop(checkpoint);
            self.mark_requires_recovery(inner);
            return Err(DurableError::RequiresRecovery);
        };
        let retired = {
            let mut store = shared.lock();
            let mut poison = PublicationPoison::armed(self.lifecycle.as_ref());
            match checkpoint.finish_drained(&mut store, self.limits, control.as_ref()) {
                Ok(retired) => {
                    poison.disarm();
                    retired
                },
                Err(error) => {
                    self.mark_requires_recovery(inner);
                    return Err(error);
                },
            }
        };
        if let Err(error) = retired.reclaim() {
            self.mark_requires_recovery(inner);
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn flush_for_retirement(
        &self,
        inner: &mut DurableInner<P>,
    ) -> Result<(), DurableError> {
        if let Err(error) = self
            .flush_authority(inner)
            .and_then(|()| self.checkpoint_index(inner, VolumeIndexPersist::RetainDeltas))
        {
            self.mark_requires_recovery(inner);
            return Err(error);
        }
        Ok(())
    }

    fn flush_authority(&self, inner: &mut DurableInner<P>) -> Result<(), DurableError> {
        if self.transaction_wal.is_enabled() {
            self.checkpoint_transaction_wal(inner)
        } else {
            let shared = inner.representations.clone();
            let mut representations = super::checkpoint_worker::lock_live_representations(
                shared.as_ref(),
                self.lifecycle.as_ref(),
            )?;
            let mut poison =
                super::checkpoint_worker::PublicationPoison::armed(self.lifecycle.as_ref());
            let representation_update =
                match self.append_pending_direct_update(inner, representations.as_deref_mut(), &[])
                {
                    Ok(update) => update,
                    Err(error) => {
                        self.mark_requires_recovery(inner);
                        poison.disarm();
                        return Err(error);
                    },
                };
            let files = match live_files_mut(&mut inner.files) {
                Ok(files) => files,
                Err(error) => {
                    self.mark_requires_recovery(inner);
                    poison.disarm();
                    return Err(error);
                },
            };
            if let Err(error) = files
                .arena
                .sync_data()
                .map_err(|source| io_error("flush object arena", source))
            {
                self.mark_requires_recovery(inner);
                poison.disarm();
                return Err(error);
            }
            if let Some(store) = representations.as_mut() {
                if let Some(update) = representation_update
                    && let Err(error) = store.publish_direct_update(update)
                {
                    self.mark_requires_recovery(inner);
                    poison.disarm();
                    return Err(error);
                }
                if let Err(error) = store.flush() {
                    self.mark_requires_recovery(inner);
                    poison.disarm();
                    return Err(error);
                }
            }
            if let Err(error) = files
                .roots
                .sync_data()
                .map_err(|source| io_error("flush root journal", source))
            {
                self.mark_requires_recovery(inner);
                poison.disarm();
                return Err(error);
            }
            // Hold the physical guard through volume durability.
            match self.sync_volume() {
                Ok(()) => {
                    poison.disarm();
                    Ok(())
                },
                Err(error) => {
                    self.mark_requires_recovery(inner);
                    poison.disarm();
                    Err(error)
                },
            }
        }
    }

    pub(super) fn sync_volume(&self) -> Result<(), DurableError> {
        let Some(volume) = self.volume.read().as_ref().cloned() else {
            return Ok(());
        };
        volume
            .sync()
            .map_err(|source| io_error("flush volume container", source))
    }

    pub(in crate::engine::durable) fn checkpoint_transaction_wal(
        &self,
        inner: &mut DurableInner<P>,
    ) -> Result<(), DurableError> {
        // Own one physical fence through canonical fold, WAL reset and index
        // publication. Poison must become visible before that fence releases
        // on every error or panic, including errors after the fold itself.
        let shared = inner.representations.clone();
        let mut representations = super::checkpoint_worker::lock_live_representations(
            shared.as_ref(),
            self.lifecycle.as_ref(),
        )?;
        let mut poison =
            super::checkpoint_worker::PublicationPoison::armed(self.lifecycle.as_ref());
        let result = (|| {
            self.fold_pending_wal(inner, representations.as_deref_mut())?;
            let mut wal = self.wal.lock();
            if let Some(writer) = wal.as_mut() {
                writer.checkpoint().map_err(wal_durable_error)?;
            }
            self.checkpoint_index(inner, VolumeIndexPersist::RetainDeltas)?;
            Ok(())
        })();
        if result.is_err() {
            self.mark_requires_recovery(inner);
        } else {
            poison.disarm();
        }
        result
    }

    fn fold_pending_wal(
        &self,
        inner: &mut DurableInner<P>,
        mut representations: Option<&mut super::representations::RepresentationStore>,
    ) -> Result<(), DurableError> {
        let pending = inner.pending_wal.take();
        let mut new_ids = Vec::new();
        let mut new_payloads = Vec::new();
        {
            let files = live_files_mut(&mut inner.files)?;
            for (id, object) in pending.objects() {
                if object.location().is_some() {
                    continue;
                }
                if let Some(location) = inner.index.get(id).copied() {
                    let (_, payload) = read_indexed_object_with_payload(
                        &files.arena,
                        *id,
                        location,
                        &self.identity,
                        self.limits,
                    )?;
                    if payload.as_slice() != object.payload() {
                        return Err(crate::storage_model::ModelError::ObjectCollision(*id).into());
                    }
                    continue;
                }
                new_ids.push(*id);
                new_payloads.push(object.payload());
            }
            if !new_payloads.is_empty() {
                let appended = append_frames(&mut files.arena, ARENA_MAGIC, &new_payloads)?;
                if appended.len() != new_ids.len() {
                    return Err(DurableError::Corrupt {
                        file: super::ARENA_FILE,
                        offset: 0,
                        detail: "WAL overlay fold returned the wrong object count",
                    });
                }
                for (id, location) in new_ids.iter().copied().zip(appended) {
                    inner.index.insert(id, location);
                    inner.pending_index_locations.push((id, location));
                }
            }
            let journals = pending
                .roots()
                .iter()
                .map(super::wal::PendingWalRoot::journal)
                .collect::<Vec<_>>();
            if !journals.is_empty() {
                append_frames(&mut files.roots, ROOT_MAGIC, &journals)?;
            }
        }

        let staged_direct = pending
            .objects()
            .filter_map(|(_, object)| object.direct().cloned())
            .collect::<Vec<_>>();
        let representation_update = self.append_pending_direct_update(
            inner,
            representations.as_deref_mut(),
            &staged_direct,
        )?;
        let files = live_files_mut(&mut inner.files)?;
        files
            .arena
            .sync_data()
            .map_err(|source| io_error("flush WAL checkpoint object arena", source))?;
        if let Some(store) = representations.as_mut() {
            if let Some(update) = representation_update {
                store.publish_direct_update(update)?;
            }
            store.flush()?;
        }
        files
            .roots
            .sync_data()
            .map_err(|source| io_error("flush WAL checkpoint root journal", source))?;
        self.sync_volume()?;
        Ok(())
    }

    fn checkpoint_index(
        &self,
        inner: &mut DurableInner<P>,
        persist: VolumeIndexPersist,
    ) -> Result<(), DurableError> {
        if inner.pending_index_locations.is_empty() && inner.pending_direct_objects.is_empty() {
            let files = live_files_mut(&mut inner.files)?;
            if files
                .index_cache
                .as_mut()
                .is_some_and(index_cache_has_one_frame)
            {
                return Ok(());
            }
            if persist == VolumeIndexPersist::RetainDeltas
                && volume_index_cache_present(self, files)
            {
                return Ok(());
            }
        }
        let arena_tail = inner
            .index
            .values()
            .copied()
            .max_by_key(|location| location.offset);
        let arena_len = arena_tail
            .and_then(|location| {
                location
                    .offset
                    .checked_add(FRAME_HEADER_LEN)?
                    .checked_add(location.payload_len)
            })
            .unwrap_or(0);
        if persist == VolumeIndexPersist::RetainDeltas
            && self.on_volume_media()
            && retain_volume_index_deltas(self, inner, arena_len, arena_tail)?
        {
            return Ok(());
        }
        let state = IndexState {
            arena_len,
            arena_tail,
            objects: &inner.index,
        };
        let files = live_files_mut(&mut inner.files)?;
        drop(files.index_cache.take());
        files.index_cache = Some(self.replace_index_cache(&state)?);
        files.arena_len = arena_len;
        files.arena_tail = arena_tail;
        inner.pending_index_locations.clear();
        inner.pending_direct_objects.clear();
        Ok(())
    }

    fn on_volume_media(&self) -> bool {
        self.volume.read().is_some() && self.directory_capability.is_none()
    }
}

/// POSIX index replace is a rename. ASTVOL1 replace journals another full snapshot.
#[derive(Clone, Copy, PartialEq, Eq)]
enum VolumeIndexPersist {
    RetainDeltas,
    CompactSnapshot,
}

fn volume_index_cache_present<P, I, C>(
    engine: &DurableEngine<P, I, C>,
    files: &super::DurableFiles,
) -> bool
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    engine.on_volume_media()
        && files
            .index_cache
            .as_ref()
            .is_some_and(super::index::index_cache_starts_with_snapshot)
}

fn retain_volume_index_deltas<P, I, C>(
    engine: &DurableEngine<P, I, C>,
    inner: &mut DurableInner<P>,
    arena_len: u64,
    arena_tail: Option<super::ArenaLocation>,
) -> Result<bool, DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    {
        let files = live_files_mut(&mut inner.files)?;
        if files
            .index_cache
            .as_ref()
            .is_none_or(|cache| !super::index::index_cache_starts_with_snapshot(cache))
        {
            return Ok(false);
        }
    }
    if inner.pending_index_locations.is_empty() {
        let files = live_files_mut(&mut inner.files)?;
        files.arena_len = arena_len;
        files.arena_tail = arena_tail;
    } else {
        engine.advance_index_frontier(inner, arena_len)?;
    }
    inner.pending_direct_objects.clear();
    Ok(true)
}

fn index_cache_has_one_frame(file: &mut File) -> bool {
    if !super::index::index_cache_starts_with_snapshot(file) {
        return false;
    }
    let Ok(length) = file.metadata().map(|metadata| metadata.len()) else {
        return false;
    };
    if length < FRAME_HEADER_LEN {
        return false;
    }
    let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
    let read_len = file.read_at(&mut header, 0);
    if !matches!(read_len, Ok(read) if read == FRAME_HEADER_LEN_USIZE) {
        return false;
    }
    let payload_len = u64::from_le_bytes(header[12..20].try_into().unwrap_or([0; 8]));
    FRAME_HEADER_LEN
        .checked_add(payload_len)
        .is_some_and(|frame_end| frame_end == length)
}

/// Disposable views kept alive only until close releases its engine guards.
struct RetiredMetadata<P: Ord> {
    _index: BTreeMap<ObjectId, super::ArenaLocation>,
    _validated: BTreeSet<ObjectId>,
    _roots: BTreeMap<P, RootState>,
    _direct_objects: BTreeMap<ObjectId, super::representations::DirectArenaObject>,
    _locations: Vec<(ObjectId, super::ArenaLocation)>,
    _wal: super::wal::PendingWalOverlay<P>,
    _published_roots: Arc<BTreeMap<P, Arc<super::PublishedRoot>>>,
}

#[cfg(test)]
mod retention_tests;

#[cfg(test)]
mod root_read_tests;
