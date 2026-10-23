//! Explicit flush and close lifecycle for the durable engine.

use super::locations::LocationLookup as _;
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
        if let Err(error) = self.flush_authority(&mut inner) {
            self.mark_requires_recovery(&mut inner);
            return Err(error);
        }
        if let Err(error) = self.checkpoint_index(&mut inner, VolumeIndexPersist::RetainDeltas) {
            self.mark_requires_recovery(&mut inner);
            return Err(error);
        }
        Ok(())
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
        let mut inner = self.inner.lock();
        if inner.files.is_none() && inner.lock.is_none() {
            return Ok(());
        }
        let poisoned = inner.poisoned;
        let mut result = if inner.files.is_some() {
            if poisoned {
                Err(DurableError::RequiresRecovery)
            } else {
                self.flush_authority(&mut inner)
            }
        } else if poisoned {
            Err(DurableError::RequiresRecovery)
        } else {
            Err(DurableError::Closed)
        };
        if result.is_ok()
            && inner.files.is_some()
            && let Err(error) =
                self.checkpoint_index(&mut inner, VolumeIndexPersist::CompactSnapshot)
        {
            self.mark_requires_recovery(&mut inner);
            result = Err(error);
        }
        drop(self.wal.lock().take());
        drop(inner.representations.take());
        drop(inner.files.take());
        drop(self.arena_reader.write().take());
        self.object_cache.clear();
        self.lifecycle
            .store(LIFECYCLE_CLOSED, std::sync::atomic::Ordering::Release);
        self.discard_closed_metadata(&mut inner);
        let unlock = match inner.lock.take() {
            Some(StoreLock::Native(lock)) => fs2::FileExt::unlock(&lock)
                .map_err(|source| io_error("unlock principal store while closing", source)),
            Some(StoreLock::Volume) | None => Ok(()),
        };
        drop(self.volume.write().take());
        result.and(unlock)
    }

    fn discard_closed_metadata(&self, inner: &mut DurableInner<P>) {
        // Retained engine Arcs must not retain the entire historical locator
        // index after close. On a failed flush the arena/WAL remain authority
        // for a new engine; the closed instance can never serve these views.
        inner.index.clear();
        inner.validated.clear();
        inner.roots_by_principal.clear();
        inner.pending_direct_objects.clear();
        inner.pending_index_locations = Vec::new();
        drop(inner.pending_wal.take());
        self.published_roots.replace(&inner.roots_by_principal);
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
            return self.checkpoint_transaction_wal(inner);
        }
        let representation_update = self.append_pending_direct_update(inner, &[])?;
        let DurableInner {
            files,
            representations,
            ..
        } = inner;
        let files = live_files_mut(files)?;
        files
            .arena
            .sync_data()
            .map_err(|source| io_error("flush object arena", source))?;
        if let Some(representations) = representations {
            if let Some(update) = representation_update {
                representations.publish_direct_update(update)?;
            }
            representations.flush()?;
        }
        files
            .roots
            .sync_data()
            .map_err(|source| io_error("flush root journal", source))?;
        self.sync_volume()?;
        self.checkpoint_physical_history(inner)
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
        let result = (|| {
            self.fold_pending_wal(inner)?;
            let mut wal = self.wal.lock();
            if let Some(writer) = wal.as_mut() {
                writer.checkpoint().map_err(wal_durable_error)?;
            }
            self.checkpoint_index(inner, VolumeIndexPersist::RetainDeltas)?;
            self.checkpoint_physical_history(inner)
        })();
        if result.is_err() {
            self.mark_requires_recovery(inner);
        }
        result
    }

    fn fold_pending_wal(&self, inner: &mut DurableInner<P>) -> Result<(), DurableError> {
        let pending = inner.pending_wal.take();
        let mut new_ids = Vec::new();
        let mut new_payloads = Vec::new();
        {
            let files = live_files_mut(&mut inner.files)?;
            for (id, object) in pending.objects() {
                if object.location().is_some() {
                    continue;
                }
                if let Some(location) = inner.index.location(*id)? {
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
                    if let Err(error) = inner.index.insert(id, location) {
                        self.mark_requires_recovery(inner);
                        return Err(error);
                    }
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
        let representation_update = self.append_pending_direct_update(inner, &staged_direct)?;
        {
            let DurableInner {
                files,
                representations,
                ..
            } = inner;
            let files = live_files_mut(files)?;
            files
                .arena
                .sync_data()
                .map_err(|source| io_error("flush WAL checkpoint object arena", source))?;
            if let Some(representations) = representations {
                if let Some(update) = representation_update {
                    representations.publish_direct_update(update)?;
                }
                representations.flush()?;
            }
            files
                .roots
                .sync_data()
                .map_err(|source| io_error("flush WAL checkpoint root journal", source))?;
        }
        self.sync_volume()
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
        let arena_tail = inner.index.locations().try_fold(None, |tail, entry| {
            let (_, location) = entry?;
            Ok::<_, DurableError>(Some(tail.map_or(location, |old: super::ArenaLocation| {
                if old.offset > location.offset {
                    old
                } else {
                    location
                }
            })))
        })?;
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
            && retain_volume_index_deltas(self, inner, arena_len, arena_tail)
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
) -> bool
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    {
        let Ok(files) = live_files_mut(&mut inner.files) else {
            return false;
        };
        if files
            .index_cache
            .as_ref()
            .is_none_or(|cache| !super::index::index_cache_starts_with_snapshot(cache))
        {
            return false;
        }
    }
    if !inner.pending_index_locations.is_empty() {
        let _ = engine.advance_index_frontier(inner, arena_len);
    } else if let Ok(files) = live_files_mut(&mut inner.files) {
        files.arena_len = arena_len;
        files.arena_tail = arena_tail;
    }
    inner.pending_direct_objects.clear();
    true
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

#[cfg(test)]
mod retention_tests;

#[cfg(test)]
mod root_read_tests;
