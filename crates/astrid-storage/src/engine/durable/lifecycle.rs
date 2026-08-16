//! Explicit flush and close lifecycle for the durable engine.

use super::{
    DurableEngine, DurableError, DurableInner, FRAME_HEADER_LEN, FRAME_HEADER_LEN_USIZE, File,
    IndexState, LIFECYCLE_CLOSED, PersistentObjectIdentity, PrincipalCodec, StoreLock, io_error,
    live_files_mut, replace_index, replace_volume_index,
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
        self.checkpoint_index(&mut inner);
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
        let result = if inner.files.is_some() {
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
        if result.is_ok() && inner.files.is_some() {
            self.checkpoint_index(&mut inner);
        }
        drop(inner.representations.take());
        drop(inner.files.take());
        drop(self.arena_reader.write().take());
        self.object_cache.clear();
        self.lifecycle
            .store(LIFECYCLE_CLOSED, std::sync::atomic::Ordering::Release);
        let unlock = match inner.lock.take() {
            Some(StoreLock::Native(lock)) => fs2::FileExt::unlock(&lock)
                .map_err(|source| io_error("unlock principal store while closing", source)),
            Some(StoreLock::Volume) | None => Ok(()),
        };
        drop(self.volume.write().take());
        result.and(unlock)
    }

    fn flush_authority(&self, inner: &mut DurableInner<P>) -> Result<(), DurableError> {
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
            .map_err(|source| io_error("flush root journal", source))
    }

    fn checkpoint_index(&self, inner: &mut DurableInner<P>) {
        if inner.pending_index_locations.is_empty() && inner.pending_direct_objects.is_empty() {
            let Ok(files) = live_files_mut(&mut inner.files) else {
                return;
            };
            if files
                .index_cache
                .as_mut()
                .is_some_and(index_cache_has_one_frame)
            {
                return;
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
        let state = IndexState {
            arena_len,
            arena_tail,
            objects: inner.index.clone(),
        };
        let Ok(files) = live_files_mut(&mut inner.files) else {
            return;
        };
        drop(files.index_cache.take());
        let volume = self.volume.read();
        files.index_cache = match (self.directory_capability.as_deref(), volume.as_ref()) {
            (Some(directory), None) => replace_index(directory, &state, self.identity.scheme()),
            (None, Some(volume)) => replace_volume_index(
                std::sync::Arc::clone(volume),
                &state,
                self.identity.scheme(),
            ),
            _ => None,
        };
        files.arena_len = arena_len;
        files.arena_tail = arena_tail;
        inner.pending_index_locations.clear();
        inner.pending_direct_objects.clear();
    }
}

fn index_cache_has_one_frame(file: &mut File) -> bool {
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
