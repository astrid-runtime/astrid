//! Explicit flush and close lifecycle for the durable engine.

use super::{
    DurableEngine, DurableError, DurableInner, FRAME_HEADER_LEN, IndexState,
    PersistentObjectIdentity, PrincipalCodec, ensure_usable, io_error, live_files_mut,
    replace_index,
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
    /// Returns [`DurableError::RequiresRecovery`] after a failed write or the
    /// underlying filesystem error.
    pub fn flush(&self) -> Result<(), DurableError> {
        let mut inner = self.inner.lock();
        ensure_usable(&inner)?;
        let files = live_files_mut(&mut inner.files)?;
        if let Err(source) = files.arena.sync_data() {
            inner.poisoned = true;
            return Err(io_error("flush object arena", source));
        }
        if let Err(source) = files.roots.sync_data() {
            inner.poisoned = true;
            return Err(io_error("flush root journal", source));
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
        let result = if let Some(files) = inner.files.as_mut() {
            if poisoned {
                Err(DurableError::RequiresRecovery)
            } else if let Err(source) = files.arena.sync_data() {
                Err(io_error("flush object arena while closing", source))
            } else if let Err(source) = files.roots.sync_data() {
                Err(io_error("flush root journal while closing", source))
            } else {
                Ok(())
            }
        } else if poisoned {
            Err(DurableError::RequiresRecovery)
        } else {
            Err(DurableError::Closed)
        };
        if result.is_ok() && inner.files.is_some() {
            self.checkpoint_index(&mut inner);
        }
        drop(inner.files.take());
        let unlock = match inner.lock.take() {
            Some(lock) => fs2::FileExt::unlock(&lock)
                .map_err(|source| io_error("unlock principal store while closing", source)),
            None => Ok(()),
        };
        result.and(unlock)
    }

    fn checkpoint_index(&self, inner: &mut DurableInner<P>) {
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
        files.index_cache = replace_index(&self.directory, &state, self.identity.scheme());
        files.arena_len = arena_len;
        files.arena_tail = arena_tail;
        inner.pending_index_locations.clear();
    }
}
