//! Uncached logical-object access across physical representations.

use crate::storage_model::{ObjectId, ObjectRecord};

use super::{
    DurableEngine, DurableError, PersistentObjectIdentity, PrincipalCodec, RecoveryScope,
    read_indexed_object,
};

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Return the number of recovered immutable logical objects.
    ///
    /// # Errors
    ///
    /// Returns a recovery error when authoritative reopen cannot complete.
    pub fn object_count(&self) -> Result<usize, DurableError> {
        let inner = self.lock_usable()?;
        let overlay_only = inner
            .pending_wal
            .objects()
            .filter(|(id, _)| !inner.index.contains_key(id))
            .count();
        inner
            .index
            .len()
            .checked_add(overlay_only)
            .ok_or(DurableError::EncodingOverflow)
    }

    /// Return one recovered immutable object.
    ///
    /// # Errors
    ///
    /// Returns a recovery error when authoritative reopen cannot complete.
    pub fn object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, DurableError> {
        let mut recovery = RecoveryScope::default();
        loop {
            let (location, generation) = {
                let inner = self.lock_usable_with(&mut recovery)?;
                if let Some(object) = inner.pending_wal.get_object(&id) {
                    return Ok(Some(object.record().clone()));
                }
                (inner.index.get(&id).copied(), inner.arena_generation)
            };
            let Some(location) = location else {
                return Ok(None);
            };
            let reader_guard = self.arena_reader.read();
            let Some(reader) = reader_guard.as_ref() else {
                return Err(DurableError::Closed);
            };
            if reader.generation != generation {
                continue;
            }
            return read_indexed_object(&reader.file, id, location, &self.identity, self.limits)
                .map(Some);
        }
    }
}
