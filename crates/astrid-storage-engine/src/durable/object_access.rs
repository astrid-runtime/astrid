//! Uncached logical-object access across physical representations.

use astrid_storage_model::{ObjectId, ObjectRecord};

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
        inner
            .index
            .len()
            .checked_add(
                inner
                    .representations
                    .as_ref()
                    .map_or(0, |store| store.contiguous_count_excluding(&inner.index)),
            )
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
            let (location, contiguous, generation) = {
                let inner = self.lock_usable_with(&mut recovery)?;
                let contiguous = match inner.representations.as_ref() {
                    Some(store) => store.open_contiguous_read(id)?,
                    None => None,
                };
                (
                    inner.index.get(&id).copied(),
                    contiguous,
                    inner.arena_generation,
                )
            };
            if location.is_none()
                && let Some((file, location)) = contiguous
            {
                return super::representations::read_contiguous_object(
                    file,
                    location,
                    id,
                    &self.identity,
                )
                .map(Some);
            }
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
