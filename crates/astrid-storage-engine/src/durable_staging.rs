//! Incremental immutable-object staging for durable root transactions.

use std::collections::BTreeMap;

use astrid_storage_model::{InsertOutcome, ModelError, ObjectId, ObjectRecord};

use super::{
    ARENA_FILE, ARENA_MAGIC, DurableEngine, DurableError, PersistentObjectIdentity, PrincipalCodec,
    append_frame, append_frames, encode_object_frame, ensure_payload_limit, ensure_usable,
    read_indexed_object,
};

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Stage one immutable object without publishing a principal root.
    ///
    /// Identity is recomputed and an existing object is read back before a
    /// deduplication hit is accepted. A new frame is appended to the arena but
    /// deliberately not flushed: the next root transaction that reaches it
    /// flushes the complete arena prefix before its root-journal CAS. If no
    /// root ever reaches it, it remains an unreachable compaction candidate.
    ///
    /// This method may admit objects whose owning closure is not complete yet.
    /// [`Self::commit`] validates the complete closure inside the root-CAS
    /// critical section, so publication fails securely if staging was
    /// interrupted or concurrent garbage collection removed a dependency.
    ///
    /// # Errors
    ///
    /// Returns an identity, collision, encoding, I/O, or recovery-required
    /// error. An append failure poisons this engine instance.
    pub fn stage_object(
        &self,
        record: &ObjectRecord,
    ) -> Result<(ObjectId, InsertOutcome), DurableError> {
        let id = self.identify(record);
        let mut inner = self.inner.lock();
        ensure_usable(&inner)?;
        if let Some(location) = inner.index.get(&id).copied() {
            let existing = read_indexed_object(
                &mut inner.arena,
                id,
                location,
                self.identity.scheme(),
                self.limits,
            )?;
            if &existing != record {
                return Err(ModelError::ObjectCollision(id).into());
            }
            return Ok((id, InsertOutcome::AlreadyPresent));
        }
        let payload = encode_object_frame(self.identity.scheme(), id, record)?;
        ensure_payload_limit(ARENA_FILE, 0, payload.len(), self.limits)?;
        match append_frame(&mut inner.arena, ARENA_MAGIC, &payload) {
            Ok(location) => {
                inner.index.insert(id, location);
                Ok((id, InsertOutcome::Inserted))
            },
            Err(error) => {
                inner.poisoned = true;
                Err(error)
            },
        }
    }

    /// Stage a batch of immutable objects with one coalesced arena write.
    ///
    /// Results correspond to input order. Duplicate equal records are
    /// idempotent; all identities, existing-object bytes, encodings, and frame
    /// limits are checked before the batch writes anything. The batch is not
    /// flushed until a later root transaction reaches it.
    ///
    /// # Errors
    ///
    /// Returns an identity, collision, encoding, I/O, or recovery-required
    /// error. A write failure poisons this engine instance.
    pub fn stage_objects(
        &self,
        records: Vec<ObjectRecord>,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, DurableError> {
        let mut inner = self.inner.lock();
        ensure_usable(&inner)?;
        let mut incoming = BTreeMap::<ObjectId, ObjectRecord>::new();
        let mut outcomes = Vec::new();
        outcomes
            .try_reserve_exact(records.len())
            .map_err(|_| DurableError::EncodingOverflow)?;
        for record in records {
            let id = self.identify(&record);
            if let Some(existing) = incoming.get(&id) {
                if existing != &record {
                    return Err(ModelError::ObjectCollision(id).into());
                }
                outcomes.push((id, InsertOutcome::AlreadyPresent));
                continue;
            }
            if let Some(location) = inner.index.get(&id).copied() {
                let existing = read_indexed_object(
                    &mut inner.arena,
                    id,
                    location,
                    self.identity.scheme(),
                    self.limits,
                )?;
                if existing != record {
                    return Err(ModelError::ObjectCollision(id).into());
                }
                outcomes.push((id, InsertOutcome::AlreadyPresent));
                continue;
            }
            incoming.insert(id, record);
            outcomes.push((id, InsertOutcome::Inserted));
        }

        let mut ids = Vec::new();
        let mut payloads = Vec::new();
        ids.try_reserve_exact(incoming.len())
            .map_err(|_| DurableError::EncodingOverflow)?;
        payloads
            .try_reserve_exact(incoming.len())
            .map_err(|_| DurableError::EncodingOverflow)?;
        for (id, record) in incoming {
            let payload = encode_object_frame(self.identity.scheme(), id, &record)?;
            ensure_payload_limit(ARENA_FILE, 0, payload.len(), self.limits)?;
            ids.push(id);
            payloads.push(payload);
        }
        let appended = append_frames(&mut inner.arena, ARENA_MAGIC, &payloads);
        match appended {
            Ok(locations) => {
                inner.index.extend(ids.into_iter().zip(locations));
                Ok(outcomes)
            },
            Err(error) => {
                inner.poisoned = true;
                Err(error)
            },
        }
    }
}
