//! Incremental immutable-object staging for durable root transactions.

use std::collections::{BTreeMap, BTreeSet};

use astrid_storage_model::{InsertOutcome, ModelError, ObjectId, ObjectRecord};

use super::{
    ARENA_FILE, ARENA_MAGIC, DurableEngine, DurableError, PersistentObjectIdentity, PrincipalCodec,
    append_frame, append_frames, encode_object_frame, ensure_payload_limit, ensure_usable,
    live_files_mut, read_indexed_object,
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
            let existing = {
                let files = live_files_mut(&mut inner.files)?;
                read_indexed_object(
                    &files.arena,
                    id,
                    location,
                    self.identity.scheme(),
                    self.limits,
                )?
            };
            if &existing != record {
                return Err(ModelError::ObjectCollision(id).into());
            }
            return Ok((id, InsertOutcome::AlreadyPresent));
        }
        let payload = encode_object_frame(self.identity.scheme(), id, record)?;
        ensure_payload_limit(ARENA_FILE, 0, payload.len(), self.limits)?;
        let appended = {
            let files = live_files_mut(&mut inner.files)?;
            append_frame(&mut files.arena, ARENA_MAGIC, &payload)
        };
        match appended {
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
        let mut incoming = BTreeMap::<ObjectId, (ObjectRecord, Vec<u8>)>::new();
        let mut input_order = Vec::new();
        input_order
            .try_reserve_exact(records.len())
            .map_err(|_| DurableError::EncodingOverflow)?;
        for record in records {
            let id = self.identify(&record);
            input_order.push(id);
            if let Some((existing, _)) = incoming.get(&id) {
                if existing != &record {
                    return Err(ModelError::ObjectCollision(id).into());
                }
                continue;
            }
            let payload = encode_object_frame(self.identity.scheme(), id, &record)?;
            ensure_payload_limit(ARENA_FILE, 0, payload.len(), self.limits)?;
            incoming.insert(id, (record, payload));
        }

        let mut inner = self.inner.lock();
        ensure_usable(&inner)?;
        let mut already_present = BTreeSet::new();
        for (id, (record, _)) in &incoming {
            if let Some(location) = inner.index.get(id).copied() {
                let existing = {
                    let files = live_files_mut(&mut inner.files)?;
                    read_indexed_object(
                        &files.arena,
                        *id,
                        location,
                        self.identity.scheme(),
                        self.limits,
                    )?
                };
                if &existing != record {
                    return Err(ModelError::ObjectCollision(*id).into());
                }
                already_present.insert(*id);
            }
        }

        let mut outcomes = Vec::new();
        outcomes
            .try_reserve_exact(input_order.len())
            .map_err(|_| DurableError::EncodingOverflow)?;
        let mut accounted = already_present.clone();
        for id in input_order {
            let outcome = if accounted.insert(id) {
                InsertOutcome::Inserted
            } else {
                InsertOutcome::AlreadyPresent
            };
            outcomes.push((id, outcome));
        }

        let mut ids = Vec::new();
        let mut payloads = Vec::new();
        let append_count = incoming
            .keys()
            .filter(|id| !already_present.contains(id))
            .count();
        ids.try_reserve_exact(append_count)
            .map_err(|_| DurableError::EncodingOverflow)?;
        payloads
            .try_reserve_exact(append_count)
            .map_err(|_| DurableError::EncodingOverflow)?;
        for (id, (_, payload)) in incoming {
            if already_present.contains(&id) {
                continue;
            }
            ids.push(id);
            payloads.push(payload);
        }
        let appended = {
            let files = live_files_mut(&mut inner.files)?;
            append_frames(&mut files.arena, ARENA_MAGIC, &payloads)
        };
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
