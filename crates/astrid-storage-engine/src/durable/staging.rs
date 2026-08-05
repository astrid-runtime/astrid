//! Incremental immutable-object staging for durable root transactions.

use std::collections::{BTreeMap, BTreeSet};

use astrid_storage_model::{InsertOutcome, ModelError, ObjectId, ObjectRecord};

use super::representations::DirectArenaObject;
use super::{
    ARENA_FILE, ARENA_MAGIC, ArenaLocation, DurableEngine, DurableError, DurableInner,
    PersistentObjectIdentity, PrincipalCodec, append_frame, append_frames, encode_object_frame,
    ensure_payload_limit, live_files_mut, read_indexed_object,
};

struct PreparedStagingBatch {
    unique: BTreeMap<ObjectId, (ObjectRecord, Vec<u8>)>,
    input_order: Vec<ObjectId>,
}

struct StagingBatchAppend {
    outcomes: Vec<(ObjectId, InsertOutcome)>,
    ids: Vec<ObjectId>,
    payloads: Vec<Vec<u8>>,
}

impl PreparedStagingBatch {
    fn new<I: PersistentObjectIdentity>(
        identity: &I,
        records: Vec<ObjectRecord>,
        limits: super::RecoveryLimits,
    ) -> Result<Self, DurableError> {
        let mut unique = BTreeMap::<ObjectId, (ObjectRecord, Vec<u8>)>::new();
        let mut input_order = Vec::new();
        input_order
            .try_reserve_exact(records.len())
            .map_err(|_| DurableError::EncodingOverflow)?;
        for record in records {
            let id = identity.identify(&record);
            input_order.push(id);
            if let Some((existing, _)) = unique.get(&id) {
                if existing != &record {
                    return Err(ModelError::ObjectCollision(id).into());
                }
                continue;
            }
            let payload = encode_object_frame(identity.scheme(), id, &record)?;
            ensure_payload_limit(ARENA_FILE, 0, payload.len(), limits)?;
            unique.insert(id, (record, payload));
        }
        Ok(Self {
            unique,
            input_order,
        })
    }

    fn finish(
        self,
        already_present: &BTreeSet<ObjectId>,
    ) -> Result<StagingBatchAppend, DurableError> {
        let mut outcomes = Vec::new();
        outcomes
            .try_reserve_exact(self.input_order.len())
            .map_err(|_| DurableError::EncodingOverflow)?;
        let mut accounted = already_present.clone();
        for id in self.input_order {
            let outcome = if accounted.insert(id) {
                InsertOutcome::Inserted
            } else {
                InsertOutcome::AlreadyPresent
            };
            outcomes.push((id, outcome));
        }

        let append_count = self
            .unique
            .len()
            .checked_sub(already_present.len())
            .ok_or(DurableError::EncodingOverflow)?;
        let mut ids = Vec::new();
        let mut payloads = Vec::new();
        ids.try_reserve_exact(append_count)
            .map_err(|_| DurableError::EncodingOverflow)?;
        payloads
            .try_reserve_exact(append_count)
            .map_err(|_| DurableError::EncodingOverflow)?;
        for (id, (_, payload)) in self.unique {
            if !already_present.contains(&id) {
                ids.push(id);
                payloads.push(payload);
            }
        }
        Ok(StagingBatchAppend {
            outcomes,
            ids,
            payloads,
        })
    }
}

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
        let mut inner = self.lock_usable()?;
        if let Some(location) = inner.index.get(&id).copied() {
            let existing = {
                let files = live_files_mut(&mut inner.files)?;
                read_indexed_object(&files.arena, id, location, &self.identity, self.limits)?
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
                let direct = inner
                    .representations
                    .as_ref()
                    .map(|representations| {
                        representations.describe_direct(
                            id,
                            super::canonical_record_bytes(&payload, self.identity.scheme())?,
                            location,
                        )
                    })
                    .transpose();
                let direct = match direct {
                    Ok(direct) => direct,
                    Err(error) => {
                        self.mark_requires_recovery(&mut inner);
                        return Err(error);
                    },
                };
                inner.index.insert(id, location);
                inner.pending_index_locations.push((id, location));
                if let Some(direct) = direct {
                    inner.pending_direct_objects.insert(id, direct);
                }
                Ok((id, InsertOutcome::Inserted))
            },
            Err(error) => {
                self.mark_requires_recovery(&mut inner);
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
        let prepared = PreparedStagingBatch::new(&self.identity, records, self.limits)?;
        let mut inner = self.lock_usable()?;
        let already_present = self.verify_existing_batch(&mut inner, &prepared.unique)?;
        let append = prepared.finish(&already_present)?;
        let appended = {
            let files = live_files_mut(&mut inner.files)?;
            append_frames(&mut files.arena, ARENA_MAGIC, &append.payloads)
        };
        match appended {
            Ok(locations) => {
                self.install_appended_batch(&mut inner, &append.ids, &append.payloads, &locations)?;
                Ok(append.outcomes)
            },
            Err(error) => {
                self.mark_requires_recovery(&mut inner);
                Err(error)
            },
        }
    }

    fn verify_existing_batch(
        &self,
        inner: &mut DurableInner<P>,
        unique: &BTreeMap<ObjectId, (ObjectRecord, Vec<u8>)>,
    ) -> Result<BTreeSet<ObjectId>, DurableError> {
        let mut already_present = BTreeSet::new();
        for (id, (record, _)) in unique {
            let Some(location) = inner.index.get(id).copied() else {
                continue;
            };
            let existing = {
                let files = live_files_mut(&mut inner.files)?;
                read_indexed_object(&files.arena, *id, location, &self.identity, self.limits)?
            };
            if &existing != record {
                return Err(ModelError::ObjectCollision(*id).into());
            }
            already_present.insert(*id);
        }
        Ok(already_present)
    }

    fn install_appended_batch(
        &self,
        inner: &mut DurableInner<P>,
        ids: &[ObjectId],
        payloads: &[Vec<u8>],
        locations: &[ArenaLocation],
    ) -> Result<(), DurableError> {
        let direct = self.describe_appended_batch(inner, ids, payloads, locations);
        let direct = match direct {
            Ok(direct) => direct,
            Err(error) => {
                self.mark_requires_recovery(inner);
                return Err(error);
            },
        };
        for (id, location) in ids.iter().copied().zip(locations.iter().copied()) {
            inner.index.insert(id, location);
            inner.pending_index_locations.push((id, location));
        }
        for object in direct {
            inner.pending_direct_objects.insert(object.object, object);
        }
        Ok(())
    }

    fn describe_appended_batch(
        &self,
        inner: &DurableInner<P>,
        ids: &[ObjectId],
        payloads: &[Vec<u8>],
        locations: &[ArenaLocation],
    ) -> Result<Vec<DirectArenaObject>, DurableError> {
        let Some(representations) = &inner.representations else {
            return Ok(Vec::new());
        };
        ids.iter()
            .copied()
            .zip(payloads)
            .zip(locations.iter().copied())
            .map(|((id, payload), location)| {
                representations.describe_direct(
                    id,
                    super::canonical_record_bytes(payload, self.identity.scheme())?,
                    location,
                )
            })
            .collect()
    }
}
