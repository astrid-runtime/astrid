//! Incremental immutable-object staging for durable root transactions.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use astrid_storage_model::{InsertOutcome, ModelError, ObjectId, ObjectRecord};

use super::{
    ARENA_FILE, ARENA_MAGIC, DurableEngine, DurableError, PersistentObjectIdentity, PrincipalCodec,
    append_frame, append_frames, encode_object_frame, ensure_payload_limit, ensure_usable,
    live_files_mut, read_indexed_object,
};
use crate::PreparedProjectionObject;

type EncodedStagedObject = (ObjectRecord, Vec<u8>);

struct PreparedStageBatch {
    incoming: BTreeMap<ObjectId, EncodedStagedObject>,
    input_order: Vec<ObjectId>,
}

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Compute one immutable object identity and bind it to this engine
    /// instance for later batch staging.
    #[must_use]
    pub fn prepare_object(&self, record: ObjectRecord) -> PreparedProjectionObject {
        let id = self.identify(&record);
        PreparedProjectionObject::bound(id, record, Arc::clone(&self.preparation_origin))
    }

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
        self.stage_prepared_objects(
            records
                .into_iter()
                .map(|record| self.prepare_object(record))
                .collect(),
        )
    }

    /// Stage an engine-prepared batch with one coalesced arena write.
    ///
    /// Identity is reused only for values prepared by this exact engine
    /// instance. Values crossing an engine boundary are recomputed and checked
    /// before admission, preserving server-side identity verification.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::stage_objects`].
    pub fn stage_prepared_objects(
        &self,
        objects: Vec<PreparedProjectionObject>,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, DurableError> {
        self.stage_prepared_objects_inner(None, objects)
    }

    /// Stage an engine-prepared batch with principal-accounted cache reuse.
    ///
    /// Existing immutable records may satisfy the mandatory equality check
    /// from the governed decoded-object cache. Newly admitted records are
    /// offered to that same cache after their arena locations become visible.
    /// Cache refusal or eviction never changes admission correctness.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::stage_prepared_objects`].
    pub fn stage_prepared_objects_for(
        &self,
        principal: &P,
        objects: Vec<PreparedProjectionObject>,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, DurableError> {
        self.stage_prepared_objects_inner(Some(principal), objects)
    }

    fn stage_prepared_objects_inner(
        &self,
        principal: Option<&P>,
        objects: Vec<PreparedProjectionObject>,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, DurableError> {
        let PreparedStageBatch {
            incoming,
            input_order,
        } = self.prepare_staging_batch(objects)?;
        let cached = principal.map_or_else(BTreeMap::new, |principal| {
            incoming
                .keys()
                .filter_map(|id| {
                    self.object_cache
                        .get(principal, *id)
                        .map(|record| (*id, record))
                })
                .collect()
        });
        let mut inner = self.inner.lock();
        ensure_usable(&inner)?;
        let already_present = self.validate_staged_dedup_hits(&mut inner, &incoming, &cached)?;
        let outcomes = staging_outcomes(input_order, &already_present)?;
        let append = prepare_staged_append(incoming, &already_present, principal.is_some())?;
        let appended = {
            let files = live_files_mut(&mut inner.files)?;
            append_frames(&mut files.arena, ARENA_MAGIC, &append.payloads)
        };
        match appended {
            Ok(locations) => {
                inner.index.extend(append.ids.into_iter().zip(locations));
                drop(inner);
                if let Some(principal) = principal {
                    for (id, record) in append.cache_records {
                        self.object_cache.insert(principal, id, record);
                    }
                }
                Ok(outcomes)
            },
            Err(error) => {
                inner.poisoned = true;
                Err(error)
            },
        }
    }

    fn prepare_staging_batch(
        &self,
        objects: Vec<PreparedProjectionObject>,
    ) -> Result<PreparedStageBatch, DurableError> {
        let mut incoming = BTreeMap::<ObjectId, EncodedStagedObject>::new();
        let mut input_order = Vec::new();
        input_order
            .try_reserve_exact(objects.len())
            .map_err(|_| DurableError::EncodingOverflow)?;
        for object in objects {
            let (declared, record, origin) = object.into_parts();
            let id = if origin
                .as_ref()
                .is_some_and(|origin| Arc::ptr_eq(origin, &self.preparation_origin))
            {
                declared
            } else {
                let computed = self.identify(&record);
                if computed != declared {
                    return Err(ModelError::ObjectIdentityMismatch { declared, computed }.into());
                }
                computed
            };
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
        Ok(PreparedStageBatch {
            incoming,
            input_order,
        })
    }

    fn validate_staged_dedup_hits(
        &self,
        inner: &mut super::DurableInner<P>,
        incoming: &BTreeMap<ObjectId, EncodedStagedObject>,
        cached: &BTreeMap<ObjectId, Arc<ObjectRecord>>,
    ) -> Result<BTreeSet<ObjectId>, DurableError> {
        let mut already_present = BTreeSet::new();
        for (id, (record, _)) in incoming {
            if let Some(location) = inner.index.get(id).copied() {
                let existing = if let Some(existing) = cached.get(id) {
                    Arc::clone(existing)
                } else {
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
                    Arc::new(existing)
                };
                if existing.as_ref() != record {
                    return Err(ModelError::ObjectCollision(*id).into());
                }
                already_present.insert(*id);
            }
        }
        Ok(already_present)
    }
}

struct PreparedStagedAppend {
    ids: Vec<ObjectId>,
    payloads: Vec<Vec<u8>>,
    cache_records: Vec<(ObjectId, ObjectRecord)>,
}

fn staging_outcomes(
    input_order: Vec<ObjectId>,
    already_present: &BTreeSet<ObjectId>,
) -> Result<Vec<(ObjectId, InsertOutcome)>, DurableError> {
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
    Ok(outcomes)
}

fn prepare_staged_append(
    incoming: BTreeMap<ObjectId, EncodedStagedObject>,
    already_present: &BTreeSet<ObjectId>,
    retain_for_cache: bool,
) -> Result<PreparedStagedAppend, DurableError> {
    let append_count = incoming
        .keys()
        .filter(|id| !already_present.contains(id))
        .count();
    let mut append = PreparedStagedAppend {
        ids: Vec::new(),
        payloads: Vec::new(),
        cache_records: Vec::new(),
    };
    append
        .ids
        .try_reserve_exact(append_count)
        .map_err(|_| DurableError::EncodingOverflow)?;
    append
        .payloads
        .try_reserve_exact(append_count)
        .map_err(|_| DurableError::EncodingOverflow)?;
    if retain_for_cache {
        append
            .cache_records
            .try_reserve_exact(incoming.len())
            .map_err(|_| DurableError::EncodingOverflow)?;
    }
    for (id, (record, payload)) in incoming {
        if !already_present.contains(&id) {
            append.ids.push(id);
            append.payloads.push(payload);
        }
        if retain_for_cache {
            append.cache_records.push((id, record));
        }
    }
    Ok(append)
}
