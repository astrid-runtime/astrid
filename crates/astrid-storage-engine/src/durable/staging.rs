//! Incremental immutable-object staging for durable root transactions.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use astrid_storage_model::{
    InsertOutcome, ModelError, ObjectId, ObjectRecord, RepresentationProfileId,
};

use super::representations::{PreparedDirectArenaObject, RepresentationStore};
use super::{
    ARENA_FILE, ARENA_MAGIC, ArenaLocation, DurableEngine, DurableError, DurableInner, File,
    PersistentObjectIdentity, PreparedFrame, PrincipalCodec, append_frame, append_prepared_frames,
    encode_object_frame, ensure_payload_limit, live_files_mut, read_indexed_object,
};
use crate::projection::{object_record_retained_bytes, with_buffered_observer};
use crate::{
    PreparedProjectionBatch, PrincipalProjectionError, ProjectionObserver, ProjectionPhase,
};

struct PreparedStagingObject {
    record: ObjectRecord,
    payload: Vec<u8>,
    append: Option<PreparedStagingAppend>,
}

struct PreparedStagingAppend {
    frame: PreparedFrame,
    direct: Option<PreparedDirectArenaObject>,
}

struct PreparedStagingBatch {
    unique: BTreeMap<ObjectId, PreparedStagingObject>,
    input_order: Vec<ObjectId>,
}

struct DurablePreparedBatch {
    authority: Arc<()>,
    direct_profile: Option<RepresentationProfileId>,
    prepared: PreparedStagingBatch,
}

struct StagingBatchAppend {
    outcomes: Vec<(ObjectId, InsertOutcome)>,
    ids: Vec<ObjectId>,
    frames: Vec<PreparedFrame>,
    direct: Vec<Option<PreparedDirectArenaObject>>,
}

fn staged_closure_evidence(
    validated: &BTreeSet<ObjectId>,
    records: &BTreeMap<ObjectId, PreparedStagingObject>,
) -> BTreeSet<ObjectId> {
    // This is intentionally batch-local. Retaining reverse edges for every
    // unreachable staged object would turn an accelerator into O(history)
    // host memory. Parent-before-child batches use the ordinary commit walk.
    let mut unresolved = BTreeMap::<ObjectId, BTreeSet<ObjectId>>::new();
    let mut dependents = BTreeMap::<ObjectId, BTreeSet<ObjectId>>::new();
    for (id, prepared) in records {
        if validated.contains(id) {
            continue;
        }
        let dependencies = prepared
            .record
            .owning_references()
            .filter(|child| !validated.contains(child))
            .collect::<BTreeSet<_>>();
        for child in dependencies
            .iter()
            .filter(|child| records.contains_key(child))
        {
            dependents.entry(*child).or_default().insert(*id);
        }
        unresolved.insert(*id, dependencies);
    }

    let mut ready = unresolved
        .iter()
        .filter_map(|(id, dependencies)| dependencies.is_empty().then_some(*id))
        .collect::<VecDeque<_>>();
    let mut proven = BTreeSet::new();
    while let Some(id) = ready.pop_front() {
        if !proven.insert(id) {
            continue;
        }
        let Some(parents) = dependents.remove(&id) else {
            continue;
        };
        for parent in parents {
            let Some(dependencies) = unresolved.get_mut(&parent) else {
                continue;
            };
            dependencies.remove(&id);
            if dependencies.is_empty() {
                ready.push_back(parent);
            }
        }
    }
    proven
}

fn record_owns_validated_closure(record: &ObjectRecord, validated: &BTreeSet<ObjectId>) -> bool {
    record
        .owning_references()
        .all(|child| validated.contains(&child))
}

impl PreparedStagingBatch {
    fn new<I: PersistentObjectIdentity>(
        identity: &I,
        records: Vec<ObjectRecord>,
        limits: super::RecoveryLimits,
    ) -> Result<Self, DurableError> {
        let mut unique = BTreeMap::<ObjectId, PreparedStagingObject>::new();
        let mut input_order = Vec::new();
        input_order
            .try_reserve_exact(records.len())
            .map_err(|_| DurableError::EncodingOverflow)?;
        for record in records {
            let id = identity.identify(&record);
            input_order.push(id);
            if let Some(existing) = unique.get(&id) {
                if existing.record != record {
                    return Err(ModelError::ObjectCollision(id).into());
                }
                continue;
            }
            let payload = encode_object_frame(identity.scheme(), id, &record)?;
            ensure_payload_limit(ARENA_FILE, 0, payload.len(), limits)?;
            unique.insert(
                id,
                PreparedStagingObject {
                    record,
                    payload,
                    append: None,
                },
            );
        }
        Ok(Self {
            unique,
            input_order,
        })
    }

    fn prepare_missing<I: PersistentObjectIdentity>(
        &mut self,
        identity: &I,
        already_present: &BTreeSet<ObjectId>,
        direct_profile: Option<RepresentationProfileId>,
        observer: Option<&dyn ProjectionObserver>,
    ) -> Result<(), DurableError> {
        let mut preparation_elapsed = std::time::Duration::ZERO;
        let mut direct_identity_elapsed = std::time::Duration::ZERO;
        for (id, prepared) in &mut self.unique {
            if already_present.contains(id) {
                continue;
            }
            let preparation_started = observer.map(|_| Instant::now());
            let canonical_record = match &prepared.append {
                Some(append) => {
                    super::canonical_record_bytes(append.frame.payload(), identity.scheme())?
                },
                None => super::canonical_record_bytes(&prepared.payload, identity.scheme())?,
            };
            preparation_elapsed = preparation_elapsed.saturating_add(
                preparation_started.map_or(std::time::Duration::ZERO, |started| started.elapsed()),
            );
            let direct_started = observer.map(|_| Instant::now());
            let direct = direct_profile
                .map(|profile| PreparedDirectArenaObject::identify(profile, *id, canonical_record))
                .transpose()?;
            direct_identity_elapsed = direct_identity_elapsed.saturating_add(
                direct_started.map_or(std::time::Duration::ZERO, |started| started.elapsed()),
            );
            if let Some(append) = &mut prepared.append {
                append.direct = direct;
            } else {
                let payload = std::mem::take(&mut prepared.payload);
                let frame_started = observer.map(|_| Instant::now());
                prepared.append = Some(PreparedStagingAppend {
                    frame: PreparedFrame::new(ARENA_MAGIC, payload)?,
                    direct,
                });
                preparation_elapsed = preparation_elapsed.saturating_add(
                    frame_started.map_or(std::time::Duration::ZERO, |started| started.elapsed()),
                );
            }
        }
        if let Some(observer) = observer {
            observer.record(ProjectionPhase::ObjectPreparation, preparation_elapsed);
            observer.record(ProjectionPhase::DirectIdentity, direct_identity_elapsed);
        }
        Ok(())
    }

    fn every_missing_object_is_prepared(&self, already_present: &BTreeSet<ObjectId>) -> bool {
        self.unique
            .iter()
            .all(|(id, prepared)| already_present.contains(id) || prepared.append.is_some())
    }

    fn retained_bytes(&self) -> usize {
        let input_ids = self.input_order.len().saturating_mul(size_of::<ObjectId>());
        self.unique.values().fold(input_ids, |total, prepared| {
            let record = object_record_retained_bytes(&prepared.record);
            let encoded = prepared
                .append
                .as_ref()
                .map_or(prepared.payload.len(), |append| {
                    append.frame.retained_bytes().saturating_add(
                        append
                            .direct
                            .as_ref()
                            .map_or(0, |_| size_of::<PreparedDirectArenaObject>()),
                    )
                });
            total.saturating_add(record).saturating_add(encoded)
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
        let mut frames = Vec::new();
        let mut direct = Vec::new();
        ids.try_reserve_exact(append_count)
            .map_err(|_| DurableError::EncodingOverflow)?;
        frames
            .try_reserve_exact(append_count)
            .map_err(|_| DurableError::EncodingOverflow)?;
        direct
            .try_reserve_exact(append_count)
            .map_err(|_| DurableError::EncodingOverflow)?;
        for (id, prepared) in self.unique {
            if !already_present.contains(&id) {
                let prepared = prepared
                    .append
                    .ok_or(DurableError::InvalidRepresentationState(
                        "missing staging object was not prepared for append",
                    ))?;
                ids.push(id);
                frames.push(prepared.frame);
                direct.push(prepared.direct);
            }
        }
        Ok(StagingBatchAppend {
            outcomes,
            ids,
            frames,
            direct,
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
            if record_owns_validated_closure(record, &inner.validated) {
                inner.validated.insert(id);
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
                if record_owns_validated_closure(record, &inner.validated) {
                    inner.validated.insert(id);
                }
                Ok((id, InsertOutcome::Inserted))
            },
            Err(error) => {
                self.mark_requires_recovery(&mut inner);
                Err(error)
            },
        }
    }

    /// Stage a batch of immutable objects with bounded vectored arena writes.
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
        self.stage_objects_with_appender(records, append_prepared_frames, None)
    }

    pub(crate) fn prepare_objects_for_projection(
        &self,
        records: Vec<ObjectRecord>,
        observer: Option<&dyn ProjectionObserver>,
    ) -> Result<PreparedProjectionBatch, DurableError> {
        with_buffered_observer(observer, |buffer| {
            let prepared = self.prepare_staging_batch(records, buffer)?;
            let retained_bytes = prepared.prepared.retained_bytes();
            Ok(PreparedProjectionBatch::engine(prepared, retained_bytes))
        })
    }

    pub(crate) fn stage_prepared_for_projection(
        &self,
        prepared: PreparedProjectionBatch,
        observer: Option<&dyn ProjectionObserver>,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, PrincipalProjectionError> {
        let prepared = prepared
            .into_engine_payload::<DurablePreparedBatch>()
            .ok_or_else(foreign_preparation)?;
        if !Arc::ptr_eq(&self.preparation_authority, &prepared.authority) {
            return Err(foreign_preparation());
        }
        with_buffered_observer(observer, |buffer| {
            self.stage_prepared_batch_with_appender(prepared, append_prepared_frames, buffer)
                .map_err(crate::projection::map_durable)
        })
    }

    pub(crate) fn stage_objects_observed(
        &self,
        records: Vec<ObjectRecord>,
        observer: &dyn ProjectionObserver,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, DurableError> {
        with_buffered_observer(Some(observer), |buffer| {
            self.stage_objects_with_appender(records, append_prepared_frames, buffer)
        })
    }

    #[cfg(test)]
    pub(super) fn stage_objects_with_test_appender<A>(
        &self,
        records: Vec<ObjectRecord>,
        appender: A,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, DurableError>
    where
        A: FnMut(&mut File, &[PreparedFrame]) -> Result<Vec<ArenaLocation>, DurableError>,
    {
        self.stage_objects_with_appender(records, appender, None)
    }

    fn stage_objects_with_appender<A>(
        &self,
        records: Vec<ObjectRecord>,
        write_batch: A,
        observer: Option<&dyn ProjectionObserver>,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, DurableError>
    where
        A: FnMut(&mut File, &[PreparedFrame]) -> Result<Vec<ArenaLocation>, DurableError>,
    {
        let prepared = self.prepare_staging_batch(records, observer)?;
        self.stage_prepared_batch_with_appender(prepared, write_batch, observer)
    }

    fn prepare_staging_batch(
        &self,
        records: Vec<ObjectRecord>,
        observer: Option<&dyn ProjectionObserver>,
    ) -> Result<DurablePreparedBatch, DurableError> {
        let preparation_started = Instant::now();
        let mut prepared = PreparedStagingBatch::new(&self.identity, records, self.limits)?;
        record_phase(
            observer,
            ProjectionPhase::ObjectPreparation,
            preparation_started,
        );
        let mut inner = self.lock_usable()?;
        let direct_profile = inner
            .representations
            .as_ref()
            .map(RepresentationStore::direct_profile);
        let probe_started = Instant::now();
        let already_present = self.verify_existing_batch(&mut inner, &prepared.unique)?;
        record_phase(observer, ProjectionPhase::AdmissionProbe, probe_started);
        drop(inner);
        if already_present.len() != prepared.unique.len() {
            prepared.prepare_missing(&self.identity, &already_present, direct_profile, observer)?;
        }
        Ok(DurablePreparedBatch {
            authority: Arc::clone(&self.preparation_authority),
            direct_profile,
            prepared,
        })
    }

    fn stage_prepared_batch_with_appender<A>(
        &self,
        mut prepared_batch: DurablePreparedBatch,
        mut write_batch: A,
        observer: Option<&dyn ProjectionObserver>,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, DurableError>
    where
        A: FnMut(&mut File, &[PreparedFrame]) -> Result<Vec<ArenaLocation>, DurableError>,
    {
        loop {
            let mut inner = self.lock_usable()?;
            let active_profile = inner
                .representations
                .as_ref()
                .map(RepresentationStore::direct_profile);
            let probe_started = Instant::now();
            let already_present =
                self.verify_existing_batch(&mut inner, &prepared_batch.prepared.unique)?;
            record_phase(observer, ProjectionPhase::AdmissionProbe, probe_started);
            if already_present.len() == prepared_batch.prepared.unique.len() {
                let proven =
                    staged_closure_evidence(&inner.validated, &prepared_batch.prepared.unique);
                let outcomes = prepared_batch.prepared.finish(&already_present)?.outcomes;
                // Every record was read back and byte-compared while `inner`
                // was locked, so these tokens have the same meaning as tokens
                // earned for newly installed frames below.
                inner.validated.extend(proven);
                return Ok(outcomes);
            }
            if active_profile != prepared_batch.direct_profile
                || !prepared_batch
                    .prepared
                    .every_missing_object_is_prepared(&already_present)
            {
                drop(inner);
                prepared_batch.prepared.prepare_missing(
                    &self.identity,
                    &already_present,
                    active_profile,
                    observer,
                )?;
                prepared_batch.direct_profile = active_profile;
                continue;
            }
            let proven = staged_closure_evidence(&inner.validated, &prepared_batch.prepared.unique);
            let append = prepared_batch.prepared.finish(&already_present)?;
            let append_started = Instant::now();
            let append_result = {
                let files = live_files_mut(&mut inner.files)?;
                write_batch(&mut files.arena, &append.frames)
            };
            record_phase(observer, ProjectionPhase::ArenaAppend, append_started);
            match append_result {
                Ok(locations) => {
                    let map_started = Instant::now();
                    self.install_appended_batch(
                        &mut inner,
                        &append.ids,
                        append.direct,
                        &locations,
                    )?;
                    // Install evidence only after every corresponding location
                    // and direct description is present. Any earlier failure
                    // leaves the validated frontier unchanged.
                    inner.validated.extend(proven);
                    record_phase(observer, ProjectionPhase::PhysicalMapUpdate, map_started);
                    return Ok(append.outcomes);
                },
                Err(error) => {
                    self.mark_requires_recovery(&mut inner);
                    return Err(error);
                },
            }
        }
    }

    fn verify_existing_batch(
        &self,
        inner: &mut DurableInner<P>,
        unique: &BTreeMap<ObjectId, PreparedStagingObject>,
    ) -> Result<BTreeSet<ObjectId>, DurableError> {
        let mut already_present = BTreeSet::new();
        for (id, prepared) in unique {
            let Some(location) = inner.index.get(id).copied() else {
                continue;
            };
            let existing = {
                let files = live_files_mut(&mut inner.files)?;
                read_indexed_object(&files.arena, *id, location, &self.identity, self.limits)?
            };
            if existing != prepared.record {
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
        direct: Vec<Option<PreparedDirectArenaObject>>,
        locations: &[ArenaLocation],
    ) -> Result<(), DurableError> {
        if ids.len() != locations.len() || ids.len() != direct.len() {
            self.mark_requires_recovery(inner);
            return Err(DurableError::InvalidRepresentationState(
                "prepared staging batch lengths disagree",
            ));
        }
        for (id, location) in ids.iter().copied().zip(locations.iter().copied()) {
            inner.index.insert(id, location);
            inner.pending_index_locations.push((id, location));
        }
        for (prepared, location) in direct.into_iter().zip(locations.iter().copied()) {
            if let Some(object) = prepared.map(|prepared| prepared.place(location)) {
                inner.pending_direct_objects.insert(object.object, object);
            }
        }
        Ok(())
    }
}

fn record_phase(
    observer: Option<&dyn ProjectionObserver>,
    phase: ProjectionPhase,
    started: Instant,
) {
    if let Some(observer) = observer {
        observer.record(phase, started.elapsed());
    }
}

fn foreign_preparation() -> PrincipalProjectionError {
    PrincipalProjectionError::Engine(
        "prepared object batch does not belong to this engine".to_owned(),
    )
}

#[cfg(test)]
mod closure_evidence_tests {
    use astrid_storage_model::{
        ObjectClass, ObjectFormatVersion, ObjectKind, ObjectReference, ReferenceLabel,
    };

    use super::*;

    fn prepared(record: ObjectRecord) -> PreparedStagingObject {
        PreparedStagingObject {
            record,
            payload: Vec::new(),
            append: None,
        }
    }

    fn record(references: Vec<ObjectReference>) -> ObjectRecord {
        ObjectRecord::new(
            ObjectKind::Evidence,
            ObjectFormatVersion::V1,
            Vec::new(),
            references,
            0,
            ObjectClass::Metadata,
        )
        .unwrap()
    }

    #[test]
    fn closure_evidence_is_order_independent_and_deduplicates_child_edges() {
        let child = ObjectId::new([1; 32]);
        let parent = ObjectId::new([2; 32]);
        let mut records = BTreeMap::new();
        records.insert(
            parent,
            prepared(record(vec![
                ObjectReference::owns(ReferenceLabel::new(b"first".to_vec()), child),
                ObjectReference::owns(ReferenceLabel::new(b"second".to_vec()), child),
            ])),
        );
        records.insert(child, prepared(record(Vec::new())));

        assert_eq!(
            staged_closure_evidence(&BTreeSet::new(), &records),
            BTreeSet::from([child, parent])
        );
    }

    #[test]
    fn closure_evidence_rejects_missing_children_and_cycles() {
        let first = ObjectId::new([1; 32]);
        let second = ObjectId::new([2; 32]);
        let missing = ObjectId::new([3; 32]);
        let mut records = BTreeMap::new();
        records.insert(
            first,
            prepared(record(vec![ObjectReference::owns(
                ReferenceLabel::new(b"second".to_vec()),
                second,
            )])),
        );
        records.insert(
            second,
            prepared(record(vec![ObjectReference::owns(
                ReferenceLabel::new(b"first".to_vec()),
                first,
            )])),
        );
        records.insert(
            ObjectId::new([4; 32]),
            prepared(record(vec![ObjectReference::owns(
                ReferenceLabel::new(b"missing".to_vec()),
                missing,
            )])),
        );

        assert!(staged_closure_evidence(&BTreeSet::new(), &records).is_empty());
    }
}
