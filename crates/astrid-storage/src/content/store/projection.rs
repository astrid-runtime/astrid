use super::{
    Arc, BTreeMap, CatalogRoot, ContentObjectSink, ContentReadError, ContentSource,
    ContentStreamError, ContentVerificationState, InsertOutcome, ModelError, ObjectClass, ObjectId,
    ObjectRecord, ObjectReference, PhantomData, PrincipalContentError, PrincipalProjectionEngine,
    PrincipalProjectionError, ProjectionCachePayload, ReferenceKind, ReferenceLabel, RootState,
    STAGING_BATCH_TARGET_BYTES, VerifiedContent,
};
#[cfg(not(target_family = "wasm"))]
use crate::engine::PreparedProjectionBatch;
use crate::engine::ProjectionObserver;

#[derive(Clone)]
pub(super) struct ContentHeader {
    pub(super) root: Option<RootState>,
    pub(super) catalog: Option<CatalogRoot>,
    pub(super) previous_catalog_quota_bytes: u64,
    pub(super) other_quota_bytes: u64,
    pub(super) preserved_state: Vec<ObjectReference>,
    pub(super) preserved_commit: Vec<ObjectReference>,
}

impl ContentHeader {
    pub(super) fn empty() -> Self {
        Self {
            root: None,
            catalog: None,
            previous_catalog_quota_bytes: 0,
            other_quota_bytes: 0,
            preserved_state: Vec::new(),
            preserved_commit: Vec::new(),
        }
    }
}

impl ProjectionCachePayload for ContentHeader {
    fn retained_bytes(&self) -> u64 {
        let reference_bytes = |references: &Vec<ObjectReference>| {
            references.iter().fold(
                references
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ObjectReference>()),
                |total, reference| total.saturating_add(reference.label().as_bytes().len()),
            )
        };
        u64::try_from(
            std::mem::size_of::<Self>()
                .saturating_add(reference_bytes(&self.preserved_state))
                .saturating_add(reference_bytes(&self.preserved_commit)),
        )
        .unwrap_or(u64::MAX)
    }
}

pub(super) struct CachedVerifiedContent(pub(super) VerifiedContent);

impl ProjectionCachePayload for CachedVerifiedContent {
    fn retained_bytes(&self) -> u64 {
        u64::try_from(std::mem::size_of::<Self>()).unwrap_or(u64::MAX)
    }
}

pub(super) struct CachedPartialVerification(pub(super) ContentVerificationState);

impl ProjectionCachePayload for CachedPartialVerification {
    fn retained_bytes(&self) -> u64 {
        self.0.retained_bytes()
    }
}

pub(super) struct EngineIdentity<'a, P, E> {
    engine: &'a E,
    marker: PhantomData<fn() -> P>,
}

impl<'a, P, E> EngineIdentity<'a, P, E> {
    pub(super) const fn new(engine: &'a E) -> Self {
        Self {
            engine,
            marker: PhantomData,
        }
    }
}

impl<P, E> crate::storage_model::ObjectIdentity for EngineIdentity<'_, P, E>
where
    E: PrincipalProjectionEngine<P>,
{
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        self.engine.identify_object(record)
    }
}

pub(super) struct EngineSource<'a, P, E> {
    engine: &'a E,
    principal: &'a P,
}

impl<'a, P, E> EngineSource<'a, P, E> {
    pub(super) const fn new(engine: &'a E, principal: &'a P) -> Self {
        Self { engine, principal }
    }
}

impl<P, E> ContentSource for EngineSource<'_, P, E>
where
    E: PrincipalProjectionEngine<P>,
{
    type Error = PrincipalProjectionError;

    fn load_content_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, Self::Error> {
        self.engine.load_object_for(self.principal, id)
    }

    fn load_shared_content_object(
        &self,
        id: ObjectId,
    ) -> Result<Option<Arc<ObjectRecord>>, Self::Error> {
        self.engine.load_shared_object_for(self.principal, id)
    }

    fn load_content_objects(
        &self,
        ids: &[ObjectId],
    ) -> Result<Vec<Option<ObjectRecord>>, Self::Error> {
        self.engine.load_objects_for(self.principal, ids)
    }

    fn load_shared_content_objects(
        &self,
        ids: &[ObjectId],
    ) -> Result<Vec<Option<Arc<ObjectRecord>>>, Self::Error> {
        self.engine.load_shared_objects_for(self.principal, ids)
    }
}

pub(super) struct StagedObjectBatch {
    records: BTreeMap<ObjectId, ObjectRecord>,
}

impl StagedObjectBatch {
    pub(super) fn into_records(self) -> Vec<ObjectRecord> {
        self.records.into_values().collect()
    }

    pub(super) fn expected(&self) -> Vec<ObjectId> {
        self.records.keys().copied().collect()
    }
}

pub(super) trait BatchAdmission<P, E> {
    fn admit(
        &mut self,
        engine: &E,
        batch: StagedObjectBatch,
    ) -> Result<u64, PrincipalProjectionError>;
}

pub(super) struct DirectAdmission;

impl<P, E> BatchAdmission<P, E> for DirectAdmission
where
    E: PrincipalProjectionEngine<P>,
{
    fn admit(
        &mut self,
        engine: &E,
        batch: StagedObjectBatch,
    ) -> Result<u64, PrincipalProjectionError> {
        admit_object_batch(engine, batch)
    }
}

pub(super) struct EngineSink<'a, P, E, A = DirectAdmission> {
    engine: &'a E,
    admission: A,
    pub(super) objects_inserted: u64,
    pending_bytes: usize,
    peak_pending_bytes: usize,
    pending: BTreeMap<ObjectId, ObjectRecord>,
    marker: PhantomData<fn() -> P>,
}

impl<'a, P, E> EngineSink<'a, P, E, DirectAdmission> {
    pub(super) const fn new(engine: &'a E) -> Self {
        Self::with_admission(engine, DirectAdmission)
    }
}

impl<'a, P, E, A> EngineSink<'a, P, E, A> {
    pub(super) const fn with_admission(engine: &'a E, admission: A) -> Self {
        Self {
            engine,
            admission,
            objects_inserted: 0,
            pending_bytes: 0,
            peak_pending_bytes: 0,
            pending: BTreeMap::new(),
            marker: PhantomData,
        }
    }

    pub(super) const fn admission(&self) -> &A {
        &self.admission
    }

    pub(super) const fn peak_pending_bytes(&self) -> usize {
        self.peak_pending_bytes
    }
}

impl<P, E, A> EngineSink<'_, P, E, A>
where
    E: PrincipalProjectionEngine<P>,
    A: BatchAdmission<P, E>,
{
    pub(super) fn finish(&mut self) -> Result<(), PrincipalProjectionError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let batch = StagedObjectBatch {
            records: std::mem::take(&mut self.pending),
        };
        self.pending_bytes = 0;
        self.objects_inserted = self
            .objects_inserted
            .checked_add(self.admission.admit(self.engine, batch)?)
            .ok_or(PrincipalProjectionError::Model(
                ModelError::ArithmeticOverflow,
            ))?;
        Ok(())
    }
}

impl<P, E, A> ContentObjectSink for EngineSink<'_, P, E, A>
where
    E: PrincipalProjectionEngine<P>,
    A: BatchAdmission<P, E>,
{
    type Error = PrincipalProjectionError;

    fn stage_content_object(&mut self, record: ObjectRecord) -> Result<ObjectId, Self::Error> {
        let id = self.engine.identify_object(&record);
        match self.pending.get(&id) {
            Some(existing) if existing == &record => return Ok(id),
            Some(_) => {
                return Err(PrincipalProjectionError::Model(
                    ModelError::ObjectCollision(id),
                ));
            },
            None => {},
        }
        self.pending_bytes = self
            .pending_bytes
            .saturating_add(staged_record_size(&record));
        self.peak_pending_bytes = self.peak_pending_bytes.max(self.pending_bytes);
        self.pending.insert(id, record);
        if self.pending_bytes >= STAGING_BATCH_TARGET_BYTES {
            self.finish()?;
        }
        Ok(id)
    }
}

pub(super) fn admit_object_batch<P, E>(
    engine: &E,
    batch: StagedObjectBatch,
) -> Result<u64, PrincipalProjectionError>
where
    E: PrincipalProjectionEngine<P>,
{
    let expected = batch.expected();
    let outcomes = engine.stage_objects(batch.into_records())?;
    validate_admission_outcomes(expected, outcomes)
}

pub(super) fn admit_object_batch_observed<P, E>(
    engine: &E,
    batch: StagedObjectBatch,
    observer: &dyn ProjectionObserver,
) -> Result<u64, PrincipalProjectionError>
where
    E: PrincipalProjectionEngine<P>,
{
    let expected = batch.expected();
    let outcomes = engine.stage_objects_observed(batch.into_records(), observer)?;
    validate_admission_outcomes(expected, outcomes)
}

#[cfg(not(target_family = "wasm"))]
pub(super) fn admit_prepared_object_batch<P, E>(
    engine: &E,
    expected: Vec<ObjectId>,
    prepared: PreparedProjectionBatch,
    observer: Option<&dyn ProjectionObserver>,
) -> Result<u64, PrincipalProjectionError>
where
    E: PrincipalProjectionEngine<P>,
{
    let outcomes = match observer {
        Some(observer) => engine.stage_prepared_objects_observed(prepared, observer)?,
        None => engine.stage_prepared_objects(prepared)?,
    };
    validate_admission_outcomes(expected, outcomes)
}

fn validate_admission_outcomes(
    expected: Vec<ObjectId>,
    outcomes: Vec<(ObjectId, InsertOutcome)>,
) -> Result<u64, PrincipalProjectionError> {
    if outcomes.len() != expected.len() {
        return Err(PrincipalProjectionError::Engine(
            "staging engine returned the wrong outcome count".to_owned(),
        ));
    }
    let mut inserted = 0_u64;
    for (expected, (computed, outcome)) in expected.into_iter().zip(outcomes) {
        if computed != expected {
            return Err(PrincipalProjectionError::Model(
                ModelError::ObjectIdentityMismatch {
                    declared: expected,
                    computed,
                },
            ));
        }
        if outcome == InsertOutcome::Inserted {
            inserted = inserted
                .checked_add(1)
                .ok_or(PrincipalProjectionError::Model(
                    ModelError::ArithmeticOverflow,
                ))?;
        }
    }
    Ok(inserted)
}

fn staged_record_size(record: &ObjectRecord) -> usize {
    record
        .references()
        .iter()
        .fold(record.canonical_bytes().len(), |size, reference| {
            size.saturating_add(reference.label().as_bytes().len())
                .saturating_add(40)
        })
        .saturating_add(64)
}

pub(super) fn map_read_error(
    error: ContentReadError<PrincipalProjectionError>,
) -> PrincipalContentError {
    match error {
        ContentReadError::Content(error) => error.into(),
        ContentReadError::Source(error) => error.into(),
    }
}

pub(super) fn map_stream_error(
    error: ContentStreamError<PrincipalProjectionError>,
) -> PrincipalContentError {
    match error {
        ContentStreamError::Content(error) => error.into(),
        ContentStreamError::Source(error) => PrincipalContentError::ContentSource(error),
        ContentStreamError::Sink(error) => error.into(),
    }
}

pub(super) fn owned_target(
    object: ObjectId,
    record: &ObjectRecord,
    label: &[u8],
) -> Result<ObjectId, PrincipalContentError> {
    let reference = record
        .reference(&ReferenceLabel::new(label))
        .ok_or_else(|| invalid(object, "required principal reference is missing"))?;
    if reference.kind() != ReferenceKind::Owns {
        return Err(invalid(
            object,
            "required principal reference is not owning",
        ));
    }
    Ok(reference.target())
}

pub(super) fn require_structural(
    object: ObjectId,
    record: &ObjectRecord,
) -> Result<(), PrincipalContentError> {
    if !record.canonical_bytes().is_empty()
        || record.logical_bytes() != 0
        || record.class() != ObjectClass::Metadata
    {
        return Err(invalid(
            object,
            "principal structural object carries payload",
        ));
    }
    Ok(())
}

pub(super) fn invalid(object: ObjectId, detail: &'static str) -> PrincipalContentError {
    PrincipalContentError::InvalidGraph { object, detail }
}
