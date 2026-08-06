use super::*;
use astrid_storage_engine::PreparedProjectionBatch;

struct RejectFirstBatchEngine {
    inner: Engine,
    reject: AtomicBool,
}

impl RejectFirstBatchEngine {
    fn new() -> Self {
        Self {
            inner: Engine::new(TestIdentity),
            reject: AtomicBool::new(true),
        }
    }
}

impl PrincipalProjectionEngine<String> for RejectFirstBatchEngine {
    fn identify_object(&self, record: &ObjectRecord) -> ObjectId {
        self.inner.identify(record)
    }

    fn stage_object(
        &self,
        record: ObjectRecord,
    ) -> Result<(ObjectId, InsertOutcome), PrincipalProjectionError> {
        self.inner.put_object(record).map_err(Into::into)
    }

    fn stage_objects(
        &self,
        records: Vec<ObjectRecord>,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, PrincipalProjectionError> {
        if self.reject.swap(false, Ordering::SeqCst) {
            return Err(PrincipalProjectionError::Engine(
                "injected bulk appender failure".to_owned(),
            ));
        }
        records
            .into_iter()
            .map(|record| self.inner.put_object(record).map_err(Into::into))
            .collect()
    }

    fn prepare_objects(
        &self,
        records: Vec<ObjectRecord>,
    ) -> Result<PreparedProjectionBatch, PrincipalProjectionError> {
        <Engine as PrincipalProjectionEngine<String>>::prepare_objects(&self.inner, records)
    }

    fn stage_prepared_objects(
        &self,
        prepared: PreparedProjectionBatch,
    ) -> Result<Vec<(ObjectId, InsertOutcome)>, PrincipalProjectionError> {
        if self.reject.swap(false, Ordering::SeqCst) {
            return Err(PrincipalProjectionError::Engine(
                "injected bulk appender failure".to_owned(),
            ));
        }
        <Engine as PrincipalProjectionEngine<String>>::stage_prepared_objects(&self.inner, prepared)
    }

    fn current_root(
        &self,
        principal: &String,
    ) -> Result<Option<RootState>, PrincipalProjectionError> {
        Ok(self.inner.root(principal))
    }

    fn load_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, PrincipalProjectionError> {
        Ok(self.inner.object(id))
    }

    fn commit_root(
        &self,
        transaction: RootTransaction<String>,
    ) -> Result<CommitOutcome, PrincipalProjectionError> {
        self.inner.commit(transaction).map_err(Into::into)
    }

    fn flush_projection(&self) -> Result<(), PrincipalProjectionError> {
        Ok(())
    }
}

#[test]
fn parallel_admission_reports_a_source_independent_pending_bound() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(engine);
    let workers = NonZeroUsize::new(4).unwrap();
    let ingests = (0..workers.get())
        .map(|index| {
            ContentIngest::new(
                ContentName::new(format!("bounded-{index}")).unwrap(),
                io::Cursor::new(bytes(5 * 1024 * 1024 + index)),
            )
        })
        .collect::<Vec<_>>();

    let (outcome, diagnostics) = store
        .put_streaming_batch_with_operator_diagnostics(
            &"alice".to_owned(),
            ingests,
            BulkIngestPolicy::new(workers),
            None,
        )
        .unwrap();

    let per_worker_bound = crate::content::store::STAGING_BATCH_TARGET_BYTES
        + usize::try_from(crate::content::ChunkingProfile::ASTRID_V1.maximum_bytes()).unwrap()
        + 64 * 1024;
    assert_eq!(outcome.entries().len(), workers.get());
    assert!(diagnostics.peak_pending_admission_bytes() > 0);
    assert!(!diagnostics.pipeline_elapsed().is_zero());
    assert!(!diagnostics.source_build_elapsed().is_zero());
    assert!(!diagnostics.admission_elapsed().is_zero());
    assert!(!diagnostics.publication_elapsed().is_zero());
    assert!(!diagnostics.object_preparation_elapsed().is_zero());
    assert!(!diagnostics.root_publication_elapsed().is_zero());
    assert!(
        diagnostics.peak_pending_admission_bytes()
            <= workers
                .get()
                .saturating_add(2)
                .saturating_mul(per_worker_bound)
    );
}

#[test]
fn single_worker_diagnostics_measure_the_staging_batch_peak() {
    let store = PrincipalContentStore::from_engine(Arc::new(Engine::new(TestIdentity)));
    let (_, diagnostics) = store
        .put_streaming_batch_with_operator_diagnostics(
            &"alice".to_owned(),
            [ContentIngest::new(
                ContentName::new("single").unwrap(),
                io::Cursor::new(bytes(5 * 1024 * 1024)),
            )],
            BulkIngestPolicy::new(NonZeroUsize::MIN),
            None,
        )
        .unwrap();

    assert!(diagnostics.peak_pending_admission_bytes() > 0);
}

#[test]
fn cache_only_diagnostics_report_no_source_admission_pipeline() {
    let store = PrincipalContentStore::from_engine(Arc::new(Engine::new(TestIdentity)));
    let cache = ContentChangeCache::new(NonZeroU64::new(1024 * 1024).unwrap());
    let value = bytes(2 * 1024 * 1024);
    let observation = SourceObservation::trusted(source_fingerprint(
        "/workspace/cached-only.bin",
        value.len() as u64,
        42,
    ));
    let name = ContentName::new("cached-only.bin").unwrap();
    store
        .put_streaming_batch_with_operator_diagnostics(
            &"alice".to_owned(),
            [
                ContentIngest::new(name.clone(), io::Cursor::new(value.clone()))
                    .with_observation(observation.clone()),
            ],
            BulkIngestPolicy::new(NonZeroUsize::MIN),
            Some(&cache),
        )
        .unwrap();

    let (_, diagnostics) = store
        .put_streaming_batch_with_operator_diagnostics(
            &"alice".to_owned(),
            [ContentIngest::new(name, io::Cursor::new(value)).with_observation(observation)],
            BulkIngestPolicy::new(NonZeroUsize::MIN),
            Some(&cache),
        )
        .unwrap();

    assert!(diagnostics.pipeline_elapsed().is_zero());
    assert!(diagnostics.source_build_elapsed().is_zero());
    assert!(diagnostics.admission_elapsed().is_zero());
    assert_eq!(diagnostics.peak_pending_admission_bytes(), 0);
}

#[test]
fn parallel_appender_failure_publishes_no_root() {
    let engine = Arc::new(RejectFirstBatchEngine::new());
    let store = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let owner = "alice".to_owned();

    let error = store
        .put_streaming_batch_with_policy(
            &owner,
            [
                ContentIngest::new(
                    ContentName::new("first").unwrap(),
                    io::Cursor::new(bytes(5 * 1024 * 1024)),
                ),
                ContentIngest::new(
                    ContentName::new("second").unwrap(),
                    io::Cursor::new(bytes(5 * 1024 * 1024 + 1)),
                ),
            ],
            BulkIngestPolicy::new(NonZeroUsize::new(2).unwrap()),
        )
        .unwrap_err();

    assert!(matches!(
        error,
        PrincipalContentError::Projection(PrincipalProjectionError::Engine(ref detail))
            if detail == "injected bulk appender failure"
    ));
    assert_eq!(engine.inner.root(&owner), None);
    assert!(store.list(&owner).unwrap().is_empty());
}

#[test]
fn parallel_source_failure_cancels_without_publishing_or_deadlocking() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let owner = "alice".to_owned();
    let value = bytes(8 * 1024 * 1024);

    let error = store
        .put_streaming_batch_with_policy(
            &owner,
            [
                ContentIngest::new(
                    ContentName::new("complete").unwrap(),
                    FailAfter {
                        bytes: value.clone(),
                        offset: 0,
                        limit: usize::MAX,
                    },
                ),
                ContentIngest::new(
                    ContentName::new("fails").unwrap(),
                    FailAfter {
                        bytes: value,
                        offset: 0,
                        limit: 1024 * 1024,
                    },
                ),
            ],
            BulkIngestPolicy::new(NonZeroUsize::new(2).unwrap()),
        )
        .unwrap_err();

    assert!(matches!(error, PrincipalContentError::ContentSource(_)));
    assert_eq!(engine.root(&owner), None);
    assert!(store.list(&owner).unwrap().is_empty());
}

#[test]
fn worker_schedule_cannot_change_the_canonical_batch_root() {
    let build = |workers| {
        let store = PrincipalContentStore::from_engine(Arc::new(Engine::new(TestIdentity)));
        let outcome = store
            .put_streaming_batch_with_policy(
                &"alice".to_owned(),
                (0..4)
                    .map(|index| {
                        ContentIngest::new(
                            ContentName::new(format!("file-{index}")).unwrap(),
                            io::Cursor::new(bytes(2 * 1024 * 1024 + index)),
                        )
                    })
                    .collect::<Vec<_>>(),
                BulkIngestPolicy::new(NonZeroUsize::new(workers).unwrap()),
            )
            .unwrap();
        (
            outcome.principal_root(),
            outcome
                .entries()
                .iter()
                .map(|entry| (entry.name().clone(), entry.descriptor()))
                .collect::<Vec<_>>(),
        )
    };

    assert_eq!(build(2), build(4));
}
