//! Bounded parallel construction and atomic multi-name publication.

#[cfg(not(target_family = "wasm"))]
mod admission;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use astrid_storage_engine::{ProjectionObserver, ProjectionPhase};
use parking_lot::Mutex;

use super::projection::{BatchAdmission, StagedObjectBatch, admit_object_batch_observed};
use super::{
    CatalogSummary, CatalogValidation, CatalogValue, EngineSink, ModelError, ObjectReference,
    PrincipalContentStore, PrincipalProjectionEngine, PrincipalProjectionError, ReferenceKind,
    VerifiedContent, build_content_streaming, insert, invalid, lookup, map_stream_error,
};
use crate::content::{
    BulkIngestDiagnostics, BulkIngestPhaseDurations, BulkIngestPolicy, ChunkingProfile,
    ContentBatchEntry, ContentBatchWriteOutcome, ContentChangeCache, ContentIngest, ContentName,
    ContentObservation, PrincipalContentError, SourceObservation,
};

type PendingIngest<R> = (ContentName, (R, ChunkingProfile, Option<SourceObservation>));
type OrderedIngests<R> = BTreeMap<ContentName, (R, ChunkingProfile, Option<SourceObservation>)>;
type PartitionedIngests<R> = (
    BTreeMap<ContentName, PreparedContent>,
    VecDeque<PendingIngest<R>>,
);
type WorkerEntry = (ContentName, VerifiedContent, Option<SourceObservation>);
type WorkerResult = Result<WorkerBuild, PrincipalContentError>;

pub(super) struct WorkerBuild {
    entries: Vec<WorkerEntry>,
    objects_inserted: u64,
    source_build_elapsed: Duration,
    admission_elapsed: Duration,
    peak_pending_bytes: usize,
}

struct BulkExecution {
    outcome: ContentBatchWriteOutcome,
    diagnostics: BulkIngestDiagnostics,
}

#[derive(Default)]
struct BulkPhaseObserver {
    elapsed: Mutex<BTreeMap<ProjectionPhase, Duration>>,
}

impl BulkPhaseObserver {
    fn elapsed(&self, phase: ProjectionPhase) -> Duration {
        self.elapsed.lock().get(&phase).copied().unwrap_or_default()
    }
}

impl ProjectionObserver for BulkPhaseObserver {
    fn record(&self, phase: ProjectionPhase, elapsed: Duration) {
        let mut phases = self.elapsed.lock();
        let total = phases.entry(phase).or_default();
        *total = total.saturating_add(elapsed);
    }
}

#[derive(Clone)]
struct PreparedContent {
    verified: VerifiedContent,
    observation: ContentObservation,
}

impl<P, E> PrincipalContentStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    pub(crate) fn publish_verified_batch(
        &self,
        principal: &P,
        entries: impl IntoIterator<Item = (ContentName, VerifiedContent)>,
        staged_objects_inserted: u64,
    ) -> Result<ContentBatchWriteOutcome, PrincipalContentError> {
        let mut completed = BTreeMap::new();
        for (name, verified) in entries {
            if completed
                .insert(
                    name.clone(),
                    PreparedContent {
                        verified,
                        observation: ContentObservation::BytesObserved,
                    },
                )
                .is_some()
            {
                return Err(PrincipalContentError::DuplicateBatchName(name));
            }
        }
        if completed.is_empty() {
            return Err(PrincipalContentError::EmptyBatch);
        }
        self.publish_batch(principal, &completed, staged_objects_inserted, None)
    }

    /// Stream and atomically publish several names under one principal root.
    ///
    /// Sources are consumed in canonical name order. Content records are
    /// staged in bounded coalesced batches, then every catalog mutation is
    /// authorized by one root compare-and-swap and one durability boundary.
    /// A root conflict retries only the catalog transaction; source bytes are
    /// never read twice. Duplicate names are rejected before any source is
    /// consumed.
    ///
    /// # Errors
    ///
    /// Returns a source, content, duplicate-name, quota, graph, or projection
    /// error without publishing a partial batch.
    pub fn put_streaming_batch<R, I>(
        &self,
        principal: &P,
        ingests: I,
    ) -> Result<ContentBatchWriteOutcome, PrincipalContentError>
    where
        R: Read + Send,
        I: IntoIterator<Item = ContentIngest<R>>,
    {
        self.put_streaming_batch_internal(
            principal,
            ingests,
            BulkIngestPolicy::default(),
            None,
            false,
        )
        .map(|execution| execution.outcome)
    }

    /// Stream and atomically publish a batch with explicit worker policy.
    ///
    /// Each worker owns a bounded `FastCDC` buffer and coalesced staging sink.
    /// Workers perform chunking, identity construction, and encoding outside
    /// the engine mutation lock; the durable engine remains the single serial
    /// appender and the final principal publication remains one transaction.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::put_streaming_batch`].
    pub fn put_streaming_batch_with_policy<R, I>(
        &self,
        principal: &P,
        ingests: I,
        policy: BulkIngestPolicy,
    ) -> Result<ContentBatchWriteOutcome, PrincipalContentError>
    where
        R: Read + Send,
        I: IntoIterator<Item = ContentIngest<R>>,
    {
        self.put_streaming_batch_internal(principal, ingests, policy, None, false)
            .map(|execution| execution.outcome)
    }

    /// Stream a batch with trusted change-token reuse and explicit policy.
    ///
    /// A cache hit is possible only for an ingest carrying a trusted source
    /// observation that exactly matches a prior byte-verified build. Untrusted
    /// metadata always falls through to the source reader. The cache is a
    /// bounded process-local accelerator and never enters a root or export.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::put_streaming_batch`].
    pub fn put_streaming_batch_with_change_cache<R, I>(
        &self,
        principal: &P,
        ingests: I,
        policy: BulkIngestPolicy,
        cache: &ContentChangeCache,
    ) -> Result<ContentBatchWriteOutcome, PrincipalContentError>
    where
        R: Read + Send,
        I: IntoIterator<Item = ContentIngest<R>>,
    {
        self.put_streaming_batch_internal(principal, ingests, policy, Some(cache), false)
            .map(|execution| execution.outcome)
    }

    /// Stream a batch while collecting privileged operator diagnostics.
    ///
    /// This is the measured form of
    /// [`Self::put_streaming_batch_with_change_cache`]. Diagnostics describe
    /// shared-engine timing and memory occupancy; callers must keep them below
    /// every principal-visible boundary.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::put_streaming_batch`].
    pub fn put_streaming_batch_with_operator_diagnostics<R, I>(
        &self,
        principal: &P,
        ingests: I,
        policy: BulkIngestPolicy,
        cache: Option<&ContentChangeCache>,
    ) -> Result<(ContentBatchWriteOutcome, BulkIngestDiagnostics), PrincipalContentError>
    where
        R: Read + Send,
        I: IntoIterator<Item = ContentIngest<R>>,
    {
        self.put_streaming_batch_internal(principal, ingests, policy, cache, true)
            .map(|execution| (execution.outcome, execution.diagnostics))
    }

    fn put_streaming_batch_internal<R, I>(
        &self,
        principal: &P,
        ingests: I,
        policy: BulkIngestPolicy,
        cache: Option<&ContentChangeCache>,
        observe: bool,
    ) -> Result<BulkExecution, PrincipalContentError>
    where
        R: Read + Send,
        I: IntoIterator<Item = ContentIngest<R>>,
    {
        let ordered = ordered_ingests(ingests)?;
        let phase_observer = observe.then(|| Arc::new(BulkPhaseObserver::default()));
        let (mut completed, pending) = self.partition_cached_ingests(principal, ordered, cache)?;
        let pipeline_started = Instant::now();
        if pending.is_empty() {
            return self.publish_cached_batch(principal, &completed, phase_observer.as_ref());
        }

        let worker_count = policy.worker_threads().get().min(pending.len());
        let (results, staged_objects_inserted, peak_pending_bytes, admission_elapsed) =
            if worker_count == 1 {
                let queue = Mutex::new(pending);
                let cancelled = AtomicBool::new(false);
                let build = match phase_observer.as_deref() {
                    Some(observer) => build_worker_observed(self, &queue, &cancelled, observer)?,
                    None => build_worker(self, &queue, &cancelled)?,
                };
                let admission_elapsed = build.admission_elapsed;
                let peak_pending_bytes = build.peak_pending_bytes;
                (vec![build], 0_u64, peak_pending_bytes, admission_elapsed)
            } else {
                #[cfg(target_family = "wasm")]
                return Err(PrincipalContentError::Projection(
                    PrincipalProjectionError::Engine(
                        "parallel bulk ingestion requires host worker authority".to_owned(),
                    ),
                ));
                #[cfg(not(target_family = "wasm"))]
                {
                    let parallel = admission::build_parallel(
                        self,
                        pending,
                        worker_count,
                        phase_observer.as_ref(),
                    )?;
                    (
                        parallel
                            .entries
                            .into_iter()
                            .map(|mut build| {
                                build.objects_inserted = 0;
                                build.admission_elapsed = Duration::ZERO;
                                build
                            })
                            .collect(),
                        parallel.objects_inserted,
                        parallel.peak_pending_bytes,
                        parallel.admission_elapsed,
                    )
                }
            };
        let pipeline_elapsed = pipeline_started.elapsed();

        let mut objects_inserted = staged_objects_inserted;
        let mut source_build_elapsed = Duration::ZERO;
        for build in results {
            objects_inserted = objects_inserted
                .checked_add(build.objects_inserted)
                .ok_or(PrincipalContentError::AccountingOverflow)?;
            source_build_elapsed = source_build_elapsed.saturating_add(build.source_build_elapsed);
            for (name, verified, observation) in build.entries {
                if let Some((cache, observation)) = cache.zip(observation.as_ref()) {
                    // A token can only become reusable after every pending
                    // record from this worker was admitted successfully.
                    cache.record(observation, verified);
                }
                completed.insert(
                    name,
                    PreparedContent {
                        verified,
                        observation: ContentObservation::BytesObserved,
                    },
                );
            }
        }
        let publication_started = Instant::now();
        let outcome = self.publish_batch(
            principal,
            &completed,
            objects_inserted,
            phase_observer.as_ref(),
        )?;
        Ok(BulkExecution {
            outcome,
            diagnostics: BulkIngestDiagnostics::new(
                pipeline_elapsed,
                source_build_elapsed,
                admission_elapsed,
                publication_started.elapsed(),
                peak_pending_bytes,
                phase_durations(phase_observer.as_deref()),
            ),
        })
    }

    fn publish_cached_batch(
        &self,
        principal: &P,
        completed: &BTreeMap<ContentName, PreparedContent>,
        observer: Option<&Arc<BulkPhaseObserver>>,
    ) -> Result<BulkExecution, PrincipalContentError> {
        let publication_started = Instant::now();
        let outcome = self.publish_batch(principal, completed, 0, observer)?;
        Ok(BulkExecution {
            outcome,
            diagnostics: BulkIngestDiagnostics::new(
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
                publication_started.elapsed(),
                0,
                phase_durations(observer.map(Arc::as_ref)),
            ),
        })
    }

    fn partition_cached_ingests<R>(
        &self,
        principal: &P,
        ordered: OrderedIngests<R>,
        cache: Option<&ContentChangeCache>,
    ) -> Result<PartitionedIngests<R>, PrincipalContentError> {
        let mut completed = BTreeMap::new();
        let mut pending = VecDeque::new();
        for (name, (source, profile, observation)) in ordered {
            let cached = cache
                .zip(observation.as_ref())
                .and_then(|(cache, observation)| cache.lookup(observation, profile));
            let cached = match cached {
                Some(verified) if self.cached_closure_available(principal, verified)? => {
                    Some(verified)
                },
                Some(_) | None => None,
            };
            if let Some(verified) = cached {
                completed.insert(
                    name,
                    PreparedContent {
                        verified,
                        observation: ContentObservation::ChangeTokenObserved,
                    },
                );
            } else {
                pending.push_back((name, (source, profile, observation)));
            }
        }
        Ok((completed, pending))
    }

    /// Confirm that every immutable object named by a cached file still exists.
    ///
    /// Change-cache entries are disposable observations, not liveness pins. A
    /// compaction or a different engine instance may therefore retain the file
    /// object while dropping one of its descendants. The builder minted the
    /// descriptor from a canonical acyclic content DAG, so walking owning edges
    /// needs only a bounded work list; repeated chunk identities may be probed
    /// more than once rather than retaining an unbounded visited set.
    fn cached_closure_available(
        &self,
        principal: &P,
        verified: VerifiedContent,
    ) -> Result<bool, PrincipalContentError> {
        let mut pending = vec![verified.descriptor().file()];
        while let Some(object) = pending.pop() {
            let Some(record) = self.engine.load_object_for(principal, object)? else {
                return Ok(false);
            };
            pending.extend(
                record
                    .references()
                    .iter()
                    .filter(|reference| reference.kind() == ReferenceKind::Owns)
                    .map(ObjectReference::target),
            );
        }
        Ok(true)
    }

    fn publish_batch(
        &self,
        principal: &P,
        completed: &BTreeMap<ContentName, PreparedContent>,
        staged_objects_inserted: u64,
        observer: Option<&Arc<BulkPhaseObserver>>,
    ) -> Result<ContentBatchWriteOutcome, PrincipalContentError> {
        loop {
            let mut header = self.header(principal)?.as_ref().clone();
            let mut catalog_records = BTreeMap::new();
            let mut changed = false;
            for (name, prepared) in completed {
                let descriptor = prepared.verified.descriptor();
                let previous = lookup(header.catalog, name, &mut |object| {
                    catalog_records
                        .get(&object)
                        .cloned()
                        .map_or_else(|| self.load_required_for(principal, object), Ok)
                })?;
                if previous.is_some_and(|entry| entry.file == descriptor.file()) {
                    continue;
                }
                let mutation = insert(
                    header.catalog,
                    name,
                    CatalogValue {
                        file: descriptor.file(),
                        logical_bytes: descriptor.logical_bytes(),
                    },
                    &mut |object| {
                        catalog_records
                            .get(&object)
                            .cloned()
                            .map_or_else(|| self.load_required_for(principal, object), Ok)
                    },
                    &|record| self.engine.identify_object(record),
                )?;
                header.catalog = mutation.root;
                for (_, record) in mutation.records {
                    self.insert(&mut catalog_records, record)?;
                }
                changed = true;
            }

            if !changed {
                let first = completed
                    .values()
                    .next()
                    .ok_or(PrincipalContentError::EmptyBatch)?;
                let root = header.root.ok_or_else(|| {
                    invalid(
                        first.verified.descriptor().file(),
                        "unchanged batch exists without a principal root",
                    )
                })?;
                for prepared in completed.values() {
                    self.mark_verified(principal, prepared.verified);
                }
                return Ok(batch_outcome(completed, root, staged_objects_inserted));
            }

            self.enforce_quota(principal, &header)?;
            let catalog = header.catalog;
            retain_final_catalog_records(catalog, &mut catalog_records);
            let transaction =
                self.encode_transaction(principal.clone(), header, None, catalog_records)?;
            let commit = match observer {
                Some(observer) => self.engine.commit_root_observed(
                    transaction,
                    Arc::clone(observer) as Arc<dyn ProjectionObserver>,
                ),
                None => self.engine.commit_root(transaction),
            };
            match commit {
                Ok(outcome) => {
                    self.validated_catalogs.lock().insert(
                        principal.clone(),
                        CatalogValidation {
                            root: catalog.map(|root| root.object),
                            summary: catalog.map_or(CatalogSummary::default(), |root| root.summary),
                        },
                    );
                    for prepared in completed.values() {
                        self.mark_verified(principal, prepared.verified);
                    }
                    let objects_inserted = staged_objects_inserted
                        .checked_add(outcome.objects_inserted())
                        .ok_or(PrincipalContentError::AccountingOverflow)?;
                    return Ok(batch_outcome(completed, outcome.root(), objects_inserted));
                },
                Err(PrincipalProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(error.into()),
            }
        }
    }
}

fn ordered_ingests<R, I>(ingests: I) -> Result<OrderedIngests<R>, PrincipalContentError>
where
    I: IntoIterator<Item = ContentIngest<R>>,
{
    let mut ordered = BTreeMap::new();
    for ingest in ingests {
        let (name, source, profile, observation) = ingest.into_parts();
        if ordered
            .insert(name.clone(), (source, profile, observation))
            .is_some()
        {
            return Err(PrincipalContentError::DuplicateBatchName(name));
        }
    }
    if ordered.is_empty() {
        return Err(PrincipalContentError::EmptyBatch);
    }
    Ok(ordered)
}

fn phase_durations(observer: Option<&BulkPhaseObserver>) -> BulkIngestPhaseDurations {
    let elapsed = |phase| observer.map_or(Duration::ZERO, |observer| observer.elapsed(phase));
    BulkIngestPhaseDurations {
        object_preparation: elapsed(ProjectionPhase::ObjectPreparation),
        admission_probe: elapsed(ProjectionPhase::AdmissionProbe),
        direct_identity: elapsed(ProjectionPhase::DirectIdentity),
        arena_append: elapsed(ProjectionPhase::ArenaAppend),
        physical_map_update: elapsed(ProjectionPhase::PhysicalMapUpdate),
        closure_validation: elapsed(ProjectionPhase::ClosureValidation),
        root_publication: elapsed(ProjectionPhase::RootPublication),
        flush: elapsed(ProjectionPhase::Flush),
    }
}

fn retain_final_catalog_records(
    catalog: Option<super::CatalogRoot>,
    records: &mut BTreeMap<astrid_storage_model::ObjectId, astrid_storage_model::ObjectRecord>,
) {
    let mut reachable = BTreeSet::new();
    let mut pending = catalog
        .map(|root| root.object)
        .into_iter()
        .collect::<Vec<_>>();
    while let Some(object) = pending.pop() {
        if !reachable.insert(object) {
            continue;
        }
        let Some(record) = records.get(&object) else {
            continue;
        };
        pending.extend(
            record
                .references()
                .iter()
                .filter(|reference| reference.kind() == ReferenceKind::Owns)
                .map(ObjectReference::target),
        );
    }
    records.retain(|object, _| reachable.contains(object));
}

fn build_worker<P, E, R>(
    store: &PrincipalContentStore<P, E>,
    queue: &Mutex<VecDeque<PendingIngest<R>>>,
    cancelled: &AtomicBool,
) -> WorkerResult
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
    R: Read + Send,
{
    let mut sink = EngineSink::<P, E>::new(store.engine.as_ref());
    let mut completed = Vec::new();
    let mut source_build_elapsed = Duration::ZERO;
    loop {
        if cancelled.load(Ordering::Acquire) {
            break;
        }
        let next = queue.lock().pop_front();
        let Some((name, (source, profile, observation))) = next else {
            break;
        };
        let build_started = Instant::now();
        let streamed = match build_content_streaming(profile, source, &mut sink) {
            Ok(streamed) => streamed,
            Err(error) => {
                cancelled.store(true, Ordering::Release);
                return Err(map_stream_error(error));
            },
        };
        source_build_elapsed = source_build_elapsed.saturating_add(build_started.elapsed());
        completed.push((name, streamed.verified_content(), observation));
    }
    sink.finish()?;
    Ok(WorkerBuild {
        entries: completed,
        objects_inserted: sink.objects_inserted,
        source_build_elapsed,
        admission_elapsed: Duration::ZERO,
        peak_pending_bytes: sink.peak_pending_bytes(),
    })
}

struct ObservedDirectAdmission<'a> {
    observer: &'a BulkPhaseObserver,
    elapsed: Duration,
}

impl<P, E> BatchAdmission<P, E> for ObservedDirectAdmission<'_>
where
    E: PrincipalProjectionEngine<P>,
{
    fn admit(
        &mut self,
        engine: &E,
        batch: StagedObjectBatch,
    ) -> Result<u64, PrincipalProjectionError> {
        let started = Instant::now();
        let outcome = admit_object_batch_observed(engine, batch, self.observer);
        self.elapsed = self.elapsed.saturating_add(started.elapsed());
        outcome
    }
}

fn build_worker_observed<P, E, R>(
    store: &PrincipalContentStore<P, E>,
    queue: &Mutex<VecDeque<PendingIngest<R>>>,
    cancelled: &AtomicBool,
    observer: &BulkPhaseObserver,
) -> WorkerResult
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
    R: Read + Send,
{
    let admission = ObservedDirectAdmission {
        observer,
        elapsed: Duration::ZERO,
    };
    let mut sink = EngineSink::<P, E, _>::with_admission(store.engine.as_ref(), admission);
    let started = Instant::now();
    let mut completed = Vec::new();
    while !cancelled.load(Ordering::Acquire) {
        let Some((name, (source, profile, observation))) = queue.lock().pop_front() else {
            break;
        };
        let streamed = build_content_streaming(profile, source, &mut sink).map_err(|error| {
            cancelled.store(true, Ordering::Release);
            map_stream_error(error)
        })?;
        completed.push((name, streamed.verified_content(), observation));
    }
    sink.finish()?;
    let source_build_elapsed = started.elapsed().saturating_sub(sink.admission().elapsed);
    let admission_elapsed = sink.admission().elapsed;
    Ok(WorkerBuild {
        entries: completed,
        objects_inserted: sink.objects_inserted,
        source_build_elapsed,
        admission_elapsed,
        peak_pending_bytes: sink.peak_pending_bytes(),
    })
}

fn batch_outcome(
    completed: &BTreeMap<ContentName, PreparedContent>,
    root: astrid_storage_model::RootState,
    objects_inserted: u64,
) -> ContentBatchWriteOutcome {
    let entries = completed
        .iter()
        .map(|(name, prepared)| {
            ContentBatchEntry::new(
                name.clone(),
                prepared.verified.descriptor(),
                prepared.observation,
            )
        })
        .collect();
    ContentBatchWriteOutcome::new(entries, root, objects_inserted)
}
