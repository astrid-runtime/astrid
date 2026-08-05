//! Bounded parallel construction and atomic multi-name publication.

use std::collections::{BTreeMap, VecDeque};
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;

use super::{
    CatalogSummary, CatalogValidation, CatalogValue, EngineSink, ModelError, PrincipalContentStore,
    PrincipalProjectionEngine, PrincipalProjectionError, VerifiedContent, build_content_streaming,
    insert, invalid, lookup, map_stream_error,
};
use crate::content::{
    BulkIngestPolicy, ChunkingProfile, ContentBatchEntry, ContentBatchWriteOutcome,
    ContentChangeCache, ContentIngest, ContentName, ContentObservation, PrincipalContentError,
    SourceObservation,
};

type PendingIngest<R> = (ContentName, (R, ChunkingProfile, Option<SourceObservation>));
type WorkerEntry = (ContentName, VerifiedContent, Option<SourceObservation>);
type WorkerResult = Result<(Vec<WorkerEntry>, u64), PrincipalContentError>;

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
        self.put_streaming_batch_internal(principal, ingests, BulkIngestPolicy::default(), None)
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
        self.put_streaming_batch_internal(principal, ingests, policy, None)
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
        self.put_streaming_batch_internal(principal, ingests, policy, Some(cache))
    }

    fn put_streaming_batch_internal<R, I>(
        &self,
        principal: &P,
        ingests: I,
        policy: BulkIngestPolicy,
        cache: Option<&ContentChangeCache>,
    ) -> Result<ContentBatchWriteOutcome, PrincipalContentError>
    where
        R: Read + Send,
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

        let mut completed = BTreeMap::new();
        let mut pending = VecDeque::new();
        for (name, (source, profile, observation)) in ordered {
            let cached = cache
                .zip(observation.as_ref())
                .and_then(|(cache, observation)| cache.lookup(observation));
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
        if pending.is_empty() {
            return self.publish_batch(principal, &completed, 0);
        }

        let worker_count = policy.worker_threads().get().min(pending.len());
        let queue = Arc::new(Mutex::new(pending));
        let cancelled = Arc::new(AtomicBool::new(false));
        let results = if worker_count == 1 {
            vec![build_worker(self, queue.as_ref(), cancelled.as_ref())?]
        } else {
            #[cfg(target_family = "wasm")]
            return Err(PrincipalContentError::Projection(
                PrincipalProjectionError::Engine(
                    "parallel bulk ingestion requires host worker authority".to_owned(),
                ),
            ));
            #[cfg(not(target_family = "wasm"))]
            std::thread::scope(|scope| {
                let mut handles = Vec::with_capacity(worker_count);
                for _ in 0..worker_count {
                    let queue = Arc::clone(&queue);
                    let cancelled = Arc::clone(&cancelled);
                    handles.push(
                        scope.spawn(move || build_worker(self, queue.as_ref(), cancelled.as_ref())),
                    );
                }
                handles
                    .into_iter()
                    .map(|handle| {
                        handle.join().map_err(|_| {
                            PrincipalContentError::Projection(PrincipalProjectionError::Engine(
                                "bulk content worker panicked".to_owned(),
                            ))
                        })?
                    })
                    .collect::<Result<Vec<_>, PrincipalContentError>>()
            })?
        };

        let mut objects_inserted = 0_u64;
        for (worker_entries, worker_objects_inserted) in results {
            objects_inserted = objects_inserted
                .checked_add(worker_objects_inserted)
                .ok_or(PrincipalContentError::AccountingOverflow)?;
            for (name, verified, observation) in worker_entries {
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
        self.publish_batch(principal, &completed, objects_inserted)
    }

    fn publish_batch(
        &self,
        principal: &P,
        completed: &BTreeMap<ContentName, PreparedContent>,
        staged_objects_inserted: u64,
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
            let transaction =
                self.encode_transaction(principal.clone(), header, None, catalog_records)?;
            match self.engine.commit_root(transaction) {
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
    loop {
        if cancelled.load(Ordering::Acquire) {
            break;
        }
        let next = queue.lock().pop_front();
        let Some((name, (source, profile, observation))) = next else {
            break;
        };
        let streamed = match build_content_streaming(profile, source, &mut sink) {
            Ok(streamed) => streamed,
            Err(error) => {
                cancelled.store(true, Ordering::Release);
                return Err(map_stream_error(error));
            },
        };
        completed.push((name, streamed.verified_content(), observation));
    }
    sink.finish()?;
    Ok((completed, sink.objects_inserted))
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
