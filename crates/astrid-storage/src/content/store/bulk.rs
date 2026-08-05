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
    BulkIngestPolicy, ContentBatchEntry, ContentBatchWriteOutcome, ContentIngest, ContentName,
    PrincipalContentError,
};

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
        self.put_streaming_batch_with_policy(principal, ingests, BulkIngestPolicy::default())
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
        let mut ordered = BTreeMap::new();
        for ingest in ingests {
            let (name, source, profile) = ingest.into_parts();
            if ordered.insert(name.clone(), (source, profile)).is_some() {
                return Err(PrincipalContentError::DuplicateBatchName(name));
            }
        }
        if ordered.is_empty() {
            return Err(PrincipalContentError::EmptyBatch);
        }

        let worker_count = policy.worker_threads().get().min(ordered.len());
        let queue = Arc::new(Mutex::new(VecDeque::from_iter(ordered)));
        let cancelled = Arc::new(AtomicBool::new(false));
        let results = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            for _ in 0..worker_count {
                let queue = Arc::clone(&queue);
                let cancelled = Arc::clone(&cancelled);
                handles.push(scope.spawn(move || {
                    let mut sink = EngineSink::<P, E>::new(self.engine.as_ref());
                    let mut completed = Vec::new();
                    loop {
                        if cancelled.load(Ordering::Acquire) {
                            break;
                        }
                        let next = queue.lock().pop_front();
                        let Some((name, (source, profile))) = next else {
                            break;
                        };
                        let streamed = match build_content_streaming(profile, source, &mut sink) {
                            Ok(streamed) => streamed,
                            Err(error) => {
                                cancelled.store(true, Ordering::Release);
                                return Err(map_stream_error(error));
                            },
                        };
                        completed.push((name, streamed.verified_content()));
                    }
                    sink.finish()?;
                    Ok((completed, sink.objects_inserted))
                }));
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
        })?;

        let mut completed = BTreeMap::new();
        let mut objects_inserted = 0_u64;
        for (worker_entries, worker_objects_inserted) in results {
            objects_inserted = objects_inserted
                .checked_add(worker_objects_inserted)
                .ok_or(PrincipalContentError::AccountingOverflow)?;
            completed.extend(worker_entries);
        }
        self.publish_batch(principal, &completed, objects_inserted)
    }

    fn publish_batch(
        &self,
        principal: &P,
        completed: &BTreeMap<ContentName, VerifiedContent>,
        staged_objects_inserted: u64,
    ) -> Result<ContentBatchWriteOutcome, PrincipalContentError> {
        loop {
            let mut header = self.header(principal)?.as_ref().clone();
            let mut catalog_records = BTreeMap::new();
            let mut changed = false;
            for (name, verified) in completed {
                let descriptor = verified.descriptor();
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
                        first.descriptor().file(),
                        "unchanged batch exists without a principal root",
                    )
                })?;
                for verified in completed.values().copied() {
                    self.mark_verified(principal, verified);
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
                    for verified in completed.values().copied() {
                        self.mark_verified(principal, verified);
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

fn batch_outcome(
    completed: &BTreeMap<ContentName, VerifiedContent>,
    root: astrid_storage_model::RootState,
    objects_inserted: u64,
) -> ContentBatchWriteOutcome {
    let entries = completed
        .iter()
        .map(|(name, verified)| ContentBatchEntry::new(name.clone(), verified.descriptor()))
        .collect();
    ContentBatchWriteOutcome::new(entries, root, objects_inserted)
}
