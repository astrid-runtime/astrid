//! Owner-root publication for prepared bulk ingests.

use std::collections::{BTreeMap, BTreeSet};

use super::super::{
    CatalogRoot, CatalogValue, EngineIdentity, ModelError, ObjectId, ObjectRecord, ObjectReference,
    PrincipalContentStore, PrincipalProjectionEngine, ReferenceKind, delete, insert, invalid,
    lookup,
};
use super::{BatchPublicationContext, BulkPhaseObserver, PreparedContent};
use crate::content::{
    ChunkingProfile, ContentBatchEntry, ContentBatchWriteOutcome, ContentName, ContentObservation,
    PrepareDerivedBatchContent, PrincipalContentError,
};
use crate::content_dag::build_content;
use crate::engine::{PrincipalProjectionError, ProjectionObserver};
use crate::storage_model::RootState;

pub(super) type PreparedDerivedBatch = (
    BTreeMap<ContentName, super::PreparedContent>,
    BTreeMap<ObjectId, ObjectRecord>,
);

impl<P, E> PrincipalContentStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    pub(super) fn apply_batch_removals(
        &self,
        principal: &P,
        catalog: &mut Option<CatalogRoot>,
        removals: &[ContentName],
        records: &mut BTreeMap<ObjectId, ObjectRecord>,
    ) -> Result<bool, PrincipalContentError> {
        let mut changed = false;
        for name in removals {
            let mutation = delete(
                *catalog,
                name,
                &mut |object| match records.get(&object) {
                    Some(record) => Ok(record.clone()),
                    None => self.load_required_for(principal, object),
                },
                &|record| self.engine.identify_object(record),
            )?;
            if mutation.previous.is_some() {
                *catalog = mutation.root;
                for (_, record) in mutation.records {
                    self.insert(records, record)?;
                }
                changed = true;
            }
        }
        Ok(changed)
    }

    pub(super) fn publish_batch(
        &self,
        principal: &P,
        source_completed: &BTreeMap<ContentName, super::PreparedContent>,
        staged_objects_inserted: u64,
        observer: Option<&std::sync::Arc<BulkPhaseObserver>>,
        deferred_records: Option<&BTreeMap<ObjectId, ObjectRecord>>,
        publication: BatchPublicationContext<'_>,
    ) -> Result<ContentBatchWriteOutcome, PrincipalContentError> {
        let (publication_completed, derived_records) = self.prepare_derived_batch(
            source_completed,
            publication.removals,
            publication.derived,
        )?;
        let completed = &publication_completed;
        loop {
            let mut header = self.header(principal)?.as_ref().clone();
            self.check_batch_expectation(principal, &header, publication.expectation)?;
            let mut catalog_records = BTreeMap::<ObjectId, ObjectRecord>::new();
            let mut changed = false;
            changed |= self.apply_batch_removals(
                principal,
                &mut header.catalog,
                publication.removals,
                &mut catalog_records,
            )?;
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
            if let Some(deferred_records) = deferred_records {
                for record in deferred_records.values() {
                    self.insert(&mut catalog_records, record.clone())?;
                }
            }
            for record in derived_records.values() {
                self.insert(&mut catalog_records, record.clone())?;
            }
            retain_final_catalog_records(catalog, &mut catalog_records);
            let transaction =
                self.encode_transaction(principal.clone(), header.clone(), None, catalog_records)?;
            let commit = match observer {
                Some(observer) => self.engine.commit_root_observed(
                    transaction,
                    std::sync::Arc::clone(observer) as std::sync::Arc<dyn ProjectionObserver>,
                ),
                None => self.engine.commit_root(transaction),
            };
            match commit {
                Ok(outcome) => {
                    self.finish_catalog_commit(principal, header, outcome.root());
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

    fn prepare_derived_batch(
        &self,
        source_completed: &BTreeMap<ContentName, super::PreparedContent>,
        removals: &[ContentName],
        derived: Option<&mut dyn PrepareDerivedBatchContent>,
    ) -> Result<PreparedDerivedBatch, PrincipalContentError> {
        let Some(derived) = derived else {
            return Ok((source_completed.clone(), BTreeMap::new()));
        };
        let descriptors = source_completed
            .iter()
            .map(|(name, prepared)| (name.clone(), prepared.verified.descriptor()))
            .collect::<BTreeMap<_, _>>();
        let (name, bytes) = derived.prepare(&descriptors)?;
        if source_completed.contains_key(&name) || removals.contains(&name) {
            return Err(PrincipalContentError::DuplicateBatchName(name));
        }
        let built = build_content(
            &EngineIdentity::<P, E>::new(self.engine.as_ref()),
            ChunkingProfile::ASTRID_V1,
            &bytes,
        )?;
        let verified = built.verified_content();
        let records = built.into_records().into_iter().collect();
        let mut completed = source_completed.clone();
        completed.insert(
            name,
            PreparedContent {
                verified,
                observation: ContentObservation::BytesObserved,
            },
        );
        Ok((completed, records))
    }
}

pub(super) fn retain_final_catalog_records(
    catalog: Option<CatalogRoot>,
    records: &mut BTreeMap<ObjectId, ObjectRecord>,
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

pub(super) fn batch_outcome(
    completed: &BTreeMap<ContentName, PreparedContent>,
    root: RootState,
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
