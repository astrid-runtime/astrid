use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::marker::PhantomData;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

use crate::content_dag::{
    BuiltContent, ChunkingProfile, ContentDescriptor, ContentError, ContentObjectSink,
    VerifiedContent, build_content, build_content_streaming, describe_content, open_content,
    read_opened_content_and_verify,
};
use crate::engine::{
    PrincipalProjectionEngine, PrincipalProjectionError, ProjectionCacheEntry, ProjectionCacheKey,
    ProjectionCachePayload, RootTransaction,
};
use crate::storage_model::{
    InsertOutcome, ModelError, ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind,
    ObjectRecord, ObjectReference, ReferenceKind, ReferenceLabel, RootState,
};
use parking_lot::Mutex;

use super::catalog::{
    CONTENT_COMPONENT_LABEL, CatalogRoot, CatalogSummary, CatalogValidation, CatalogValue,
    build_catalog, decode_legacy_catalog, delete, insert, list, list_prefix as catalog_list_prefix,
    lookup, root_from_record, validate_catalog,
};
use super::kv_projection::PrincipalKvAdapter;
use super::{
    ContentBatchExpectation, ContentEntry, ContentName, ContentReadBatchEntry, ContentWriteOutcome,
    PrincipalContentError,
};
use crate::kv::{KvQuotaResolver, KvValidationCache, validated_projection_quota};
use crate::principal_graph::{LEGACY_PRINCIPAL_GRAPH_VERSION, PRINCIPAL_GRAPH_VERSION};

const KV_COMPONENT_LABEL: &[u8] = b"kv";
const PARENT_LABEL: &[u8] = b"parent";
const STATE_LABEL: &[u8] = b"state";
// Soft write-coalescing target, not a record, file, or deployment limit.
pub(super) const STAGING_BATCH_TARGET_BYTES: usize = 4 * 1024 * 1024;
pub(super) const VERIFIED_CONTENT_CACHE_KEY: ProjectionCacheKey = ProjectionCacheKey::new(1);
pub(super) const PARTIAL_VERIFICATION_CACHE_KEY: ProjectionCacheKey = ProjectionCacheKey::new(2);
const DECODED_HEADER_CACHE_KEY: ProjectionCacheKey = ProjectionCacheKey::new(3);

fn validated_rename_sets<'a>(
    moves: &'a [(ContentName, ContentName)],
    replacements: &'a [ContentName],
) -> Option<(BTreeSet<&'a ContentName>, BTreeSet<&'a ContentName>)> {
    let sources = moves
        .iter()
        .map(|(source, _)| source)
        .collect::<BTreeSet<_>>();
    let destinations = moves
        .iter()
        .map(|(_, destination)| destination)
        .collect::<BTreeSet<_>>();
    let replacement_set = replacements.iter().collect::<BTreeSet<_>>();
    (sources.len() == moves.len()
        && destinations.len() == moves.len()
        && replacement_set.len() == replacements.len())
    .then_some((sources, replacement_set))
}

/// Named content projection over one shared principal-state engine.
pub struct PrincipalContentStore<P: Ord, E> {
    engine: Arc<E>,
    quota: Option<Arc<dyn KvQuotaResolver<P>>>,
    validated_catalogs: Arc<Mutex<BTreeMap<P, CatalogValidation>>>,
    validated_kv: Arc<KvValidationCache<P>>,
    read_leases: Arc<ContentReadLeaseRegistry<P>>,
    #[cfg(test)]
    list_invocations: AtomicU64,
}

impl<P: Ord, E> fmt::Debug for PrincipalContentStore<P, E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrincipalContentStore")
            .finish_non_exhaustive()
    }
}

impl<P, E> PrincipalContentStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    /// Convert one principal's legacy flat content catalog in place.
    ///
    /// The operation is idempotent and publishes through the ordinary
    /// principal-root compare-and-swap. It is invoked only by the ordered
    /// native-store migration while the kernel singleton lock is held.
    pub(crate) fn migrate_legacy_catalog(
        &self,
        principal: &P,
    ) -> Result<bool, PrincipalContentError> {
        loop {
            let Some(root) = self.engine.current_root(principal)? else {
                return Ok(false);
            };
            let commit = self.load_migration_graph_object(root.commit, ObjectKind::Commit)?;
            require_structural(root.commit, &commit)?;
            let state_id = owned_target(root.commit, &commit, STATE_LABEL)?;
            let state = self.load_migration_graph_object(state_id, ObjectKind::PrincipalState)?;
            require_structural(state_id, &state)?;
            let Some(content_reference) =
                state.reference(&ReferenceLabel::new(CONTENT_COMPONENT_LABEL))
            else {
                return Ok(false);
            };
            if content_reference.kind() != ReferenceKind::Owns {
                return Err(invalid(
                    state_id,
                    "principal content component is not owning",
                ));
            }
            let catalog_id = content_reference.target();
            let catalog_record = self.load_required(catalog_id)?;
            if catalog_record.format_version() != ObjectFormatVersion::V1 {
                let root = root_from_record(catalog_id, &catalog_record)?;
                let validation =
                    validate_catalog(Some(root), &mut |object| self.load_required(object))?;
                self.validated_catalogs
                    .lock()
                    .insert(principal.clone(), validation);
                return Ok(false);
            }
            let legacy = decode_legacy_catalog(catalog_id, &catalog_record)?;
            for entry in legacy.entries.values() {
                let descriptor = describe_content(
                    &EngineSource::<P, E>::new(self.engine.as_ref(), principal),
                    entry.file,
                )
                .map_err(map_read_error)?;
                if descriptor.logical_bytes() != entry.logical_bytes {
                    return Err(invalid(
                        entry.file,
                        "legacy catalog and file logical lengths disagree",
                    ));
                }
            }
            let (catalog, catalog_records) = build_catalog(&legacy.entries, &|record| {
                self.engine.identify_object(record)
            })?;
            let preserved_state = state
                .references()
                .iter()
                .filter(|reference| reference.label().as_bytes() != CONTENT_COMPONENT_LABEL)
                .cloned()
                .collect();
            let preserved_commit = commit
                .references()
                .iter()
                .filter(|reference| {
                    reference.label().as_bytes() != STATE_LABEL
                        && reference.label().as_bytes() != PARENT_LABEL
                })
                .cloned()
                .collect();
            let header = ContentHeader {
                root: Some(root),
                catalog,
                previous_catalog_quota_bytes: legacy.quota_bytes,
                other_quota_bytes: 0,
                preserved_state,
                preserved_commit,
            };
            let transaction =
                self.encode_transaction(principal.clone(), header, None, catalog_records)?;
            match self.engine.commit_root(transaction) {
                Ok(_) => {
                    self.validated_catalogs.lock().insert(
                        principal.clone(),
                        CatalogValidation {
                            root: catalog.map(|root| root.object),
                            summary: catalog.map_or(CatalogSummary::default(), |root| root.summary),
                        },
                    );
                    return Ok(true);
                },
                Err(PrincipalProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Store bytes under `name` using Astrid's pinned chunking profile.
    ///
    /// # Errors
    ///
    /// Returns a content, principal-graph, projection, or quota error without
    /// publishing a partial root.
    pub fn put(
        &self,
        principal: &P,
        name: &ContentName,
        bytes: &[u8],
    ) -> Result<ContentWriteOutcome, PrincipalContentError> {
        self.put_with_profile(principal, name, bytes, ChunkingProfile::ASTRID_V1)
    }

    /// Store bytes under `name` using an explicit persistent profile.
    ///
    /// # Errors
    ///
    /// Returns a content, principal-graph, projection, or quota error without
    /// publishing a partial root.
    pub fn put_with_profile(
        &self,
        principal: &P,
        name: &ContentName,
        bytes: &[u8],
        profile: ChunkingProfile,
    ) -> Result<ContentWriteOutcome, PrincipalContentError> {
        let built = build_content(
            &EngineIdentity::<P, E>::new(self.engine.as_ref()),
            profile,
            bytes,
        )?;
        self.publish(principal, name, built.verified_content(), Some(&built), 0)
    }

    /// Stream bytes under `name` using Astrid's pinned chunking profile.
    ///
    /// The blocking source is consumed once. Immutable content objects are
    /// staged incrementally, then the completed file is published through the
    /// ordinary principal-root compare-and-swap. Callers running on an async
    /// executor must invoke this method from a blocking worker.
    ///
    /// # Errors
    ///
    /// Returns a source, content, principal-graph, projection, or quota error
    /// without publishing a partial file.
    pub fn put_streaming<R: Read>(
        &self,
        principal: &P,
        name: &ContentName,
        source: R,
    ) -> Result<ContentWriteOutcome, PrincipalContentError> {
        self.put_streaming_with_profile(principal, name, source, ChunkingProfile::ASTRID_V1)
    }

    /// Stream bytes under `name` using an explicit persistent profile.
    ///
    /// Source failure leaves no immutable objects. Deferred records enter the
    /// engine only after quota authorization in the root transaction. Root
    /// conflicts retry only catalog publication; source bytes are not read again.
    ///
    /// # Errors
    ///
    /// Returns a source, content, principal-graph, projection, or quota error
    /// without publishing a partial file.
    pub fn put_streaming_with_profile<R: Read>(
        &self,
        principal: &P,
        name: &ContentName,
        source: R,
        profile: ChunkingProfile,
    ) -> Result<ContentWriteOutcome, PrincipalContentError> {
        if let Some((bound, limit)) = self.quota_staging_bound(principal)? {
            let (verified, records) = self.stage_deferred_bounded(source, profile, bound, limit)?;
            self.publish_deferred(principal, name, verified, &records)
        } else {
            let (verified, objects_inserted) = self.stage_streaming(source, profile)?;
            self.publish(principal, name, verified, None, objects_inserted)
        }
    }

    pub(crate) fn stage_streaming<R: Read>(
        &self,
        source: R,
        profile: ChunkingProfile,
    ) -> Result<(VerifiedContent, u64), PrincipalContentError> {
        let mut sink = EngineSink::<P, E>::new(self.engine.as_ref());
        let streamed =
            build_content_streaming(profile, source, &mut sink).map_err(map_stream_error)?;
        sink.finish()?;
        Ok((streamed.verified_content(), sink.objects_inserted))
    }

    pub(crate) fn stage_deferred<R: Read>(
        &self,
        source: R,
        profile: ChunkingProfile,
    ) -> Result<(VerifiedContent, Vec<ObjectRecord>), PrincipalContentError> {
        let mut sink = EngineSink::<P, E, _>::with_admission(
            self.engine.as_ref(),
            DeferredAdmission::default(),
        );
        let streamed =
            build_content_streaming(profile, source, &mut sink).map_err(map_stream_error)?;
        sink.finish()?;
        let records = sink.admission_mut().take_records();
        Ok((streamed.verified_content(), records))
    }

    pub(crate) fn stage_deferred_bounded<R: Read>(
        &self,
        source: R,
        profile: ChunkingProfile,
        bound: u64,
        limit: u64,
    ) -> Result<(VerifiedContent, Vec<ObjectRecord>), PrincipalContentError> {
        let probe = bound
            .checked_add(1)
            .ok_or(PrincipalContentError::AccountingOverflow)?;
        let (verified, records) = self.stage_deferred(source.take(probe), profile)?;
        if verified.descriptor().logical_bytes() > bound {
            return Err(PrincipalContentError::QuotaExceeded { used: probe, limit });
        }
        Ok((verified, records))
    }

    fn publish(
        &self,
        principal: &P,
        name: &ContentName,
        verified: VerifiedContent,
        built: Option<&BuiltContent>,
        staged_objects_inserted: u64,
    ) -> Result<ContentWriteOutcome, PrincipalContentError> {
        let descriptor = verified.descriptor();
        loop {
            let mut header = self.header(principal)?.as_ref().clone();
            let previous = self.catalog_lookup(principal, header.catalog, name)?;
            if previous.is_some_and(|entry| entry.file == descriptor.file()) {
                let root = header.root.ok_or_else(|| {
                    invalid(
                        descriptor.file(),
                        "catalog entry exists without a principal root",
                    )
                })?;
                self.mark_verified(principal, verified);
                return Ok(ContentWriteOutcome::new(
                    descriptor,
                    root,
                    staged_objects_inserted,
                ));
            }
            let mutation = insert(
                header.catalog,
                name,
                CatalogValue {
                    file: descriptor.file(),
                    logical_bytes: descriptor.logical_bytes(),
                },
                &mut |object| self.load_required_for(principal, object),
                &|record| self.engine.identify_object(record),
            )?;
            header.catalog = mutation.root;
            self.enforce_quota(principal, &header)?;
            let catalog = header.catalog;
            let transaction =
                self.encode_transaction(principal.clone(), header, built, mutation.records)?;
            match self.engine.commit_root(transaction) {
                Ok(outcome) => {
                    self.validated_catalogs.lock().insert(
                        principal.clone(),
                        CatalogValidation {
                            root: catalog.map(|root| root.object),
                            summary: catalog.map_or(CatalogSummary::default(), |root| root.summary),
                        },
                    );
                    self.mark_verified(principal, verified);
                    let objects_inserted = staged_objects_inserted
                        .checked_add(outcome.objects_inserted())
                        .ok_or(PrincipalContentError::AccountingOverflow)?;
                    return Ok(ContentWriteOutcome::new(
                        descriptor,
                        outcome.root(),
                        objects_inserted,
                    ));
                },
                Err(PrincipalProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub(crate) fn publish_deferred(
        &self,
        principal: &P,
        name: &ContentName,
        verified: VerifiedContent,
        staged_records: &[ObjectRecord],
    ) -> Result<ContentWriteOutcome, PrincipalContentError> {
        let descriptor = verified.descriptor();
        loop {
            let mut header = self.header(principal)?.as_ref().clone();
            let previous = self.catalog_lookup(principal, header.catalog, name)?;
            if previous.is_some_and(|entry| entry.file == descriptor.file()) {
                let root = header.root.ok_or_else(|| {
                    invalid(
                        descriptor.file(),
                        "catalog entry exists without a principal root",
                    )
                })?;
                self.mark_verified(principal, verified);
                return Ok(ContentWriteOutcome::new(descriptor, root, 0));
            }
            let mutation = insert(
                header.catalog,
                name,
                CatalogValue {
                    file: descriptor.file(),
                    logical_bytes: descriptor.logical_bytes(),
                },
                &mut |object| self.load_required_for(principal, object),
                &|record| self.engine.identify_object(record),
            )?;
            header.catalog = mutation.root;
            self.enforce_quota(principal, &header)?;
            let mut records = staged_records
                .iter()
                .cloned()
                .map(|record| (self.engine.identify_object(&record), record))
                .collect::<BTreeMap<_, _>>();
            for (_, record) in mutation.records {
                self.insert(&mut records, record)?;
            }
            let catalog = header.catalog;
            let transaction = self.encode_transaction(principal.clone(), header, None, records)?;
            match self.engine.commit_root(transaction) {
                Ok(outcome) => {
                    self.validated_catalogs.lock().insert(
                        principal.clone(),
                        CatalogValidation {
                            root: catalog.map(|root| root.object),
                            summary: catalog.map_or(CatalogSummary::default(), |root| root.summary),
                        },
                    );
                    self.mark_verified(principal, verified);
                    return Ok(ContentWriteOutcome::new(
                        descriptor,
                        outcome.root(),
                        outcome.objects_inserted(),
                    ));
                },
                Err(PrincipalProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Remove one named content value.
    ///
    /// Immutable chunks remain available while any authoritative root reaches
    /// them and become garbage-collection candidates otherwise.
    ///
    /// # Errors
    ///
    /// Returns a principal-graph or projection error without partially
    /// changing the catalog.
    pub fn delete(&self, principal: &P, name: &ContentName) -> Result<bool, PrincipalContentError> {
        loop {
            let mut header = self.header(principal)?.as_ref().clone();
            let mutation = delete(
                header.catalog,
                name,
                &mut |object| self.load_required_for(principal, object),
                &|record| self.engine.identify_object(record),
            )?;
            let Some(_) = mutation.previous else {
                return Ok(false);
            };
            header.catalog = mutation.root;
            let catalog = header.catalog;
            let transaction =
                self.encode_transaction(principal.clone(), header, None, mutation.records)?;
            match self.engine.commit_root(transaction) {
                Ok(_) => {
                    self.validated_catalogs.lock().insert(
                        principal.clone(),
                        CatalogValidation {
                            root: catalog.map(|root| root.object),
                            summary: catalog.map_or(CatalogSummary::default(), |root| root.summary),
                        },
                    );
                    return Ok(true);
                },
                Err(PrincipalProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Atomically remove several named content values under one owner-root
    /// compare-and-swap.
    ///
    /// Missing names are ignored. The return value is `true` when at least one
    /// name was removed. Duplicate names are rejected before any root
    /// mutation is attempted. This primitive is intentionally narrow: callers
    /// that need prefix semantics must first resolve the exact canonical names
    /// they own, then pass those names here.
    ///
    /// # Errors
    ///
    /// Returns a principal-graph or projection error without publishing a
    /// partial deletion.
    pub fn delete_batch(
        &self,
        principal: &P,
        names: &[ContentName],
    ) -> Result<bool, PrincipalContentError> {
        self.delete_batch_if(principal, names, &ContentBatchExpectation::Any)
    }

    /// Atomically remove several names only when their current object IDs
    /// satisfy `expectation`.
    ///
    /// # Errors
    ///
    /// Returns a duplicate-name, precondition, graph, or projection error
    /// without publishing a partial deletion.
    pub fn delete_batch_if(
        &self,
        principal: &P,
        names: &[ContentName],
        expectation: &ContentBatchExpectation,
    ) -> Result<bool, PrincipalContentError> {
        if names.is_empty() {
            return Ok(false);
        }
        let mut unique = BTreeSet::new();
        for name in names {
            if !unique.insert(name) {
                return Err(PrincipalContentError::DuplicateBatchName(name.clone()));
            }
        }
        loop {
            let mut header = self.header(principal)?.as_ref().clone();
            self.check_batch_expectation(principal, &header, Some(expectation))?;
            let mut records = BTreeMap::<ObjectId, ObjectRecord>::new();
            let mut changed = false;
            for name in names {
                let mutation = delete(
                    header.catalog,
                    name,
                    &mut |object| match records.get(&object) {
                        Some(record) => Ok(record.clone()),
                        None => self.load_required_for(principal, object),
                    },
                    &|record| self.engine.identify_object(record),
                )?;
                let Some(_) = mutation.previous else {
                    continue;
                };
                changed = true;
                header.catalog = mutation.root;
                records.extend(mutation.records);
            }
            if !changed {
                return Ok(false);
            }
            let catalog = header.catalog;
            let transaction = self.encode_transaction(principal.clone(), header, None, records)?;
            match self.engine.commit_root(transaction) {
                Ok(_) => {
                    self.validated_catalogs.lock().insert(
                        principal.clone(),
                        CatalogValidation {
                            root: catalog.map(|root| root.object),
                            summary: catalog.map_or(CatalogSummary::default(), |root| root.summary),
                        },
                    );
                    return Ok(true);
                },
                Err(PrincipalProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Atomically rename exact catalog names without reconstructing file bytes.
    ///
    /// Every source must exist, destinations must be unique, and a destination
    /// may not exist unless it is also one of the supplied sources. Validation
    /// and publication occur against the same owner-root generation; root
    /// conflicts retry the complete move from a fresh snapshot.
    ///
    /// # Errors
    ///
    /// Returns a projection, quota, or validation error. `Ok(false)` means the
    /// source/destination preconditions did not hold and no root was published.
    pub fn rename_batch(
        &self,
        principal: &P,
        moves: &[(ContentName, ContentName)],
    ) -> Result<bool, PrincipalContentError> {
        self.rename_batch_replacing(principal, moves, &[])
    }

    /// Atomically rename exact catalog names and remove admitted destinations.
    ///
    /// `replacements` are deleted in the same owner-root transition before
    /// the moved values are inserted. Callers must perform filesystem type and
    /// empty-directory checks before admitting replacement names.
    ///
    /// # Errors
    ///
    /// Returns a principal-graph, projection, or quota error without partially
    /// changing the catalog.
    pub fn rename_batch_replacing(
        &self,
        principal: &P,
        moves: &[(ContentName, ContentName)],
        replacements: &[ContentName],
    ) -> Result<bool, PrincipalContentError> {
        if moves.is_empty() {
            return Ok(true);
        }
        let Some((sources, replacements)) = validated_rename_sets(moves, replacements) else {
            return Ok(false);
        };
        loop {
            let mut header = self.header(principal)?.as_ref().clone();
            let mut values = Vec::with_capacity(moves.len());
            for (source, destination) in moves {
                let Some(value) = self.catalog_lookup(principal, header.catalog, source)? else {
                    return Ok(false);
                };
                if !sources.contains(destination)
                    && !replacements.contains(destination)
                    && self
                        .catalog_lookup(principal, header.catalog, destination)?
                        .is_some()
                {
                    return Ok(false);
                }
                values.push(value);
            }

            let mut records = BTreeMap::<ObjectId, ObjectRecord>::new();
            for (source, _) in moves {
                let mutation = delete(
                    header.catalog,
                    source,
                    &mut |object| match records.get(&object) {
                        Some(record) => Ok(record.clone()),
                        None => self.load_required_for(principal, object),
                    },
                    &|record| self.engine.identify_object(record),
                )?;
                if mutation.previous.is_none() {
                    return Ok(false);
                }
                header.catalog = mutation.root;
                records.extend(mutation.records);
            }
            for replacement in &replacements {
                if sources.contains(replacement) {
                    continue;
                }
                let mutation = delete(
                    header.catalog,
                    replacement,
                    &mut |object| match records.get(&object) {
                        Some(record) => Ok(record.clone()),
                        None => self.load_required_for(principal, object),
                    },
                    &|record| self.engine.identify_object(record),
                )?;
                if mutation.previous.is_none() {
                    return Ok(false);
                }
                header.catalog = mutation.root;
                records.extend(mutation.records);
            }
            for ((_, destination), value) in moves.iter().zip(values) {
                let mutation = insert(
                    header.catalog,
                    destination,
                    value,
                    &mut |object| match records.get(&object) {
                        Some(record) => Ok(record.clone()),
                        None => self.load_required_for(principal, object),
                    },
                    &|record| self.engine.identify_object(record),
                )?;
                if mutation.previous.is_some() {
                    return Ok(false);
                }
                header.catalog = mutation.root;
                records.extend(mutation.records);
            }
            self.enforce_quota(principal, &header)?;
            let catalog = header.catalog;
            let transaction = self.encode_transaction(principal.clone(), header, None, records)?;
            match self.engine.commit_root(transaction) {
                Ok(_) => {
                    self.validated_catalogs.lock().insert(
                        principal.clone(),
                        CatalogValidation {
                            root: catalog.map(|root| root.object),
                            summary: catalog.map_or(CatalogSummary::default(), |root| root.summary),
                        },
                    );
                    return Ok(true);
                },
                Err(PrincipalProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// List a principal's named content in canonical byte order.
    ///
    /// # Errors
    ///
    /// Returns a principal-graph or projection error when the authoritative
    /// catalog cannot be decoded.
    pub fn list(&self, principal: &P) -> Result<Vec<ContentEntry>, PrincipalContentError> {
        #[cfg(test)]
        self.list_invocations.fetch_add(1, Ordering::Relaxed);
        let header = self.header(principal)?;
        list(header.catalog, &mut |object| {
            self.load_required_for(principal, object)
        })
    }

    /// List names beginning with an explicit catalog prefix.
    ///
    /// Prefix matching is performed on canonical catalog names and does not
    /// interpret path traversal or host separators. Callers that own a
    /// reserved component (such as `capsules/`) should use this method instead
    /// of exposing the entire owner catalog to discovery code.
    ///
    /// # Errors
    ///
    /// Returns a principal graph or projection error when the owner catalog
    /// cannot be decoded.
    pub fn list_prefix(
        &self,
        principal: &P,
        prefix: &str,
    ) -> Result<Vec<ContentEntry>, PrincipalContentError> {
        if prefix.is_empty() {
            return self.list(principal);
        }
        let prefix =
            ContentName::new(prefix.to_owned()).map_err(PrincipalContentError::InvalidName)?;
        let header = self.header(principal)?;
        catalog_list_prefix(header.catalog, &prefix, &mut |object| {
            self.load_required_for(principal, object)
        })
    }

    /// Describe one named value without reading its chunks.
    ///
    /// # Errors
    ///
    /// Returns a content, principal-graph, or projection error when metadata
    /// is missing or invalid.
    pub fn describe(
        &self,
        principal: &P,
        name: &ContentName,
    ) -> Result<Option<ContentDescriptor>, PrincipalContentError> {
        self.open_read(principal, name)
            .map(|handle| handle.map(|handle| handle.descriptor()))
    }

    /// Open one named value for repeated verified reads.
    ///
    /// The principal root, catalog entry, and canonical file descriptor are
    /// resolved once. The resulting handle continues to address that immutable
    /// generation when the same catalog name is later replaced or deleted. A
    /// compaction caller that does not retain a `ReadHandle` root may collect
    /// the old closure; subsequent reads then fail with
    /// [`ContentError::MissingObject`] rather than returning newer bytes.
    ///
    /// # Errors
    ///
    /// Returns a content, principal-graph, or projection error when metadata
    /// is missing or invalid.
    pub fn open_read(
        &self,
        principal: &P,
        name: &ContentName,
    ) -> Result<Option<PrincipalContentReadHandle<P, E>>, PrincipalContentError> {
        let header = self.header(principal)?;
        let Some(entry) = self.catalog_lookup(principal, header.catalog, name)? else {
            return Ok(None);
        };
        let root = header
            .root
            .ok_or_else(|| invalid(entry.file, "catalog entry exists without a principal root"))?;
        let verified = self
            .engine
            .load_projection_cache(principal, entry.file, VERIFIED_CONTENT_CACHE_KEY)
            .and_then(|entry| entry.downcast::<CachedVerifiedContent>())
            .map(|verified| verified.0);
        let opened = match verified {
            Some(verified) => verified.opened_content(),
            None => open_content(
                &EngineSource::<P, E>::new(self.engine.as_ref(), principal),
                entry.file,
            )
            .map_err(map_read_error)?,
        };
        let descriptor = opened.descriptor();
        if descriptor.logical_bytes() != entry.logical_bytes {
            return Err(invalid(
                entry.file,
                "catalog and file logical lengths disagree",
            ));
        }
        let lease = self.read_leases.register(principal.clone(), entry.file);
        Ok(Some(PrincipalContentReadHandle {
            engine: Arc::clone(&self.engine),
            opened,
            principal: principal.clone(),
            principal_root: root,
            _lease: lease,
        }))
    }

    /// Return immutable file roots held by currently open read handles.
    ///
    /// The returned roots are a point-in-time snapshot for a compaction
    /// retention plan. Handles opened or dropped after capture are covered by
    /// the engine fence recheck; a stale plan fails closed.
    pub(crate) fn compaction_read_handle_roots(&self) -> Vec<(P, ObjectId)> {
        self.read_leases.roots()
    }

    /// Reconstruct one complete named value.
    ///
    /// # Errors
    ///
    /// Returns a content, principal-graph, projection, range, or allocation
    /// error when the value cannot be reconstructed exactly.
    pub fn read(
        &self,
        principal: &P,
        name: &ContentName,
    ) -> Result<Option<Vec<u8>>, PrincipalContentError> {
        let Some(handle) = self.open_read(principal, name)? else {
            return Ok(None);
        };
        handle.read().map(Some)
    }

    /// Read several names from one immutable owner-root snapshot.
    ///
    /// Each returned descriptor and byte vector is tied to the same decoded
    /// catalog header. Callers can use the descriptors as a conditional batch
    /// expectation without a preflight race between separate reads.
    ///
    /// # Errors
    ///
    /// Returns a content, graph, projection, or verification error without
    /// returning partial results.
    pub fn read_batch(
        &self,
        principal: &P,
        names: &[ContentName],
    ) -> Result<Vec<Option<ContentReadBatchEntry>>, PrincipalContentError> {
        let header = self.header(principal)?;
        let source = EngineSource::<P, E>::new(self.engine.as_ref(), principal);
        let mut result = Vec::with_capacity(names.len());
        for name in names {
            let Some(entry) = self.catalog_lookup(principal, header.catalog, name)? else {
                result.push(None);
                continue;
            };
            let opened = open_content(&source, entry.file).map_err(map_read_error)?;
            let descriptor = opened.descriptor();
            if descriptor.logical_bytes() != entry.logical_bytes {
                return Err(invalid(
                    entry.file,
                    "catalog and file logical lengths disagree",
                ));
            }
            let (bytes, verified) =
                read_opened_content_and_verify(&source, opened).map_err(map_read_error)?;
            self.mark_verified(principal, verified);
            result.push(Some(ContentReadBatchEntry { descriptor, bytes }));
        }
        Ok(result)
    }

    /// Reconstruct an exact range of one named value.
    ///
    /// # Errors
    ///
    /// Returns a content, principal-graph, projection, range, or allocation
    /// error when the requested bytes cannot be reconstructed exactly.
    pub fn read_range(
        &self,
        principal: &P,
        name: &ContentName,
        offset: u64,
        length: u64,
    ) -> Result<Option<Vec<u8>>, PrincipalContentError> {
        let Some(handle) = self.open_read(principal, name)? else {
            return Ok(None);
        };
        handle.read_range(offset, length).map(Some)
    }

    /// Flush authoritative object and root records.
    ///
    /// # Errors
    ///
    /// Returns a projection error when durable state cannot be flushed.
    pub fn flush(&self) -> Result<(), PrincipalContentError> {
        self.engine.flush_projection().map_err(Into::into)
    }

    fn mark_verified(&self, principal: &P, verified: VerifiedContent) {
        let file = verified.descriptor().file();
        let _ = self.engine.load_shared_object_for(principal, file);
        let _ =
            self.engine
                .discard_projection_cache(principal, file, PARTIAL_VERIFICATION_CACHE_KEY);
        let _ = self.engine.retain_projection_cache(
            principal,
            file,
            VERIFIED_CONTENT_CACHE_KEY,
            ProjectionCacheEntry::new(CachedVerifiedContent(verified)),
        );
    }

    fn header(&self, principal: &P) -> Result<Arc<ContentHeader>, PrincipalContentError> {
        let root = self.engine.current_root(principal)?;
        if let Some(root) = root
            && let Some(header) = self
                .engine
                .load_projection_cache(principal, root.commit, DECODED_HEADER_CACHE_KEY)
                .and_then(|entry| entry.downcast::<ContentHeader>())
            && header.root == Some(root)
        {
            return Ok(header);
        }
        let header = self.decode_header(principal, root)?;
        let Some(root) = root else {
            return Ok(Arc::new(header));
        };
        if self.engine.retain_projection_cache(
            principal,
            root.commit,
            DECODED_HEADER_CACHE_KEY,
            ProjectionCacheEntry::new(header.clone()),
        ) && let Some(retained) = self
            .engine
            .load_projection_cache(principal, root.commit, DECODED_HEADER_CACHE_KEY)
            .and_then(|entry| entry.downcast::<ContentHeader>())
        {
            return Ok(retained);
        }
        Ok(Arc::new(header))
    }
}

mod bulk;
mod constructors;
mod internals;
mod native;
mod projection;
mod read_handle;
mod workspace;

use read_handle::ContentReadLeaseRegistry;
pub use read_handle::PrincipalContentReadHandle;

use projection::{
    CachedVerifiedContent, ContentHeader, DeferredAdmission, EngineIdentity, EngineSink,
    EngineSource, invalid, map_read_error, map_stream_error, owned_target, require_structural,
};

pub use workspace::{
    WorkspaceBindingLifecycle, WorkspaceBranchBinding, WorkspaceBranchDescriptor,
    WorkspaceBranchError, WorkspaceBranchStore, WorkspaceFilesystem, WorkspaceUid,
};
pub(crate) use workspace::{is_workspace_branch_label, workspace_branch_quota_from_loader};
