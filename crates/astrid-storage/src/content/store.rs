use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::marker::PhantomData;
use std::sync::Arc;

use astrid_storage_content::{
    BuiltContent, ChunkingProfile, ContentDescriptor, ContentError, ContentObjectSink,
    ContentReadError, ContentSource, ContentStreamError, ContentVerificationState, OpenedContent,
    VerifiedContent, build_content, build_content_streaming, describe_content, open_content,
    read_opened_content_and_verify, read_opened_content_range_with_verification,
    read_verified_content, read_verified_content_range,
};
use astrid_storage_engine::{
    PrincipalProjectionEngine, PrincipalProjectionError, ProjectionCacheEntry, ProjectionCacheKey,
    ProjectionCachePayload, RootTransaction,
};
use astrid_storage_model::{
    InsertOutcome, ModelError, ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind,
    ObjectRecord, ObjectReference, ReferenceKind, ReferenceLabel, RootState,
};
use parking_lot::Mutex;

use super::catalog::{
    CONTENT_COMPONENT_LABEL, CatalogRoot, CatalogSummary, CatalogValidation, CatalogValue,
    build_catalog, decode_legacy_catalog, delete, insert, list, lookup, root_from_record,
    validate_catalog,
};
use super::kv_projection::PrincipalKvAdapter;
use super::{ContentEntry, ContentName, ContentWriteOutcome, PrincipalContentError};
use crate::kv::{KvQuotaResolver, KvValidationCache, validated_projection_quota};
use crate::principal_graph::{LEGACY_PRINCIPAL_GRAPH_VERSION, PRINCIPAL_GRAPH_VERSION};

const KV_COMPONENT_LABEL: &[u8] = b"kv";
const PARENT_LABEL: &[u8] = b"parent";
const STATE_LABEL: &[u8] = b"state";
// Soft write-coalescing target, not a record, file, or deployment limit.
pub(super) const STAGING_BATCH_TARGET_BYTES: usize = 4 * 1024 * 1024;
const VERIFIED_CONTENT_CACHE_KEY: ProjectionCacheKey = ProjectionCacheKey::new(1);
const PARTIAL_VERIFICATION_CACHE_KEY: ProjectionCacheKey = ProjectionCacheKey::new(2);
const DECODED_HEADER_CACHE_KEY: ProjectionCacheKey = ProjectionCacheKey::new(3);

/// Named content projection over one shared principal-state engine.
pub struct PrincipalContentStore<P: Ord, E> {
    engine: Arc<E>,
    quota: Option<Arc<dyn KvQuotaResolver<P>>>,
    validated_catalogs: Arc<Mutex<BTreeMap<P, CatalogValidation>>>,
    validated_kv: Arc<KvValidationCache<P>>,
}

/// Principal-scoped immutable content handle for repeated verified reads.
///
/// The handle captures the root generation and decoded file descriptor that
/// authorized the open. Later catalog changes do not retarget an existing
/// handle. A compaction caller must retain the descriptor's closure as a
/// `ReadHandle` root while it promises continued readability. Without that
/// lease, collecting the closure makes later reads fail with
/// [`ContentError::MissingObject`]; a handle never retargets to newer bytes.
pub struct PrincipalContentReadHandle<P: Ord, E> {
    engine: Arc<E>,
    opened: OpenedContent,
    principal: P,
    principal_root: RootState,
}

impl<P: Ord, E> fmt::Debug for PrincipalContentReadHandle<P, E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrincipalContentReadHandle")
            .field("descriptor", &self.opened.descriptor())
            .field("principal_root", &self.principal_root)
            .finish_non_exhaustive()
    }
}

impl<P, E> PrincipalContentReadHandle<P, E>
where
    P: Clone + Ord,
    E: PrincipalProjectionEngine<P>,
{
    /// Return the immutable descriptor validated when the handle was opened.
    #[must_use]
    pub const fn descriptor(&self) -> ContentDescriptor {
        self.opened.descriptor()
    }

    /// Return the principal root generation that authorized this handle.
    #[must_use]
    pub const fn principal_root(&self) -> RootState {
        self.principal_root
    }

    /// Reconstruct the complete opened value.
    ///
    /// # Errors
    ///
    /// Returns a content or projection error when verification or allocation
    /// fails. This includes [`ContentError::MissingObject`] if a compaction
    /// caller allowed the opened closure to be collected.
    pub fn read(&self) -> Result<Vec<u8>, PrincipalContentError> {
        let source = EngineSource::<P, E>::new(self.engine.as_ref(), &self.principal);
        if let Some(verified) = self.verified() {
            return read_verified_content(&source, verified).map_err(map_read_error);
        }
        let (bytes, verified) =
            read_opened_content_and_verify(&source, self.opened).map_err(map_read_error)?;
        self.mark_verified(verified);
        Ok(bytes)
    }

    /// Reconstruct an exact range of the opened value.
    ///
    /// # Errors
    ///
    /// Returns a content, projection, range, or allocation error when the
    /// requested bytes cannot be reconstructed exactly. This includes
    /// [`ContentError::MissingObject`] if a compaction caller allowed the
    /// opened closure to be collected.
    pub fn read_range(&self, offset: u64, length: u64) -> Result<Vec<u8>, PrincipalContentError> {
        let source = EngineSource::<P, E>::new(self.engine.as_ref(), &self.principal);
        if let Some(verified) = self.verified() {
            return read_verified_content_range(&source, verified, offset, length)
                .map_err(map_read_error);
        }
        let file = self.opened.descriptor().file();
        let known = self
            .engine
            .load_projection_cache(&self.principal, file, PARTIAL_VERIFICATION_CACHE_KEY)
            .and_then(|entry| entry.downcast::<CachedPartialVerification>());
        let empty = ContentVerificationState::default();
        let (bytes, delta) = read_opened_content_range_with_verification(
            &source,
            self.opened,
            known.as_deref().map_or(&empty, |known| &known.0),
            offset,
            length,
        )
        .map_err(map_read_error)?;
        if !delta.is_empty() {
            let mut next = known
                .as_deref()
                .map_or_else(ContentVerificationState::default, |known| known.0.clone());
            next.merge(delta);
            let _ = self.engine.retain_projection_cache(
                &self.principal,
                file,
                PARTIAL_VERIFICATION_CACHE_KEY,
                ProjectionCacheEntry::new(CachedPartialVerification(next)),
            );
        }
        Ok(bytes)
    }

    fn verified(&self) -> Option<VerifiedContent> {
        self.engine
            .load_projection_cache(
                &self.principal,
                self.opened.descriptor().file(),
                VERIFIED_CONTENT_CACHE_KEY,
            )
            .and_then(|entry| entry.downcast::<CachedVerifiedContent>())
            .map(|verified| verified.0)
    }

    fn mark_verified(&self, verified: VerifiedContent) {
        let file = verified.descriptor().file();
        let _ = self.engine.discard_projection_cache(
            &self.principal,
            file,
            PARTIAL_VERIFICATION_CACHE_KEY,
        );
        let _ = self.engine.retain_projection_cache(
            &self.principal,
            file,
            VERIFIED_CONTENT_CACHE_KEY,
            ProjectionCacheEntry::new(CachedVerifiedContent(verified)),
        );
    }
}

impl<P: Ord, E> PrincipalContentStore<P, E> {
    /// Construct with live principal quota resolution.
    #[must_use]
    pub fn from_engine_with_quota(engine: Arc<E>, quota: Arc<dyn KvQuotaResolver<P>>) -> Self {
        Self {
            engine,
            quota: Some(quota),
            validated_catalogs: Arc::new(Mutex::new(BTreeMap::new())),
            validated_kv: Arc::new(KvValidationCache::default()),
        }
    }

    pub(crate) fn from_engine_with_quota_and_validation(
        engine: Arc<E>,
        quota: Arc<dyn KvQuotaResolver<P>>,
        validated_catalogs: Arc<Mutex<BTreeMap<P, CatalogValidation>>>,
        validated_kv: Arc<KvValidationCache<P>>,
    ) -> Self {
        Self {
            engine,
            quota: Some(quota),
            validated_catalogs,
            validated_kv,
        }
    }

    pub(crate) fn from_engine_with_validation(
        engine: Arc<E>,
        validated_catalogs: Arc<Mutex<BTreeMap<P, CatalogValidation>>>,
    ) -> Self {
        Self {
            engine,
            quota: None,
            validated_catalogs,
            validated_kv: Arc::new(KvValidationCache::default()),
        }
    }

    #[cfg(test)]
    pub(crate) fn validated_catalog_count(&self) -> usize {
        self.validated_catalogs.lock().len()
    }
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
    /// Source or staging failure may leave unreachable immutable objects for
    /// compaction, but no principal root can observe them. Root conflicts
    /// retry only catalog publication; source bytes are not read again.
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
        let mut sink = EngineSink::<P, E>::new(self.engine.as_ref());
        let streamed =
            build_content_streaming(profile, source, &mut sink).map_err(map_stream_error)?;
        sink.finish()?;
        self.publish(
            principal,
            name,
            streamed.verified_content(),
            None,
            sink.objects_inserted,
        )
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

    /// List a principal's named content in canonical byte order.
    ///
    /// # Errors
    ///
    /// Returns a principal-graph or projection error when the authoritative
    /// catalog cannot be decoded.
    pub fn list(&self, principal: &P) -> Result<Vec<ContentEntry>, PrincipalContentError> {
        let header = self.header(principal)?;
        list(header.catalog, &mut |object| {
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
        Ok(Some(PrincipalContentReadHandle {
            engine: Arc::clone(&self.engine),
            opened,
            principal: principal.clone(),
            principal_root: root,
        }))
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

    fn decode_header(
        &self,
        principal: &P,
        root: Option<RootState>,
    ) -> Result<ContentHeader, PrincipalContentError> {
        let Some(root) = root else {
            return Ok(ContentHeader::empty());
        };
        let commit = self.load_typed(
            principal,
            root.commit,
            ObjectKind::Commit,
            PRINCIPAL_GRAPH_VERSION,
        )?;
        require_structural(root.commit, &commit)?;
        let state_id = owned_target(root.commit, &commit, STATE_LABEL)?;
        let state = self.load_typed(
            principal,
            state_id,
            ObjectKind::PrincipalState,
            PRINCIPAL_GRAPH_VERSION,
        )?;
        require_structural(state_id, &state)?;

        let mut catalog = None;
        let mut other_quota_bytes = 0_u64;
        let mut preserved_state = Vec::new();
        for reference in state.references() {
            if reference.kind() != ReferenceKind::Owns {
                return Err(invalid(state_id, "principal component is not owning"));
            }
            match reference.label().as_bytes() {
                CONTENT_COMPONENT_LABEL => {
                    let record = self
                        .engine
                        .load_object_for(principal, reference.target())?
                        .ok_or_else(|| ContentError::MissingObject(reference.target()))?;
                    let root = root_from_record(reference.target(), &record)?;
                    let cached = self
                        .validated_catalogs
                        .lock()
                        .get(principal)
                        .copied()
                        .filter(|validation| validation.root == Some(root.object));
                    let validation = if let Some(validation) = cached {
                        validation
                    } else {
                        let validation = validate_catalog(Some(root), &mut |object| {
                            self.load_required_for(principal, object)
                        })?;
                        self.validated_catalogs
                            .lock()
                            .insert(principal.clone(), validation);
                        validation
                    };
                    if validation.summary != root.summary {
                        return Err(invalid(
                            root.object,
                            "content catalog validation totals disagree",
                        ));
                    }
                    catalog = Some(root);
                },
                KV_COMPONENT_LABEL => {
                    other_quota_bytes = other_quota_bytes
                        .checked_add(self.kv_quota(principal, reference.target())?)
                        .ok_or(PrincipalContentError::AccountingOverflow)?;
                    preserved_state.push(reference.clone());
                },
                _ => {
                    preserved_state.push(reference.clone());
                },
            }
        }
        let preserved_commit = commit
            .references()
            .iter()
            .filter(|reference| {
                reference.label().as_bytes() != STATE_LABEL
                    && reference.label().as_bytes() != PARENT_LABEL
            })
            .cloned()
            .collect();
        Ok(ContentHeader {
            root: Some(root),
            previous_catalog_quota_bytes: catalog.map_or(0, |root| root.summary.quota_bytes),
            catalog,
            other_quota_bytes,
            preserved_state,
            preserved_commit,
        })
    }

    fn kv_quota(&self, principal: &P, object: ObjectId) -> Result<u64, PrincipalContentError> {
        validated_projection_quota(
            &PrincipalKvAdapter::new(self.engine.as_ref()),
            principal,
            object,
            self.validated_kv.as_ref(),
        )
        .map_err(|_| invalid(object, "invalid KV component accounting"))
    }

    fn load_typed(
        &self,
        principal: &P,
        object: ObjectId,
        kind: ObjectKind,
        version: ObjectFormatVersion,
    ) -> Result<ObjectRecord, PrincipalContentError> {
        let record = self
            .engine
            .load_object_for(principal, object)?
            .ok_or(ContentError::MissingObject(object))?;
        if record.kind() != kind || record.format_version() != version {
            return Err(invalid(
                object,
                "principal object has wrong kind or version",
            ));
        }
        Ok(record)
    }

    fn load_migration_graph_object(
        &self,
        object: ObjectId,
        kind: ObjectKind,
    ) -> Result<ObjectRecord, PrincipalContentError> {
        let record = self
            .engine
            .load_object(object)?
            .ok_or(ContentError::MissingObject(object))?;
        if record.kind() != kind
            || (record.format_version() != PRINCIPAL_GRAPH_VERSION
                && record.format_version() != LEGACY_PRINCIPAL_GRAPH_VERSION)
        {
            return Err(invalid(
                object,
                "principal migration object has wrong kind or version",
            ));
        }
        Ok(record)
    }

    fn enforce_quota(
        &self,
        principal: &P,
        header: &ContentHeader,
    ) -> Result<(), PrincipalContentError> {
        let Some(quota) = &self.quota else {
            return Ok(());
        };
        let Some(limit) = quota
            .max_logical_bytes(principal)
            .map_err(PrincipalContentError::QuotaPolicy)?
        else {
            return Ok(());
        };
        let used = header
            .other_quota_bytes
            .checked_add(header.catalog.map_or(0, |root| root.summary.quota_bytes))
            .ok_or(PrincipalContentError::AccountingOverflow)?;
        let previous = header
            .other_quota_bytes
            .checked_add(header.previous_catalog_quota_bytes)
            .ok_or(PrincipalContentError::AccountingOverflow)?;
        if used > limit && used > previous {
            return Err(PrincipalContentError::QuotaExceeded { used, limit });
        }
        Ok(())
    }

    fn encode_transaction(
        &self,
        principal: P,
        header: ContentHeader,
        built: Option<&BuiltContent>,
        catalog_records: BTreeMap<ObjectId, ObjectRecord>,
    ) -> Result<RootTransaction<P>, PrincipalContentError> {
        let mut records: BTreeMap<ObjectId, ObjectRecord> = built
            .map(|built| built.records().iter().cloned().collect())
            .unwrap_or_default();
        for (_, record) in catalog_records {
            self.insert(&mut records, record)?;
        }
        let mut state_references = header.preserved_state;
        if let Some(catalog) = header.catalog {
            state_references.push(ObjectReference::owns(
                ReferenceLabel::new(CONTENT_COMPONENT_LABEL.to_vec()),
                catalog.object,
            ));
        }
        state_references.sort();
        let state = ObjectRecord::new(
            ObjectKind::PrincipalState,
            PRINCIPAL_GRAPH_VERSION,
            Vec::new(),
            state_references,
            0,
            ObjectClass::Metadata,
        )
        .map_err(PrincipalProjectionError::Model)?;
        let state = self.insert(&mut records, state)?;

        let mut commit_references = header.preserved_commit;
        if let Some(previous) = header.root {
            commit_references.push(ObjectReference::new(
                ReferenceLabel::new(PARENT_LABEL.to_vec()),
                previous.commit,
                ReferenceKind::Lineage,
            ));
        }
        commit_references.push(ObjectReference::owns(
            ReferenceLabel::new(STATE_LABEL.to_vec()),
            state,
        ));
        commit_references.sort();
        let commit = ObjectRecord::new(
            ObjectKind::Commit,
            PRINCIPAL_GRAPH_VERSION,
            Vec::new(),
            commit_references,
            0,
            ObjectClass::Metadata,
        )
        .map_err(PrincipalProjectionError::Model)?;
        let commit = self.insert(&mut records, commit)?;
        Ok(RootTransaction::new(
            principal,
            header.root,
            commit,
            records.into_iter().collect(),
        ))
    }

    fn catalog_lookup(
        &self,
        principal: &P,
        root: Option<CatalogRoot>,
        name: &ContentName,
    ) -> Result<Option<CatalogValue>, PrincipalContentError> {
        lookup(root, name, &mut |object| {
            self.load_required_for(principal, object)
        })
    }

    fn load_required(&self, object: ObjectId) -> Result<ObjectRecord, PrincipalContentError> {
        self.engine
            .load_object(object)?
            .ok_or_else(|| ContentError::MissingObject(object).into())
    }

    fn load_required_for(
        &self,
        principal: &P,
        object: ObjectId,
    ) -> Result<ObjectRecord, PrincipalContentError> {
        self.engine
            .load_object_for(principal, object)?
            .ok_or_else(|| ContentError::MissingObject(object).into())
    }

    fn insert(
        &self,
        records: &mut BTreeMap<ObjectId, ObjectRecord>,
        record: ObjectRecord,
    ) -> Result<ObjectId, PrincipalContentError> {
        let id = self.engine.identify_object(&record);
        match records.get(&id) {
            Some(existing) if existing == &record => {},
            Some(_) => {
                return Err(
                    PrincipalProjectionError::Model(ModelError::ObjectCollision(id)).into(),
                );
            },
            None => {
                records.insert(id, record);
            },
        }
        Ok(id)
    }
}

mod bulk;
mod native;
mod projection;

use projection::{
    CachedPartialVerification, CachedVerifiedContent, ContentHeader, EngineIdentity, EngineSink,
    EngineSource, invalid, map_read_error, map_stream_error, owned_target, require_structural,
};
