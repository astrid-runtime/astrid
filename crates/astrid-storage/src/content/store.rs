use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::marker::PhantomData;
use std::sync::Arc;

use astrid_storage_content::{
    BuiltContent, ChunkingProfile, ContentDescriptor, ContentError, ContentObjectSink,
    ContentReadError, ContentSource, ContentStreamError, build_content, build_content_streaming,
    describe_content, read_content, read_content_range,
};
use astrid_storage_engine::{PrincipalProjectionEngine, PrincipalProjectionError, RootTransaction};
use astrid_storage_model::{
    InsertOutcome, ModelError, ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind,
    ObjectRecord, ObjectReference, ReferenceKind, ReferenceLabel, RootState,
};

use super::catalog::{
    CONTENT_COMPONENT_LABEL, Catalog, CatalogValue, decode_catalog, encode_catalog,
};
use super::{ContentEntry, ContentName, ContentWriteOutcome, PrincipalContentError};
use crate::kv::KvQuotaResolver;

const KV_COMPONENT_LABEL: &[u8] = b"kv";
const PARENT_LABEL: &[u8] = b"parent";
const STATE_LABEL: &[u8] = b"state";
// Soft write-coalescing target, not a record, file, or deployment limit.
const STAGING_BATCH_TARGET_BYTES: usize = 4 * 1024 * 1024;
const PRINCIPAL_GRAPH_VERSION: ObjectFormatVersion = match ObjectFormatVersion::new(3) {
    Some(version) => version,
    None => unreachable!(),
};

/// Named content projection over one shared principal-state engine.
pub struct PrincipalContentStore<P: Ord, E> {
    engine: Arc<E>,
    quota: Option<Arc<dyn KvQuotaResolver<P>>>,
}

impl<P: Ord, E> PrincipalContentStore<P, E> {
    /// Construct without a principal-specific quota.
    #[must_use]
    pub const fn from_engine(engine: Arc<E>) -> Self {
        Self {
            engine,
            quota: None,
        }
    }

    /// Construct with live principal quota resolution.
    #[must_use]
    pub fn from_engine_with_quota(engine: Arc<E>, quota: Arc<dyn KvQuotaResolver<P>>) -> Self {
        Self {
            engine,
            quota: Some(quota),
        }
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
        self.publish(principal, name, built.descriptor(), Some(&built), 0)
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
            streamed.descriptor(),
            None,
            sink.objects_inserted,
        )
    }

    fn publish(
        &self,
        principal: &P,
        name: &ContentName,
        descriptor: ContentDescriptor,
        built: Option<&BuiltContent>,
        staged_objects_inserted: u64,
    ) -> Result<ContentWriteOutcome, PrincipalContentError> {
        loop {
            let mut header = self.header(principal.clone())?;
            if header
                .catalog
                .entries
                .get(name)
                .is_some_and(|entry| entry.file == descriptor.file())
            {
                let root = header.root.ok_or_else(|| {
                    invalid(
                        descriptor.file(),
                        "catalog entry exists without a principal root",
                    )
                })?;
                return Ok(ContentWriteOutcome::new(descriptor, root, 0));
            }
            header.catalog.insert(
                name.clone(),
                CatalogValue {
                    file: descriptor.file(),
                    logical_bytes: descriptor.logical_bytes(),
                },
            )?;
            self.enforce_quota(principal, &header)?;
            let transaction = self.encode_transaction(header, built)?;
            match self.engine.commit_root(transaction) {
                Ok(outcome) => {
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
            let mut header = self.header(principal.clone())?;
            if header.catalog.remove(name)?.is_none() {
                return Ok(false);
            }
            let transaction = self.encode_transaction(header, None)?;
            match self.engine.commit_root(transaction) {
                Ok(_) => return Ok(true),
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
        self.header(principal.clone())
            .map(|header| header.catalog.list())
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
        let header = self.header(principal.clone())?;
        let Some(entry) = header.catalog.entries.get(name) else {
            return Ok(None);
        };
        let descriptor =
            describe_content(&EngineSource::<P, E>::new(self.engine.as_ref()), entry.file)
                .map_err(map_read_error)?;
        if descriptor.logical_bytes() != entry.logical_bytes {
            return Err(invalid(
                entry.file,
                "catalog and file logical lengths disagree",
            ));
        }
        Ok(Some(descriptor))
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
        let Some(descriptor) = self.describe(principal, name)? else {
            return Ok(None);
        };
        read_content(
            &EngineSource::<P, E>::new(self.engine.as_ref()),
            descriptor.file(),
        )
        .map(Some)
        .map_err(map_read_error)
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
        let Some(descriptor) = self.describe(principal, name)? else {
            return Ok(None);
        };
        read_content_range(
            &EngineSource::<P, E>::new(self.engine.as_ref()),
            descriptor.file(),
            offset,
            length,
        )
        .map(Some)
        .map_err(map_read_error)
    }

    /// Flush authoritative object and root records.
    ///
    /// # Errors
    ///
    /// Returns a projection error when durable state cannot be flushed.
    pub fn flush(&self) -> Result<(), PrincipalContentError> {
        self.engine.flush_projection().map_err(Into::into)
    }

    fn header(&self, principal: P) -> Result<ContentHeader<P>, PrincipalContentError> {
        let Some(root) = self.engine.current_root(&principal)? else {
            return Ok(ContentHeader::empty(principal));
        };
        let commit = self.load_typed(root.commit, ObjectKind::Commit, PRINCIPAL_GRAPH_VERSION)?;
        require_structural(root.commit, &commit)?;
        let state_id = owned_target(root.commit, &commit, STATE_LABEL)?;
        let state = self.load_typed(
            state_id,
            ObjectKind::PrincipalState,
            PRINCIPAL_GRAPH_VERSION,
        )?;
        require_structural(state_id, &state)?;

        let mut catalog = Catalog::default();
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
                        .load_object(reference.target())?
                        .ok_or_else(|| ContentError::MissingObject(reference.target()))?;
                    catalog = decode_catalog(reference.target(), &record)?;
                },
                KV_COMPONENT_LABEL => {
                    other_quota_bytes = other_quota_bytes
                        .checked_add(self.kv_quota(reference.target())?)
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
            principal,
            root: Some(root),
            previous_catalog_quota_bytes: catalog.quota_bytes,
            catalog,
            other_quota_bytes,
            preserved_state,
            preserved_commit,
        })
    }

    fn kv_quota(&self, object: ObjectId) -> Result<u64, PrincipalContentError> {
        let record = self.load_typed(object, ObjectKind::NamespaceMap, PRINCIPAL_GRAPH_VERSION)?;
        if record.canonical_bytes().len() != 8 || record.class() != ObjectClass::Metadata {
            return Err(invalid(object, "invalid KV component accounting"));
        }
        Ok(u64::from_le_bytes(
            record
                .canonical_bytes()
                .try_into()
                .map_err(|_| PrincipalContentError::AccountingOverflow)?,
        ))
    }

    fn load_typed(
        &self,
        object: ObjectId,
        kind: ObjectKind,
        version: ObjectFormatVersion,
    ) -> Result<ObjectRecord, PrincipalContentError> {
        let record = self
            .engine
            .load_object(object)?
            .ok_or(ContentError::MissingObject(object))?;
        if record.kind() != kind || record.format_version() != version {
            return Err(invalid(
                object,
                "principal object has wrong kind or version",
            ));
        }
        Ok(record)
    }

    fn enforce_quota(
        &self,
        principal: &P,
        header: &ContentHeader<P>,
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
            .checked_add(header.catalog.quota_bytes)
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
        header: ContentHeader<P>,
        built: Option<&BuiltContent>,
    ) -> Result<RootTransaction<P>, PrincipalContentError> {
        let mut records: BTreeMap<ObjectId, ObjectRecord> = built
            .map(|built| built.records().iter().cloned().collect())
            .unwrap_or_default();
        let mut state_references = header.preserved_state;
        if !header.catalog.entries.is_empty() {
            let catalog = encode_catalog(&header.catalog)?;
            let catalog = self.insert(&mut records, catalog)?;
            state_references.push(ObjectReference::owns(
                ReferenceLabel::new(CONTENT_COMPONENT_LABEL.to_vec()),
                catalog,
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
            header.principal,
            header.root,
            commit,
            records.into_iter().collect(),
        ))
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

struct ContentHeader<P> {
    principal: P,
    root: Option<RootState>,
    catalog: Catalog,
    previous_catalog_quota_bytes: u64,
    other_quota_bytes: u64,
    preserved_state: Vec<ObjectReference>,
    preserved_commit: Vec<ObjectReference>,
}

impl<P> ContentHeader<P> {
    fn empty(principal: P) -> Self {
        Self {
            principal,
            root: None,
            catalog: Catalog::default(),
            previous_catalog_quota_bytes: 0,
            other_quota_bytes: 0,
            preserved_state: Vec::new(),
            preserved_commit: Vec::new(),
        }
    }
}

struct EngineIdentity<'a, P, E> {
    engine: &'a E,
    marker: PhantomData<fn() -> P>,
}

impl<'a, P, E> EngineIdentity<'a, P, E> {
    const fn new(engine: &'a E) -> Self {
        Self {
            engine,
            marker: PhantomData,
        }
    }
}

impl<P, E> astrid_storage_model::ObjectIdentity for EngineIdentity<'_, P, E>
where
    E: PrincipalProjectionEngine<P>,
{
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        self.engine.identify_object(record)
    }
}

struct EngineSource<'a, P, E> {
    engine: &'a E,
    marker: PhantomData<fn() -> P>,
}

impl<'a, P, E> EngineSource<'a, P, E> {
    const fn new(engine: &'a E) -> Self {
        Self {
            engine,
            marker: PhantomData,
        }
    }
}

impl<P, E> ContentSource for EngineSource<'_, P, E>
where
    E: PrincipalProjectionEngine<P>,
{
    type Error = PrincipalProjectionError;

    fn load_content_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, Self::Error> {
        self.engine.load_object(id)
    }
}

struct EngineSink<'a, P, E> {
    engine: &'a E,
    objects_inserted: u64,
    pending_bytes: usize,
    pending: BTreeMap<ObjectId, ObjectRecord>,
    marker: PhantomData<fn() -> P>,
}

impl<'a, P, E> EngineSink<'a, P, E> {
    const fn new(engine: &'a E) -> Self {
        Self {
            engine,
            objects_inserted: 0,
            pending_bytes: 0,
            pending: BTreeMap::new(),
            marker: PhantomData,
        }
    }
}

impl<P, E> EngineSink<'_, P, E>
where
    E: PrincipalProjectionEngine<P>,
{
    fn finish(&mut self) -> Result<(), PrincipalProjectionError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let pending = std::mem::take(&mut self.pending);
        self.pending_bytes = 0;
        let expected: Vec<_> = pending.keys().copied().collect();
        let outcomes = self.engine.stage_objects(pending.into_values().collect())?;
        if outcomes.len() != expected.len() {
            return Err(PrincipalProjectionError::Engine(
                "staging engine returned the wrong outcome count".to_owned(),
            ));
        }
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
                self.objects_inserted =
                    self.objects_inserted
                        .checked_add(1)
                        .ok_or(PrincipalProjectionError::Model(
                            ModelError::ArithmeticOverflow,
                        ))?;
            }
        }
        Ok(())
    }
}

impl<P, E> ContentObjectSink for EngineSink<'_, P, E>
where
    E: PrincipalProjectionEngine<P>,
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
        self.pending.insert(id, record);
        if self.pending_bytes >= STAGING_BATCH_TARGET_BYTES {
            self.finish()?;
        }
        Ok(id)
    }
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

fn map_read_error(error: ContentReadError<PrincipalProjectionError>) -> PrincipalContentError {
    match error {
        ContentReadError::Content(error) => error.into(),
        ContentReadError::Source(error) => error.into(),
    }
}

fn map_stream_error(error: ContentStreamError<PrincipalProjectionError>) -> PrincipalContentError {
    match error {
        ContentStreamError::Content(error) => error.into(),
        ContentStreamError::Source(error) => PrincipalContentError::ContentSource(error),
        ContentStreamError::Sink(error) => error.into(),
    }
}

fn owned_target(
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

fn require_structural(
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

fn invalid(object: ObjectId, detail: &'static str) -> PrincipalContentError {
    PrincipalContentError::InvalidGraph { object, detail }
}
