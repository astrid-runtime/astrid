//! Engine-bound preparation of contiguous file representations.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;

use astrid_storage_content::{
    ChunkingProfile, ContentDescriptor, ContentObjectSink, ContentStreamError, VerifiedContent,
    build_content_streaming,
};
use astrid_storage_model::{
    BlobId, CanonicalChunkingProfile, Coverage, InsertOutcome, ObjectId, ObjectKind, ObjectRecord,
    ProfileKind, Recipe, ReconstructionBounds, RepresentationAdmissionEvidence,
    RepresentationOutputObservation, RepresentationProfile, RepresentationProfileId,
    RepresentationRecord,
};

use super::representations::PhysicalIdentityV1;
use super::{
    DurableEngine, DurableError, FaultPoint, PersistentObjectIdentity, PrincipalCodec, io_error,
};

const PREPARATION_BATCH_BYTES: usize = 4 * 1024 * 1024;

/// Engine-bound result of one complete contiguous-file construction pass.
///
/// The value proves canonical chunking and stages only File, `ChunkTree`, and
/// admission-evidence objects. Raw chunk bytes remain in the caller's sealed
/// source until the later crash-safe adoption transition.
pub struct PreparedContiguousFile {
    verified: VerifiedContent,
    objects_inserted: u64,
    pub(super) payload: PreparedContiguousPayload,
}

/// A contiguous representation that is durable and available for root publication.
pub struct PublishedContiguousFile {
    verified: VerifiedContent,
    objects_inserted: u64,
}

impl PublishedContiguousFile {
    /// Return the canonical logical file descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> ContentDescriptor {
        self.verified.descriptor()
    }

    /// Return the builder-issued verification proof.
    #[must_use]
    pub const fn verified_content(&self) -> VerifiedContent {
        self.verified
    }

    /// Return privileged structural-object admission diagnostics.
    #[must_use]
    pub const fn objects_inserted(&self) -> u64 {
        self.objects_inserted
    }
}

impl PreparedContiguousFile {
    /// Return the canonical logical file descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> ContentDescriptor {
        self.verified.descriptor()
    }

    /// Return the builder-issued proof of canonical content boundaries.
    #[must_use]
    pub const fn verified_content(&self) -> VerifiedContent {
        self.verified
    }

    /// Return privileged newly-admitted structural-object diagnostics.
    ///
    /// This value must remain below guest-visible APIs because it can reveal
    /// cross-principal deduplication.
    #[must_use]
    pub const fn objects_inserted(&self) -> u64 {
        self.objects_inserted
    }
}

pub(super) struct PreparedContiguousPayload {
    pub(super) authority: Arc<()>,
    pub(super) profile: RepresentationProfile,
    pub(super) profile_id: RepresentationProfileId,
    pub(super) blob: BlobId,
    pub(super) representation: RepresentationRecord,
    pub(super) evidence: ObjectRecord,
    pub(super) slices: BTreeMap<ObjectId, ContiguousSlice>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ContiguousSlice {
    pub(super) offset: u64,
    pub(super) length: u64,
}

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Construct and stage a canonical content DAG without appending raw chunks.
    ///
    /// The caller supplies the exact logical prefix length. The source is read
    /// once and must end at that boundary. Structural records and admission
    /// evidence are identity-checked through the ordinary arena path; no
    /// representation or principal root is published by this operation.
    ///
    /// # Errors
    ///
    /// Returns a content, source-I/O, identity, arena-admission, or physical
    /// model error. Earlier unreachable structural records may remain staged.
    pub fn prepare_contiguous_file<R: Read>(
        &self,
        profile: ChunkingProfile,
        logical_bytes: u64,
        source: R,
    ) -> Result<PreparedContiguousFile, DurableError> {
        let (physical_profile, profile_id) = self.contiguous_profile()?;
        let mut source = HashingReader::new(source, profile_id, logical_bytes);
        let mut sink = ContiguousSink::new(self);
        let streamed =
            build_content_streaming(profile, &mut source, &mut sink).map_err(map_stream_error)?;
        sink.finish()?;
        if source.bytes_read != logical_bytes
            || streamed.descriptor().logical_bytes() != logical_bytes
        {
            return Err(DurableError::InvalidRepresentationState(
                "contiguous source length disagrees with its sealed intent",
            ));
        }
        let blob = source.finish();
        let descriptor = streamed.descriptor();
        let chunking_profile = CanonicalChunkingProfile::fastcdc_v2020(
            profile.minimum_bytes(),
            profile.average_bytes(),
            profile.maximum_bytes(),
            profile.gear_seed(),
        )?;
        let coverage = Coverage::canonical_file_chunks(
            descriptor.file(),
            streamed.verified_content().opened_content().content_root(),
            descriptor.logical_bytes(),
            descriptor.chunk_count(),
            chunking_profile,
        )?;
        let provisional = RepresentationRecord::new(
            profile_id,
            coverage.clone(),
            Recipe::ContiguousFile { blob },
            sink.canonical_output_bytes,
            sink.canonical_output_bytes.max(1),
            Some(ObjectId::new([0; 32])),
        )?;
        let evidence = RepresentationAdmissionEvidence::new(
            &PhysicalIdentityV1,
            &provisional,
            blob,
            logical_bytes,
            &sink.observations,
        )?
        .object_record()?;
        let evidence_id = self.identify(&evidence);
        let representation = RepresentationRecord::new(
            profile_id,
            coverage,
            Recipe::ContiguousFile { blob },
            sink.canonical_output_bytes,
            sink.canonical_output_bytes.max(1),
            Some(evidence_id),
        )?;
        representation.validate_against_profile(&PhysicalIdentityV1, &physical_profile)?;
        let (_, evidence_outcome) = self.stage_object(&evidence)?;
        let objects_inserted = sink
            .objects_inserted
            .checked_add(u64::from(evidence_outcome == InsertOutcome::Inserted))
            .ok_or(DurableError::EncodingOverflow)?;
        Ok(PreparedContiguousFile {
            verified: streamed.verified_content(),
            objects_inserted,
            payload: PreparedContiguousPayload {
                authority: Arc::clone(&self.preparation_authority),
                profile: physical_profile,
                profile_id,
                blob,
                representation,
                evidence,
                slices: sink.slices,
            },
        })
    }

    /// Copy a prepared stream into the canonical loose-blob namespace and
    /// publish its verified physical representation.
    ///
    /// This is the universal fallback. Hosted staging should prefer
    /// [`Self::publish_contiguous_from_path`] so a same-volume copy-on-write
    /// clone can retain the sealed source while sharing its data extents.
    ///
    /// # Errors
    ///
    /// Returns a foreign-preparation, source-I/O, blob-verification, evidence,
    /// representation-CAS, or durability error. A physical publication error
    /// poisons the engine until authoritative recovery completes.
    pub fn publish_contiguous_copy<R: Read>(
        &self,
        prepared: PreparedContiguousFile,
        source: R,
    ) -> Result<PublishedContiguousFile, DurableError> {
        self.validate_contiguous_preparation(&prepared)?;
        self.flush()?;
        self.fail_if(FaultPoint::AfterContiguousStructuralFlush)?;
        let logical_bytes = prepared.verified.descriptor().logical_bytes();
        super::representations::install_loose_blob_copy(
            &self.directory,
            prepared.payload.blob,
            prepared.payload.profile_id,
            logical_bytes,
            source,
        )?;
        self.fail_if(FaultPoint::AfterContiguousBlobInstall)?;
        self.publish_installed_contiguous(prepared)
    }

    /// Adopt a sealed native file as a contiguous physical representation.
    ///
    /// Same-volume APFS and Linux filesystems use a copy-on-write clone and
    /// truncate only the clone's staging footer. The sealed source therefore
    /// remains an independently recoverable retry witness without a second
    /// full-data write. Unsupported filesystems use the verified copy path.
    ///
    /// # Errors
    ///
    /// Returns a foreign-preparation, source-I/O, blob-verification, evidence,
    /// representation-CAS, or durability error. A physical publication error
    /// poisons the engine until authoritative recovery completes.
    pub fn publish_contiguous_from_path(
        &self,
        prepared: PreparedContiguousFile,
        source: &std::path::Path,
    ) -> Result<PublishedContiguousFile, DurableError> {
        self.validate_contiguous_preparation(&prepared)?;
        self.flush()?;
        self.fail_if(FaultPoint::AfterContiguousStructuralFlush)?;
        let logical_bytes = prepared.verified.descriptor().logical_bytes();
        super::representations::install_loose_blob_from_path(
            &self.directory,
            prepared.payload.blob,
            prepared.payload.profile_id,
            logical_bytes,
            source,
        )?;
        self.fail_if(FaultPoint::AfterContiguousBlobInstall)?;
        self.publish_installed_contiguous(prepared)
    }

    fn validate_contiguous_preparation(
        &self,
        prepared: &PreparedContiguousFile,
    ) -> Result<(), DurableError> {
        let payload = &prepared.payload;
        if !Arc::ptr_eq(&payload.authority, &self.preparation_authority) {
            return Err(DurableError::InvalidRepresentationState(
                "contiguous preparation belongs to a different engine",
            ));
        }
        if self.identify(&payload.evidence)
            != payload.representation.verification_evidence().ok_or(
                DurableError::InvalidRepresentationState(
                    "contiguous representation omits admission evidence",
                ),
            )?
        {
            return Err(DurableError::InvalidRepresentationState(
                "contiguous evidence identity changed after preparation",
            ));
        }
        Ok(())
    }

    fn publish_installed_contiguous(
        &self,
        prepared: PreparedContiguousFile,
    ) -> Result<PublishedContiguousFile, DurableError> {
        let PreparedContiguousFile {
            verified,
            objects_inserted,
            payload,
        } = prepared;
        let mut inner = self.lock_usable()?;
        let evidence_id = self.identify(&payload.evidence);
        if !inner.index.contains_key(&evidence_id) {
            return Err(DurableError::InvalidRepresentationState(
                "contiguous evidence is not durable in the object arena",
            ));
        }
        let update =
            {
                let representations = inner.representations.as_mut().ok_or(
                    DurableError::InvalidRepresentationState(
                        "contiguous publication requires active physical authority",
                    ),
                )?;
                representations.append_contiguous_update(
                    &payload.profile,
                    &payload.representation,
                    &payload.slices,
                )?
            };
        let publication =
            (|| {
                self.fail_if(FaultPoint::AfterContiguousMetadataAppend)?;
                let representations = inner.representations.as_mut().ok_or(
                    DurableError::InvalidRepresentationState(
                        "contiguous physical authority disappeared",
                    ),
                )?;
                if let Some(update) = update {
                    representations.publish_direct_update(update)?;
                }
                self.fail_if(FaultPoint::AfterContiguousStatePublish)?;
                representations.flush()
            })();
        if let Err(error) = publication {
            self.mark_requires_recovery(&mut inner);
            return Err(error);
        }
        Ok(PublishedContiguousFile {
            verified,
            objects_inserted,
        })
    }

    fn contiguous_profile(
        &self,
    ) -> Result<(RepresentationProfile, RepresentationProfileId), DurableError> {
        let frozen_specification = {
            let inner = self.lock_usable()?;
            inner
                .representations
                .as_ref()
                .ok_or(DurableError::InvalidRepresentationState(
                    "contiguous preparation requires active physical authority",
                ))?
                .frozen_specification()?
        };
        let bounds = ReconstructionBounds::new(1, 3, u64::MAX, u64::MAX, 1, u64::MAX, 1)?;
        let profile = RepresentationProfile::new_builtin(
            ProfileKind::ContiguousFile,
            bounds,
            frozen_specification,
        )?;
        let id = profile.identify(&PhysicalIdentityV1)?;
        Ok((profile, id))
    }
}

struct ContiguousSink<'a, P: Ord, I, C> {
    engine: &'a DurableEngine<P, I, C>,
    pending: Vec<ObjectRecord>,
    pending_bytes: usize,
    objects_inserted: u64,
    offset: u64,
    canonical_output_bytes: u64,
    observations: Vec<RepresentationOutputObservation>,
    slices: BTreeMap<ObjectId, ContiguousSlice>,
}

impl<'a, P: Ord, I, C> ContiguousSink<'a, P, I, C> {
    const fn new(engine: &'a DurableEngine<P, I, C>) -> Self {
        Self {
            engine,
            pending: Vec::new(),
            pending_bytes: 0,
            objects_inserted: 0,
            offset: 0,
            canonical_output_bytes: 0,
            observations: Vec::new(),
            slices: BTreeMap::new(),
        }
    }
}

impl<P, I, C> ContiguousSink<'_, P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    fn finish(&mut self) -> Result<(), DurableError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let records = std::mem::take(&mut self.pending);
        self.pending_bytes = 0;
        for (_, outcome) in self.engine.stage_objects(records)? {
            self.objects_inserted = self
                .objects_inserted
                .checked_add(u64::from(outcome == InsertOutcome::Inserted))
                .ok_or(DurableError::EncodingOverflow)?;
        }
        Ok(())
    }
}

impl<P, I, C> ContentObjectSink for ContiguousSink<'_, P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    type Error = DurableError;

    fn stage_content_object(&mut self, record: ObjectRecord) -> Result<ObjectId, Self::Error> {
        let id = self.engine.identify(&record);
        if record.kind() == ObjectKind::Chunk {
            let length = u64::try_from(record.canonical_bytes().len())
                .map_err(|_| DurableError::EncodingOverflow)?;
            if !self.slices.contains_key(&id) {
                let canonical_record_bytes = record.retained_bytes()?;
                self.canonical_output_bytes = self
                    .canonical_output_bytes
                    .checked_add(canonical_record_bytes)
                    .ok_or(DurableError::EncodingOverflow)?;
                self.observations.push(RepresentationOutputObservation::new(
                    id,
                    canonical_record_bytes,
                ));
                self.slices.insert(
                    id,
                    ContiguousSlice {
                        offset: self.offset,
                        length,
                    },
                );
            }
            self.offset = self
                .offset
                .checked_add(length)
                .ok_or(DurableError::EncodingOverflow)?;
            return Ok(id);
        }
        self.pending_bytes = self
            .pending_bytes
            .saturating_add(record.canonical_bytes().len())
            .saturating_add(record.references().len().saturating_mul(64))
            .saturating_add(64);
        self.pending.push(record);
        if self.pending_bytes >= PREPARATION_BATCH_BYTES {
            self.finish()?;
        }
        Ok(id)
    }
}

struct HashingReader<R> {
    inner: R,
    hasher: blake3::Hasher,
    bytes_read: u64,
}

impl<R> HashingReader<R> {
    fn new(inner: R, profile: RepresentationProfileId, logical_bytes: u64) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key("astrid-blob-identity-v1\0");
        hasher.update(&1_u16.to_le_bytes());
        hasher.update(&2_u16.to_le_bytes());
        hasher.update(&32_u32.to_le_bytes());
        hasher.update(profile.as_bytes());
        hasher.update(&logical_bytes.to_le_bytes());
        Self {
            inner,
            hasher,
            bytes_read: 0,
        }
    }

    fn finish(self) -> BlobId {
        BlobId::new(*self.hasher.finalize().as_bytes())
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        self.bytes_read = self
            .bytes_read
            .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        Ok(read)
    }
}

fn map_stream_error(error: ContentStreamError<DurableError>) -> DurableError {
    match error {
        ContentStreamError::Content(error) => error.into(),
        ContentStreamError::Source(source) => io_error("read contiguous staged content", source),
        ContentStreamError::Sink(error) => error,
    }
}
