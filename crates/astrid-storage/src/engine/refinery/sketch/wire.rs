//! Canonical format for bottom-k pass descriptors and Derived records.

use crate::storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, ObjectReference,
    ReferenceKind, ReferenceLabel,
};

use super::{
    BottomKSketch, BottomKSketchDescriptor, BottomKSketchError, SketchSampleSize, SketchScoreWidth,
};

pub(super) const SCORE_DOMAIN: &str = "astrid bottom-k chunk score v1";

const DESCRIPTOR_MAGIC: &[u8] = b"astrid-bottom-k-descriptor-v1\0";
const SKETCH_MAGIC: &[u8] = b"astrid-bottom-k-sketch-v1\0";
const CONSTRUCTION: u16 = 1;
const HASH_ALGORITHM_BLAKE3_DERIVE_KEY: u16 = 1;
const DUPLICATE_TREATMENT_SET: u16 = 1;
const ORDERING_UNSIGNED_LEXICOGRAPHIC: u16 = 1;
const EMPTY_INPUT_EMPTY_SAMPLE: u16 = 1;
const SMALL_INPUT_ALL_DISTINCT: u16 = 1;
const PROFILE_BINDING_FASTCDC_FIELDS: u16 = 1;
const CURRENT_IDENTITY_ALGORITHM: u16 = 1;
const CURRENT_IDENTITY_CONSTRUCTION: u16 = 1;
const CURRENT_IDENTITY_LENGTH: u32 = 32;
const PASS_DESCRIPTOR_LABEL: &[u8] = b"00-pass-descriptor";
const SOURCE_FILE_LABEL: &[u8] = b"01-source-file";

pub(super) fn descriptor_record(
    descriptor: BottomKSketchDescriptor,
) -> Result<ObjectRecord, BottomKSketchError> {
    let mut canonical = Vec::new();
    canonical.extend_from_slice(DESCRIPTOR_MAGIC);
    canonical.extend_from_slice(&CONSTRUCTION.to_le_bytes());
    canonical.extend_from_slice(&HASH_ALGORITHM_BLAKE3_DERIVE_KEY.to_le_bytes());
    canonical.extend_from_slice(&descriptor.score_width().code().to_le_bytes());
    canonical.extend_from_slice(&DUPLICATE_TREATMENT_SET.to_le_bytes());
    canonical.extend_from_slice(&ORDERING_UNSIGNED_LEXICOGRAPHIC.to_le_bytes());
    canonical.extend_from_slice(&descriptor.sample_size().get().to_le_bytes());
    canonical.extend_from_slice(&EMPTY_INPUT_EMPTY_SAMPLE.to_le_bytes());
    canonical.extend_from_slice(&SMALL_INPUT_ALL_DISTINCT.to_le_bytes());
    canonical.extend_from_slice(&PROFILE_BINDING_FASTCDC_FIELDS.to_le_bytes());
    let domain_length =
        u16::try_from(SCORE_DOMAIN.len()).map_err(|_| BottomKSketchError::ArithmeticOverflow)?;
    canonical.extend_from_slice(&domain_length.to_le_bytes());
    canonical.extend_from_slice(SCORE_DOMAIN.as_bytes());
    ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        canonical,
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .map_err(BottomKSketchError::Model)
}

pub(super) fn decode_descriptor(
    record: &ObjectRecord,
) -> Result<BottomKSketchDescriptor, BottomKSketchError> {
    if record.kind() != ObjectKind::Evidence
        || record.format_version() != ObjectFormatVersion::V1
        || record.class() != ObjectClass::Metadata
        || record.logical_bytes() != 0
        || !record.references().is_empty()
    {
        return Err(BottomKSketchError::NonCanonicalRecord);
    }
    let mut cursor = Cursor::new(record.canonical_bytes());
    cursor.magic(DESCRIPTOR_MAGIC)?;
    cursor.expect_u16(CONSTRUCTION)?;
    cursor.expect_u16(HASH_ALGORITHM_BLAKE3_DERIVE_KEY)?;
    let score_width =
        SketchScoreWidth::from_code(cursor.u16()?).ok_or(BottomKSketchError::NonCanonicalRecord)?;
    cursor.expect_u16(DUPLICATE_TREATMENT_SET)?;
    cursor.expect_u16(ORDERING_UNSIGNED_LEXICOGRAPHIC)?;
    let sample_size =
        SketchSampleSize::new(cursor.u16()?).ok_or(BottomKSketchError::NonCanonicalRecord)?;
    cursor.expect_u16(EMPTY_INPUT_EMPTY_SAMPLE)?;
    cursor.expect_u16(SMALL_INPUT_ALL_DISTINCT)?;
    cursor.expect_u16(PROFILE_BINDING_FASTCDC_FIELDS)?;
    let domain_length = usize::from(cursor.u16()?);
    if cursor.bytes(domain_length)? != SCORE_DOMAIN.as_bytes() {
        return Err(BottomKSketchError::NonCanonicalRecord);
    }
    cursor.done()?;
    let descriptor = BottomKSketchDescriptor::new(score_width, sample_size);
    if descriptor_record(descriptor)? != *record {
        return Err(BottomKSketchError::NonCanonicalRecord);
    }
    Ok(descriptor)
}

pub(super) fn sketch_record(sketch: &BottomKSketch) -> Result<ObjectRecord, BottomKSketchError> {
    let source = sketch.source();
    let profile = source.profile();
    let mut canonical = Vec::new();
    canonical.extend_from_slice(SKETCH_MAGIC);
    canonical.extend_from_slice(&CONSTRUCTION.to_le_bytes());
    canonical.extend_from_slice(&sketch.score_width().code().to_le_bytes());
    canonical.extend_from_slice(&sketch.sample_size().get().to_le_bytes());
    let score_count =
        u16::try_from(sketch.scores().len()).map_err(|_| BottomKSketchError::ArithmeticOverflow)?;
    canonical.extend_from_slice(&score_count.to_le_bytes());
    push_current_identity(&mut canonical, sketch.descriptor().object_id());
    push_current_identity(&mut canonical, source.file());
    canonical.extend_from_slice(&profile.minimum_bytes().to_le_bytes());
    canonical.extend_from_slice(&profile.average_bytes().to_le_bytes());
    canonical.extend_from_slice(&profile.maximum_bytes().to_le_bytes());
    canonical.extend_from_slice(&profile.gear_seed().to_le_bytes());
    canonical.extend_from_slice(&source.logical_bytes().to_le_bytes());
    canonical.extend_from_slice(&source.chunk_count().to_le_bytes());
    canonical.extend_from_slice(&sketch.unique_chunk_objects().to_le_bytes());
    for score in sketch.scores() {
        canonical.extend_from_slice(&score[..sketch.score_width().bytes()]);
    }

    let references = vec![
        ObjectReference::new(
            ReferenceLabel::new(PASS_DESCRIPTOR_LABEL.to_vec()),
            sketch.descriptor().object_id(),
            ReferenceKind::Evidence,
        ),
        ObjectReference::new(
            ReferenceLabel::new(SOURCE_FILE_LABEL.to_vec()),
            source.file(),
            ReferenceKind::Evidence,
        ),
    ];
    ObjectRecord::new(
        ObjectKind::Derived,
        ObjectFormatVersion::V1,
        canonical,
        references,
        0,
        ObjectClass::Metadata,
    )
    .map_err(BottomKSketchError::Model)
}

fn push_current_identity(bytes: &mut Vec<u8>, id: ObjectId) {
    bytes.extend_from_slice(&CURRENT_IDENTITY_ALGORITHM.to_le_bytes());
    bytes.extend_from_slice(&CURRENT_IDENTITY_CONSTRUCTION.to_le_bytes());
    bytes.extend_from_slice(&CURRENT_IDENTITY_LENGTH.to_le_bytes());
    bytes.extend_from_slice(id.as_bytes());
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn magic(&mut self, magic: &[u8]) -> Result<(), BottomKSketchError> {
        if self.bytes(magic.len())? == magic {
            Ok(())
        } else {
            Err(BottomKSketchError::NonCanonicalRecord)
        }
    }

    fn expect_u16(&mut self, expected: u16) -> Result<(), BottomKSketchError> {
        if self.u16()? == expected {
            Ok(())
        } else {
            Err(BottomKSketchError::NonCanonicalRecord)
        }
    }

    fn u16(&mut self) -> Result<u16, BottomKSketchError> {
        Ok(u16::from_le_bytes(
            self.bytes(2)?
                .try_into()
                .map_err(|_| BottomKSketchError::NonCanonicalRecord)?,
        ))
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], BottomKSketchError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(BottomKSketchError::NonCanonicalRecord)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(BottomKSketchError::NonCanonicalRecord)?;
        self.offset = end;
        Ok(bytes)
    }

    fn done(self) -> Result<(), BottomKSketchError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(BottomKSketchError::NonCanonicalRecord)
        }
    }
}
