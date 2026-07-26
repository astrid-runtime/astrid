use std::collections::{BTreeMap, BTreeSet};

use astrid_storage_model::{
    ObjectClass, ObjectId, ObjectIdentity, ObjectKind, ObjectRecord, ObjectReference,
    ReferenceLabel,
};
use fastcdc::v2020::{FastCDC, Normalization};

use crate::{
    CHUNK_TREE_FANOUT, CONTENT_LABEL, ChunkingProfile, ContentDescriptor, ContentError,
    FORMAT_VERSION, encode_file_header, insert_record,
};

/// Canonical records produced for one file.
///
/// Records are sorted by identifier and contain no duplicates. The file
/// descriptor is the owning root of every returned record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltContent {
    descriptor: ContentDescriptor,
    records: Vec<(ObjectId, ObjectRecord)>,
    unique_chunks: u64,
}

impl BuiltContent {
    /// Return the canonical file descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> ContentDescriptor {
        self.descriptor
    }

    /// Borrow every unique record required by the file closure.
    #[must_use]
    pub fn records(&self) -> &[(ObjectId, ObjectRecord)] {
        &self.records
    }

    /// Consume the build and return its unique records.
    #[must_use]
    pub fn into_records(self) -> Vec<(ObjectId, ObjectRecord)> {
        self.records
    }

    /// Return the number of distinct chunk objects.
    #[must_use]
    pub const fn unique_chunks(&self) -> u64 {
        self.unique_chunks
    }
}

#[derive(Clone, Copy)]
struct Child {
    id: ObjectId,
    logical_bytes: u64,
    chunk_count: u64,
}

/// Build a canonical content DAG from ordinary bytes.
///
/// The `FastCDC` gear fingerprint determines boundaries only; cryptographic
/// object identity is supplied by `identity` and covers every chunk byte and
/// structural field.
///
/// # Errors
///
/// Returns a profile, length, collision, or object-model error without
/// producing a partial build.
pub fn build_content<I: ObjectIdentity>(
    identity: &I,
    profile: ChunkingProfile,
    source: &[u8],
) -> Result<BuiltContent, ContentError> {
    let logical_bytes = u64::try_from(source.len()).map_err(|_| ContentError::LengthOverflow)?;
    let mut records = BTreeMap::new();
    let mut chunks = Vec::new();
    let mut unique_chunks = BTreeSet::new();

    if !source.is_empty() {
        let chunker = FastCDC::with_level_and_seed(
            source,
            usize::try_from(profile.minimum_bytes()).map_err(|_| ContentError::LengthOverflow)?,
            usize::try_from(profile.average_bytes()).map_err(|_| ContentError::LengthOverflow)?,
            usize::try_from(profile.maximum_bytes()).map_err(|_| ContentError::LengthOverflow)?,
            Normalization::Level1,
            profile.gear_seed(),
        );
        for chunk in chunker {
            let end = chunk
                .offset
                .checked_add(chunk.length)
                .ok_or(ContentError::LengthOverflow)?;
            let bytes = source
                .get(chunk.offset..end)
                .ok_or(ContentError::LengthOverflow)?;
            let record = ObjectRecord::new(
                ObjectKind::Chunk,
                FORMAT_VERSION,
                bytes.to_vec(),
                Vec::new(),
                0,
                ObjectClass::Data,
            )?;
            let id = insert_record(identity, &mut records, record)?;
            unique_chunks.insert(id);
            chunks.push(Child {
                id,
                logical_bytes: u64::try_from(bytes.len())
                    .map_err(|_| ContentError::LengthOverflow)?,
                chunk_count: 1,
            });
        }
    }

    let chunk_count = u64::try_from(chunks.len()).map_err(|_| ContentError::LengthOverflow)?;
    let content = build_tree(identity, &mut records, chunks)?;
    let references = content
        .map(|child| {
            vec![ObjectReference::owns(
                ReferenceLabel::new(CONTENT_LABEL.to_vec()),
                child.id,
            )]
        })
        .unwrap_or_default();
    let file = ObjectRecord::new(
        ObjectKind::File,
        FORMAT_VERSION,
        encode_file_header(profile, logical_bytes, chunk_count),
        references,
        0,
        ObjectClass::Metadata,
    )?;
    let file = insert_record(identity, &mut records, file)?;
    Ok(BuiltContent {
        descriptor: ContentDescriptor::new(file, logical_bytes, chunk_count, profile),
        records: records.into_iter().collect(),
        unique_chunks: u64::try_from(unique_chunks.len())
            .map_err(|_| ContentError::LengthOverflow)?,
    })
}

fn build_tree<I: ObjectIdentity>(
    identity: &I,
    records: &mut BTreeMap<ObjectId, ObjectRecord>,
    mut level: Vec<Child>,
) -> Result<Option<Child>, ContentError> {
    if level.is_empty() {
        return Ok(None);
    }
    if level.len() == 1 {
        return Ok(level.pop());
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(CHUNK_TREE_FANOUT));
        for group in level.chunks(CHUNK_TREE_FANOUT) {
            next.push(build_tree_node(identity, records, group)?);
        }
        level = next;
    }
    Ok(level.pop())
}

fn build_tree_node<I: ObjectIdentity>(
    identity: &I,
    records: &mut BTreeMap<ObjectId, ObjectRecord>,
    children: &[Child],
) -> Result<Child, ContentError> {
    let count = u16::try_from(children.len()).map_err(|_| ContentError::LengthOverflow)?;
    let logical_bytes = children.iter().try_fold(0_u64, |total, child| {
        total
            .checked_add(child.logical_bytes)
            .ok_or(ContentError::LengthOverflow)
    })?;
    let chunk_count = children.iter().try_fold(0_u64, |total, child| {
        total
            .checked_add(child.chunk_count)
            .ok_or(ContentError::LengthOverflow)
    })?;
    let mut bytes = Vec::with_capacity(18_usize.saturating_add(children.len().saturating_mul(16)));
    bytes.extend_from_slice(&count.to_le_bytes());
    bytes.extend_from_slice(&logical_bytes.to_le_bytes());
    bytes.extend_from_slice(&chunk_count.to_le_bytes());
    let mut references = Vec::with_capacity(children.len());
    for (index, child) in children.iter().enumerate() {
        bytes.extend_from_slice(&child.logical_bytes.to_le_bytes());
        bytes.extend_from_slice(&child.chunk_count.to_le_bytes());
        let index = u16::try_from(index).map_err(|_| ContentError::LengthOverflow)?;
        references.push(ObjectReference::owns(
            ReferenceLabel::new(index.to_be_bytes().to_vec()),
            child.id,
        ));
    }
    let tree = ObjectRecord::new(
        ObjectKind::ChunkTree,
        FORMAT_VERSION,
        bytes,
        references,
        0,
        ObjectClass::Metadata,
    )?;
    let id = insert_record(identity, records, tree)?;
    Ok(Child {
        id,
        logical_bytes,
        chunk_count,
    })
}
