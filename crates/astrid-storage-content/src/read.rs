use alloc::vec::Vec;
use core::fmt;

use astrid_storage_model::{
    ObjectClass, ObjectId, ObjectKind, ObjectRecord, ReferenceKind, ReferenceLabel,
};

use crate::{
    CHUNK_TREE_FANOUT, CONTENT_LABEL, ChunkingProfile, ContentDescriptor, ContentError,
    FORMAT_VERSION, decode_file_header,
};

/// Fallible object-loading boundary used for lazy content reconstruction.
pub trait ContentSource {
    /// Storage-specific read failure.
    type Error;

    /// Load one immutable object by logical identity.
    ///
    /// # Errors
    ///
    /// Returns the source-specific error when the backing object arena cannot
    /// complete the read.
    fn load_content_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, Self::Error>;
}

/// Content grammar failure or an underlying source failure.
#[derive(Debug)]
pub enum ContentReadError<E> {
    /// Canonical content graph was missing or invalid.
    Content(ContentError),
    /// The backing object source failed.
    Source(E),
}

impl<E: fmt::Display> fmt::Display for ContentReadError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Content(error) => error.fmt(formatter),
            Self::Source(error) => write!(formatter, "content source: {error}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> core::error::Error for ContentReadError<E> {}

impl<E> From<ContentError> for ContentReadError<E> {
    fn from(error: ContentError) -> Self {
        Self::Content(error)
    }
}

/// Decode one file descriptor without reading its chunks.
///
/// # Errors
///
/// Returns a source error, missing-object error, or canonical grammar error.
pub fn describe_content<S: ContentSource>(
    source: &S,
    file: ObjectId,
) -> Result<ContentDescriptor, ContentReadError<S::Error>> {
    let record = load(source, file)?;
    let (profile, logical_bytes, chunk_count, _) = decode_file(file, &record)?;
    Ok(ContentDescriptor::new(
        file,
        logical_bytes,
        chunk_count,
        profile,
    ))
}

/// Reconstruct all bytes represented by one file object.
///
/// # Errors
///
/// Returns a source, allocation, missing-object, or canonical grammar error.
pub fn read_content<S: ContentSource>(
    source: &S,
    file: ObjectId,
) -> Result<Vec<u8>, ContentReadError<S::Error>> {
    let descriptor = describe_content(source, file)?;
    read_content_range(source, file, 0, descriptor.logical_bytes())
}

/// Reconstruct an exact byte range while traversing only overlapping chunks.
///
/// # Errors
///
/// Returns an out-of-bounds, source, allocation, missing-object, or canonical
/// grammar error.
pub fn read_content_range<S: ContentSource>(
    source: &S,
    file: ObjectId,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, ContentReadError<S::Error>> {
    let record = load(source, file)?;
    let (_, logical_bytes, chunk_count, content) = decode_file(file, &record)?;
    let end = offset
        .checked_add(length)
        .ok_or(ContentError::RangeOutOfBounds {
            offset,
            length,
            file_length: logical_bytes,
        })?;
    if offset > logical_bytes || end > logical_bytes {
        return Err(ContentError::RangeOutOfBounds {
            offset,
            length,
            file_length: logical_bytes,
        }
        .into());
    }
    let capacity = usize::try_from(length).map_err(|_| ContentError::LengthOverflow)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| ContentError::LengthOverflow)?;
    if length == 0 {
        return Ok(output);
    }
    let content = content.ok_or(ContentError::InvalidObject {
        object: file,
        detail: "non-empty file has no content reference",
    })?;
    append_range(
        source,
        content,
        ExpectedShape {
            logical_bytes,
            chunk_count,
            tree_depth: canonical_tree_depth(chunk_count),
        },
        RequestedRange { start: offset, end },
        &mut output,
    )?;
    if output.len() != capacity {
        return Err(ContentError::InvalidObject {
            object: file,
            detail: "content tree reconstructed the wrong range length",
        }
        .into());
    }
    Ok(output)
}

#[derive(Clone, Copy)]
struct ExpectedShape {
    logical_bytes: u64,
    chunk_count: u64,
    tree_depth: u32,
}

#[derive(Clone, Copy)]
struct RequestedRange {
    start: u64,
    end: u64,
}

fn append_range<S: ContentSource>(
    source: &S,
    object: ObjectId,
    shape: ExpectedShape,
    range: RequestedRange,
    output: &mut Vec<u8>,
) -> Result<(), ContentReadError<S::Error>> {
    let record = load(source, object)?;
    match record.kind() {
        ObjectKind::Chunk => {
            validate_chunk(object, &record, shape)?;
            let start = usize::try_from(range.start).map_err(|_| ContentError::LengthOverflow)?;
            let end = usize::try_from(range.end).map_err(|_| ContentError::LengthOverflow)?;
            let bytes =
                record
                    .canonical_bytes()
                    .get(start..end)
                    .ok_or(ContentError::InvalidObject {
                        object,
                        detail: "chunk range exceeds payload",
                    })?;
            output.extend_from_slice(bytes);
            Ok(())
        },
        ObjectKind::ChunkTree => {
            if shape.tree_depth == 0 {
                return Err(ContentError::InvalidObject {
                    object,
                    detail: "chunk tree exceeds canonical depth",
                }
                .into());
            }
            let children = decode_tree(object, &record, shape)?;
            let mut cursor = 0_u64;
            for (child, child_length, child_chunk_count) in children {
                let child_end = cursor
                    .checked_add(child_length)
                    .ok_or(ContentError::LengthOverflow)?;
                if range.start < child_end && range.end > cursor {
                    append_range(
                        source,
                        child,
                        ExpectedShape {
                            logical_bytes: child_length,
                            chunk_count: child_chunk_count,
                            tree_depth: shape.tree_depth.saturating_sub(1),
                        },
                        RequestedRange {
                            start: range.start.saturating_sub(cursor),
                            end: range.end.min(child_end).saturating_sub(cursor),
                        },
                        output,
                    )?;
                }
                cursor = child_end;
            }
            Ok(())
        },
        _ => Err(ContentError::InvalidObject {
            object,
            detail: "file content points to an unsupported object kind",
        }
        .into()),
    }
}

fn decode_file(
    object: ObjectId,
    record: &ObjectRecord,
) -> Result<(ChunkingProfile, u64, u64, Option<ObjectId>), ContentError> {
    if record.kind() != ObjectKind::File
        || record.format_version() != FORMAT_VERSION
        || record.class() != ObjectClass::Metadata
        || record.logical_bytes() != 0
    {
        return Err(ContentError::InvalidObject {
            object,
            detail: "invalid file object type or accounting",
        });
    }
    let (profile, logical_bytes, chunk_count) =
        decode_file_header(object, record.canonical_bytes())?;
    let label = ReferenceLabel::new(CONTENT_LABEL);
    let content = record.reference(&label);
    match (
        logical_bytes,
        chunk_count,
        content,
        record.references().len(),
    ) {
        (0, 0, None, 0) => Ok((profile, 0, 0, None)),
        (0, _, _, _) => Err(ContentError::InvalidObject {
            object,
            detail: "empty file has chunks or content",
        }),
        (_, 0, _, _) => Err(ContentError::InvalidObject {
            object,
            detail: "non-empty file has no chunks",
        }),
        (_, _, Some(reference), 1) if reference.kind() == ReferenceKind::Owns => Ok((
            profile,
            logical_bytes,
            chunk_count,
            Some(reference.target()),
        )),
        _ => Err(ContentError::InvalidObject {
            object,
            detail: "invalid file content reference",
        }),
    }
}

fn validate_chunk(
    object: ObjectId,
    record: &ObjectRecord,
    shape: ExpectedShape,
) -> Result<(), ContentError> {
    let actual =
        u64::try_from(record.canonical_bytes().len()).map_err(|_| ContentError::LengthOverflow)?;
    if record.format_version() != FORMAT_VERSION
        || record.class() != ObjectClass::Data
        || record.logical_bytes() != 0
        || !record.references().is_empty()
        || actual != shape.logical_bytes
        || shape.chunk_count != 1
        || shape.tree_depth != 0
    {
        return Err(ContentError::InvalidObject {
            object,
            detail: "invalid chunk object",
        });
    }
    Ok(())
}

fn decode_tree(
    object: ObjectId,
    record: &ObjectRecord,
    shape: ExpectedShape,
) -> Result<Vec<(ObjectId, u64, u64)>, ContentError> {
    let bytes = record.canonical_bytes();
    if record.format_version() != FORMAT_VERSION
        || record.class() != ObjectClass::Metadata
        || record.logical_bytes() != 0
        || bytes.len() < 18
    {
        return Err(ContentError::InvalidObject {
            object,
            detail: "invalid chunk-tree object",
        });
    }
    let count = usize::from(u16::from_le_bytes(
        bytes[0..2]
            .try_into()
            .map_err(|_| ContentError::LengthOverflow)?,
    ));
    let logical_bytes = u64::from_le_bytes(
        bytes[2..10]
            .try_into()
            .map_err(|_| ContentError::LengthOverflow)?,
    );
    let chunk_count = u64::from_le_bytes(
        bytes[10..18]
            .try_into()
            .map_err(|_| ContentError::LengthOverflow)?,
    );
    if count == 0
        || count > CHUNK_TREE_FANOUT
        || record.references().len() != count
        || bytes.len() != 18_usize.saturating_add(count.saturating_mul(16))
        || logical_bytes != shape.logical_bytes
        || chunk_count != shape.chunk_count
    {
        return Err(ContentError::InvalidObject {
            object,
            detail: "chunk-tree header is inconsistent",
        });
    }
    let mut children = Vec::with_capacity(count);
    let mut total = 0_u64;
    let mut total_chunks = 0_u64;
    let child_capacity = tree_capacity(shape.tree_depth.saturating_sub(1));
    for (index, reference) in record.references().iter().enumerate() {
        let expected_label = u16::try_from(index)
            .map_err(|_| ContentError::LengthOverflow)?
            .to_be_bytes();
        if reference.label().as_bytes() != expected_label || reference.kind() != ReferenceKind::Owns
        {
            return Err(ContentError::InvalidObject {
                object,
                detail: "chunk-tree child reference is non-canonical",
            });
        }
        let start = 18_usize.saturating_add(index.saturating_mul(16));
        let child_length = u64::from_le_bytes(
            bytes[start..start.saturating_add(8)]
                .try_into()
                .map_err(|_| ContentError::LengthOverflow)?,
        );
        let child_chunk_count = u64::from_le_bytes(
            bytes[start.saturating_add(8)..start.saturating_add(16)]
                .try_into()
                .map_err(|_| ContentError::LengthOverflow)?,
        );
        if child_length == 0
            || child_chunk_count == 0
            || child_chunk_count > child_capacity
            || (index.saturating_add(1) < count && child_chunk_count != child_capacity)
        {
            return Err(ContentError::InvalidObject {
                object,
                detail: "chunk-tree child shape is non-canonical",
            });
        }
        total = total
            .checked_add(child_length)
            .ok_or(ContentError::LengthOverflow)?;
        total_chunks = total_chunks
            .checked_add(child_chunk_count)
            .ok_or(ContentError::LengthOverflow)?;
        children.push((reference.target(), child_length, child_chunk_count));
    }
    if total != logical_bytes || total_chunks != chunk_count {
        return Err(ContentError::InvalidObject {
            object,
            detail: "chunk-tree child totals do not sum to header",
        });
    }
    Ok(children)
}

fn canonical_tree_depth(chunk_count: u64) -> u32 {
    let mut depth = 0_u32;
    let mut capacity = 1_u64;
    while capacity < chunk_count {
        capacity = capacity.saturating_mul(CHUNK_TREE_FANOUT as u64);
        depth = depth.saturating_add(1);
    }
    depth
}

fn tree_capacity(depth: u32) -> u64 {
    (0..depth).fold(1_u64, |capacity, _| {
        capacity.saturating_mul(CHUNK_TREE_FANOUT as u64)
    })
}

fn load<S: ContentSource>(
    source: &S,
    object: ObjectId,
) -> Result<ObjectRecord, ContentReadError<S::Error>> {
    source
        .load_content_object(object)
        .map_err(ContentReadError::Source)?
        .ok_or_else(|| ContentError::MissingObject(object).into())
}
