use alloc::vec::Vec;
use core::fmt;

use astrid_storage_model::{
    ObjectClass, ObjectId, ObjectKind, ObjectRecord, ReferenceKind, ReferenceLabel,
};

use crate::{
    CHUNK_TREE_FANOUT, CONTENT_LABEL, ChunkingProfile, ContentDescriptor, ContentError,
    FORMAT_VERSION,
    boundary::{is_canonical_boundary, is_canonical_final_chunk},
    decode_file_header,
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

impl<E> core::error::Error for ContentReadError<E>
where
    E: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Content(error) => Some(error),
            Self::Source(error) => Some(error),
        }
    }
}

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
    let record = load(source, file)?;
    let decoded = decode_file(file, &record)?;
    let logical_bytes = decoded.1;
    read_decoded_range(source, file, decoded, 0, logical_bytes)
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
    let decoded = decode_file(file, &record)?;
    read_decoded_range(source, file, decoded, offset, length)
}

fn read_decoded_range<S: ContentSource>(
    source: &S,
    file: ObjectId,
    decoded: (ChunkingProfile, u64, u64, Option<ObjectId>),
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, ContentReadError<S::Error>> {
    let (profile, logical_bytes, chunk_count, content) = decoded;
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
    let shape = ExpectedShape {
        logical_bytes,
        chunk_count,
        tree_depth: canonical_tree_depth(chunk_count),
        profile,
        ends_file: true,
    };
    let mut boundaries = BoundaryWindow::default();
    append_range(
        source,
        content,
        shape,
        RequestedRange { start: offset, end },
        0,
        &mut output,
        &mut boundaries,
    )?;
    boundaries.validate_neighbors(source, content, shape, logical_bytes)?;
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
    profile: ChunkingProfile,
    ends_file: bool,
}

#[derive(Clone, Copy)]
struct RequestedRange {
    start: u64,
    end: u64,
}

struct LoadedChunk {
    object: ObjectId,
    start: u64,
    bytes: Vec<u8>,
}

impl LoadedChunk {
    fn end(&self) -> Result<u64, ContentError> {
        self.start
            .checked_add(u64::try_from(self.bytes.len()).map_err(|_| ContentError::LengthOverflow)?)
            .ok_or(ContentError::LengthOverflow)
    }
}

#[derive(Default)]
struct BoundaryWindow {
    first_start: Option<u64>,
    first_prefix: Vec<u8>,
    last: Option<LoadedChunk>,
}

impl BoundaryWindow {
    fn observe(
        &mut self,
        object: ObjectId,
        start: u64,
        bytes: &[u8],
        profile: ChunkingProfile,
    ) -> Result<(), ContentError> {
        if bytes.is_empty() {
            return Err(ContentError::InvalidObject {
                object,
                detail: "content chunk is empty",
            });
        }
        let prefix_length = bytes.len().min(2);
        let prefix = &bytes[..prefix_length];
        if let Some(previous) = &self.last {
            if previous.end()? != start {
                return Err(ContentError::InvalidObject {
                    object,
                    detail: "content traversal skipped an overlapping chunk",
                });
            }
            validate_boundary(previous, prefix, profile)?;
        } else {
            self.first_start = Some(start);
            self.first_prefix.extend_from_slice(prefix);
        }
        self.last = Some(LoadedChunk {
            object,
            start,
            bytes: bytes.to_vec(),
        });
        Ok(())
    }

    fn validate_neighbors<S: ContentSource>(
        &self,
        source: &S,
        content: ObjectId,
        shape: ExpectedShape,
        logical_bytes: u64,
    ) -> Result<(), ContentReadError<S::Error>> {
        let first_start = self.first_start.ok_or(ContentError::InvalidObject {
            object: content,
            detail: "non-empty range selected no content chunk",
        })?;
        if first_start > 0 {
            let previous =
                load_chunk_at_offset(source, content, shape, 0, first_start.saturating_sub(1))?;
            validate_boundary(&previous, &self.first_prefix, shape.profile)?;
        }
        let last = self.last.as_ref().ok_or(ContentError::InvalidObject {
            object: content,
            detail: "non-empty range selected no final content chunk",
        })?;
        let last_end = last.end()?;
        if last_end < logical_bytes {
            let next = load_chunk_at_offset(source, content, shape, 0, last_end)?;
            let prefix_length = next.bytes.len().min(2);
            validate_boundary(last, &next.bytes[..prefix_length], shape.profile)?;
        } else if shape.chunk_count > 1 && !is_canonical_final_chunk(&last.bytes, shape.profile) {
            return Err(ContentError::InvalidObject {
                object: last.object,
                detail: "final chunk violates the declared FastCDC profile",
            }
            .into());
        }
        Ok(())
    }
}

fn validate_boundary(
    left: &LoadedChunk,
    right_prefix: &[u8],
    profile: ChunkingProfile,
) -> Result<(), ContentError> {
    if is_canonical_boundary(&left.bytes, right_prefix, profile) {
        Ok(())
    } else {
        Err(ContentError::InvalidObject {
            object: left.object,
            detail: "chunk boundary violates the declared FastCDC profile",
        })
    }
}

fn append_range<S: ContentSource>(
    source: &S,
    object: ObjectId,
    shape: ExpectedShape,
    range: RequestedRange,
    base_offset: u64,
    output: &mut Vec<u8>,
    boundaries: &mut BoundaryWindow,
) -> Result<(), ContentReadError<S::Error>> {
    let record = load(source, object)?;
    match record.kind() {
        ObjectKind::Chunk => {
            validate_chunk(object, &record, shape)?;
            boundaries.observe(object, base_offset, record.canonical_bytes(), shape.profile)?;
            let chunk_end = base_offset
                .checked_add(shape.logical_bytes)
                .ok_or(ContentError::LengthOverflow)?;
            let start = usize::try_from(range.start.max(base_offset).saturating_sub(base_offset))
                .map_err(|_| ContentError::LengthOverflow)?;
            let end = usize::try_from(range.end.min(chunk_end).saturating_sub(base_offset))
                .map_err(|_| ContentError::LengthOverflow)?;
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
            let child_count = children.len();
            for (index, (child, child_length, child_chunk_count)) in
                children.into_iter().enumerate()
            {
                let child_end = cursor
                    .checked_add(child_length)
                    .ok_or(ContentError::LengthOverflow)?;
                let child_base = base_offset
                    .checked_add(cursor)
                    .ok_or(ContentError::LengthOverflow)?;
                let child_absolute_end = base_offset
                    .checked_add(child_end)
                    .ok_or(ContentError::LengthOverflow)?;
                if range.start < child_absolute_end && range.end > child_base {
                    append_range(
                        source,
                        child,
                        ExpectedShape {
                            logical_bytes: child_length,
                            chunk_count: child_chunk_count,
                            tree_depth: shape.tree_depth.saturating_sub(1),
                            profile: shape.profile,
                            ends_file: shape.ends_file && index.saturating_add(1) == child_count,
                        },
                        range,
                        child_base,
                        output,
                        boundaries,
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

fn load_chunk_at_offset<S: ContentSource>(
    source: &S,
    object: ObjectId,
    shape: ExpectedShape,
    base_offset: u64,
    target_offset: u64,
) -> Result<LoadedChunk, ContentReadError<S::Error>> {
    let record = load(source, object)?;
    match record.kind() {
        ObjectKind::Chunk => {
            validate_chunk(object, &record, shape)?;
            let end = base_offset
                .checked_add(shape.logical_bytes)
                .ok_or(ContentError::LengthOverflow)?;
            if target_offset < base_offset || target_offset >= end {
                return Err(ContentError::InvalidObject {
                    object,
                    detail: "chunk lookup offset is outside the payload",
                }
                .into());
            }
            Ok(LoadedChunk {
                object,
                start: base_offset,
                bytes: record.canonical_bytes().to_vec(),
            })
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
            let child_count = children.len();
            for (index, (child, child_length, child_chunk_count)) in
                children.into_iter().enumerate()
            {
                let child_base = base_offset
                    .checked_add(cursor)
                    .ok_or(ContentError::LengthOverflow)?;
                let child_end = child_base
                    .checked_add(child_length)
                    .ok_or(ContentError::LengthOverflow)?;
                if target_offset >= child_base && target_offset < child_end {
                    return load_chunk_at_offset(
                        source,
                        child,
                        ExpectedShape {
                            logical_bytes: child_length,
                            chunk_count: child_chunk_count,
                            tree_depth: shape.tree_depth.saturating_sub(1),
                            profile: shape.profile,
                            ends_file: shape.ends_file && index.saturating_add(1) == child_count,
                        },
                        child_base,
                        target_offset,
                    );
                }
                cursor = cursor
                    .checked_add(child_length)
                    .ok_or(ContentError::LengthOverflow)?;
            }
            Err(ContentError::InvalidObject {
                object,
                detail: "chunk lookup found no covering child",
            }
            .into())
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
    if logical_bytes != 0
        && (chunk_count == 1) != (logical_bytes <= u64::from(profile.maximum_bytes()))
    {
        return Err(ContentError::InvalidObject {
            object,
            detail: "file chunk count violates the whole-object threshold",
        });
    }
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
    validate_profile_bounds(
        object,
        actual,
        shape.chunk_count,
        shape.profile,
        shape.ends_file,
    )?;
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
        validate_profile_bounds(
            object,
            child_length,
            child_chunk_count,
            shape.profile,
            shape.ends_file && index.saturating_add(1) == count,
        )?;
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

fn validate_profile_bounds(
    object: ObjectId,
    logical_bytes: u64,
    chunk_count: u64,
    profile: ChunkingProfile,
    ends_file: bool,
) -> Result<(), ContentError> {
    let maximum = u64::from(profile.maximum_bytes());
    let maximum_total = chunk_count
        .checked_mul(maximum)
        .ok_or(ContentError::LengthOverflow)?;
    let required_full_chunks = if ends_file {
        chunk_count.saturating_sub(1)
    } else {
        chunk_count
    };
    // FastCDC 2020 begins its two-byte loop at floor(minimum / 2), so an odd
    // declared minimum has an effective non-final lower bound one byte lower.
    let effective_minimum = u64::from(profile.minimum_bytes() & !1);
    let mut minimum_total = required_full_chunks
        .checked_mul(effective_minimum)
        .ok_or(ContentError::LengthOverflow)?;
    if ends_file {
        minimum_total = minimum_total
            .checked_add(1)
            .ok_or(ContentError::LengthOverflow)?;
    }
    if logical_bytes < minimum_total || logical_bytes > maximum_total {
        return Err(ContentError::InvalidObject {
            object,
            detail: "content shape violates the declared chunking profile",
        });
    }
    Ok(())
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
