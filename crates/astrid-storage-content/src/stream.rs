//! Bounded-source-memory construction of canonical content DAGs.

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Cursor, Read};

use astrid_storage_model::{ObjectId, ObjectRecord};
use fastcdc::v2020::{Normalization, StreamCDC};

use crate::build::{Child, chunk_record, file_record, tree_record};
use crate::{
    CHUNK_TREE_FANOUT, ChunkingProfile, ContentDescriptor, ContentError, OpenedContent,
    VerifiedContent,
};

/// Sink for immutable records emitted during streaming content construction.
///
/// Implementations own the object-identity boundary: they must compute the
/// canonical identifier for `record`, stage it without publishing a principal
/// root, and reject an identity collision with a different existing record.
/// Repeated equal records must be idempotent.
pub trait ContentObjectSink {
    /// Sink-specific staging failure.
    type Error;

    /// Identity-check and stage one canonical immutable record.
    ///
    /// # Errors
    ///
    /// Returns a sink error without making a principal root authoritative.
    fn stage_content_object(&mut self, record: ObjectRecord) -> Result<ObjectId, Self::Error>;
}

/// Metadata produced by a streaming content build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamedContent {
    verified: VerifiedContent,
    unique_chunks: u64,
}

impl StreamedContent {
    /// Return the canonical file descriptor.
    #[must_use]
    pub const fn descriptor(self) -> ContentDescriptor {
        self.verified.descriptor()
    }

    /// Return proof that the streaming builder validated every file boundary.
    #[must_use]
    pub const fn verified_content(self) -> VerifiedContent {
        self.verified
    }

    /// Return the number of distinct chunk identities in the file.
    #[must_use]
    pub const fn unique_chunks(self) -> u64 {
        self.unique_chunks
    }
}

/// Failure while reading, constructing, or staging streamed content.
#[derive(Debug)]
pub enum ContentStreamError<E> {
    /// Canonical content construction failed.
    Content(ContentError),
    /// The byte source failed.
    Source(io::Error),
    /// The staging sink failed.
    Sink(E),
}

impl<E: fmt::Display> fmt::Display for ContentStreamError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Content(error) => write!(formatter, "{error}"),
            Self::Source(error) => write!(formatter, "content source: {error}"),
            Self::Sink(error) => write!(formatter, "content staging sink: {error}"),
        }
    }
}

impl<E> std::error::Error for ContentStreamError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Content(error) => Some(error),
            Self::Source(error) => Some(error),
            Self::Sink(error) => Some(error),
        }
    }
}

/// Build a canonical content DAG from a blocking byte stream.
///
/// Source memory is bounded by a constant multiple of the profile maximum:
/// prefetch, `FastCDC`'s internal buffer, and the current emitted chunk. The
/// builder retains only chunk identities and aggregate metadata while the sink
/// stages chunk and tree records. The resulting file descriptor and object
/// graph are byte-for-byte identical to
/// [`build_content`](crate::build_content), independent of source read
/// fragmentation.
///
/// A source or sink failure can occur after earlier immutable records were
/// staged. The sink must keep those records unreachable until its caller
/// publishes the returned descriptor through the normal principal-root commit.
/// Aborted staging may be discarded immediately or reclaimed as unreachable
/// data; this function never publishes a root.
///
/// # Errors
///
/// Returns a source, sink, profile-length, or object-model error. No file
/// descriptor is returned unless every source byte and canonical record was
/// staged successfully.
pub fn build_content_streaming<R, S>(
    profile: ChunkingProfile,
    mut source: R,
    sink: &mut S,
) -> Result<StreamedContent, ContentStreamError<S::Error>>
where
    R: Read,
    S: ContentObjectSink,
{
    let minimum =
        usize::try_from(profile.minimum_bytes()).map_err(content(ContentError::LengthOverflow))?;
    let average =
        usize::try_from(profile.average_bytes()).map_err(content(ContentError::LengthOverflow))?;
    let maximum =
        usize::try_from(profile.maximum_bytes()).map_err(content(ContentError::LengthOverflow))?;
    let prefix_limit = maximum
        .checked_add(1)
        .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?;
    let mut prefix = Vec::with_capacity(prefix_limit);
    source
        .by_ref()
        .take(u64::try_from(prefix_limit).map_err(content(ContentError::LengthOverflow))?)
        .read_to_end(&mut prefix)
        .map_err(ContentStreamError::Source)?;

    let mut chunks = Vec::new();
    let mut unique_chunks = BTreeSet::new();
    let mut logical_bytes = 0_u64;
    if prefix.len() <= maximum {
        if !prefix.is_empty() {
            stage_chunk(
                sink,
                &prefix,
                &mut chunks,
                &mut unique_chunks,
                &mut logical_bytes,
            )?;
        }
    } else {
        let chunker = StreamCDC::with_level_and_seed(
            Cursor::new(prefix).chain(source),
            minimum,
            average,
            maximum,
            Normalization::Level1,
            profile.gear_seed(),
        );
        for result in chunker {
            let chunk =
                result.map_err(|error| ContentStreamError::Source(io::Error::from(error)))?;
            stage_chunk(
                sink,
                &chunk.data,
                &mut chunks,
                &mut unique_chunks,
                &mut logical_bytes,
            )?;
        }
    }

    let chunk_count = u64::try_from(chunks.len()).map_err(content(ContentError::LengthOverflow))?;
    let content_root = stage_tree(sink, chunks)?;
    let file = file_record(profile, logical_bytes, chunk_count, content_root)
        .map_err(ContentStreamError::Content)?;
    let file = sink
        .stage_content_object(file)
        .map_err(ContentStreamError::Sink)?;
    let descriptor = ContentDescriptor::new(file, logical_bytes, chunk_count, profile);
    Ok(StreamedContent {
        verified: VerifiedContent::new(OpenedContent::new(
            descriptor,
            content_root.map(|child| child.id),
        )),
        unique_chunks: u64::try_from(unique_chunks.len())
            .map_err(content(ContentError::LengthOverflow))?,
    })
}

fn stage_chunk<S: ContentObjectSink>(
    sink: &mut S,
    bytes: &[u8],
    chunks: &mut Vec<Child>,
    unique_chunks: &mut BTreeSet<ObjectId>,
    logical_bytes: &mut u64,
) -> Result<(), ContentStreamError<S::Error>> {
    let record = chunk_record(bytes).map_err(ContentStreamError::Content)?;
    let id = sink
        .stage_content_object(record)
        .map_err(ContentStreamError::Sink)?;
    let length = u64::try_from(bytes.len()).map_err(content(ContentError::LengthOverflow))?;
    *logical_bytes = logical_bytes
        .checked_add(length)
        .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?;
    unique_chunks.insert(id);
    chunks.push(Child {
        id,
        logical_bytes: length,
        chunk_count: 1,
    });
    Ok(())
}

fn stage_tree<S: ContentObjectSink>(
    sink: &mut S,
    mut level: Vec<Child>,
) -> Result<Option<Child>, ContentStreamError<S::Error>> {
    if level.is_empty() {
        return Ok(None);
    }
    if level.len() == 1 {
        return Ok(level.pop());
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(CHUNK_TREE_FANOUT));
        for children in level.chunks(CHUNK_TREE_FANOUT) {
            let (record, logical_bytes, chunk_count) =
                tree_record(children).map_err(ContentStreamError::Content)?;
            let id = sink
                .stage_content_object(record)
                .map_err(ContentStreamError::Sink)?;
            next.push(Child {
                id,
                logical_bytes,
                chunk_count,
            });
        }
        level = next;
    }
    Ok(level.pop())
}

fn content<SinkError, SourceError>(
    error: ContentError,
) -> impl FnOnce(SourceError) -> ContentStreamError<SinkError> {
    move |_| ContentStreamError::Content(error)
}
