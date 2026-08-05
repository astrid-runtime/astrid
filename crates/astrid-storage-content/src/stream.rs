//! Bounded-source-memory construction of canonical content DAGs.

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
/// builder retains only the open right edge of the content tree and aggregate
/// metadata while the sink stages chunk and tree records. Exact distinct-chunk
/// accounting is intentionally delegated to the sink or store: computing it
/// inside the builder would retain one identity per unique chunk and defeat
/// the bounded-memory contract. The resulting file descriptor and object graph
/// are byte-for-byte identical to
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

    let mut tree = StreamingTree::default();
    let mut logical_bytes = 0_u64;
    if prefix.len() <= maximum {
        if !prefix.is_empty() {
            let child = stage_chunk(sink, &prefix, &mut logical_bytes)?;
            tree.push(sink, child)?;
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
            let child = stage_chunk(sink, &chunk.data, &mut logical_bytes)?;
            tree.push(sink, child)?;
        }
    }

    let chunk_count = tree.chunk_count();
    let content_root = tree.finish(sink)?;
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
    })
}

fn stage_chunk<S: ContentObjectSink>(
    sink: &mut S,
    bytes: &[u8],
    logical_bytes: &mut u64,
) -> Result<Child, ContentStreamError<S::Error>> {
    let record = chunk_record(bytes).map_err(ContentStreamError::Content)?;
    let id = sink
        .stage_content_object(record)
        .map_err(ContentStreamError::Sink)?;
    let length = u64::try_from(bytes.len()).map_err(content(ContentError::LengthOverflow))?;
    *logical_bytes = logical_bytes
        .checked_add(length)
        .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?;
    Ok(Child {
        id,
        logical_bytes: length,
        chunk_count: 1,
    })
}

/// Incremental canonical tree packer.
///
/// Every complete fanout group is emitted as soon as it fills. Only the open
/// right edge remains resident, so metadata is bounded by
/// `tree depth * CHUNK_TREE_FANOUT` rather than source chunk count.
#[derive(Default)]
pub(super) struct StreamingTree {
    levels: Vec<Vec<Child>>,
    chunk_count: u64,
}

impl StreamingTree {
    pub(super) const fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    #[cfg(test)]
    pub(super) fn pending_children(&self) -> usize {
        self.levels.iter().map(Vec::len).sum()
    }

    #[cfg(test)]
    pub(super) const fn levels_for_test(&self) -> usize {
        self.levels.len()
    }

    pub(super) fn push<S: ContentObjectSink>(
        &mut self,
        sink: &mut S,
        child: Child,
    ) -> Result<(), ContentStreamError<S::Error>> {
        self.chunk_count = self
            .chunk_count
            .checked_add(child.chunk_count)
            .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?;
        self.push_at_level(sink, 0, child)
    }

    fn push_at_level<S: ContentObjectSink>(
        &mut self,
        sink: &mut S,
        mut level: usize,
        mut child: Child,
    ) -> Result<(), ContentStreamError<S::Error>> {
        loop {
            if self.levels.len() <= level {
                self.levels.push(Vec::with_capacity(CHUNK_TREE_FANOUT));
            }
            let children = &mut self.levels[level];
            children.push(child);
            if children.len() < CHUNK_TREE_FANOUT {
                return Ok(());
            }
            child = stage_tree_node(sink, children)?;
            children.clear();
            level = level
                .checked_add(1)
                .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?;
        }
    }

    pub(super) fn finish<S: ContentObjectSink>(
        mut self,
        sink: &mut S,
    ) -> Result<Option<Child>, ContentStreamError<S::Error>> {
        if self.chunk_count == 0 {
            return Ok(None);
        }
        let mut level = 0_usize;
        loop {
            let has_higher = self
                .levels
                .get(level.saturating_add(1)..)
                .is_some_and(|levels| levels.iter().any(|children| !children.is_empty()));
            let children = self
                .levels
                .get_mut(level)
                .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?;
            if children.is_empty() {
                level = level
                    .checked_add(1)
                    .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?;
                continue;
            }
            if children.len() == 1 && !has_higher {
                return Ok(children.pop());
            }
            let parent = stage_tree_node(sink, children)?;
            children.clear();
            let parent_level = level
                .checked_add(1)
                .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?;
            self.push_at_level(sink, parent_level, parent)?;
            level = level
                .checked_add(1)
                .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?;
        }
    }
}

fn stage_tree_node<S: ContentObjectSink>(
    sink: &mut S,
    children: &[Child],
) -> Result<Child, ContentStreamError<S::Error>> {
    let (record, logical_bytes, chunk_count) =
        tree_record(children).map_err(ContentStreamError::Content)?;
    let id = sink
        .stage_content_object(record)
        .map_err(ContentStreamError::Sink)?;
    Ok(Child {
        id,
        logical_bytes,
        chunk_count,
    })
}

fn content<SinkError, SourceError>(
    error: ContentError,
) -> impl FnOnce(SourceError) -> ContentStreamError<SinkError> {
    move |_| ContentStreamError::Content(error)
}
