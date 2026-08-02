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
    peak_pending_tree_children: usize,
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

    /// Return the peak number of child summaries retained for tree assembly.
    ///
    /// This is host-side construction evidence, not a deduplication outcome.
    #[must_use]
    pub const fn peak_pending_tree_children(self) -> usize {
        self.peak_pending_tree_children
    }
}

/// Bounded carry stack for canonical fanout-packed `ChunkTree` construction.
///
/// Each level retains only its unfinished right edge. A full group is staged
/// immediately and its aggregate child is carried into the next level.
pub(super) struct TreeAccumulator {
    levels: Vec<Vec<Child>>,
    pending_children: usize,
    peak_pending_children: usize,
}

impl TreeAccumulator {
    pub(super) fn new() -> Self {
        Self {
            levels: Vec::new(),
            pending_children: 0,
            peak_pending_children: 0,
        }
    }

    pub(super) fn push<S: ContentObjectSink>(
        &mut self,
        sink: &mut S,
        child: Child,
    ) -> Result<(), ContentStreamError<S::Error>> {
        self.push_at(sink, 0, child)
    }

    fn push_at<S: ContentObjectSink>(
        &mut self,
        sink: &mut S,
        mut level: usize,
        child: Child,
    ) -> Result<(), ContentStreamError<S::Error>> {
        let mut carried = child;
        loop {
            if level == self.levels.len() {
                self.levels.push(Vec::with_capacity(CHUNK_TREE_FANOUT));
            }
            let children = &mut self.levels[level];
            children.push(carried);
            self.pending_children = self
                .pending_children
                .checked_add(1)
                .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?;
            self.peak_pending_children = self.peak_pending_children.max(self.pending_children);
            if children.len() != CHUNK_TREE_FANOUT {
                return Ok(());
            }
            carried = stage_tree_node(sink, children)?;
            self.pending_children = self
                .pending_children
                .checked_sub(children.len())
                .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?;
            children.clear();
            level = level
                .checked_add(1)
                .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?;
        }
    }

    pub(super) fn finish<S: ContentObjectSink>(
        mut self,
        sink: &mut S,
    ) -> Result<(Option<Child>, usize), ContentStreamError<S::Error>> {
        loop {
            let Some(level) = self.levels.iter().position(|children| !children.is_empty()) else {
                return Ok((None, self.peak_pending_children));
            };
            let higher_start = level
                .checked_add(1)
                .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?;
            let has_higher_children = self.levels[higher_start..]
                .iter()
                .any(|children| !children.is_empty());
            if self.levels[level].len() == 1 && !has_higher_children {
                let root = self.levels[level]
                    .pop()
                    .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?;
                self.pending_children = self
                    .pending_children
                    .checked_sub(1)
                    .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?;
                return Ok((Some(root), self.peak_pending_children));
            }

            let parent = stage_tree_node(sink, &self.levels[level])?;
            self.pending_children = self
                .pending_children
                .checked_sub(self.levels[level].len())
                .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?;
            self.levels[level].clear();
            self.push_at(
                sink,
                level
                    .checked_add(1)
                    .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?,
                parent,
            )?;
        }
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
/// builder retains only the unfinished right edge at each active tree level
/// while the sink stages chunk and completed tree records. Live builder
/// metadata is `O(tree depth * fanout)`, independent of the chunk count. The
/// resulting file descriptor and object graph are byte-for-byte identical to
/// [`build_content`](crate::build_content), independent of source read
/// fragmentation.
///
/// The streaming result deliberately does not compute an exact distinct-chunk
/// count: exact distinct counting requires retaining or externally spilling a
/// set proportional to the chunk count and is not part of logical identity.
/// Offline evidence can derive that diagnostic from staged records.
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

    let mut tree = TreeAccumulator::new();
    let mut logical_bytes = 0_u64;
    let mut chunk_count = 0_u64;
    if prefix.len() <= maximum {
        if !prefix.is_empty() {
            stage_chunk(
                sink,
                &prefix,
                &mut tree,
                &mut logical_bytes,
                &mut chunk_count,
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
                &mut tree,
                &mut logical_bytes,
                &mut chunk_count,
            )?;
        }
    }

    let (content_root, peak_pending_tree_children) = tree.finish(sink)?;
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
        peak_pending_tree_children,
    })
}

fn stage_chunk<S: ContentObjectSink>(
    sink: &mut S,
    bytes: &[u8],
    tree: &mut TreeAccumulator,
    logical_bytes: &mut u64,
    chunk_count: &mut u64,
) -> Result<(), ContentStreamError<S::Error>> {
    let record = chunk_record(bytes).map_err(ContentStreamError::Content)?;
    let id = sink
        .stage_content_object(record)
        .map_err(ContentStreamError::Sink)?;
    let length = u64::try_from(bytes.len()).map_err(content(ContentError::LengthOverflow))?;
    *logical_bytes = logical_bytes
        .checked_add(length)
        .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?;
    *chunk_count = chunk_count
        .checked_add(1)
        .ok_or_else(|| ContentStreamError::Content(ContentError::LengthOverflow))?;
    tree.push(
        sink,
        Child {
            id,
            logical_bytes: length,
            chunk_count: 1,
        },
    )
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
