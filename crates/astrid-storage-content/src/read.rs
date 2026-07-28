use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::fmt;

use astrid_storage_model::{
    ObjectClass, ObjectId, ObjectKind, ObjectRecord, ReferenceKind, ReferenceLabel,
};

use crate::{
    CHUNK_TREE_FANOUT, CONTENT_LABEL, ChunkingProfile, ContentDescriptor, ContentError,
    FORMAT_VERSION, OpenedContent, VerifiedContent, boundary::is_canonical_boundary,
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

    /// Load one immutable object through a shared allocation.
    ///
    /// The default preserves existing sources by wrapping their owned result.
    /// Caching sources should override this method so a hit is only a reference
    /// count increment.
    ///
    /// # Errors
    ///
    /// Returns the source-specific error when the backing object arena cannot
    /// complete the read.
    fn load_shared_content_object(
        &self,
        id: ObjectId,
    ) -> Result<Option<Arc<ObjectRecord>>, Self::Error> {
        self.load_content_object(id)
            .map(|record| record.map(Arc::new))
    }

    /// Load a bounded group of immutable objects in request order.
    ///
    /// The default preserves sources without a batch path. Durable sources may
    /// coalesce physically adjacent immutable frames into fewer positional
    /// reads without changing validation or missing-object semantics.
    ///
    /// # Errors
    ///
    /// Returns the source-specific error when the backing object arena cannot
    /// complete the reads.
    fn load_content_objects(
        &self,
        ids: &[ObjectId],
    ) -> Result<Vec<Option<ObjectRecord>>, Self::Error> {
        ids.iter().map(|id| self.load_content_object(*id)).collect()
    }

    /// Load a bounded group through shared allocations in request order.
    ///
    /// The default preserves existing sources while allowing caching sources
    /// to return their resident immutable allocations without cloning them.
    ///
    /// # Errors
    ///
    /// Returns the source-specific error when the backing object arena cannot
    /// complete the reads.
    fn load_shared_content_objects(
        &self,
        ids: &[ObjectId],
    ) -> Result<Vec<Option<Arc<ObjectRecord>>>, Self::Error> {
        self.load_content_objects(ids).map(|records| {
            records
                .into_iter()
                .map(|record| record.map(Arc::new))
                .collect()
        })
    }
}

/// Process-local proofs for canonical boundaries inside immutable chunk trees.
///
/// Proofs are keyed by the identity of the tree node, the exact edge between
/// two adjacent children, and every identity-bearing chunking parameter. The
/// fields are private: non-empty state can only be produced by a successful
/// validating read. Embedders should partition this state at their authority
/// boundary and charge retained memory. Astrid's principal store keeps it in
/// the governed principal/object projection cache.
///
/// Each tree uses one 128-bit edge bitmap, so verification metadata is bounded
/// by the number of visited tree nodes rather than the logical file size.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContentVerificationState {
    edges: BTreeMap<VerificationDomain, u128>,
}

impl ContentVerificationState {
    /// Merge proofs returned by a successful range read.
    pub fn merge(&mut self, delta: ContentVerificationDelta) {
        for (domain, edges) in delta.edges {
            *self.edges.entry(domain).or_default() |= edges;
        }
    }

    /// Return a conservative resident-memory charge for process-local proof
    /// reuse.
    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        let entry = core::mem::size_of::<VerificationDomain>()
            .saturating_add(core::mem::size_of::<u128>())
            .saturating_add(core::mem::size_of::<usize>().saturating_mul(3));
        u64::try_from(
            core::mem::size_of::<Self>().saturating_add(self.edges.len().saturating_mul(entry)),
        )
        .unwrap_or(u64::MAX)
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn boundary_count(&self) -> u64 {
        self.edges
            .values()
            .map(|edges| u64::from(edges.count_ones()))
            .sum()
    }

    fn contains(&self, edge: VerifiedEdge) -> bool {
        self.edges
            .get(&edge.domain)
            .is_some_and(|edges| edges & edge.mask() != 0)
    }
}

/// Newly validated boundary proofs from one successful range read.
///
/// The type has no public constructor. A delta exists only after the content
/// reader has validated every boundary it contains.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContentVerificationDelta {
    edges: BTreeMap<VerificationDomain, u128>,
}

impl ContentVerificationDelta {
    /// Return whether the read discovered no new boundary proofs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn boundary_count(&self) -> u64 {
        self.edges
            .values()
            .map(|edges| u64::from(edges.count_ones()))
            .sum()
    }

    fn insert(&mut self, edge: VerifiedEdge) {
        *self.edges.entry(edge.domain).or_default() |= edge.mask();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct VerificationDomain {
    tree: ObjectId,
    minimum_bytes: u32,
    average_bytes: u32,
    maximum_bytes: u32,
    gear_seed: u64,
}

impl VerificationDomain {
    const fn new(tree: ObjectId, profile: ChunkingProfile) -> Self {
        Self {
            tree,
            minimum_bytes: profile.minimum_bytes(),
            average_bytes: profile.average_bytes(),
            maximum_bytes: profile.maximum_bytes(),
            gear_seed: profile.gear_seed(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VerifiedEdge {
    domain: VerificationDomain,
    left_child: u16,
}

impl VerifiedEdge {
    const fn new(tree: ObjectId, left_child: u16, profile: ChunkingProfile) -> Self {
        Self {
            domain: VerificationDomain::new(tree, profile),
            left_child,
        }
    }

    fn mask(self) -> u128 {
        1_u128 << u32::from(self.left_child)
    }
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
    open_content(source, file).map(OpenedContent::descriptor)
}

/// Open one immutable file for repeated reads.
///
/// The canonical file descriptor is loaded and validated once. Tree nodes and
/// chunks remain lazily loaded and verified for each requested range.
///
/// # Errors
///
/// Returns a source error, missing-object error, or canonical grammar error.
pub fn open_content<S: ContentSource>(
    source: &S,
    file: ObjectId,
) -> Result<OpenedContent, ContentReadError<S::Error>> {
    let record = load(source, file)?;
    let (profile, logical_bytes, chunk_count, content) = decode_file(file, &record)?;
    Ok(OpenedContent::new(
        ContentDescriptor::new(file, logical_bytes, chunk_count, profile),
        content,
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
    read_opened_content(source, open_content(source, file)?)
}

/// Reconstruct all bytes from an opened immutable file.
///
/// # Errors
///
/// Returns a source, allocation, missing-object, or canonical grammar error.
pub fn read_opened_content<S: ContentSource>(
    source: &S,
    opened: OpenedContent,
) -> Result<Vec<u8>, ContentReadError<S::Error>> {
    read_opened_content_and_verify(source, opened).map(|(bytes, _)| bytes)
}

/// Reconstruct all bytes and return proof of complete boundary validation.
///
/// # Errors
///
/// Returns a source, allocation, missing-object, or canonical grammar error.
/// No verification token is returned unless reconstruction and every canonical
/// boundary check complete successfully.
pub fn read_opened_content_and_verify<S: ContentSource>(
    source: &S,
    opened: OpenedContent,
) -> Result<(Vec<u8>, VerifiedContent), ContentReadError<S::Error>> {
    let descriptor = opened.descriptor();
    let (bytes, _) = read_decoded_range(
        source,
        descriptor.file(),
        (
            descriptor.profile(),
            descriptor.logical_bytes(),
            descriptor.chunk_count(),
            opened.content(),
        ),
        0,
        descriptor.logical_bytes(),
        BoundaryMode::Validate,
    )?;
    Ok((bytes, VerifiedContent::new(opened)))
}

/// Reconstruct all bytes from a previously verified immutable file.
///
/// Object identities and source checks remain enforced; only redundant
/// content-boundary validation is skipped.
///
/// # Errors
///
/// Returns a source, allocation, missing-object, or canonical grammar error.
pub fn read_verified_content<S: ContentSource>(
    source: &S,
    verified: VerifiedContent,
) -> Result<Vec<u8>, ContentReadError<S::Error>> {
    let opened = verified.opened_content();
    let descriptor = opened.descriptor();
    read_decoded_range(
        source,
        descriptor.file(),
        (
            descriptor.profile(),
            descriptor.logical_bytes(),
            descriptor.chunk_count(),
            opened.content(),
        ),
        0,
        descriptor.logical_bytes(),
        BoundaryMode::Skip,
    )
    .map(|(bytes, _)| bytes)
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
    read_opened_content_range(source, open_content(source, file)?, offset, length)
}

/// Reconstruct an exact byte range from an opened immutable file.
///
/// # Errors
///
/// Returns an out-of-bounds, source, allocation, missing-object, or canonical
/// grammar error.
pub fn read_opened_content_range<S: ContentSource>(
    source: &S,
    opened: OpenedContent,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, ContentReadError<S::Error>> {
    let descriptor = opened.descriptor();
    read_decoded_range(
        source,
        descriptor.file(),
        (
            descriptor.profile(),
            descriptor.logical_bytes(),
            descriptor.chunk_count(),
            opened.content(),
        ),
        offset,
        length,
        BoundaryMode::Validate,
    )
    .map(|(bytes, _)| bytes)
}

/// Reconstruct a range while reusing and extending local boundary proofs.
///
/// The known state can skip only `FastCDC` boundaries already validated for the
/// exact immutable tree edge and chunking profile. Object loading, canonical
/// decoding, shape validation, and range checks always remain active. The
/// returned delta is empty or contains only proofs established by this
/// successful read; callers may merge it after releasing any shared read lock.
///
/// # Errors
///
/// Returns an out-of-bounds, source, allocation, missing-object, or canonical
/// grammar error. No delta is returned when any check fails.
pub fn read_opened_content_range_with_verification<S: ContentSource>(
    source: &S,
    opened: OpenedContent,
    known: &ContentVerificationState,
    offset: u64,
    length: u64,
) -> Result<(Vec<u8>, ContentVerificationDelta), ContentReadError<S::Error>> {
    let descriptor = opened.descriptor();
    read_decoded_range(
        source,
        descriptor.file(),
        (
            descriptor.profile(),
            descriptor.logical_bytes(),
            descriptor.chunk_count(),
            opened.content(),
        ),
        offset,
        length,
        BoundaryMode::Reuse(known),
    )
}

/// Reconstruct a range from a previously verified immutable file.
///
/// Object identities and source checks remain enforced; only redundant
/// content-boundary validation is skipped.
///
/// # Errors
///
/// Returns an out-of-bounds, source, allocation, missing-object, or canonical
/// grammar error.
pub fn read_verified_content_range<S: ContentSource>(
    source: &S,
    verified: VerifiedContent,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, ContentReadError<S::Error>> {
    let opened = verified.opened_content();
    let descriptor = opened.descriptor();
    read_decoded_range(
        source,
        descriptor.file(),
        (
            descriptor.profile(),
            descriptor.logical_bytes(),
            descriptor.chunk_count(),
            opened.content(),
        ),
        offset,
        length,
        BoundaryMode::Skip,
    )
    .map(|(bytes, _)| bytes)
}

#[derive(Clone, Copy)]
enum BoundaryMode<'a> {
    Skip,
    Validate,
    Reuse(&'a ContentVerificationState),
}

fn read_decoded_range<S: ContentSource>(
    source: &S,
    file: ObjectId,
    decoded: (ChunkingProfile, u64, u64, Option<ObjectId>),
    offset: u64,
    length: u64,
    boundary_mode: BoundaryMode<'_>,
) -> Result<(Vec<u8>, ContentVerificationDelta), ContentReadError<S::Error>> {
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
        return Ok((output, ContentVerificationDelta::default()));
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
    let mut boundaries = match boundary_mode {
        BoundaryMode::Skip => None,
        BoundaryMode::Validate => Some(BoundaryWindow::new(None)),
        BoundaryMode::Reuse(known) => Some(BoundaryWindow::new(Some(known))),
    };
    let record = load(source, content)?;
    let mut traversal = RangeTraversal {
        range: RequestedRange { start: offset, end },
        output: &mut output,
        boundaries: &mut boundaries,
    };
    append_loaded_range(
        source,
        TraversalNode {
            object: content,
            record,
            shape,
            base_offset: 0,
            path: Vec::new(),
        },
        &mut traversal,
    )?;
    if let Some(boundaries) = &mut boundaries {
        boundaries.validate_neighbors(source, content, shape, logical_bytes)?;
    }
    if output.len() != capacity {
        return Err(ContentError::InvalidObject {
            object: file,
            detail: "content tree reconstructed the wrong range length",
        }
        .into());
    }
    Ok((
        output,
        boundaries
            .map(BoundaryWindow::into_delta)
            .unwrap_or_default(),
    ))
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
    path: Vec<TreeStep>,
}

struct TraversalNode {
    object: ObjectId,
    record: Arc<ObjectRecord>,
    shape: ExpectedShape,
    base_offset: u64,
    path: Vec<TreeStep>,
}

struct RangeTraversal<'output, 'verification> {
    range: RequestedRange,
    output: &'output mut Vec<u8>,
    boundaries: &'output mut Option<BoundaryWindow<'verification>>,
}

impl LoadedChunk {
    fn end(&self) -> Result<u64, ContentError> {
        self.start
            .checked_add(u64::try_from(self.bytes.len()).map_err(|_| ContentError::LengthOverflow)?)
            .ok_or(ContentError::LengthOverflow)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TreeStep {
    tree: ObjectId,
    child_index: u16,
    child_count: u16,
}

struct BoundaryWindow<'a> {
    known: Option<&'a ContentVerificationState>,
    delta: ContentVerificationDelta,
    first_start: Option<u64>,
    first_prefix: Vec<u8>,
    first_path: Vec<TreeStep>,
    last: Option<LoadedChunk>,
}

impl<'a> BoundaryWindow<'a> {
    fn new(known: Option<&'a ContentVerificationState>) -> Self {
        Self {
            known,
            delta: ContentVerificationDelta::default(),
            first_start: None,
            first_prefix: Vec::new(),
            first_path: Vec::new(),
            last: None,
        }
    }

    fn into_delta(self) -> ContentVerificationDelta {
        self.delta
    }

    fn observe(
        &mut self,
        object: ObjectId,
        start: u64,
        bytes: &[u8],
        path: &[TreeStep],
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
        if let Some(previous) = self.last.take() {
            if previous.end()? != start {
                return Err(ContentError::InvalidObject {
                    object,
                    detail: "content traversal skipped an overlapping chunk",
                });
            }
            let edge = edge_between(&previous.path, path, object, profile)?;
            self.validate_edge(&previous, prefix, edge, profile)?;
        } else {
            self.first_start = Some(start);
            self.first_prefix.extend_from_slice(prefix);
            self.first_path.extend_from_slice(path);
        }
        self.last = Some(LoadedChunk {
            object,
            start,
            bytes: bytes.to_vec(),
            path: path.to_vec(),
        });
        Ok(())
    }

    fn validate_neighbors<S: ContentSource>(
        &mut self,
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
            let edge = edge_before(&self.first_path, content, shape.profile)?;
            if !self.is_verified(edge) {
                let previous = load_chunk_at_offset(
                    source,
                    content,
                    shape,
                    0,
                    first_start.saturating_sub(1),
                    Vec::new(),
                )?;
                let prefix = self.first_prefix.clone();
                self.validate_edge(&previous, &prefix, edge, shape.profile)?;
            }
        }
        let last = self.last.take().ok_or(ContentError::InvalidObject {
            object: content,
            detail: "non-empty range selected no final content chunk",
        })?;
        let last_end = last.end()?;
        if last_end < logical_bytes {
            let edge = edge_after(&last.path, content, shape.profile)?;
            if !self.is_verified(edge) {
                let next = load_chunk_at_offset(source, content, shape, 0, last_end, Vec::new())?;
                let prefix_length = next.bytes.len().min(2);
                self.validate_edge(&last, &next.bytes[..prefix_length], edge, shape.profile)?;
            }
        }
        Ok(())
    }

    fn is_verified(&self, edge: VerifiedEdge) -> bool {
        self.known.is_some_and(|known| known.contains(edge))
            || self
                .delta
                .edges
                .get(&edge.domain)
                .is_some_and(|edges| edges & edge.mask() != 0)
    }

    fn validate_edge(
        &mut self,
        left: &LoadedChunk,
        right_prefix: &[u8],
        edge: VerifiedEdge,
        profile: ChunkingProfile,
    ) -> Result<(), ContentError> {
        if self.is_verified(edge) {
            return Ok(());
        }
        validate_boundary(left, right_prefix, profile)?;
        self.delta.insert(edge);
        Ok(())
    }
}

fn edge_between(
    left: &[TreeStep],
    right: &[TreeStep],
    object: ObjectId,
    profile: ChunkingProfile,
) -> Result<VerifiedEdge, ContentError> {
    for (left, right) in left.iter().zip(right) {
        if left == right {
            continue;
        }
        if left.tree == right.tree && right.child_index == left.child_index.saturating_add(1) {
            return Ok(VerifiedEdge::new(left.tree, left.child_index, profile));
        }
        return Err(ContentError::InvalidObject {
            object,
            detail: "adjacent chunks have inconsistent tree paths",
        });
    }
    Err(ContentError::InvalidObject {
        object,
        detail: "adjacent chunks do not diverge at a tree edge",
    })
}

fn edge_before(
    path: &[TreeStep],
    object: ObjectId,
    profile: ChunkingProfile,
) -> Result<VerifiedEdge, ContentError> {
    path.iter()
        .rev()
        .find(|step| step.child_index > 0)
        .map(|step| VerifiedEdge::new(step.tree, step.child_index.saturating_sub(1), profile))
        .ok_or(ContentError::InvalidObject {
            object,
            detail: "non-initial chunk has no preceding tree edge",
        })
}

fn edge_after(
    path: &[TreeStep],
    object: ObjectId,
    profile: ChunkingProfile,
) -> Result<VerifiedEdge, ContentError> {
    path.iter()
        .rev()
        .find(|step| step.child_index.saturating_add(1) < step.child_count)
        .map(|step| VerifiedEdge::new(step.tree, step.child_index, profile))
        .ok_or(ContentError::InvalidObject {
            object,
            detail: "non-final chunk has no following tree edge",
        })
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

fn append_loaded_range<S: ContentSource>(
    source: &S,
    node: TraversalNode,
    traversal: &mut RangeTraversal<'_, '_>,
) -> Result<(), ContentReadError<S::Error>> {
    match node.record.kind() {
        ObjectKind::Chunk => append_chunk_range(node, traversal),
        ObjectKind::ChunkTree => append_tree_range(source, node, traversal),
        _ => Err(ContentError::InvalidObject {
            object: node.object,
            detail: "file content points to an unsupported object kind",
        }
        .into()),
    }
}

fn append_chunk_range<E>(
    node: TraversalNode,
    traversal: &mut RangeTraversal<'_, '_>,
) -> Result<(), ContentReadError<E>> {
    let TraversalNode {
        object,
        record,
        shape,
        base_offset,
        path,
    } = node;
    validate_chunk(object, &record, shape)?;
    if let Some(boundaries) = traversal.boundaries.as_mut() {
        boundaries.observe(
            object,
            base_offset,
            record.canonical_bytes(),
            &path,
            shape.profile,
        )?;
    }
    let chunk_end = base_offset
        .checked_add(shape.logical_bytes)
        .ok_or(ContentError::LengthOverflow)?;
    let start = usize::try_from(
        traversal
            .range
            .start
            .max(base_offset)
            .saturating_sub(base_offset),
    )
    .map_err(|_| ContentError::LengthOverflow)?;
    let end = usize::try_from(
        traversal
            .range
            .end
            .min(chunk_end)
            .saturating_sub(base_offset),
    )
    .map_err(|_| ContentError::LengthOverflow)?;
    let bytes = record
        .canonical_bytes()
        .get(start..end)
        .ok_or(ContentError::InvalidObject {
            object,
            detail: "chunk range exceeds payload",
        })?;
    traversal.output.extend_from_slice(bytes);
    Ok(())
}

fn append_tree_range<S: ContentSource>(
    source: &S,
    node: TraversalNode,
    traversal: &mut RangeTraversal<'_, '_>,
) -> Result<(), ContentReadError<S::Error>> {
    let TraversalNode {
        object,
        record,
        shape,
        base_offset,
        path,
    } = node;
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
    let child_count_u16 = u16::try_from(child_count).map_err(|_| ContentError::LengthOverflow)?;
    let mut selected = Vec::new();
    for (index, (child, child_length, child_chunk_count)) in children.into_iter().enumerate() {
        let child_end = cursor
            .checked_add(child_length)
            .ok_or(ContentError::LengthOverflow)?;
        let child_base = base_offset
            .checked_add(cursor)
            .ok_or(ContentError::LengthOverflow)?;
        let child_absolute_end = base_offset
            .checked_add(child_end)
            .ok_or(ContentError::LengthOverflow)?;
        if traversal.range.start < child_absolute_end && traversal.range.end > child_base {
            let child_index = u16::try_from(index).map_err(|_| ContentError::LengthOverflow)?;
            let mut child_path = path.clone();
            child_path.push(TreeStep {
                tree: object,
                child_index,
                child_count: child_count_u16,
            });
            selected.push((
                child,
                ExpectedShape {
                    logical_bytes: child_length,
                    chunk_count: child_chunk_count,
                    tree_depth: shape.tree_depth.saturating_sub(1),
                    profile: shape.profile,
                    ends_file: shape.ends_file && index.saturating_add(1) == child_count,
                },
                child_base,
                child_path,
            ));
        }
        cursor = child_end;
    }
    let ids: Vec<_> = selected.iter().map(|(child, _, _, _)| *child).collect();
    let records = load_many(source, &ids)?;
    for ((child, child_shape, child_base, child_path), record) in selected.into_iter().zip(records)
    {
        append_loaded_range(
            source,
            TraversalNode {
                object: child,
                record,
                shape: child_shape,
                base_offset: child_base,
                path: child_path,
            },
            traversal,
        )?;
    }
    Ok(())
}

fn load_many<S: ContentSource>(
    source: &S,
    objects: &[ObjectId],
) -> Result<Vec<Arc<ObjectRecord>>, ContentReadError<S::Error>> {
    let Some(first) = objects.first().copied() else {
        return Ok(Vec::new());
    };
    let records = source
        .load_shared_content_objects(objects)
        .map_err(ContentReadError::Source)?;
    if records.len() != objects.len() {
        return Err(ContentError::InvalidObject {
            object: first,
            detail: "content source returned the wrong batch length",
        }
        .into());
    }
    objects
        .iter()
        .copied()
        .zip(records)
        .map(|(object, record)| {
            record.ok_or_else(|| ContentReadError::Content(ContentError::MissingObject(object)))
        })
        .collect()
}

fn load_chunk_at_offset<S: ContentSource>(
    source: &S,
    object: ObjectId,
    shape: ExpectedShape,
    base_offset: u64,
    target_offset: u64,
    path: Vec<TreeStep>,
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
                path,
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
                    let child_index =
                        u16::try_from(index).map_err(|_| ContentError::LengthOverflow)?;
                    let child_count_u16 =
                        u16::try_from(child_count).map_err(|_| ContentError::LengthOverflow)?;
                    let mut child_path = path;
                    child_path.push(TreeStep {
                        tree: object,
                        child_index,
                        child_count: child_count_u16,
                    });
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
                        child_path,
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
    let mut minimum_total = required_full_chunks
        .checked_mul(u64::from(profile.minimum_bytes()))
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
) -> Result<Arc<ObjectRecord>, ContentReadError<S::Error>> {
    source
        .load_shared_content_object(object)
        .map_err(ContentReadError::Source)?
        .ok_or_else(|| ContentError::MissingObject(object).into())
}
