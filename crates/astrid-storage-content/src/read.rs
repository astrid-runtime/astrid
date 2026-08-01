use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::fmt;

use astrid_storage_model::{ObjectId, ObjectRecord};

use crate::{ChunkingProfile, ContentDescriptor, ContentError, OpenedContent, VerifiedContent};

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

mod traversal;

use traversal::{BoundaryMode, decode_file, load, read_decoded_range};
