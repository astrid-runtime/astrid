//! Deterministic, evictable resemblance sketches over verified content chunks.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::fmt;
use std::num::NonZeroU16;

use astrid_storage_content::{
    ContentDescriptor, ContentReadError, ContentSource, describe_content,
};
use astrid_storage_model::{ModelError, ObjectId, ObjectIdentity, ObjectKind, ObjectRecord};

use super::{
    ProposedRefineryOutput, RefineryBatchContext, RefineryPass, RefineryPassDescriptorId,
    RefineryProposalError, RefineryProposalSink, RefineryRunError, VerifiedRefineryObject,
    run_refinery_observer,
};

mod wire;

use wire::{decode_descriptor, descriptor_record, sketch_record};

#[cfg(test)]
mod tests;

/// Non-zero number of scores retained by one bottom-k sketch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SketchSampleSize(NonZeroU16);

impl SketchSampleSize {
    /// Construct a non-zero sample size.
    #[must_use]
    pub const fn new(value: u16) -> Option<Self> {
        match NonZeroU16::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return the number of scores retained.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

/// Width of each non-authoritative resemblance score.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SketchScoreWidth {
    /// First 128 bits of the pinned BLAKE3 score.
    Bits128,
    /// Complete 256-bit pinned BLAKE3 score.
    Bits256,
}

impl SketchScoreWidth {
    /// Return the score width in bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        match self {
            Self::Bits128 => 128,
            Self::Bits256 => 256,
        }
    }

    pub(super) const fn bytes(self) -> usize {
        match self {
            Self::Bits128 => 16,
            Self::Bits256 => 32,
        }
    }

    pub(super) const fn code(self) -> u16 {
        match self {
            Self::Bits128 => 1,
            Self::Bits256 => 2,
        }
    }

    pub(super) const fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::Bits128),
            2 => Some(Self::Bits256),
            _ => None,
        }
    }
}

/// Canonical parameters for one pinned bottom-k Refinery transform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BottomKSketchDescriptor {
    score_width: SketchScoreWidth,
    sample_size: SketchSampleSize,
}

impl BottomKSketchDescriptor {
    /// Measured format-1 descriptor: 256 retained 128-bit scores.
    pub const ASTRID_V1: Self = Self {
        score_width: SketchScoreWidth::Bits128,
        sample_size: SketchSampleSize(
            NonZeroU16::new(256).expect("the frozen sample size is non-zero"),
        ),
    };

    /// Construct one fully specified transform descriptor.
    #[must_use]
    pub const fn new(score_width: SketchScoreWidth, sample_size: SketchSampleSize) -> Self {
        Self {
            score_width,
            sample_size,
        }
    }

    /// Return the retained score width.
    #[must_use]
    pub const fn score_width(self) -> SketchScoreWidth {
        self.score_width
    }

    /// Return the maximum retained score count.
    #[must_use]
    pub const fn sample_size(self) -> SketchSampleSize {
        self.sample_size
    }

    /// Construct the canonical Evidence record that names this pass.
    ///
    /// # Errors
    ///
    /// Returns an object-model error if the descriptor violates the generic
    /// record grammar.
    pub fn record(self) -> Result<ObjectRecord, BottomKSketchError> {
        descriptor_record(self)
    }
}

/// Verified typed view of one canonical bottom-k Derived record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BottomKSketch {
    descriptor: RefineryPassDescriptorId,
    source: ContentDescriptor,
    score_width: SketchScoreWidth,
    sample_size: SketchSampleSize,
    unique_chunk_objects: u64,
    scores: Vec<[u8; 32]>,
}

impl BottomKSketch {
    /// Return the exact pinned pass descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> RefineryPassDescriptorId {
        self.descriptor
    }

    /// Return the exact source File identity and chunking profile.
    #[must_use]
    pub const fn source(&self) -> ContentDescriptor {
        self.source
    }

    /// Return the score width.
    #[must_use]
    pub const fn score_width(&self) -> SketchScoreWidth {
        self.score_width
    }

    /// Return the configured maximum score count.
    #[must_use]
    pub const fn sample_size(&self) -> SketchSampleSize {
        self.sample_size
    }

    /// Return the number of distinct chunk objects seen in the exact closure.
    #[must_use]
    pub const fn unique_chunk_objects(&self) -> u64 {
        self.unique_chunk_objects
    }

    /// Return retained scores in ascending byte order.
    ///
    /// For 128-bit descriptors the final 16 bytes of each array are zero.
    #[must_use]
    pub fn scores(&self) -> &[[u8; 32]] {
        &self.scores
    }
}

/// Failure while building or verifying resemblance metadata.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BottomKSketchError {
    /// A declared object did not match its recomputed identity.
    ObjectIdentityMismatch(ObjectId),
    /// The exact source closure repeated an object identity.
    DuplicateObject(ObjectId),
    /// A source File or owning descendant was absent.
    MissingObject(ObjectId),
    /// The source owning graph contained a cycle.
    ObjectCycle(ObjectId),
    /// Input included an object outside the source File closure.
    ExtraneousObject(ObjectId),
    /// The source File descriptor was malformed.
    InvalidContent(String),
    /// A byte or retained-output resource ceiling was exceeded.
    ResourceBudgetExceeded,
    /// Integer or allocation accounting overflowed.
    ArithmeticOverflow,
    /// The object model rejected a generated record.
    Model(ModelError),
    /// The proposal sink rejected the generated record.
    Proposal(RefineryProposalError),
    /// Descriptor or sketch bytes were not the one canonical representation.
    NonCanonicalRecord,
    /// A sketch did not equal deterministic recomputation over its source.
    RecomputedSketchMismatch,
}

impl fmt::Display for BottomKSketchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectIdentityMismatch(id) => {
                write!(formatter, "object identity mismatch at {id:?}")
            },
            Self::DuplicateObject(id) => write!(formatter, "duplicate source object {id:?}"),
            Self::MissingObject(id) => write!(formatter, "source closure misses object {id:?}"),
            Self::ObjectCycle(id) => write!(formatter, "source closure cycles at {id:?}"),
            Self::ExtraneousObject(id) => write!(formatter, "extraneous source object {id:?}"),
            Self::InvalidContent(error) => write!(formatter, "invalid source content: {error}"),
            Self::ResourceBudgetExceeded => {
                formatter.write_str("Refinery resource budget exceeded")
            },
            Self::ArithmeticOverflow => formatter.write_str("bottom-k accounting overflow"),
            Self::Model(error) => write!(formatter, "invalid bottom-k record: {error}"),
            Self::Proposal(error) => write!(formatter, "bottom-k proposal failed: {error}"),
            Self::NonCanonicalRecord => formatter.write_str("non-canonical bottom-k record"),
            Self::RecomputedSketchMismatch => {
                formatter.write_str("bottom-k sketch differs from deterministic recomputation")
            },
        }
    }
}

impl std::error::Error for BottomKSketchError {}

#[derive(Debug)]
struct BottomKAccumulator {
    width: SketchScoreWidth,
    limit: usize,
    scores: Vec<[u8; 32]>,
}

impl BottomKAccumulator {
    fn new(descriptor: BottomKSketchDescriptor) -> Result<Self, BottomKSketchError> {
        let limit = usize::from(descriptor.sample_size().get());
        let mut scores = Vec::new();
        scores
            .try_reserve_exact(limit)
            .map_err(|_| BottomKSketchError::ArithmeticOverflow)?;
        Ok(Self {
            width: descriptor.score_width(),
            limit,
            scores,
        })
    }

    fn clear(&mut self) {
        self.scores.clear();
    }

    fn observe(&mut self, bytes: &[u8]) -> Result<(), BottomKSketchError> {
        let mut hasher = blake3::Hasher::new_derive_key(wire::SCORE_DOMAIN);
        let byte_length =
            u64::try_from(bytes.len()).map_err(|_| BottomKSketchError::ArithmeticOverflow)?;
        hasher.update(&byte_length.to_le_bytes());
        hasher.update(bytes);
        let mut score = *hasher.finalize().as_bytes();
        score[self.width.bytes()..].fill(0);

        match self.scores.binary_search(&score) {
            Ok(_) => {},
            Err(index) => {
                if self.scores.len() == self.limit {
                    if index == self.limit {
                        return Ok(());
                    }
                    self.scores.pop();
                }
                self.scores.insert(index, score);
            },
        }
        Ok(())
    }
}

struct BottomKPass {
    descriptor: BottomKSketchDescriptor,
    descriptor_id: RefineryPassDescriptorId,
    source: ContentDescriptor,
    context: Option<RefineryBatchContext>,
    input_bytes: u64,
    unique_chunk_objects: u64,
    accumulator: BottomKAccumulator,
}

impl BottomKPass {
    fn new(
        descriptor: BottomKSketchDescriptor,
        descriptor_id: RefineryPassDescriptorId,
        source: ContentDescriptor,
    ) -> Result<Self, BottomKSketchError> {
        Ok(Self {
            descriptor,
            descriptor_id,
            source,
            context: None,
            input_bytes: 0,
            unique_chunk_objects: 0,
            accumulator: BottomKAccumulator::new(descriptor)?,
        })
    }
}

impl RefineryPass for BottomKPass {
    type Error = BottomKSketchError;

    fn descriptor(&self) -> RefineryPassDescriptorId {
        self.descriptor_id
    }

    fn begin(&mut self, context: RefineryBatchContext) -> Result<(), Self::Error> {
        self.context = Some(context);
        self.input_bytes = 0;
        self.unique_chunk_objects = 0;
        self.accumulator.clear();
        Ok(())
    }

    fn observe(
        &mut self,
        object: VerifiedRefineryObject<'_>,
        _proposals: &mut RefineryProposalSink,
    ) -> Result<(), Self::Error> {
        let retained = object
            .as_record()
            .retained_bytes()
            .map_err(BottomKSketchError::Model)?;
        self.input_bytes = self
            .input_bytes
            .checked_add(retained)
            .ok_or(BottomKSketchError::ArithmeticOverflow)?;
        let context = self.context.ok_or(BottomKSketchError::NonCanonicalRecord)?;
        if self.input_bytes > context.budget().bytes_read() {
            return Err(BottomKSketchError::ResourceBudgetExceeded);
        }
        if object.as_record().kind() == ObjectKind::Chunk {
            self.unique_chunk_objects = self
                .unique_chunk_objects
                .checked_add(1)
                .ok_or(BottomKSketchError::ArithmeticOverflow)?;
            self.accumulator
                .observe(object.as_record().canonical_bytes())?;
        }
        Ok(())
    }

    fn finish(&mut self, proposals: &mut RefineryProposalSink) -> Result<(), Self::Error> {
        let context = self.context.ok_or(BottomKSketchError::NonCanonicalRecord)?;
        let sketch = BottomKSketch {
            descriptor: self.descriptor_id,
            source: self.source,
            score_width: self.descriptor.score_width(),
            sample_size: self.descriptor.sample_size(),
            unique_chunk_objects: self.unique_chunk_objects,
            scores: self.accumulator.scores.clone(),
        };
        let record = sketch_record(&sketch)?;
        if record.retained_bytes().map_err(BottomKSketchError::Model)?
            > context.budget().retained_output_bytes()
        {
            return Err(BottomKSketchError::ResourceBudgetExceeded);
        }
        proposals
            .propose_derived(record)
            .map_err(BottomKSketchError::Proposal)
    }

    fn checkpoint(&self) -> Option<super::RefineryCheckpointId> {
        None
    }
}

/// Build one canonical, untrusted bottom-k proposal over an exact File closure.
///
/// The input may appear in any order. It must contain each object in the
/// source File's complete `Owns` closure exactly once and no unrelated object.
/// Generated metadata remains advisory until ordinary identity admission.
///
/// # Errors
///
/// Returns an identity, closure, content, budget, or record error without
/// emitting a partial sketch.
pub fn build_bottom_k_sketch<I>(
    identity: &I,
    descriptor: BottomKSketchDescriptor,
    context: RefineryBatchContext,
    source_file: ObjectId,
    objects: &[(ObjectId, ObjectRecord)],
) -> Result<Vec<ProposedRefineryOutput>, BottomKSketchError>
where
    I: ObjectIdentity,
{
    let records = exact_source_closure(identity, source_file, objects)?;
    let source = describe_source(&records, source_file)?;
    let descriptor_id = RefineryPassDescriptorId::new(identity.identify(&descriptor.record()?));
    let mut pass = BottomKPass::new(descriptor, descriptor_id, source)?;
    run_refinery_observer(identity, &mut pass, context, objects).map_err(map_run_error)
}

/// Decode and independently recompute one bottom-k sketch from its source.
///
/// # Errors
///
/// Returns a canonical-form, identity, closure, or deterministic mismatch.
pub fn verify_bottom_k_sketch<I>(
    identity: &I,
    descriptor_record: &ObjectRecord,
    sketch_record_value: &ObjectRecord,
    source_file: ObjectId,
    objects: &[(ObjectId, ObjectRecord)],
) -> Result<BottomKSketch, BottomKSketchError>
where
    I: ObjectIdentity,
{
    let descriptor = decode_descriptor(descriptor_record)?;
    let descriptor_id = RefineryPassDescriptorId::new(identity.identify(descriptor_record));
    let records = exact_source_closure(identity, source_file, objects)?;
    let source = describe_source(&records, source_file)?;
    let mut accumulator = BottomKAccumulator::new(descriptor)?;
    let mut unique_chunk_objects = 0_u64;
    for record in records.values() {
        if record.kind() == ObjectKind::Chunk {
            unique_chunk_objects = unique_chunk_objects
                .checked_add(1)
                .ok_or(BottomKSketchError::ArithmeticOverflow)?;
            accumulator.observe(record.canonical_bytes())?;
        }
    }
    let expected = BottomKSketch {
        descriptor: descriptor_id,
        source,
        score_width: descriptor.score_width(),
        sample_size: descriptor.sample_size(),
        unique_chunk_objects,
        scores: accumulator.scores,
    };
    if sketch_record(&expected)? != *sketch_record_value {
        return Err(BottomKSketchError::RecomputedSketchMismatch);
    }
    Ok(expected)
}

fn map_run_error(error: RefineryRunError<BottomKSketchError>) -> BottomKSketchError {
    match error {
        RefineryRunError::ObjectIdentityMismatch(id) => {
            BottomKSketchError::ObjectIdentityMismatch(id)
        },
        RefineryRunError::Pass(error) => error,
    }
}

fn exact_source_closure<'a, I>(
    identity: &I,
    source: ObjectId,
    objects: &'a [(ObjectId, ObjectRecord)],
) -> Result<BTreeMap<ObjectId, &'a ObjectRecord>, BottomKSketchError>
where
    I: ObjectIdentity,
{
    let mut records = BTreeMap::new();
    for (declared, record) in objects {
        if identity.identify(record) != *declared {
            return Err(BottomKSketchError::ObjectIdentityMismatch(*declared));
        }
        if records.insert(*declared, record).is_some() {
            return Err(BottomKSketchError::DuplicateObject(*declared));
        }
    }

    let mut marks = BTreeMap::<ObjectId, u8>::new();
    let mut stack = vec![(source, false)];
    while let Some((id, leaving)) = stack.pop() {
        if leaving {
            marks.insert(id, 2);
            continue;
        }
        match marks.get(&id).copied() {
            Some(1) => return Err(BottomKSketchError::ObjectCycle(id)),
            Some(2) => continue,
            _ => {},
        }
        let record = records
            .get(&id)
            .ok_or(BottomKSketchError::MissingObject(id))?;
        marks.insert(id, 1);
        stack.push((id, true));
        for child in record.owning_references().rev() {
            stack.push((child, false));
        }
    }
    let closure: BTreeSet<_> = marks.into_keys().collect();
    if let Some(extraneous) = records.keys().find(|id| !closure.contains(id)) {
        return Err(BottomKSketchError::ExtraneousObject(*extraneous));
    }
    Ok(records)
}

fn describe_source(
    records: &BTreeMap<ObjectId, &ObjectRecord>,
    source: ObjectId,
) -> Result<ContentDescriptor, BottomKSketchError> {
    describe_content(&BorrowedSource { records }, source).map_err(map_content_error)
}

struct BorrowedSource<'a> {
    records: &'a BTreeMap<ObjectId, &'a ObjectRecord>,
}

impl ContentSource for BorrowedSource<'_> {
    type Error = Infallible;

    fn load_content_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, Self::Error> {
        Ok(self.records.get(&id).map(|record| (*record).clone()))
    }
}

fn map_content_error(error: ContentReadError<Infallible>) -> BottomKSketchError {
    match error {
        ContentReadError::Content(error) => BottomKSketchError::InvalidContent(error.to_string()),
        ContentReadError::Source(error) => match error {},
    }
}
