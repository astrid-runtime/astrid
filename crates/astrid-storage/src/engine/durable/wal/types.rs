use std::fmt;
use std::num::NonZeroU64;

use super::super::RecoveryLimits;
use crate::storage_model::{ObjectId, RootState};

/// The parser bound applied independently to every physical record payload.
pub(crate) type WalLimits = RecoveryLimits;

/// The parser bound applied to an ASTWAL2 physical payload.
///
/// `RecoveryLimits` describes the canonical arena/root payload.  Every WAL
/// payload prepends a fixed logical-record header, so its physical bound must
/// include that header while remaining representable by this process.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct WalPhysicalLimit(WalLength);

impl WalPhysicalLimit {
    /// Derive the physical WAL bound from the canonical payload bound.
    pub(super) fn from_canonical(canonical: u64, record_header_len: usize) -> Self {
        let process_addressable = u64::try_from(usize::MAX).unwrap_or(u64::MAX);
        let header = u64::try_from(record_header_len).unwrap_or(u64::MAX);
        let physical = canonical.saturating_add(header).min(process_addressable);
        Self(WalLength::new(physical))
    }

    /// Return the bounded physical payload length.
    pub(super) const fn length(self) -> WalLength {
        self.0
    }
}

/// A non-zero transaction sequence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct WalSequence(NonZeroU64);

impl WalSequence {
    /// Construct a sequence, rejecting the reserved zero value.
    pub(super) const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return the wire sequence value.
    pub(super) const fn get(self) -> u64 {
        self.0.get()
    }
}

/// A record ordinal within one transaction; Begin is ordinal zero.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct WalOrdinal(u64);

impl WalOrdinal {
    /// Construct an ordinal from its wire value.
    pub(super) const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the wire ordinal value.
    pub(super) const fn get(self) -> u64 {
        self.0
    }

    /// Advance to the next ordinal without wrapping.
    pub(super) const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

/// A byte offset in the WAL stream.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct WalOffset(u64);

impl WalOffset {
    /// Construct an offset from its wire value.
    pub(super) const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the wire offset value.
    pub(super) const fn get(self) -> u64 {
        self.0
    }

    /// Advance by a bounded record length without wrapping.
    pub(super) const fn checked_add(self, length: WalLength) -> Option<Self> {
        match self.0.checked_add(length.0) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// Validated scanner state for resuming appends at a clean EOF or truncatable
/// uncommitted tail.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct WalResumeState {
    append_offset: WalOffset,
    last_sequence: Option<WalSequence>,
}

impl WalResumeState {
    /// Construct a state at the exact append/truncation boundary.
    pub(super) const fn new(append_offset: WalOffset, last_sequence: Option<WalSequence>) -> Self {
        Self {
            append_offset,
            last_sequence,
        }
    }

    pub(super) const fn into_parts(self) -> (WalOffset, Option<WalSequence>) {
        (self.append_offset, self.last_sequence)
    }
}

/// A bounded byte length.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct WalLength(u64);

impl WalLength {
    /// Construct a byte length.
    pub(super) const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the wire length value.
    pub(super) const fn get(self) -> u64 {
        self.0
    }

    /// Convert to a process-sized length.
    pub(super) fn as_usize(self) -> Result<usize, WalError> {
        usize::try_from(self.0).map_err(|_| WalError::LengthOverflow { value: self })
    }

    /// Add two lengths without wrapping.
    pub(super) const fn checked_add(self, other: Self) -> Option<Self> {
        match self.0.checked_add(other.0) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// A bounded count of logical records.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct WalCount(u64);

impl WalCount {
    /// Construct a record count.
    pub(super) const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the wire count value.
    pub(super) const fn get(self) -> u64 {
        self.0
    }

    /// Add one record without wrapping.
    pub(super) const fn checked_inc(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// A domain-separated BLAKE3 digest of one transaction's logical records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WalDigest([u8; 32]);

impl WalDigest {
    /// Construct a digest from its wire bytes.
    pub(super) const fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    /// Borrow the digest bytes.
    pub(super) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Optional non-authoritative Begin hints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WalBeginHints {
    object_count: WalCount,
    root_count: WalCount,
    logical_bytes: WalLength,
}

impl WalBeginHints {
    /// Construct hints; scanners intentionally do not trust them.
    pub(super) const fn new(
        object_count: WalCount,
        root_count: WalCount,
        logical_bytes: WalLength,
    ) -> Self {
        Self {
            object_count,
            root_count,
            logical_bytes,
        }
    }

    /// Return the hinted object count.
    pub(super) const fn object_count(self) -> WalCount {
        self.object_count
    }

    /// Return the hinted root count.
    pub(super) const fn root_count(self) -> WalCount {
        self.root_count
    }

    /// Return the hinted logical byte count.
    pub(super) const fn logical_bytes(self) -> WalLength {
        self.logical_bytes
    }
}

/// A kind byte in the ASTWAL2 logical record grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WalRecordKind {
    /// Starts one transaction.
    Begin,
    /// Carries one canonical immutable object frame.
    Object,
    /// Carries one canonical principal-root transition.
    Root,
    /// Commits one transaction after all prior records.
    Commit,
}

impl WalRecordKind {
    /// Return the stable wire tag.
    pub(super) const fn tag(self) -> u8 {
        match self {
            Self::Begin => 1,
            Self::Object => 2,
            Self::Root => 3,
            Self::Commit => 4,
        }
    }

    /// Decode a stable wire tag.
    pub(super) const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Begin),
            2 => Some(Self::Object),
            3 => Some(Self::Root),
            4 => Some(Self::Commit),
            _ => None,
        }
    }
}

/// A typed root transition decoded from a canonical root record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WalRootTransition {
    principal: Vec<u8>,
    expected: Option<RootState>,
    replacement: RootState,
}

impl WalRootTransition {
    /// Construct a transition from canonical principal bytes and roots.
    pub(super) fn new(
        principal: Vec<u8>,
        expected: Option<RootState>,
        replacement: RootState,
    ) -> Self {
        Self {
            principal,
            expected,
            replacement,
        }
    }

    /// Borrow canonical principal bytes.
    pub(super) fn principal(&self) -> &[u8] {
        &self.principal
    }

    /// Return the expected prior root.
    pub(super) const fn expected(&self) -> Option<RootState> {
        self.expected
    }

    /// Return the replacement root.
    pub(super) const fn replacement(&self) -> RootState {
        self.replacement
    }
}

/// Descriptor for one object record; payload bytes are not retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WalObjectDescriptor {
    pub(super) offset: WalOffset,
    pub(super) length: WalLength,
    pub(super) id: ObjectId,
    pub(super) logical_bytes: WalLength,
}

impl WalObjectDescriptor {
    /// Return the physical record offset.
    pub(super) const fn offset(self) -> WalOffset {
        self.offset
    }

    /// Return the physical record length.
    pub(super) const fn length(self) -> WalLength {
        self.length
    }

    /// Return the canonical object identifier.
    pub(super) const fn id(self) -> ObjectId {
        self.id
    }
}

/// Descriptor for one root record; only the typed transition is retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WalRootDescriptor {
    pub(super) offset: WalOffset,
    pub(super) length: WalLength,
    pub(super) transition: WalRootTransition,
}

impl WalRootDescriptor {
    /// Return the physical record offset.
    pub(super) const fn offset(&self) -> WalOffset {
        self.offset
    }

    /// Borrow the typed root transition.
    pub(super) fn transition(&self) -> &WalRootTransition {
        &self.transition
    }
}

/// Descriptor emitted when one complete transaction commits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WalCommitDescriptor {
    pub(super) offset: WalOffset,
    pub(super) length: WalLength,
    pub(super) sequence: WalSequence,
    pub(super) logical_count: WalCount,
    pub(super) object_count: WalCount,
    pub(super) root_count: WalCount,
    pub(super) logical_bytes: WalLength,
    pub(super) digest: WalDigest,
}

/// Descriptor emitted for a Begin record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WalBeginDescriptor {
    /// Begin record offset.
    pub(super) offset: WalOffset,
    /// Transaction sequence.
    pub(super) sequence: WalSequence,
    /// Identity scheme declared by the transaction.
    pub(super) scheme: super::super::IdentityScheme,
    /// Optional non-authoritative hints.
    pub(super) hints: Option<WalBeginHints>,
}

/// Descriptor emitted as the scanner reaches a physical tail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WalScanTail {
    pub(crate) offset: WalOffset,
    pub(crate) kind: WalTailKind,
}

/// Why scanning stopped at a physical tail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WalTailKind {
    /// Header or payload ended before a complete physical record.
    Incomplete,
    /// A complete record had a checksum mismatch.
    InvalidChecksum,
}

/// Summary of one complete transaction's committed physical span.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WalTransactionDescriptor {
    pub(super) begin_offset: WalOffset,
    pub(super) commit: WalCommitDescriptor,
}

/// One streaming scanner event. Object payloads are never retained here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WalEvent {
    /// A transaction began.
    Begin(WalBeginDescriptor),
    /// One canonical object descriptor was validated.
    Object(WalObjectDescriptor),
    /// One canonical root transition was validated.
    Root(WalRootDescriptor),
    /// The transaction's Commit marker was validated.
    Commit(WalTransactionDescriptor),
    /// The scanner reached an uncommitted physical tail.
    Tail(WalScanTail),
}

/// A parser or writer failure.
#[derive(Debug)]
pub(crate) enum WalError {
    /// An underlying stream operation failed.
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Source I/O error.
        source: std::io::Error,
    },
    /// A checksum-valid record violated the grammar.
    Corrupt {
        /// Record offset.
        offset: WalOffset,
        /// Stable detail.
        detail: &'static str,
    },
    /// A bad physical record was followed by another valid physical record.
    InteriorCorruption {
        /// Bad record offset.
        offset: WalOffset,
        /// Stable detail.
        detail: &'static str,
    },
    /// A complete record exceeded the per-record parser bound.
    FrameTooLarge {
        /// Record offset.
        offset: WalOffset,
        /// Declared payload length.
        declared: WalLength,
        /// Configured payload limit.
        limit: WalLength,
    },
    /// A persisted length overflowed process arithmetic.
    LengthOverflow {
        /// Unrepresentable length.
        value: WalLength,
    },
    /// A persisted count overflowed checked arithmetic.
    CountOverflow {
        /// Counter name.
        field: &'static str,
    },
    /// A sequence was zero or regressed.
    SequenceRegression {
        /// Prior committed sequence.
        previous: WalSequence,
        /// Regressing sequence.
        current: WalSequence,
    },
    /// A record's sequence differed from the active transaction.
    SequenceMismatch {
        /// Expected sequence.
        expected: WalSequence,
        /// Found sequence.
        found: WalSequence,
    },
    /// A record ordinal was not exactly the next ordinal.
    OrdinalMismatch {
        /// Expected ordinal.
        expected: WalOrdinal,
        /// Found ordinal.
        found: WalOrdinal,
    },
    /// A Commit marker sequence differed from Begin.
    CommitSequenceMismatch {
        /// Begin sequence.
        expected: WalSequence,
        /// Commit sequence.
        found: WalSequence,
    },
    /// Commit counts or logical bytes differed from the streamed records.
    CommitCountMismatch {
        /// Stable counter name.
        field: &'static str,
    },
    /// Commit digest differed from the streamed records.
    DigestMismatch,
    /// Identity scheme did not match the validated caller contract.
    IdentitySchemeMismatch,
    /// Canonical object identity did not match its payload.
    ObjectIdentityMismatch {
        /// Object identifier supplied by the frame.
        object: ObjectId,
    },
    /// Principal bytes did not satisfy the caller's canonical codec.
    PrincipalMismatch,
    /// Object or principal ordering was not strict.
    OrderingViolation,
    /// The transaction had no root transition.
    ZeroRoots,
    /// Writer call order or transaction shape was invalid.
    InvalidTransaction(&'static str),
    /// A payload could not be encoded without overflow.
    Encoding(&'static str),
}

impl fmt::Display for WalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "WAL {operation}: {source}"),
            Self::Corrupt { offset, detail } => {
                write!(
                    formatter,
                    "corrupt WAL record at {}: {detail}",
                    offset.get()
                )
            },
            Self::InteriorCorruption { offset, detail } => {
                write!(
                    formatter,
                    "interior WAL corruption at {}: {detail}",
                    offset.get()
                )
            },
            Self::FrameTooLarge {
                offset,
                declared,
                limit,
            } => write!(
                formatter,
                "WAL record at {} declares {} bytes over {}",
                offset.get(),
                declared.get(),
                limit.get()
            ),
            Self::LengthOverflow { value } => {
                write!(
                    formatter,
                    "WAL length {} overflows process arithmetic",
                    value.get()
                )
            },
            Self::CountOverflow { field } => write!(formatter, "WAL {field} count overflow"),
            Self::SequenceRegression { previous, current } => write!(
                formatter,
                "WAL sequence regressed from {} to {}",
                previous.get(),
                current.get()
            ),
            Self::SequenceMismatch { expected, found } => write!(
                formatter,
                "WAL record sequence {} differs from {}",
                found.get(),
                expected.get()
            ),
            Self::OrdinalMismatch { expected, found } => write!(
                formatter,
                "WAL ordinal {} differs from {}",
                found.get(),
                expected.get()
            ),
            Self::CommitSequenceMismatch { expected, found } => write!(
                formatter,
                "WAL commit sequence {} differs from {}",
                found.get(),
                expected.get()
            ),
            Self::CommitCountMismatch { field } => {
                write!(formatter, "WAL commit {field} mismatch")
            },
            Self::DigestMismatch => formatter.write_str("WAL commit digest mismatch"),
            Self::IdentitySchemeMismatch => formatter.write_str("WAL identity scheme mismatch"),
            Self::ObjectIdentityMismatch { object } => {
                write!(formatter, "WAL object identity mismatch for {object:?}")
            },
            Self::PrincipalMismatch => formatter.write_str("WAL principal is not canonical"),
            Self::OrderingViolation => formatter.write_str("WAL record ordering violation"),
            Self::ZeroRoots => formatter.write_str("WAL transaction has no root transition"),
            Self::InvalidTransaction(detail) | Self::Encoding(detail) => {
                formatter.write_str(detail)
            },
        }
    }
}

impl std::error::Error for WalError {}
