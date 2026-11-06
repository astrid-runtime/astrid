//! Checked identities for immutable extent-index records.

use std::io;
use std::num::NonZeroU64;

/// Fixed reference grammar; this is independent of the number of live extents.
pub(in crate::volume::hosted) const PAGE_REFERENCE_BYTES: usize = 80;

/// A byte inside application payload, distinct from a record-header identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::volume::hosted) struct PayloadOffset(u64);

impl PayloadOffset {
    pub(in crate::volume::hosted) fn new(value: u64) -> io::Result<Self> {
        if value < 8 {
            return Err(invalid("extent-index payload overlaps volume header"));
        }
        Ok(Self(value))
    }

    pub(in crate::volume::hosted) fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::volume::hosted) struct RecordOffset(u64);

impl RecordOffset {
    pub(in crate::volume::hosted) fn new(value: u64) -> io::Result<Self> {
        // ASTVOL1's eight-byte identity cannot contain a record.
        if value < 8 {
            return Err(invalid("extent-index record overlaps volume header"));
        }
        Ok(Self(value))
    }

    pub(in crate::volume::hosted) fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::volume::hosted) struct RecordSequence(NonZeroU64);

impl RecordSequence {
    pub(in crate::volume::hosted) fn new(value: u64) -> io::Result<Self> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| invalid("extent-index sequence is zero"))
    }

    pub(in crate::volume::hosted) fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::volume::hosted) struct ExtentCount(NonZeroU64);

impl ExtentCount {
    pub(in crate::volume::hosted) fn new(value: u64) -> io::Result<Self> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| invalid("extent-index reference has no extents"))
    }

    pub(in crate::volume::hosted) fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::volume::hosted) struct ExtentRange {
    start: u64,
    end: u64,
}

impl ExtentRange {
    pub(in crate::volume::hosted) fn new(start: u64, end: u64) -> io::Result<Self> {
        if start >= end {
            return Err(invalid("extent-index range is empty or reversed"));
        }
        Ok(Self { start, end })
    }

    pub(in crate::volume::hosted) fn start(self) -> u64 {
        self.start
    }

    pub(in crate::volume::hosted) fn end(self) -> u64 {
        self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::volume::hosted) struct PageLevel(u8);

impl PageLevel {
    pub(in crate::volume::hosted) fn new(value: u8) -> io::Result<Self> {
        // A branch has at least two nonempty children. A level of 64 would
        // require 2^64 disjoint nonempty extents in a u64 logical space.
        if u32::from(value) >= u64::BITS {
            return Err(invalid("extent-index level exceeds logical key space"));
        }
        Ok(Self(value))
    }

    pub(in crate::volume::hosted) fn get(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::volume::hosted) struct PageRef {
    offset: RecordOffset,
    sequence: RecordSequence,
    checksum: [u8; 32],
    range: ExtentRange,
    extent_count: ExtentCount,
    level: PageLevel,
}

impl PageRef {
    pub(in crate::volume::hosted) fn new(
        offset: RecordOffset,
        sequence: RecordSequence,
        checksum: [u8; 32],
        range: ExtentRange,
        extent_count: ExtentCount,
        level: PageLevel,
    ) -> io::Result<Self> {
        let count = extent_count.get();
        if count > range.end.strict_sub(range.start)
            || count < 1_u64.strict_shl(u32::from(level.get()))
        {
            return Err(invalid("extent-index count contradicts range or level"));
        }
        Ok(Self {
            offset,
            sequence,
            checksum,
            range,
            extent_count,
            level,
        })
    }

    pub(in crate::volume::hosted) fn offset(self) -> RecordOffset {
        self.offset
    }

    pub(in crate::volume::hosted) fn sequence(self) -> RecordSequence {
        self.sequence
    }

    pub(in crate::volume::hosted) fn checksum(&self) -> &[u8; 32] {
        &self.checksum
    }

    pub(in crate::volume::hosted) fn range(self) -> ExtentRange {
        self.range
    }

    pub(in crate::volume::hosted) fn extent_count(self) -> ExtentCount {
        self.extent_count
    }

    pub(in crate::volume::hosted) fn level(self) -> PageLevel {
        self.level
    }

    /// The complete child record and its sequence precede its immutable parent.
    pub(in crate::volume::hosted) fn require_before(
        self,
        offset: RecordOffset,
        sequence: RecordSequence,
    ) -> io::Result<()> {
        if self.sequence >= sequence
            || self
                .offset
                .get()
                .checked_add(super::INDEX_PAGE_RECORD_BYTES)
                .is_none_or(|end| end > offset.get())
        {
            return Err(invalid("extent-index child does not precede parent"));
        }
        Ok(())
    }

    pub(in crate::volume::hosted) fn require_child(self, child: Self) -> io::Result<()> {
        child.require_before(self.offset, self.sequence)?;
        if self.level.get() == 0
            || child.level.get().strict_add(1) != self.level.get()
            || child.range.start < self.range.start
            || child.range.end > self.range.end
            || child.extent_count.get() >= self.extent_count.get()
        {
            return Err(invalid("extent-index child contradicts parent summary"));
        }
        Ok(())
    }

    pub(in crate::volume::hosted) fn encode(self) -> [u8; PAGE_REFERENCE_BYTES] {
        let mut bytes = [0; PAGE_REFERENCE_BYTES];
        bytes[..8].copy_from_slice(&self.offset.get().to_le_bytes());
        bytes[8..16].copy_from_slice(&self.sequence.get().to_le_bytes());
        bytes[16..48].copy_from_slice(&self.checksum);
        bytes[48..56].copy_from_slice(&self.range.start.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.range.end.to_le_bytes());
        bytes[64..72].copy_from_slice(&self.extent_count.get().to_le_bytes());
        bytes[72] = self.level.get();
        bytes
    }

    pub(in crate::volume::hosted) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != PAGE_REFERENCE_BYTES || bytes[73..].iter().any(|byte| *byte != 0) {
            return Err(invalid("invalid extent-index reference framing"));
        }
        let integer = |offset: usize| -> io::Result<u64> {
            let field = bytes[offset..offset.strict_add(8)]
                .try_into()
                .map_err(|_| invalid("truncated extent-index reference integer"))?;
            Ok(u64::from_le_bytes(field))
        };
        let checksum = bytes[16..48]
            .try_into()
            .map_err(|_| invalid("truncated extent-index reference checksum"))?;
        Self::new(
            RecordOffset::new(integer(0)?)?,
            RecordSequence::new(integer(8)?)?,
            checksum,
            ExtentRange::new(integer(48)?, integer(56)?)?,
            ExtentCount::new(integer(64)?)?,
            PageLevel::new(bytes[72])?,
        )
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[path = "reference_tests.rs"]
mod tests;
