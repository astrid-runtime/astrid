//! Fixed-size immutable pages. Fan-out follows the wire grammar, not a quota.

use std::io;

use super::reference::{
    ExtentCount, ExtentRange, PAGE_REFERENCE_BYTES, PageLevel, PageRef, PayloadOffset,
    RecordOffset, RecordSequence,
};

pub(in crate::volume::hosted) const PAGE_BYTES: usize = 4096;
const HEADER_BYTES: usize = 16;
const EXTENT_BYTES: usize = 24;
const PAGE_MAGIC: [u8; 8] = *b"ASTXPG1\0";
pub(in crate::volume::hosted) const LEAF_CAPACITY: usize =
    (PAGE_BYTES - HEADER_BYTES) / EXTENT_BYTES;
pub(in crate::volume::hosted) const BRANCH_CAPACITY: usize =
    (PAGE_BYTES - HEADER_BYTES) / PAGE_REFERENCE_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::volume::hosted) struct IndexedExtent {
    range: ExtentRange,
    physical: PayloadOffset,
}

impl IndexedExtent {
    pub(in crate::volume::hosted) fn new(start: u64, end: u64, physical: u64) -> io::Result<Self> {
        let range = ExtentRange::new(start, end)?;
        let physical = PayloadOffset::new(physical)?;
        physical
            .get()
            .checked_add(end.strict_sub(start))
            .ok_or_else(|| invalid("extent-index physical range overflow"))?;
        Ok(Self { range, physical })
    }

    pub(in crate::volume::hosted) fn range(self) -> ExtentRange {
        self.range
    }
    pub(in crate::volume::hosted) fn physical(self) -> PayloadOffset {
        self.physical
    }

    fn require_before(self, offset: RecordOffset) -> io::Result<()> {
        let end = self
            .physical
            .get()
            .checked_add(self.range.end().strict_sub(self.range.start()))
            .ok_or_else(|| invalid("extent-index physical range overflow"))?;
        if end > offset.get() {
            return Err(invalid("extent-index data follows its page"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::volume::hosted) enum Page {
    Leaf(Vec<IndexedExtent>),
    Branch(Vec<PageRef>),
}

impl Page {
    pub(in crate::volume::hosted) fn encode(&self) -> io::Result<[u8; PAGE_BYTES]> {
        let (level, _, _) = self.summary()?;
        let mut bytes = [0_u8; PAGE_BYTES];
        bytes[..8].copy_from_slice(&PAGE_MAGIC);
        bytes[8] = level.get();
        let count = match self {
            Self::Leaf(entries) => entries.len(),
            Self::Branch(entries) => entries.len(),
        };
        bytes[12..14].copy_from_slice(
            &u16::try_from(count)
                .map_err(|_| invalid("page count overflow"))?
                .to_le_bytes(),
        );
        match self {
            Self::Leaf(entries) => {
                for (entry, output) in entries
                    .iter()
                    .zip(bytes[HEADER_BYTES..].chunks_exact_mut(EXTENT_BYTES))
                {
                    output[..8].copy_from_slice(&entry.range.start().to_le_bytes());
                    output[8..16].copy_from_slice(&entry.range.end().to_le_bytes());
                    output[16..24].copy_from_slice(&entry.physical.get().to_le_bytes());
                }
            },
            Self::Branch(entries) => {
                for (entry, output) in entries
                    .iter()
                    .zip(bytes[HEADER_BYTES..].chunks_exact_mut(PAGE_REFERENCE_BYTES))
                {
                    output.copy_from_slice(&entry.encode());
                }
            },
        }
        Ok(bytes)
    }

    pub(in crate::volume::hosted) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != PAGE_BYTES
            || bytes[..8] != PAGE_MAGIC
            || bytes[9..12] != [0; 3]
            || bytes[14..16] != [0; 2]
        {
            return Err(invalid("invalid extent-index page header"));
        }
        let level = PageLevel::new(bytes[8])?;
        let count = usize::from(u16::from_le_bytes([bytes[12], bytes[13]]));
        let width = if level.get() == 0 {
            EXTENT_BYTES
        } else {
            PAGE_REFERENCE_BYTES
        };
        let capacity = PAGE_BYTES.strict_sub(HEADER_BYTES).strict_div(width);
        if count == 0 || count > capacity || (level.get() != 0 && count < 2) {
            return Err(invalid("invalid extent-index page count"));
        }
        let end = HEADER_BYTES.strict_add(count.strict_mul(width));
        if bytes[end..].iter().any(|byte| *byte != 0) {
            return Err(invalid("extent-index page padding is not zero"));
        }
        let entries = bytes[HEADER_BYTES..end].chunks_exact(width);
        let page = if level.get() == 0 {
            Self::Leaf(
                entries
                    .map(|entry| {
                        IndexedExtent::new(
                            integer(&entry[..8])?,
                            integer(&entry[8..16])?,
                            integer(&entry[16..24])?,
                        )
                    })
                    .collect::<io::Result<_>>()?,
            )
        } else {
            Self::Branch(entries.map(PageRef::decode).collect::<io::Result<_>>()?)
        };
        if page.summary()?.0 != level {
            return Err(invalid("extent-index page level mismatch"));
        }
        Ok(page)
    }

    pub(in crate::volume::hosted) fn reference(
        &self,
        offset: RecordOffset,
        sequence: RecordSequence,
        checksum: [u8; 32],
    ) -> io::Result<PageRef> {
        let (level, range, count) = self.summary()?;
        let reference = PageRef::new(offset, sequence, checksum, range, count, level)?;
        match self {
            Self::Leaf(entries) => {
                for entry in entries {
                    entry.require_before(offset)?;
                }
            },
            Self::Branch(children) => {
                for child in children {
                    reference.require_child(*child)?;
                }
            },
        }
        Ok(reference)
    }

    pub(in crate::volume::hosted) fn validate_reference(
        &self,
        reference: PageRef,
    ) -> io::Result<()> {
        if self.reference(
            reference.offset(),
            reference.sequence(),
            *reference.checksum(),
        )? != reference
        {
            return Err(invalid("extent-index page does not match its reference"));
        }
        Ok(())
    }

    pub(super) fn summary(&self) -> io::Result<(PageLevel, ExtentRange, ExtentCount)> {
        match self {
            Self::Leaf(entries) => {
                if entries.is_empty() || entries.len() > LEAF_CAPACITY {
                    return Err(invalid("invalid extent-index leaf size"));
                }
                let ranges = entries.iter().map(|entry| entry.range);
                let range = ordered_range(ranges)?;
                let count = ExtentCount::new(
                    u64::try_from(entries.len()).map_err(|_| invalid("leaf count overflow"))?,
                )?;
                Ok((PageLevel::new(0)?, range, count))
            },
            Self::Branch(children) => {
                if children.len() < 2 || children.len() > BRANCH_CAPACITY {
                    return Err(invalid("invalid extent-index branch size"));
                }
                let first = children
                    .first()
                    .ok_or_else(|| invalid("missing branch child"))?;
                let child_level = first.level().get();
                if children
                    .iter()
                    .any(|child| child.level().get() != child_level)
                {
                    return Err(invalid("mixed extent-index child levels"));
                }
                let level = PageLevel::new(
                    child_level
                        .checked_add(1)
                        .ok_or_else(|| invalid("page level overflow"))?,
                )?;
                let range = ordered_range(children.iter().map(|child| child.range()))?;
                let count = children.iter().try_fold(0_u64, |sum, child| {
                    sum.checked_add(child.extent_count().get())
                        .ok_or_else(|| invalid("branch count overflow"))
                })?;
                Ok((level, range, ExtentCount::new(count)?))
            },
        }
    }
}

fn ordered_range(mut ranges: impl Iterator<Item = ExtentRange>) -> io::Result<ExtentRange> {
    let first = ranges
        .next()
        .ok_or_else(|| invalid("empty extent-index page"))?;
    let mut end = first.end();
    for range in ranges {
        if range.start() < end {
            return Err(invalid("extent-index entries overlap or are unordered"));
        }
        end = range.end();
    }
    ExtentRange::new(first.start(), end)
}

fn integer(bytes: &[u8]) -> io::Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| invalid("invalid extent-index integer"))?,
    ))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[path = "codec_tests.rs"]
mod tests;
