//! Region catalogue for a checkpoint whose extents live in immutable pages.

use std::collections::BTreeMap;
use std::io;

use super::super::{VolumeRegion, recover::MAX_COMMIT_SNAPSHOT_BYTES};
use super::reference::{PAGE_REFERENCE_BYTES, PageRef, RecordOffset, RecordSequence};

pub(in crate::volume::hosted) const CHECKPOINT_MAGIC: [u8; 8] = *b"ASTMAP2\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::volume::hosted) struct RegionRoot {
    length: u64,
    root: Option<PageRef>,
}

impl RegionRoot {
    pub(in crate::volume::hosted) fn new(
        length: u64,
        root: Option<PageRef>,
        commit_offset: RecordOffset,
        commit_sequence: RecordSequence,
    ) -> io::Result<Self> {
        let region = Self { length, root };
        region.validate(commit_offset, commit_sequence)?;
        Ok(region)
    }

    pub(in crate::volume::hosted) fn length(self) -> u64 {
        self.length
    }

    pub(in crate::volume::hosted) fn root(self) -> Option<PageRef> {
        self.root
    }

    fn validate(self, offset: RecordOffset, sequence: RecordSequence) -> io::Result<()> {
        if let Some(root) = self.root {
            root.require_before(offset, sequence)?;
            if root.range().end() > self.length {
                return Err(invalid("extent-index root extends beyond its region"));
            }
        }
        Ok(())
    }
}

pub(in crate::volume::hosted) fn encode(
    regions: &BTreeMap<VolumeRegion, RegionRoot>,
    offset: RecordOffset,
    sequence: RecordSequence,
) -> io::Result<Vec<u8>> {
    let count = u32::try_from(regions.len())
        .map_err(|_| invalid("too many regions in extent-index checkpoint"))?;
    let size = encoded_size(regions)?;
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(&CHECKPOINT_MAGIC);
    bytes.extend_from_slice(&count.to_le_bytes());
    for (name, region) in regions {
        region.validate(offset, sequence)?;
        let name = name.as_str().as_bytes();
        let name_length = u16::try_from(name.len())
            .map_err(|_| invalid("extent-index region name is too long"))?;
        bytes.extend_from_slice(&name_length.to_le_bytes());
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(&region.length.to_le_bytes());
        bytes.push(u8::from(region.root.is_some()));
        if let Some(root) = region.root {
            bytes.extend_from_slice(&root.encode());
        }
    }
    Ok(bytes)
}

fn encoded_size(regions: &BTreeMap<VolumeRegion, RegionRoot>) -> io::Result<usize> {
    let mut size = 12_usize;
    for (name, region) in regions {
        let reference_bytes = if region.root.is_some() {
            PAGE_REFERENCE_BYTES
        } else {
            0
        };
        size = size
            .checked_add(2 + 8 + 1)
            .and_then(|size| size.checked_add(name.as_str().len()))
            .and_then(|size| size.checked_add(reference_bytes))
            .ok_or_else(|| invalid("extent-index catalogue size overflow"))?;
        if u64::try_from(size)
            .ok()
            .is_none_or(|size| size > MAX_COMMIT_SNAPSHOT_BYTES)
        {
            return Err(invalid(
                "extent-index catalogue exceeds commit record bound",
            ));
        }
    }
    Ok(size)
}

/// Decodes the catalogue only. The reader must stream-verify every named tree
/// before installing the replacement namespace; root-only checking is not open.
pub(in crate::volume::hosted) fn decode(
    bytes: &[u8],
    offset: RecordOffset,
    sequence: RecordSequence,
) -> io::Result<BTreeMap<VolumeRegion, RegionRoot>> {
    if bytes.len() < 12
        || u64::try_from(bytes.len())
            .ok()
            .is_none_or(|length| length > MAX_COMMIT_SNAPSHOT_BYTES)
        || bytes[..8] != CHECKPOINT_MAGIC
    {
        return Err(invalid("invalid extent-index checkpoint framing"));
    }
    let mut cursor = 8_usize;
    let count = u32::from_le_bytes(array(bytes, &mut cursor)?);
    let mut regions = BTreeMap::new();
    for _ in 0..count {
        let name_length = usize::from(u16::from_le_bytes(array(bytes, &mut cursor)?));
        let name = std::str::from_utf8(take(bytes, &mut cursor, name_length)?)
            .map_err(|_| invalid("extent-index region name is not UTF-8"))?;
        let name = VolumeRegion::new(name.to_owned())
            .map_err(|_| invalid("invalid extent-index region name"))?;
        if regions
            .last_key_value()
            .is_some_and(|(previous, _)| previous >= &name)
        {
            return Err(invalid(
                "extent-index catalogue names are not ordered and unique",
            ));
        }
        let length = u64::from_le_bytes(array(bytes, &mut cursor)?);
        let root = match take(bytes, &mut cursor, 1)?[0] {
            0 => None,
            1 => Some(PageRef::decode(take(
                bytes,
                &mut cursor,
                PAGE_REFERENCE_BYTES,
            )?)?),
            _ => return Err(invalid("invalid extent-index root flag")),
        };
        let region = RegionRoot::new(length, root, offset, sequence)?;
        regions.insert(name, region);
    }
    if cursor != bytes.len() {
        return Err(invalid("extent-index checkpoint has trailing bytes"));
    }
    Ok(regions)
}

fn array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> io::Result<[u8; N]> {
    take(bytes, cursor, N)?
        .try_into()
        .map_err(|_| invalid("invalid extent-index checkpoint integer"))
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> io::Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| invalid("extent-index checkpoint cursor overflow"))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid("truncated extent-index checkpoint"))?;
    *cursor = end;
    Ok(value)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[path = "checkpoint_tests.rs"]
mod tests;
