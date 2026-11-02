//! Shared logical-region reader for normal I/O and explicit physical reclaim.

use std::fs::File;
use std::io;

use super::extent_index::{records::RecordReader, reference::ExtentRange, traversal};
use super::{Extent, RegionState, overlapping_extents, recover};

pub(super) fn read(
    file: &File,
    region: &RegionState,
    offset: u64,
    buffer: &mut [u8],
) -> io::Result<usize> {
    if offset >= region.length || buffer.is_empty() {
        return Ok(0);
    }
    let wanted = usize::try_from(region.length.strict_sub(offset).min(buffer.len() as u64))
        .map_err(|_| io::Error::other("volume read length overflow"))?;
    let end = offset
        .checked_add(wanted as u64)
        .ok_or_else(|| io::Error::other("volume read range overflow"))?;
    buffer[..wanted].fill(0);
    let base_end = end.min(region.base_limit);
    if let Some(root) = region.root
        && offset < base_end
    {
        let reader = RecordReader::for_root(file, root)?;
        traversal::visit_range(
            &reader,
            root,
            ExtentRange::new(offset, base_end)?,
            &mut |entry| {
                copy_extent(
                    file,
                    entry.range().start(),
                    Extent {
                        logical_end: entry.range().end().min(base_end),
                        physical_offset: entry.physical().get(),
                    },
                    offset,
                    end,
                    &mut buffer[..wanted],
                )
            },
        )?;
    }
    for (start, extent) in overlapping_extents(region, offset, end) {
        copy_extent(file, start, extent, offset, end, &mut buffer[..wanted])?;
    }
    Ok(wanted)
}

fn copy_extent(
    file: &File,
    start: u64,
    extent: Extent,
    offset: u64,
    end: u64,
    buffer: &mut [u8],
) -> io::Result<()> {
    let copy_start = start.max(offset);
    let copy_end = extent.logical_end.min(end);
    if copy_start >= copy_end {
        return Ok(());
    }
    let physical = extent
        .physical_offset
        .checked_add(copy_start.strict_sub(start))
        .ok_or_else(|| io::Error::other("volume extent offset overflow"))?;
    let destination = usize::try_from(copy_start.strict_sub(offset))
        .map_err(|_| io::Error::other("volume destination offset overflow"))?;
    let length = usize::try_from(copy_end.strict_sub(copy_start))
        .map_err(|_| io::Error::other("volume extent length overflow"))?;
    let destination_end = destination
        .checked_add(length)
        .ok_or_else(|| io::Error::other("volume destination range overflow"))?;
    recover::read_exact_at(file, physical, &mut buffer[destination..destination_end])
}
