//! Reuse a replayed namespace only when the complete snapshot validates identically.

use super::{
    BTreeMap, MAX_COMMIT_SNAPSHOT_BYTES, RegionState, SNAPSHOT_MAGIC, VolumeRegion,
    decode_region_snapshot, read_u16, read_u32, read_u64, take,
};
use std::io;

pub(super) fn replace_from_snapshot(
    regions: &mut BTreeMap<VolumeRegion, RegionState>,
    payload: &[u8],
    physical_limit: u64,
) -> io::Result<()> {
    if matches_snapshot(regions, payload, physical_limit).unwrap_or(false) {
        return Ok(());
    }
    // Preserve the decoder's errors, snapshot-wins semantics and acceptance of
    // differently ordered region records. Never mutate live state on failure.
    *regions = decode_region_snapshot(payload, physical_limit)?;
    Ok(())
}

fn matches_snapshot(
    regions: &BTreeMap<VolumeRegion, RegionState>,
    payload: &[u8],
    physical_limit: u64,
) -> io::Result<bool> {
    if payload.len() < 12
        || payload.len() as u64 > MAX_COMMIT_SNAPSHOT_BYTES
        || payload[..SNAPSHOT_MAGIC.len()] != SNAPSHOT_MAGIC
    {
        return Ok(false);
    }
    let mut cursor = SNAPSHOT_MAGIC.len();
    if u64::from(read_u32(payload, &mut cursor)?) != regions.len() as u64 {
        return Ok(false);
    }
    for (region, state) in regions {
        let name_length = usize::from(read_u16(payload, &mut cursor)?);
        // One-to-one ordered names prove uniqueness and typed name validity.
        if take(payload, &mut cursor, name_length)? != region.as_str().as_bytes()
            || read_u64(payload, &mut cursor)? != state.length
            || u64::from(read_u32(payload, &mut cursor)?) != state.extents.len() as u64
        {
            return Ok(false);
        }
        let mut previous_end = 0;
        for (live_start, live_extent) in &state.extents {
            let start = read_u64(payload, &mut cursor)?;
            let logical_end = read_u64(payload, &mut cursor)?;
            let physical_offset = read_u64(payload, &mut cursor)?;
            // Equality alone does not prove bounds against this commit's start.
            if start != *live_start
                || logical_end != live_extent.logical_end
                || physical_offset != live_extent.physical_offset
                || start >= logical_end
                || start < previous_end
                || logical_end > state.length
                || physical_offset
                    .checked_add(logical_end.saturating_sub(start))
                    .is_none_or(|end| end > physical_limit)
            {
                return Ok(false);
            }
            previous_end = logical_end;
        }
    }
    Ok(cursor == payload.len())
}

#[cfg(test)]
mod tests;
