//! Canonical legacy extent-map snapshot encoding and validation.

use super::{
    BTreeMap, Extent, MAX_COMMIT_SNAPSHOT_BYTES, RegionState, SNAPSHOT_MAGIC, VolumeRegion,
    invalid_transition, read_u16, read_u32, read_u64, take,
};
use std::io;

/// Exact encoded namespace size, without allocating the snapshot. This is
/// format accounting, shared by the encoder and physical maintenance.
pub(in crate::volume::hosted) fn snapshot_bytes(
    regions: &BTreeMap<VolumeRegion, RegionState>,
) -> io::Result<u64> {
    regions.iter().try_fold(12_u64, |total, (region, state)| {
        let name = u64::try_from(region.as_str().len())
            .map_err(|_| invalid_transition("snapshot region name length overflow"))?;
        let extents = u64::try_from(state.extents.len())
            .map_err(|_| invalid_transition("snapshot extent count overflow"))?;
        total
            .checked_add(14)
            .and_then(|value| value.checked_add(name))
            .and_then(|value| {
                extents
                    .checked_mul(24)
                    .and_then(|bytes| value.checked_add(bytes))
            })
            .ok_or_else(|| invalid_transition("commit snapshot size overflow"))
    })
}

pub(in crate::volume::hosted) fn encode_region_snapshot(
    regions: &BTreeMap<VolumeRegion, RegionState>,
) -> io::Result<Vec<u8>> {
    if snapshot_bytes(regions)? > MAX_COMMIT_SNAPSHOT_BYTES {
        return Err(invalid_transition("commit snapshot exceeds format bound"));
    }
    let region_count = u32::try_from(regions.len())
        .map_err(|_| invalid_transition("too many regions in commit snapshot"))?;
    let mut output = Vec::new();
    output.extend_from_slice(&SNAPSHOT_MAGIC);
    output.extend_from_slice(&region_count.to_le_bytes());
    for (region, state) in regions {
        let name = region.as_str().as_bytes();
        let name_len = u16::try_from(name.len())
            .map_err(|_| invalid_transition("commit snapshot region name too long"))?;
        let extent_count = u32::try_from(state.extents.len())
            .map_err(|_| invalid_transition("too many extents in commit snapshot"))?;
        output.extend_from_slice(&name_len.to_le_bytes());
        output.extend_from_slice(name);
        output.extend_from_slice(&state.length.to_le_bytes());
        output.extend_from_slice(&extent_count.to_le_bytes());
        for (start, extent) in &state.extents {
            output.extend_from_slice(&start.to_le_bytes());
            output.extend_from_slice(&extent.logical_end.to_le_bytes());
            output.extend_from_slice(&extent.physical_offset.to_le_bytes());
        }
        if output.len() as u64 > MAX_COMMIT_SNAPSHOT_BYTES {
            return Err(invalid_transition("commit snapshot exceeds format bound"));
        }
    }
    Ok(output)
}

pub(super) fn decode_region_snapshot(
    payload: &[u8],
    physical_limit: u64,
) -> io::Result<BTreeMap<VolumeRegion, RegionState>> {
    if payload.len() as u64 > MAX_COMMIT_SNAPSHOT_BYTES || payload.len() < 12 {
        return Err(invalid_transition("invalid commit snapshot length"));
    }
    if payload[..SNAPSHOT_MAGIC.len()] != SNAPSHOT_MAGIC {
        return Err(invalid_transition("invalid commit snapshot magic"));
    }
    let mut cursor = SNAPSHOT_MAGIC.len();
    let region_count = usize::try_from(read_u32(payload, &mut cursor)?)
        .map_err(|_| invalid_transition("commit snapshot region count overflow"))?;
    let mut regions = BTreeMap::new();
    for _ in 0..region_count {
        let name_length = usize::from(read_u16(payload, &mut cursor)?);
        let name = take(payload, &mut cursor, name_length)?;
        let name = std::str::from_utf8(name)
            .map_err(|_| invalid_transition("commit snapshot region is not UTF-8"))?;
        let region = VolumeRegion::new(name.to_owned())?;
        let length = read_u64(payload, &mut cursor)?;
        let extent_count = usize::try_from(read_u32(payload, &mut cursor)?)
            .map_err(|_| invalid_transition("commit snapshot extent count overflow"))?;
        let mut extents = BTreeMap::new();
        let mut previous_end = 0_u64;
        for _ in 0..extent_count {
            let start = read_u64(payload, &mut cursor)?;
            let logical_end = read_u64(payload, &mut cursor)?;
            let physical_offset = read_u64(payload, &mut cursor)?;
            let extent_len = logical_end.saturating_sub(start);
            if start >= logical_end
                || start < previous_end
                || logical_end > length
                || physical_offset
                    .checked_add(extent_len)
                    .is_none_or(|end| end > physical_limit)
            {
                return Err(invalid_transition("invalid commit snapshot extent"));
            }
            previous_end = logical_end;
            extents.insert(
                start,
                Extent {
                    logical_end,
                    physical_offset,
                },
            );
        }
        if regions
            .insert(
                region,
                RegionState {
                    length,
                    extents,
                    ..RegionState::default()
                },
            )
            .is_some()
        {
            return Err(invalid_transition("duplicate commit snapshot region"));
        }
    }
    if cursor != payload.len() {
        return Err(invalid_transition("commit snapshot has trailing bytes"));
    }
    Ok(regions)
}
