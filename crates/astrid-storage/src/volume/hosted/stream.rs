//! Stream a known-length payload as one ASTVOL1 Write record.
//!
//! Checksum lives in the record header. This hashes while copying, then
//! patches the checksum slot. The on-disk grammar is unchanged.

use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(test)]
use std::path::Path;

#[cfg(test)]
use super::VOLUME_MAGIC;
use super::recover::FOOTER_BYTES;
use super::{
    ContainerState, HostedFileVolume, Operation, RECORD_FIXED_BYTES, RECORD_MAGIC, VolumeRegion,
    overlay_extent,
};

/// Bounce buffer for payload copy and checksum. Not an operator policy knob:
/// it does not cap blob size or change the record grammar.
const STREAM_BUFFER_BYTES: usize = 64 * 1024;
const RECORD_CHECKSUM_OFFSET: u64 = 43;

pub(super) fn write_region_from(
    volume: &HostedFileVolume,
    region: &VolumeRegion,
    offset: u64,
    payload_len: u64,
    payload: &mut dyn Read,
) -> io::Result<()> {
    if payload_len == 0 {
        return Ok(());
    }
    let mut state = volume.state.lock();
    if !state.regions.contains_key(region) {
        return Err(io::Error::new(io::ErrorKind::NotFound, region.as_str()));
    }
    let end = offset
        .checked_add(payload_len)
        .ok_or_else(|| io::Error::other("volume write range overflow"))?;
    let (physical, _) = append_from(
        &mut state,
        Operation::Write,
        region,
        offset,
        payload_len,
        payload,
    )?;
    let region_state = state
        .regions
        .get_mut(region)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, region.as_str()))?;
    overlay_extent(&mut region_state.extents, offset, end, physical);
    region_state.length = region_state.length.max(end);
    Ok(())
}

pub(super) fn append_from(
    state: &mut ContainerState,
    operation: Operation,
    region: &VolumeRegion,
    offset: u64,
    payload_len: u64,
    payload: &mut dyn Read,
) -> io::Result<(u64, u64)> {
    if payload_len == 0 {
        return super::HostedFileVolume::append(state, operation, region, offset, &[]);
    }
    let preserve_footer = state.generation > 0
        && state.durable_len != 0
        && state.physical_tail == super::PhysicalTail::TruncateToValid;
    let start = if preserve_footer && state.valid_len == state.durable_len {
        state
            .durable_len
            .checked_add(u64::try_from(FOOTER_BYTES).unwrap_or(u64::MAX))
            .ok_or_else(|| io::Error::other("volume footer offset overflow"))?
    } else {
        state.valid_len
    };
    let rollback_len = if state.physical_tail == super::PhysicalTail::PreserveSelected {
        state
            .file
            .metadata()
            .map_or(start, |metadata| metadata.len())
    } else {
        start
    };
    match append_from_inner(
        state,
        operation,
        region,
        offset,
        payload_len,
        payload,
        start,
    ) {
        Ok(result) => Ok(result),
        Err(error) => {
            let _ = state.file.set_len(rollback_len);
            let _ = state.file.seek(SeekFrom::Start(rollback_len));
            if state.last_commit_offset != 0 && rollback_len == state.durable_len {
                let _ = super::recover::write_footer(
                    &mut state.file,
                    state.last_commit_offset,
                    state.durable_len,
                    state.sequence,
                );
            }
            Err(error)
        },
    }
}

fn append_from_inner(
    state: &mut ContainerState,
    operation: Operation,
    region: &VolumeRegion,
    offset: u64,
    payload_len: u64,
    payload: &mut dyn Read,
    start: u64,
) -> io::Result<(u64, u64)> {
    let next_sequence = state
        .sequence
        .checked_add(1)
        .ok_or_else(|| io::Error::other("Astrid volume sequence exhausted"))?;
    let name = region.as_str().as_bytes();
    let name_len = u16::try_from(name.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "region name too long"))?;
    let total_len = u64::try_from(RECORD_FIXED_BYTES)
        .ok()
        .and_then(|fixed| fixed.checked_add(u64::from(name_len)))
        .and_then(|total| total.checked_add(payload_len))
        .ok_or_else(|| io::Error::other("volume record length overflow"))?;
    let mut hasher = blake3::Hasher::new_derive_key("astrid volume record v1");
    hasher.update(&next_sequence.to_le_bytes());
    hasher.update(&[operation as u8]);
    hasher.update(&name_len.to_le_bytes());
    hasher.update(&offset.to_le_bytes());
    hasher.update(&payload_len.to_le_bytes());
    hasher.update(name);

    // The previous footer ends at `valid_len` for generation-0 images. A
    // generation root still names that footer, so place the streamed record
    // after it and let the next root flip publish the new authority.
    state.footer_pending = true;
    if state.physical_tail == super::PhysicalTail::TruncateToValid {
        state.file.set_len(start)?;
    }
    state.file.seek(SeekFrom::Start(start))?;
    state.file.write_all(&RECORD_MAGIC)?;
    state.file.write_all(&total_len.to_le_bytes())?;
    state.file.write_all(&next_sequence.to_le_bytes())?;
    state.file.write_all(&[operation as u8])?;
    state.file.write_all(&name_len.to_le_bytes())?;
    state.file.write_all(&offset.to_le_bytes())?;
    state.file.write_all(&payload_len.to_le_bytes())?;
    state.file.write_all(&[0_u8; 32])?;
    state.file.write_all(name)?;
    let physical_payload = start
        .checked_add(u64::try_from(RECORD_FIXED_BYTES).unwrap_or(u64::MAX))
        .and_then(|value| value.checked_add(u64::from(name_len)))
        .ok_or_else(|| io::Error::other("volume physical offset overflow"))?;
    copy_and_hash(&mut state.file, payload, payload_len, &mut hasher)?;
    let checksum = *hasher.finalize().as_bytes();
    let checksum_at = start
        .checked_add(RECORD_CHECKSUM_OFFSET)
        .ok_or_else(|| io::Error::other("volume checksum offset overflow"))?;
    state.file.seek(SeekFrom::Start(checksum_at))?;
    state.file.write_all(&checksum)?;
    state.boundary_pending = false;
    state.valid_len = start
        .checked_add(total_len)
        .ok_or_else(|| io::Error::other("volume length overflow"))?;
    state.sequence = next_sequence;
    Ok((physical_payload, payload_len))
}

fn copy_and_hash(
    destination: &mut std::fs::File,
    source: &mut dyn Read,
    payload_len: u64,
    hasher: &mut blake3::Hasher,
) -> io::Result<()> {
    let mut remaining = payload_len;
    let mut buffer = vec![0_u8; STREAM_BUFFER_BYTES];
    while remaining != 0 {
        let want = usize::try_from(remaining.min(STREAM_BUFFER_BYTES as u64))
            .map_err(|_| io::Error::other("volume stream copy length overflow"))?;
        source.read_exact(&mut buffer[..want])?;
        hasher.update(&buffer[..want]);
        destination.write_all(&buffer[..want])?;
        remaining = remaining
            .checked_sub(want as u64)
            .ok_or_else(|| io::Error::other("volume stream copy length overflow"))?;
    }
    Ok(())
}

/// Test helper: `(region, payload_len)` for every on-disk Write record.
#[cfg(test)]
pub(crate) fn write_record_payloads(path: &Path) -> io::Result<Vec<(String, u64)>> {
    let mut file = std::fs::File::open(path)?;
    let mut magic = [0_u8; 8];
    file.read_exact(&mut magic)?;
    if magic != VOLUME_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "volume magic mismatch",
        ));
    }
    let physical_len = file.metadata()?.len();
    let mut offset = u64::try_from(VOLUME_MAGIC.len())
        .map_err(|_| io::Error::other("volume magic length overflow"))?;
    let mut records = Vec::new();
    while offset.saturating_add(RECORD_FIXED_BYTES as u64) <= physical_len {
        file.seek(SeekFrom::Start(offset))?;
        let mut fixed = [0_u8; RECORD_FIXED_BYTES];
        file.read_exact(&mut fixed)?;
        if fixed[..8] != RECORD_MAGIC {
            break;
        }
        let total_len = u64::from_le_bytes(fixed[8..16].try_into().unwrap_or([0; 8]));
        let name_len = usize::from(u16::from_le_bytes(
            fixed[25..27].try_into().unwrap_or([0; 2]),
        ));
        let payload_len = u64::from_le_bytes(fixed[35..43].try_into().unwrap_or([0; 8]));
        let mut name = vec![0_u8; name_len];
        file.read_exact(&mut name)?;
        if fixed[24] == Operation::Write as u8 {
            let name = String::from_utf8(name)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 region name"))?;
            records.push((name, payload_len));
        }
        offset = offset
            .checked_add(total_len)
            .ok_or_else(|| io::Error::other("volume scan offset overflow"))?;
    }
    Ok(records)
}
