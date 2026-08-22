//! Hosted single-container implementation of the Astrid volume contract.

#[cfg(test)]
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
#[cfg(test)]
use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
#[cfg(test)]
use std::sync::Arc;

use parking_lot::Mutex;

use super::{AstridVolume, MAX_REGION_NAME_BYTES, VolumeMetadataMutation, VolumeRegion};

mod open;
mod reclaim;
mod stream;

const VOLUME_MAGIC: [u8; 8] = *b"ASTVOL1\0";
const RECORD_MAGIC: [u8; 8] = *b"ASTREG1\0";
const RECORD_FIXED_BYTES: usize = 8 + 8 + 8 + 1 + 2 + 8 + 8 + 32;
const MAX_METADATA_MUTATIONS: usize = 1_024;
const METADATA_TRANSACTION_REGION: &str = "system/volume-metadata-transaction";
const COMMIT_REGION: &str = "system/volume-commit";
const RECOVERY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_METADATA_PAYLOAD_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
struct Extent {
    logical_end: u64,
    physical_offset: u64,
}

#[cfg(test)]
thread_local! {
    static REGION_STATE_CLONES: Cell<usize> = const { Cell::new(0) };
    static EXTENT_VISITS: Cell<usize> = const { Cell::new(0) };
}

#[derive(Debug, Default)]
struct RegionState {
    length: u64,
    extents: BTreeMap<u64, Extent>,
}

impl Clone for RegionState {
    fn clone(&self) -> Self {
        #[cfg(test)]
        REGION_STATE_CLONES.with(|count| count.set(count.get().saturating_add(1)));
        Self {
            length: self.length,
            extents: self.extents.clone(),
        }
    }
}

#[derive(Debug)]
struct ContainerState {
    file: File,
    sequence: u64,
    valid_len: u64,
    durable_len: u64,
    boundary_pending: bool,
    regions: BTreeMap<VolumeRegion, RegionState>,
}

/// Hosted realization of an Astrid volume in one container file.
pub struct HostedFileVolume {
    path: PathBuf,
    open_lock: open::OpenReclaimLock,
    state: Mutex<ContainerState>,
}

impl fmt::Debug for HostedFileVolume {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostedFileVolume")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}
impl HostedFileVolume {
    fn append(
        state: &mut ContainerState,
        operation: Operation,
        region: &VolumeRegion,
        offset: u64,
        payload: &[u8],
    ) -> io::Result<(u64, u64)> {
        let next_sequence = state
            .sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("Astrid volume sequence exhausted"))?;
        let name = region.as_str().as_bytes();
        let name_len = u16::try_from(name.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "region name too long"))?;
        let payload_len = u64::try_from(payload.len())
            .map_err(|_| io::Error::other("volume record payload is too large"))?;
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
        hasher.update(payload);
        let checksum = *hasher.finalize().as_bytes();

        state.file.seek(SeekFrom::Start(state.valid_len))?;
        state.file.write_all(&RECORD_MAGIC)?;
        state.file.write_all(&total_len.to_le_bytes())?;
        state.file.write_all(&next_sequence.to_le_bytes())?;
        state.file.write_all(&[operation as u8])?;
        state.file.write_all(&name_len.to_le_bytes())?;
        state.file.write_all(&offset.to_le_bytes())?;
        state.file.write_all(&payload_len.to_le_bytes())?;
        state.file.write_all(&checksum)?;
        state.file.write_all(name)?;
        let physical_payload = state
            .valid_len
            .checked_add(u64::try_from(RECORD_FIXED_BYTES).unwrap_or(u64::MAX))
            .and_then(|value| value.checked_add(u64::from(name_len)))
            .ok_or_else(|| io::Error::other("volume physical offset overflow"))?;
        state.file.write_all(payload)?;
        state.boundary_pending = false;
        state.valid_len = state
            .valid_len
            .checked_add(total_len)
            .ok_or_else(|| io::Error::other("volume length overflow"))?;
        state.sequence = next_sequence;
        Ok((physical_payload, payload_len))
    }

    fn make_durable(state: &mut ContainerState) -> io::Result<()> {
        if state.valid_len != state.durable_len && !state.boundary_pending {
            let region = VolumeRegion::new(COMMIT_REGION)?;
            Self::append(state, Operation::Commit, &region, 0, &[])?;
            state.boundary_pending = true;
        }
        state.file.sync_all()?;
        state.durable_len = state.valid_len;
        state.boundary_pending = false;
        Ok(())
    }
}
impl Drop for HostedFileVolume {
    fn drop(&mut self) {
        let state = self.state.get_mut();
        let _ = Self::make_durable(state);
        let _ = fs2::FileExt::unlock(&state.file);
    }
}

impl AstridVolume for HostedFileVolume {
    fn create_region(&self, region: &VolumeRegion, create_new: bool) -> io::Result<()> {
        let mut state = self.state.lock();
        if state.regions.contains_key(region) {
            return if create_new {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    region.as_str(),
                ))
            } else {
                Ok(())
            };
        }
        Self::append(&mut state, Operation::Create, region, 0, &[])?;
        state.regions.insert(region.clone(), RegionState::default());
        Ok(())
    }

    fn region_exists(&self, region: &VolumeRegion) -> io::Result<bool> {
        Ok(self.state.lock().regions.contains_key(region))
    }

    fn region_len(&self, region: &VolumeRegion) -> io::Result<u64> {
        self.state
            .lock()
            .regions
            .get(region)
            .map(|state| state.length)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, region.as_str()))
    }

    fn read_region_at(
        &self,
        region: &VolumeRegion,
        offset: u64,
        buffer: &mut [u8],
    ) -> io::Result<usize> {
        let mut state = self.state.lock();
        let Some(region_state) = state.regions.get(region) else {
            return Err(io::Error::new(io::ErrorKind::NotFound, region.as_str()));
        };
        if offset >= region_state.length || buffer.is_empty() {
            return Ok(0);
        }
        let available = region_state.length.saturating_sub(offset);
        let wanted = usize::try_from(available.min(buffer.len() as u64))
            .map_err(|_| io::Error::other("volume read length overflow"))?;
        let read_end = offset
            .checked_add(wanted as u64)
            .ok_or_else(|| io::Error::other("volume read range overflow"))?;
        // Copy only extents that overlap the requested range. Cloning the whole
        // region map on every read made catalog lookups quadratic in extents.
        let overlaps = overlapping_extents(region_state, offset, read_end);
        buffer[..wanted].fill(0);
        for (start, extent) in overlaps {
            let copy_start = start.max(offset);
            let copy_end = extent.logical_end.min(read_end);
            if copy_start >= copy_end {
                continue;
            }
            let physical = extent
                .physical_offset
                .checked_add(copy_start.saturating_sub(start))
                .ok_or_else(|| io::Error::other("volume extent offset overflow"))?;
            let destination = usize::try_from(copy_start.saturating_sub(offset))
                .map_err(|_| io::Error::other("volume destination offset overflow"))?;
            let length = usize::try_from(copy_end.saturating_sub(copy_start))
                .map_err(|_| io::Error::other("volume extent length overflow"))?;
            state.file.seek(SeekFrom::Start(physical))?;
            let destination_end = destination
                .checked_add(length)
                .ok_or_else(|| io::Error::other("volume destination range overflow"))?;
            state
                .file
                .read_exact(&mut buffer[destination..destination_end])?;
        }
        Ok(wanted)
    }

    fn write_region_from(
        &self,
        region: &VolumeRegion,
        offset: u64,
        payload_len: u64,
        payload: &mut dyn Read,
    ) -> io::Result<()> {
        stream::write_region_from(self, region, offset, payload_len, payload)
    }

    fn set_region_len(&self, region: &VolumeRegion, length: u64) -> io::Result<()> {
        let mut state = self.state.lock();
        if !state.regions.contains_key(region) {
            return Err(io::Error::new(io::ErrorKind::NotFound, region.as_str()));
        }
        Self::append(&mut state, Operation::Truncate, region, length, &[])?;
        let region_state = state
            .regions
            .get_mut(region)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, region.as_str()))?;
        truncate_extents(&mut region_state.extents, length);
        region_state.length = length;
        Ok(())
    }

    fn remove_region(&self, region: &VolumeRegion) -> io::Result<()> {
        let mut state = self.state.lock();
        if !state.regions.contains_key(region) {
            return Err(io::Error::new(io::ErrorKind::NotFound, region.as_str()));
        }
        Self::append(&mut state, Operation::Remove, region, 0, &[])?;
        state.regions.remove(region);
        Ok(())
    }

    fn rename_region(&self, source: &VolumeRegion, destination: &VolumeRegion) -> io::Result<()> {
        let mut state = self.state.lock();
        if state.regions.contains_key(destination) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                destination.as_str(),
            ));
        }
        if !state.regions.contains_key(source) {
            return Err(io::Error::new(io::ErrorKind::NotFound, source.as_str()));
        }
        Self::append(
            &mut state,
            Operation::Rename,
            source,
            0,
            destination.as_str().as_bytes(),
        )?;
        let source_state = state
            .regions
            .remove(source)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, source.as_str()))?;
        state.regions.insert(destination.clone(), source_state);
        Ok(())
    }

    fn replace_region(&self, source: &VolumeRegion, destination: &VolumeRegion) -> io::Result<()> {
        let mut state = self.state.lock();
        if !state.regions.contains_key(source) {
            return Err(io::Error::new(io::ErrorKind::NotFound, source.as_str()));
        }
        if !state.regions.contains_key(destination) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                destination.as_str(),
            ));
        }
        Self::append(
            &mut state,
            Operation::Replace,
            source,
            0,
            destination.as_str().as_bytes(),
        )?;
        let source_state = state
            .regions
            .remove(source)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, source.as_str()))?;
        state.regions.insert(destination.clone(), source_state);
        Ok(())
    }

    fn commit_metadata(&self, mutations: &[VolumeMetadataMutation]) -> io::Result<()> {
        if mutations.is_empty() || mutations.len() > MAX_METADATA_MUTATIONS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "volume metadata transaction must contain 1 to 1024 mutations",
            ));
        }
        let mut state = self.state.lock();
        let mut next_regions = state.regions.clone();
        apply_metadata_mutations(&mut next_regions, mutations)?;
        let payload = encode_metadata_mutations(mutations)?;
        let transaction = VolumeRegion::new(METADATA_TRANSACTION_REGION)?;
        Self::append(
            &mut state,
            Operation::MetadataTransaction,
            &transaction,
            0,
            &payload,
        )?;
        state.regions = next_regions;
        Ok(())
    }

    fn list_regions(&self, prefix: &str) -> io::Result<Vec<VolumeRegion>> {
        Ok(self
            .state
            .lock()
            .regions
            .keys()
            .filter(|region| region.as_str().starts_with(prefix))
            .cloned()
            .collect())
    }

    fn available_space(&self) -> io::Result<Option<u64>> {
        fs2::available_space(&self.path).map(Some)
    }

    fn reclaim(&self) -> io::Result<()> {
        reclaim::reclaim(self)
    }

    fn sync(&self) -> io::Result<()> {
        Self::make_durable(&mut self.state.lock())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Operation {
    Create = 1,
    Write = 2,
    Truncate = 3,
    Remove = 4,
    Rename = 5,
    Replace = 6,
    MetadataTransaction = 7,
    Commit = 8,
}

impl Operation {
    fn decode(value: u8) -> io::Result<Self> {
        match value {
            1 => Ok(Self::Create),
            2 => Ok(Self::Write),
            3 => Ok(Self::Truncate),
            4 => Ok(Self::Remove),
            5 => Ok(Self::Rename),
            6 => Ok(Self::Replace),
            7 => Ok(Self::MetadataTransaction),
            8 => Ok(Self::Commit),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown Astrid volume operation",
            )),
        }
    }
}

#[allow(clippy::too_many_lines)]
fn recover_container(
    file: &mut File,
) -> io::Result<(BTreeMap<VolumeRegion, RegionState>, u64, u64, u64)> {
    let physical_len = file.metadata()?.len();
    let mut offset = VOLUME_MAGIC.len() as u64;
    let mut sequence = 0_u64;
    let mut regions = BTreeMap::new();
    let mut committed_regions = BTreeMap::new();
    let mut committed_sequence = 0_u64;
    let mut committed_offset = VOLUME_MAGIC.len() as u64;
    while offset < physical_len {
        let remaining = physical_len.saturating_sub(offset);
        if remaining < RECORD_FIXED_BYTES as u64 {
            break;
        }
        file.seek(SeekFrom::Start(offset))?;
        let mut fixed = vec![0_u8; RECORD_FIXED_BYTES];
        file.read_exact(&mut fixed)?;
        if fixed[..8] != RECORD_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid Astrid volume record magic at {offset}"),
            ));
        }
        let total_len = u64::from_le_bytes(fixed[8..16].try_into().unwrap_or([0; 8]));
        let name_length = usize::from(u16::from_le_bytes(
            fixed[25..27].try_into().unwrap_or([0; 2]),
        ));
        let payload_length = u64::from_le_bytes(fixed[35..43].try_into().unwrap_or([0; 8]));
        let declared = (RECORD_FIXED_BYTES as u64)
            .checked_add(name_length as u64)
            .and_then(|value| value.checked_add(payload_length));
        if total_len < RECORD_FIXED_BYTES as u64
            || declared != Some(total_len)
            || name_length == 0
            || name_length > MAX_REGION_NAME_BYTES
        {
            if total_len > remaining {
                if has_physically_valid_record_after(file, offset.saturating_add(1), physical_len)?
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid interior Astrid volume record length at {offset}"),
                    ));
                }
                break;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid Astrid volume record length at {offset}"),
            ));
        }
        if total_len > remaining {
            if has_physically_valid_record_after(file, offset.saturating_add(1), physical_len)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid interior Astrid volume record length at {offset}"),
                ));
            }
            break;
        }
        let record_sequence = u64::from_le_bytes(fixed[16..24].try_into().unwrap_or([0; 8]));
        if record_sequence != sequence.saturating_add(1) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Astrid volume record sequence is not contiguous",
            ));
        }
        let operation = Operation::decode(fixed[24])?;
        let logical_offset = u64::from_le_bytes(fixed[27..35].try_into().unwrap_or([0; 8]));
        let checksum: [u8; 32] = fixed[43..75].try_into().unwrap_or([0; 32]);
        let mut name = vec![0_u8; name_length];
        file.read_exact(&mut name)?;
        let name = String::from_utf8(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 region name"))?;
        let region = VolumeRegion::new(name)?;
        let retain_payload = operation != Operation::Write;
        if retain_payload && payload_length > MAX_METADATA_PAYLOAD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Astrid volume metadata payload exceeds the recovery bound",
            ));
        }
        let payload_capacity = if retain_payload {
            usize::try_from(payload_length).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "volume metadata payload too large",
                )
            })?
        } else {
            0
        };
        let mut payload = Vec::with_capacity(payload_capacity);
        let mut hasher = blake3::Hasher::new_derive_key("astrid volume record v1");
        hasher.update(&record_sequence.to_le_bytes());
        hasher.update(&[operation as u8]);
        let name_len = u16::try_from(name_length)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "region name too long"))?;
        hasher.update(&name_len.to_le_bytes());
        hasher.update(&logical_offset.to_le_bytes());
        hasher.update(&payload_length.to_le_bytes());
        hasher.update(region.as_str().as_bytes());
        let mut remaining_payload = payload_length;
        let mut buffer = vec![0_u8; RECOVERY_BUFFER_BYTES];
        while remaining_payload != 0 {
            let length = usize::try_from(remaining_payload.min(RECOVERY_BUFFER_BYTES as u64))
                .map_err(|_| io::Error::other("volume recovery buffer length overflow"))?;
            file.read_exact(&mut buffer[..length])?;
            hasher.update(&buffer[..length]);
            if retain_payload {
                payload.extend_from_slice(&buffer[..length]);
            }
            remaining_payload = remaining_payload.saturating_sub(length as u64);
        }
        if hasher.finalize().as_bytes() != &checksum {
            if !has_physically_valid_record_after(file, offset.saturating_add(1), physical_len)? {
                break;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("interior Astrid volume record checksum mismatch at {offset}"),
            ));
        }
        let physical_payload = offset
            .checked_add(RECORD_FIXED_BYTES as u64)
            .and_then(|value| value.checked_add(u64::from(name_len)))
            .ok_or_else(|| io::Error::other("volume payload offset overflow"))?;
        apply_recovered(
            &mut regions,
            operation,
            region,
            logical_offset,
            physical_payload,
            payload_length,
            payload,
        )?;
        sequence = record_sequence;
        offset = offset
            .checked_add(total_len)
            .ok_or_else(|| io::Error::other("volume scan offset overflow"))?;
        if operation == Operation::Commit {
            committed_regions = regions.clone();
            committed_sequence = sequence;
            committed_offset = offset;
        }
    }
    Ok((
        committed_regions,
        committed_sequence,
        committed_offset,
        committed_offset,
    ))
}

fn has_physically_valid_record_after(file: &mut File, start: u64, end: u64) -> io::Result<bool> {
    let overlap = RECORD_MAGIC.len().saturating_sub(1);
    let mut offset = start;
    let buffer_len = RECOVERY_BUFFER_BYTES
        .checked_add(overlap)
        .ok_or_else(|| io::Error::other("volume corruption buffer length overflow"))?;
    let mut buffer = vec![0_u8; buffer_len];
    while end.saturating_sub(offset) >= RECORD_MAGIC.len() as u64 {
        let length = usize::try_from(end.saturating_sub(offset).min(buffer.len() as u64))
            .map_err(|_| io::Error::other("volume corruption scan length overflow"))?;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buffer[..length])?;
        for index in 0..=length.saturating_sub(RECORD_MAGIC.len()) {
            let magic_end = index
                .checked_add(RECORD_MAGIC.len())
                .ok_or_else(|| io::Error::other("volume corruption window overflow"))?;
            if buffer[index..magic_end] == RECORD_MAGIC {
                let candidate = offset
                    .checked_add(index as u64)
                    .ok_or_else(|| io::Error::other("volume corruption scan overflow"))?;
                if physically_valid_record_at(file, candidate, end)? {
                    return Ok(true);
                }
            }
        }
        if length <= overlap {
            break;
        }
        let advance = length
            .checked_sub(overlap)
            .ok_or_else(|| io::Error::other("volume corruption scan underflow"))?;
        let advance = u64::try_from(advance)
            .map_err(|_| io::Error::other("volume corruption scan advance overflow"))?;
        offset = offset
            .checked_add(advance)
            .ok_or_else(|| io::Error::other("volume corruption scan offset overflow"))?;
    }
    Ok(false)
}

fn physically_valid_record_at(file: &mut File, offset: u64, end: u64) -> io::Result<bool> {
    let remaining = end.saturating_sub(offset);
    if remaining < RECORD_FIXED_BYTES as u64 {
        return Ok(false);
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut fixed = [0_u8; RECORD_FIXED_BYTES];
    file.read_exact(&mut fixed)?;
    if fixed[..8] != RECORD_MAGIC {
        return Ok(false);
    }
    let total_len = u64::from_le_bytes(fixed[8..16].try_into().unwrap_or([0; 8]));
    let name_len = usize::from(u16::from_le_bytes(
        fixed[25..27].try_into().unwrap_or([0; 2]),
    ));
    let payload_len = u64::from_le_bytes(fixed[35..43].try_into().unwrap_or([0; 8]));
    let declared = (RECORD_FIXED_BYTES as u64)
        .checked_add(name_len as u64)
        .and_then(|value| value.checked_add(payload_len));
    if total_len > remaining
        || declared != Some(total_len)
        || name_len == 0
        || name_len > MAX_REGION_NAME_BYTES
        || Operation::decode(fixed[24]).is_err()
    {
        return Ok(false);
    }
    let mut name = vec![0_u8; name_len];
    file.read_exact(&mut name)?;
    if std::str::from_utf8(&name)
        .ok()
        .and_then(|name| VolumeRegion::new(name.to_owned()).ok())
        .is_none()
    {
        return Ok(false);
    }
    let mut hasher = blake3::Hasher::new_derive_key("astrid volume record v1");
    hasher.update(&fixed[16..24]);
    hasher.update(&fixed[24..25]);
    hasher.update(&fixed[25..27]);
    hasher.update(&fixed[27..35]);
    hasher.update(&fixed[35..43]);
    hasher.update(&name);
    let mut remaining_payload = payload_len;
    let mut buffer = vec![0_u8; RECOVERY_BUFFER_BYTES];
    while remaining_payload != 0 {
        let length = usize::try_from(remaining_payload.min(RECOVERY_BUFFER_BYTES as u64))
            .map_err(|_| io::Error::other("volume checksum scan length overflow"))?;
        file.read_exact(&mut buffer[..length])?;
        hasher.update(&buffer[..length]);
        remaining_payload = remaining_payload.saturating_sub(length as u64);
    }
    Ok(hasher.finalize().as_bytes() == &fixed[43..75])
}

fn apply_recovered(
    regions: &mut BTreeMap<VolumeRegion, RegionState>,
    operation: Operation,
    region: VolumeRegion,
    offset: u64,
    physical_payload: u64,
    payload_len: u64,
    payload: Vec<u8>,
) -> io::Result<()> {
    match operation {
        Operation::Create => {
            if !payload.is_empty() || regions.contains_key(&region) {
                return Err(invalid_transition("invalid create"));
            }
            regions.insert(region, RegionState::default());
        },
        Operation::Write => {
            if !payload.is_empty() || payload_len == 0 {
                return Err(invalid_transition("write retained an unexpected payload"));
            }
            let region_state = regions
                .get_mut(&region)
                .ok_or_else(|| invalid_transition("write before create"))?;
            let end = offset
                .checked_add(payload_len)
                .ok_or_else(|| invalid_transition("write range overflow"))?;
            overlay_extent(&mut region_state.extents, offset, end, physical_payload);
            region_state.length = region_state.length.max(end);
        },
        Operation::Truncate => {
            if !payload.is_empty() {
                return Err(invalid_transition("truncate has payload"));
            }
            let region_state = regions
                .get_mut(&region)
                .ok_or_else(|| invalid_transition("truncate before create"))?;
            truncate_extents(&mut region_state.extents, offset);
            region_state.length = offset;
        },
        Operation::Remove => {
            if !payload.is_empty() || regions.remove(&region).is_none() {
                return Err(invalid_transition("invalid remove"));
            }
        },
        Operation::Rename => {
            let destination = String::from_utf8(payload)
                .map_err(|_| invalid_transition("rename destination is not UTF-8"))?;
            let destination = VolumeRegion::new(destination)?;
            if regions.contains_key(&destination) {
                return Err(invalid_transition("rename destination exists"));
            }
            let source = regions
                .remove(&region)
                .ok_or_else(|| invalid_transition("rename source is absent"))?;
            regions.insert(destination, source);
        },
        Operation::Replace => {
            let destination = String::from_utf8(payload)
                .map_err(|_| invalid_transition("replace destination is not UTF-8"))?;
            let destination = VolumeRegion::new(destination)?;
            if !regions.contains_key(&destination) {
                return Err(invalid_transition("replace destination is absent"));
            }
            let source = regions
                .remove(&region)
                .ok_or_else(|| invalid_transition("replace source is absent"))?;
            regions.insert(destination, source);
        },
        Operation::MetadataTransaction => {
            if region.as_str() != METADATA_TRANSACTION_REGION || offset != 0 {
                return Err(invalid_transition("invalid metadata transaction envelope"));
            }
            let mutations = decode_metadata_mutations(&payload)?;
            apply_metadata_mutations(regions, &mutations)?;
        },
        Operation::Commit => {
            if region.as_str() != COMMIT_REGION || offset != 0 || !payload.is_empty() {
                return Err(invalid_transition("invalid volume commit boundary"));
            }
        },
    }
    Ok(())
}

fn apply_metadata_mutations(
    regions: &mut BTreeMap<VolumeRegion, RegionState>,
    mutations: &[VolumeMetadataMutation],
) -> io::Result<()> {
    for mutation in mutations {
        match mutation {
            VolumeMetadataMutation::Rename {
                source,
                destination,
            } => {
                if regions.contains_key(destination) {
                    return Err(invalid_transition("metadata rename destination exists"));
                }
                let source_state = regions
                    .remove(source)
                    .ok_or_else(|| invalid_transition("metadata rename source is absent"))?;
                regions.insert(destination.clone(), source_state);
            },
            VolumeMetadataMutation::Replace {
                source,
                destination,
            } => {
                if !regions.contains_key(destination) {
                    return Err(invalid_transition("metadata replace destination is absent"));
                }
                let source_state = regions
                    .remove(source)
                    .ok_or_else(|| invalid_transition("metadata replace source is absent"))?;
                regions.insert(destination.clone(), source_state);
            },
        }
    }
    Ok(())
}

fn encode_metadata_mutations(mutations: &[VolumeMetadataMutation]) -> io::Result<Vec<u8>> {
    let count = u16::try_from(mutations.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many metadata mutations"))?;
    let mut output = Vec::new();
    output.extend_from_slice(&count.to_le_bytes());
    for mutation in mutations {
        let (kind, source, destination) = match mutation {
            VolumeMetadataMutation::Rename {
                source,
                destination,
            } => (1_u8, source, destination),
            VolumeMetadataMutation::Replace {
                source,
                destination,
            } => (2_u8, source, destination),
        };
        output.push(kind);
        for region in [source, destination] {
            let bytes = region.as_str().as_bytes();
            let length = u16::try_from(bytes.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "metadata region name too long")
            })?;
            output.extend_from_slice(&length.to_le_bytes());
            output.extend_from_slice(bytes);
        }
    }
    Ok(output)
}

fn decode_metadata_mutations(bytes: &[u8]) -> io::Result<Vec<VolumeMetadataMutation>> {
    let mut cursor = 0_usize;
    let count = usize::from(read_u16(bytes, &mut cursor)?);
    if count == 0 || count > MAX_METADATA_MUTATIONS {
        return Err(invalid_transition("invalid metadata transaction count"));
    }
    let mut mutations = Vec::with_capacity(count);
    for _ in 0..count {
        let kind = *bytes
            .get(cursor)
            .ok_or_else(|| invalid_transition("truncated metadata transaction"))?;
        cursor = cursor
            .checked_add(1)
            .ok_or_else(|| invalid_transition("metadata transaction cursor overflow"))?;
        let source = read_metadata_region(bytes, &mut cursor)?;
        let destination = read_metadata_region(bytes, &mut cursor)?;
        let mutation = match kind {
            1 => VolumeMetadataMutation::Rename {
                source,
                destination,
            },
            2 => VolumeMetadataMutation::Replace {
                source,
                destination,
            },
            _ => return Err(invalid_transition("unknown metadata transaction mutation")),
        };
        mutations.push(mutation);
    }
    if cursor != bytes.len() {
        return Err(invalid_transition(
            "metadata transaction has trailing bytes",
        ));
    }
    Ok(mutations)
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> io::Result<u16> {
    let end = cursor
        .checked_add(2)
        .ok_or_else(|| invalid_transition("metadata transaction cursor overflow"))?;
    let field = bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_transition("truncated metadata transaction"))?;
    *cursor = end;
    Ok(u16::from_le_bytes(field.try_into().map_err(|_| {
        invalid_transition("invalid metadata transaction integer")
    })?))
}

fn read_metadata_region(bytes: &[u8], cursor: &mut usize) -> io::Result<VolumeRegion> {
    let length = usize::from(read_u16(bytes, cursor)?);
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| invalid_transition("metadata region name length overflow"))?;
    let name = bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_transition("truncated metadata region name"))?;
    *cursor = end;
    let name = std::str::from_utf8(name)
        .map_err(|_| invalid_transition("metadata region name is not UTF-8"))?;
    VolumeRegion::new(name.to_owned())
}

fn invalid_transition(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn overlapping_extents(
    region_state: &RegionState,
    offset: u64,
    read_end: u64,
) -> Vec<(u64, Extent)> {
    let start_key = region_state
        .extents
        .range(..=offset)
        .next_back()
        .and_then(|(start, extent)| (extent.logical_end > offset).then_some(*start))
        .unwrap_or(offset);
    let mut overlaps = Vec::new();
    for (start, extent) in region_state.extents.range(start_key..read_end) {
        #[cfg(test)]
        EXTENT_VISITS.with(|count| count.set(count.get().saturating_add(1)));
        if extent.logical_end > offset {
            overlaps.push((*start, *extent));
        }
    }
    overlaps
}

fn overlay_extent(extents: &mut BTreeMap<u64, Extent>, start: u64, end: u64, physical_offset: u64) {
    if start >= end {
        return;
    }
    let overlapping = extents
        .range(..end)
        .filter(|(_, extent)| extent.logical_end > start)
        .map(|(offset, extent)| (*offset, *extent))
        .collect::<Vec<_>>();
    for (offset, extent) in overlapping {
        extents.remove(&offset);
        if offset < start {
            extents.insert(
                offset,
                Extent {
                    logical_end: start,
                    physical_offset: extent.physical_offset,
                },
            );
        }
        if extent.logical_end > end {
            extents.insert(
                end,
                Extent {
                    logical_end: extent.logical_end,
                    physical_offset: extent
                        .physical_offset
                        .saturating_add(end.saturating_sub(offset)),
                },
            );
        }
    }
    extents.insert(
        start,
        Extent {
            logical_end: end,
            physical_offset,
        },
    );
}

fn truncate_extents(extents: &mut BTreeMap<u64, Extent>, length: u64) {
    let affected = extents
        .range(..)
        .filter(|(start, extent)| **start >= length || extent.logical_end > length)
        .map(|(start, extent)| (*start, *extent))
        .collect::<Vec<_>>();
    for (start, extent) in affected {
        extents.remove(&start);
        if start < length {
            extents.insert(
                start,
                Extent {
                    logical_end: length,
                    physical_offset: extent.physical_offset,
                },
            );
        }
    }
}

#[cfg(test)]
pub(crate) use stream::write_record_payloads;

#[cfg(test)]
mod tests;
