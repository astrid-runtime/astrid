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
mod recover;
mod stream;

const VOLUME_MAGIC: [u8; 8] = *b"ASTVOL1\0";
const RECORD_MAGIC: [u8; 8] = *b"ASTREG1\0";
const ROOT_MAGIC: [u8; 8] = *b"ASTROOT1";
const ROOT_SLOT_BYTES: usize = 8 + 8 + 8 + 8 + 32;
const ROOT_BYTES: usize = VOLUME_MAGIC.len() + 2 * ROOT_SLOT_BYTES;
const RECORD_FIXED_BYTES: usize = 8 + 8 + 8 + 1 + 2 + 8 + 8 + 32;
const MAX_METADATA_MUTATIONS: usize = 1_024;
const METADATA_TRANSACTION_REGION: &str = "system/volume-metadata-transaction";
const COMMIT_REGION: &str = "system/volume-commit";

#[derive(Clone, Copy, Debug)]
struct Extent {
    logical_end: u64,
    physical_offset: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PhysicalTail {
    TruncateToValid,
    PreserveSelected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootSlot {
    First,
    Second,
}

#[cfg(test)]
thread_local! {
    static ROOT_WRITE_INTERRUPT: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
pub(super) fn set_root_write_interrupt(armed: bool) {
    ROOT_WRITE_INTERRUPT.with(|interrupt| interrupt.set(armed));
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
    generation: u64,
    root_base: u64,
    root_slot: RootSlot,
    sequence: u64,
    valid_len: u64,
    durable_len: u64,
    last_commit_offset: u64,
    last_commit_has_snapshot: bool,
    boundary_pending: bool,
    footer_pending: bool,
    physical_tail: PhysicalTail,
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

        // A footer occupies the old valid-end until the next append. A
        // generation root still names that footer, so write after it until a
        // new root makes the replacement authority durable. Generation-0
        // recovery uses the EOF/header scan and retains its truncate-and-tail
        // behavior.
        state.footer_pending = true;
        let preserve_footer = state.generation > 0
            && state.durable_len != 0
            && state.physical_tail == PhysicalTail::TruncateToValid;
        let append_at = if state.physical_tail == PhysicalTail::TruncateToValid {
            if preserve_footer && state.valid_len == state.durable_len {
                state
                    .durable_len
                    .checked_add(u64::try_from(recover::FOOTER_BYTES).unwrap_or(u64::MAX))
                    .ok_or_else(|| io::Error::other("volume footer offset overflow"))?
            } else if preserve_footer {
                state.valid_len
            } else {
                state.file.set_len(state.valid_len)?;
                state.valid_len
            }
        } else {
            state.valid_len
        };
        state.file.seek(SeekFrom::Start(append_at))?;
        state.file.write_all(&RECORD_MAGIC)?;
        state.file.write_all(&total_len.to_le_bytes())?;
        state.file.write_all(&next_sequence.to_le_bytes())?;
        state.file.write_all(&[operation as u8])?;
        state.file.write_all(&name_len.to_le_bytes())?;
        state.file.write_all(&offset.to_le_bytes())?;
        state.file.write_all(&payload_len.to_le_bytes())?;
        state.file.write_all(&checksum)?;
        state.file.write_all(name)?;
        let physical_payload = append_at
            .checked_add(u64::try_from(RECORD_FIXED_BYTES).unwrap_or(u64::MAX))
            .and_then(|value| value.checked_add(u64::from(name_len)))
            .ok_or_else(|| io::Error::other("volume physical offset overflow"))?;
        state.file.write_all(payload)?;
        state.boundary_pending = false;
        state.valid_len = append_at
            .checked_add(total_len)
            .ok_or_else(|| io::Error::other("volume length overflow"))?;
        state.sequence = next_sequence;
        Ok((physical_payload, payload_len))
    }

    fn make_durable(state: &mut ContainerState) -> io::Result<()> {
        if state.last_commit_offset == 0
            && state.valid_len == VOLUME_MAGIC.len() as u64
            && state.regions.is_empty()
        {
            // Preserve the empty-container grammar: there is no commit to
            // point at until the first namespace mutation is durable.
            state.file.sync_all()?;
            return Ok(());
        }
        if (state.valid_len != state.durable_len
            || state.last_commit_offset == 0
            || !state.last_commit_has_snapshot)
            && !state.boundary_pending
        {
            let region = VolumeRegion::new(COMMIT_REGION)?;
            let snapshot = recover::encode_region_snapshot(&state.regions)?;
            let commit_offset = state.valid_len;
            Self::append(state, Operation::Commit, &region, 0, &snapshot)?;
            state.last_commit_offset = commit_offset;
            state.last_commit_has_snapshot = true;
            state.durable_len = state.valid_len;
            state.boundary_pending = true;
        }
        if state.footer_pending || state.boundary_pending {
            recover::write_footer(
                &mut state.file,
                state.last_commit_offset,
                state.durable_len,
                state.sequence,
            )?;
        }
        state.file.sync_all()?;
        if state.generation > 0 {
            // Republish the sibling first: a tear while updating the selected
            // slot still leaves one checksummed root naming either the old or
            // the new authority.
            let selected_slot = state.root_slot == RootSlot::Second;
            recover::write_root_pointer(
                &mut state.file,
                state.generation,
                state.root_base,
                state.durable_len,
                !selected_slot,
            )?;
            state.file.sync_all()?;
            #[cfg(test)]
            if ROOT_WRITE_INTERRUPT.with(Cell::get) {
                ROOT_WRITE_INTERRUPT.with(|armed| armed.set(false));
                return Err(io::Error::other("interrupted after sibling root write"));
            }
            recover::write_root_pointer(
                &mut state.file,
                state.generation,
                state.root_base,
                state.durable_len,
                selected_slot,
            )?;
            state.file.sync_all()?;
            recover::write_root_pointer(
                &mut state.file,
                state.generation,
                state.root_base,
                state.durable_len,
                true,
            )?;
            state.file.sync_all()?;
            state.root_slot = RootSlot::Second;
        }
        state.boundary_pending = false;
        state.footer_pending = false;
        Ok(())
    }

    /// Publish a compact replacement through the inode-stable volume root.
    ///
    /// This is the prerelease same-inode shrink primitive. The released
    /// [`AstridVolume::reclaim`] path remains the generic namespace swap.
    ///
    /// # Errors
    ///
    /// Returns an I/O, durability, or volume-generation error.
    pub fn reclaim_same_inode(&self) -> io::Result<()> {
        reclaim::reclaim_same_inode(self)
    }

    #[cfg(test)]
    fn detach_after_uncommitted_write_for_test(
        &self,
        region: &VolumeRegion,
        bytes: &[u8],
    ) -> io::Result<()> {
        self.write_region_at(region, 0, bytes)?;
        let mut state = self.state.lock();
        let old = std::mem::replace(&mut state.file, tempfile::tempfile()?);
        fs2::FileExt::unlock(&old)?;
        Ok(())
    }

    #[cfg(test)]
    fn detach_for_test(&self) -> io::Result<()> {
        let mut state = self.state.lock();
        let old = std::mem::replace(&mut state.file, tempfile::tempfile()?);
        fs2::FileExt::unlock(&old)?;
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

#[cfg(test)]
mod root_tests;
