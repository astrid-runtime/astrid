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

mod extent_index;
mod open;
mod reclaim;
mod recover;
mod region_io;
mod stream;

const VOLUME_MAGIC: [u8; 8] = *b"ASTVOL1\0";
const RECORD_MAGIC: [u8; 8] = *b"ASTREG1\0";
const RECORD_FIXED_BYTES: usize = 8 + 8 + 8 + 1 + 2 + 8 + 8 + 32;
const MAX_METADATA_MUTATIONS: usize = 1_024;
const METADATA_TRANSACTION_REGION: &str = "system/volume-metadata-transaction";
const COMMIT_REGION: &str = "system/volume-commit";

#[derive(Clone, Copy, Debug)]
struct Extent {
    logical_end: u64,
    physical_offset: u64,
}

struct AppendedRecord {
    payload_offset: u64,
    payload_len: u64,
    checksum: [u8; 32],
}

#[cfg(test)]
thread_local! {
    static REGION_STATE_CLONES: Cell<usize> = const { Cell::new(0) };
    static EXTENT_VISITS: Cell<usize> = const { Cell::new(0) };
    static MUTATION_EXTENT_VISITS: Cell<usize> = const { Cell::new(0) };
    static PREPARE_TRUNCATE_COUNT: Cell<usize> = const { Cell::new(0) };
    static FAIL_PREPARE_TRUNCATE: Cell<bool> = const { Cell::new(false) };
    static FAIL_ROLLBACK_TRUNCATE: Cell<bool> = const { Cell::new(false) };
    static REMAINING_APPEND_WRITES: Cell<Option<usize>> = const { Cell::new(None) };
}

#[derive(Debug, Default)]
struct RegionState {
    length: u64,
    // Legacy namespaces retain their map here until conversion. Paged
    // namespaces retain only writes since their last bounded checkpoint.
    extents: BTreeMap<u64, Extent>,
    root: Option<extent_index::reference::PageRef>,
    // A truncate permanently clips the old base, even after logical regrowth.
    base_limit: u64,
}

impl Clone for RegionState {
    fn clone(&self) -> Self {
        #[cfg(test)]
        REGION_STATE_CLONES.with(|count| count.set(count.get().saturating_add(1)));
        Self {
            length: self.length,
            extents: self.extents.clone(),
            root: self.root,
            base_limit: self.base_limit,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum FlushState {
    Required,
    Confirmed,
}

/// Process-local proof that the owned handle's physical end matches `valid_len`.
/// Independent of `footer_pending`, `flush_state` and durability acknowledgements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PhysicalTail {
    Exact,
    MayExceed,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestoreState {
    NotRequired,
    Required,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum CheckpointFormat {
    #[default]
    Legacy,
    Paged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndexCheckpoint {
    NotPrepared,
    Prepared,
}

#[derive(Debug)]
struct ContainerState {
    checkpoint_format: CheckpointFormat,
    index_checkpoint: IndexCheckpoint,
    file: File,
    sequence: u64,
    valid_len: u64,
    durable_len: u64,
    last_commit_offset: u64,
    last_snapshot_end: u64,
    boundary_pending: bool,
    footer_pending: bool,
    // Process-local proof that physical length may exceed valid_len (footer or
    // uncertain mutation). Never derived from per-append metadata queries.
    physical_tail: PhysicalTail,
    // Process-local proof only: set after a successful full flush, cleared
    // before any file mutation. A recovered footer is not this proof.
    flush_state: FlushState,
    // Publication is acknowledged only after its platform durability barrier.
    publication_pending: bool,
    #[cfg(windows)]
    restore: RestoreState,
    regions: BTreeMap<VolumeRegion, RegionState>,
}

/// Hosted realization of an Astrid volume in one container file.
pub struct HostedFileVolume {
    path: PathBuf,
    open_lock: open::OpenReclaimLock,
    state: Mutex<ContainerState>,
    /// Windows: keep admitted runtime-root authority after `state` so Drop
    /// releases the volume file before the namespace fence.
    #[cfg(windows)]
    _retained_root:
        Option<std::sync::Arc<astrid_core::platform_fs::directory_capability::RetainedPrivateRoot>>,
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
    /// Check the expected path against the currently owned container handle.
    /// Reclaim can replace this handle, so callers must not cache its inode.
    pub(crate) fn require_current_binding(&self, path: &std::path::Path) -> io::Result<()> {
        self.with_current_binding(path, |_| Ok(()))
    }

    /// Capture the actual owned inode for one final projection retirement.
    #[cfg(any(unix, windows))]
    pub(crate) fn retirement_file(&self, path: &std::path::Path) -> io::Result<std::fs::File> {
        self.with_current_binding(path, std::fs::File::try_clone)
    }

    fn with_current_binding<T>(
        &self,
        path: &std::path::Path,
        operation: impl FnOnce(&std::fs::File) -> io::Result<T>,
    ) -> io::Result<T> {
        if self.path != std::path::absolute(path)? {
            return Err(io::Error::other(
                "Astrid volume belongs to a different home",
            ));
        }
        astrid_core::platform_fs::verify_no_redirects(path)?;
        let state = self.state.lock();
        open::require_current(&state.file, path)?;
        operation(&state.file)
    }

    fn append(
        state: &mut ContainerState,
        operation: Operation,
        region: &VolumeRegion,
        offset: u64,
        payload: &[u8],
    ) -> io::Result<(u64, u64)> {
        let record = Self::append_record(state, operation, region, offset, payload)?;
        Ok((record.payload_offset, record.payload_len))
    }

    /// Clear flush proof, ensure the previous physical tail is discarded when
    /// needed, seek to `valid_len`, then mark `MayExceed` before any record write.
    fn prepare_append(state: &mut ContainerState) -> io::Result<()> {
        state.flush_state = FlushState::Required;
        state.footer_pending = true;
        if state.physical_tail == PhysicalTail::MayExceed {
            #[cfg(test)]
            {
                PREPARE_TRUNCATE_COUNT.with(|count| count.set(count.get().saturating_add(1)));
                if FAIL_PREPARE_TRUNCATE.with(Cell::get) {
                    FAIL_PREPARE_TRUNCATE.with(|flag| flag.set(false));
                    return Err(io::Error::other("injected prepare truncate failure"));
                }
            }
            state.file.set_len(state.valid_len)?;
            state.physical_tail = PhysicalTail::Exact;
        }
        state.file.seek(SeekFrom::Start(state.valid_len))?;
        // Any caller after this may write; keep the physical end uncertain until
        // the record fully publishes and advances valid_len.
        state.physical_tail = PhysicalTail::MayExceed;
        Ok(())
    }

    fn write_append_bytes(file: &mut File, bytes: &[u8]) -> io::Result<()> {
        #[cfg(test)]
        {
            let fail = REMAINING_APPEND_WRITES.with(|cell| {
                let Some(remaining) = cell.get() else {
                    return false;
                };
                if remaining == 0 {
                    true
                } else {
                    cell.set(Some(remaining.saturating_sub(1)));
                    false
                }
            });
            if fail {
                // Leave a real physical tail beyond valid_len for retry coverage.
                let prefix = bytes.len().min(8);
                if prefix != 0 {
                    file.write_all(&bytes[..prefix])?;
                }
                return Err(io::Error::other("injected append write failure"));
            }
        }
        file.write_all(bytes)
    }

    fn set_len_for_rollback(state: &mut ContainerState, len: u64) -> io::Result<()> {
        #[cfg(test)]
        {
            if FAIL_ROLLBACK_TRUNCATE.with(Cell::get) {
                FAIL_ROLLBACK_TRUNCATE.with(|flag| flag.set(false));
                return Err(io::Error::other("injected rollback truncate failure"));
            }
        }
        state.file.set_len(len)
    }

    fn append_record(
        state: &mut ContainerState,
        operation: Operation,
        region: &VolumeRegion,
        offset: u64,
        payload: &[u8],
    ) -> io::Result<AppendedRecord> {
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

        // A footer may occupy the old valid-end until the next append. Discard
        // it only when the process-local proof says the physical end may exceed
        // valid_len; valid_len itself excludes the footer.
        Self::prepare_append(state)?;
        Self::write_append_bytes(&mut state.file, &RECORD_MAGIC)?;
        Self::write_append_bytes(&mut state.file, &total_len.to_le_bytes())?;
        Self::write_append_bytes(&mut state.file, &next_sequence.to_le_bytes())?;
        Self::write_append_bytes(&mut state.file, &[operation as u8])?;
        Self::write_append_bytes(&mut state.file, &name_len.to_le_bytes())?;
        Self::write_append_bytes(&mut state.file, &offset.to_le_bytes())?;
        Self::write_append_bytes(&mut state.file, &payload_len.to_le_bytes())?;
        Self::write_append_bytes(&mut state.file, &checksum)?;
        Self::write_append_bytes(&mut state.file, name)?;
        let physical_payload = state
            .valid_len
            .checked_add(u64::try_from(RECORD_FIXED_BYTES).unwrap_or(u64::MAX))
            .and_then(|value| value.checked_add(u64::from(name_len)))
            .ok_or_else(|| io::Error::other("volume physical offset overflow"))?;
        Self::write_append_bytes(&mut state.file, payload)?;
        state.boundary_pending = false;
        state.valid_len = state
            .valid_len
            .checked_add(total_len)
            .ok_or_else(|| io::Error::other("volume length overflow"))?;
        state.sequence = next_sequence;
        // Plain append has no rollback: only a fully published record returns Exact.
        state.physical_tail = PhysicalTail::Exact;
        Ok(AppendedRecord {
            payload_offset: physical_payload,
            payload_len,
            checksum,
        })
    }

    fn make_durable(state: &mut ContainerState) -> io::Result<()> {
        Self::make_durable_with(state, File::sync_all)
    }

    fn make_durable_with(
        state: &mut ContainerState,
        flush: impl FnOnce(&File) -> io::Result<()>,
    ) -> io::Result<()> {
        if state.flush_state == FlushState::Confirmed {
            return Ok(());
        }
        if state.checkpoint_format == CheckpointFormat::Legacy
            && state.last_commit_offset == 0
            && state.valid_len == VOLUME_MAGIC.len() as u64
            && state.regions.is_empty()
        {
            // Preserve the empty-container grammar: there is no commit to
            // point at until the first namespace mutation is durable.
            flush(&state.file)?;
            state.flush_state = FlushState::Confirmed;
            return Ok(());
        }
        if Self::needs_commit(state) {
            let region = VolumeRegion::new(COMMIT_REGION)?;
            let payload = Self::commit_payload(state)?;
            let commit_start = state.valid_len;
            Self::append(state, Operation::Commit, &region, 0, &payload)?;
            if !payload.is_empty() {
                state.last_commit_offset = commit_start;
                state.last_snapshot_end = state.valid_len;
                state.index_checkpoint = IndexCheckpoint::NotPrepared;
            }
            state.durable_len = state.valid_len;
            state.boundary_pending = true;
        }
        if state.footer_pending || state.boundary_pending {
            // Footer IO extends physical length beyond valid_len on success or
            // may leave an uncertain tail on failure; retain MayExceed either way.
            state.physical_tail = PhysicalTail::MayExceed;
            recover::write_footer(
                &mut state.file,
                state.last_commit_offset,
                state.durable_len,
                state.sequence,
            )?;
        }
        flush(&state.file)?;
        state.boundary_pending = false;
        state.footer_pending = false;
        state.flush_state = FlushState::Confirmed;
        Ok(())
    }

    fn needs_commit(state: &ContainerState) -> bool {
        !state.boundary_pending
            && (state.valid_len != state.durable_len
                || state.last_snapshot_end == 0
                || state.index_checkpoint == IndexCheckpoint::Prepared)
    }

    fn commit_payload(state: &mut ContainerState) -> io::Result<Vec<u8>> {
        if state.last_snapshot_end != 0 && state.index_checkpoint == IndexCheckpoint::NotPrepared {
            let tail = state
                .valid_len
                .checked_sub(state.last_snapshot_end)
                .ok_or_else(|| io::Error::other("volume snapshot tail underflow"))?;
            let empty_commit = (RECORD_FIXED_BYTES as u64)
                .checked_add(
                    u64::try_from(COMMIT_REGION.len())
                        .map_err(|_| io::Error::other("volume commit region length overflow"))?,
                )
                .ok_or_else(|| io::Error::other("volume empty commit length overflow"))?;
            if tail
                .checked_add(empty_commit)
                .is_some_and(|end| end <= recover::MAX_COMMIT_SNAPSHOT_BYTES)
            {
                return Ok(Vec::new());
            }
        }
        if state.checkpoint_format == CheckpointFormat::Legacy
            && recover::snapshot_bytes(&state.regions)? <= recover::MAX_COMMIT_SNAPSHOT_BYTES
        {
            recover::encode_region_snapshot(&state.regions)
        } else {
            extent_index::publication::prepare_checkpoint(state)
        }
    }
}
impl Drop for HostedFileVolume {
    fn drop(&mut self) {
        let state = self.state.get_mut();
        if reclaim::finish_publication(&self.path, state).is_ok() {
            let _ = Self::make_durable(state);
        }
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
        let state = self.state.lock();
        let Some(region_state) = state.regions.get(region) else {
            return Err(io::Error::new(io::ErrorKind::NotFound, region.as_str()));
        };
        region_io::read(&state.file, region_state, offset, buffer)
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
        region_state.base_limit = region_state.base_limit.min(length);
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
        let _open_guard = self.open_lock.lock();
        let mut state = self.state.lock();
        reclaim::finish_publication(&self.path, &mut state)?;
        Self::make_durable(&mut state)
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
    IndexPage = 9,
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
            9 => Ok(Self::IndexPage),
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
    // Extents never overlap, so only the predecessor can cross `start`.
    // All earlier extents are irrelevant even when this is a pure append.
    let first = mutation_start(extents, start);
    let overlapping = extents
        .range(first..end)
        .inspect(|_| record_mutation_extent_visit())
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
    let first = mutation_start(extents, length);
    let affected = extents
        .range(first..)
        .inspect(|_| record_mutation_extent_visit())
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

fn mutation_start(extents: &BTreeMap<u64, Extent>, offset: u64) -> u64 {
    extents
        .range(..=offset)
        .next_back()
        .and_then(|(start, extent)| (extent.logical_end > offset).then_some(*start))
        .unwrap_or(offset)
}

fn record_mutation_extent_visit() {
    #[cfg(test)]
    MUTATION_EXTENT_VISITS.with(|count| count.set(count.get().saturating_add(1)));
}

#[cfg(test)]
pub(crate) use stream::write_record_payloads;

#[cfg(test)]
mod tests;

#[cfg(test)]
fn reset_prepare_truncate_count() {
    PREPARE_TRUNCATE_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
fn prepare_truncate_count() -> usize {
    PREPARE_TRUNCATE_COUNT.with(Cell::get)
}

#[cfg(test)]
fn set_fail_prepare_truncate(value: bool) {
    FAIL_PREPARE_TRUNCATE.with(|flag| flag.set(value));
}

#[cfg(test)]
fn set_fail_rollback_truncate(value: bool) {
    FAIL_ROLLBACK_TRUNCATE.with(|flag| flag.set(value));
}

#[cfg(test)]
fn set_remaining_append_writes(value: Option<usize>) {
    REMAINING_APPEND_WRITES.with(|cell| cell.set(value));
}

#[cfg(test)]
mod append_tail_tests;

#[cfg(test)]
mod sync_tests;

#[cfg(test)]
mod checkpoint_tests;
#[cfg(test)]
mod test_support;

#[cfg(test)]
mod extent_mutation_tests;

#[cfg(test)]
mod open_tests;

#[cfg(test)]
mod maintenance_tests;
