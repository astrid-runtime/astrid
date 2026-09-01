//! Hosted volume recovery, commit snapshots, and the EOF durability footer.

#[cfg(test)]
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};

use super::{
    COMMIT_REGION, Extent, MAX_REGION_NAME_BYTES, METADATA_TRANSACTION_REGION, Operation,
    RECORD_FIXED_BYTES, RECORD_MAGIC, ROOT_BYTES, ROOT_MAGIC, ROOT_SLOT_BYTES, RegionState,
    VOLUME_MAGIC, VolumeRegion, apply_metadata_mutations, decode_metadata_mutations,
    invalid_transition, overlay_extent, truncate_extents,
};

const RECOVERY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_METADATA_PAYLOAD_BYTES: u64 = 2 * 1024 * 1024;
// This is a format bound, not an operator knob: a commit must be bounded so
// open can retain metadata while refusing unbounded allocations. 65k arena
// extents are about 1.6 MiB before region names and framing.
const MAX_COMMIT_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024;
const SNAPSHOT_MAGIC: [u8; 8] = *b"ASTMAP1\0";
const FOOTER_MAGIC: [u8; 8] = *b"ASTFTR1\0";
pub(super) const FOOTER_BYTES: usize = FOOTER_MAGIC.len() + 8 + 8 + 8 + 32;

#[cfg(test)]
thread_local! {
    static READ_HEADER_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(super) fn reset_read_header_count() {
    READ_HEADER_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(super) fn read_header_count() -> usize {
    READ_HEADER_COUNT.with(Cell::get)
}

#[derive(Debug)]
pub(super) struct Recovery {
    pub(super) generation: u64,
    pub(super) root_base: u64,
    pub(super) pointer_slot: bool,
    pub(super) regions: BTreeMap<VolumeRegion, RegionState>,
    pub(super) sequence: u64,
    pub(super) valid_len: u64,
    pub(super) durable_len: u64,
    pub(super) last_commit_offset: u64,
    pub(super) last_commit_has_snapshot: bool,
    pub(super) footer_present: bool,
    pub(super) authority_len: u64,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct RootPointer {
    pub(super) generation: u64,
    pub(super) root_base: u64,
    pub(super) footer_offset: u64,
    pub(super) slot: bool,
}

#[derive(Clone, Debug)]
struct RecordHeader {
    total_len: u64,
    sequence: u64,
    operation: Operation,
    logical_offset: u64,
    checksum: [u8; 32],
    name: VolumeRegion,
    payload_offset: u64,
    payload_len: u64,
}

pub(super) fn recover_container(file: &mut File) -> io::Result<Recovery> {
    if let Some(recovery) = recover_from_root(file)? {
        return Ok(recovery);
    }
    if let Some(recovery) = recover_from_footer(file)? {
        return Ok(recovery);
    }
    advise_random_access(file);
    recover_from_headers(file)
}

pub(super) fn write_root_pointer(
    file: &mut File,
    generation: u64,
    root_base: u64,
    footer_offset: u64,
    slot: bool,
) -> io::Result<()> {
    if generation == 0 || root_base == 0 {
        return Err(invalid_transition("invalid volume root pointer"));
    }
    let mut encoded = Vec::with_capacity(ROOT_SLOT_BYTES);
    encoded.extend_from_slice(&ROOT_MAGIC);
    encoded.extend_from_slice(&generation.to_le_bytes());
    encoded.extend_from_slice(&root_base.to_le_bytes());
    encoded.extend_from_slice(&footer_offset.to_le_bytes());
    let checksum = root_checksum(generation, root_base, footer_offset);
    encoded.extend_from_slice(&checksum);
    let offset = u64::try_from(if slot {
        ROOT_BYTES - ROOT_SLOT_BYTES
    } else {
        VOLUME_MAGIC.len()
    })
    .map_err(|_| invalid_transition("volume root offset overflow"))?;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&encoded)
}

fn root_checksum(generation: u64, root_base: u64, footer_offset: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("astrid volume root v1");
    hasher.update(&ROOT_MAGIC);
    hasher.update(&generation.to_le_bytes());
    hasher.update(&root_base.to_le_bytes());
    hasher.update(&footer_offset.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn decode_root_pointer(
    file: &File,
    slot: bool,
    physical_len: u64,
) -> io::Result<Option<RootPointer>> {
    let slot_offset = if slot {
        ROOT_BYTES - ROOT_SLOT_BYTES
    } else {
        VOLUME_MAGIC.len()
    };
    if physical_len.saturating_sub(slot_offset as u64) < ROOT_SLOT_BYTES as u64 {
        return Ok(None);
    }
    let mut encoded = [0_u8; ROOT_SLOT_BYTES];
    read_exact_at(file, slot_offset as u64, &mut encoded)?;
    if encoded[..ROOT_MAGIC.len()] != ROOT_MAGIC {
        return Ok(None);
    }
    let generation = u64::from_le_bytes(read_array::<8>(&encoded[8..16])?);
    let root_base = u64::from_le_bytes(read_array::<8>(&encoded[16..24])?);
    let footer_offset = u64::from_le_bytes(read_array::<8>(&encoded[24..32])?);
    let checksum = &encoded[32..ROOT_SLOT_BYTES];
    if generation == 0
        || root_base == 0
        || checksum != root_checksum(generation, root_base, footer_offset).as_slice()
    {
        return Ok(None);
    }
    if footer_offset != 0
        && footer_offset
            .checked_add(FOOTER_BYTES as u64)
            .is_none_or(|end| end > physical_len)
    {
        return Ok(None);
    }
    Ok(Some(RootPointer {
        generation,
        root_base,
        footer_offset,
        slot,
    }))
}

fn recovery_from_pointer(
    file: &mut File,
    pointer: RootPointer,
    physical_len: u64,
) -> io::Result<Option<Recovery>> {
    if pointer.footer_offset == 0 {
        if pointer.root_base != ROOT_BYTES as u64 || physical_len != ROOT_BYTES as u64 {
            return Ok(None);
        }
        return Ok(Some(Recovery {
            generation: pointer.generation,
            root_base: pointer.root_base,
            pointer_slot: pointer.slot,
            regions: BTreeMap::new(),
            sequence: 0,
            valid_len: ROOT_BYTES as u64,
            durable_len: 0,
            last_commit_offset: 0,
            last_commit_has_snapshot: false,
            footer_present: false,
            authority_len: ROOT_BYTES as u64,
        }));
    }
    let authority_len = pointer
        .footer_offset
        .checked_add(FOOTER_BYTES as u64)
        .ok_or_else(|| invalid_transition("volume root authority overflow"))?;
    let Some(mut recovery) = recover_footer_at(file, pointer.footer_offset, authority_len, true)?
    else {
        return Ok(None);
    };
    recovery.generation = pointer.generation;
    recovery.root_base = pointer.root_base;
    recovery.pointer_slot = pointer.slot;
    recovery.authority_len = authority_len;
    Ok(Some(recovery))
}

fn recover_from_root(file: &mut File) -> io::Result<Option<Recovery>> {
    let physical_len = file.metadata()?.len();
    let mut candidates = [
        decode_root_pointer(file, false, physical_len)?,
        decode_root_pointer(file, true, physical_len)?,
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    candidates.sort_by_key(|pointer| std::cmp::Reverse(pointer.generation));
    for pointer in candidates {
        if let Some(recovery) = recovery_from_pointer(file, pointer, physical_len)? {
            return Ok(Some(recovery));
        }
    }
    for slot_offset in [VOLUME_MAGIC.len(), ROOT_BYTES - ROOT_SLOT_BYTES] {
        let marker_end = u64::try_from(slot_offset)
            .ok()
            .and_then(|offset| offset.checked_add(ROOT_MAGIC.len() as u64));
        if marker_end.is_none_or(|end| physical_len < end) {
            continue;
        }
        let mut marker = [0_u8; ROOT_MAGIC.len()];
        read_exact_at(file, slot_offset as u64, &mut marker)?;
        if marker == ROOT_MAGIC {
            return Err(invalid_transition("invalid Astrid volume root pointer"));
        }
    }
    Ok(None)
}

pub(super) fn encode_region_snapshot(
    regions: &BTreeMap<VolumeRegion, RegionState>,
) -> io::Result<Vec<u8>> {
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

pub(super) fn write_footer(
    file: &mut File,
    last_commit_offset: u64,
    durable_len: u64,
    sequence: u64,
) -> io::Result<()> {
    if last_commit_offset == 0 {
        return Err(invalid_transition("volume footer has no commit"));
    }
    let checksum = footer_checksum(last_commit_offset, durable_len, sequence);
    if file.metadata()?.len() < durable_len {
        file.set_len(durable_len)?;
    }
    file.seek(SeekFrom::Start(durable_len))?;
    file.write_all(&FOOTER_MAGIC)?;
    file.write_all(&last_commit_offset.to_le_bytes())?;
    file.write_all(&durable_len.to_le_bytes())?;
    file.write_all(&sequence.to_le_bytes())?;
    file.write_all(&checksum)?;
    Ok(())
}

fn recover_from_footer(file: &File) -> io::Result<Option<Recovery>> {
    let physical_len = file.metadata()?.len();
    if physical_len < FOOTER_BYTES as u64 {
        return Ok(None);
    }
    let footer_offset = physical_len
        .checked_sub(FOOTER_BYTES as u64)
        .ok_or_else(|| io::Error::other("volume footer offset underflow"))?;
    recover_footer_at(file, footer_offset, physical_len, true)
}

fn recover_footer_at(
    file: &File,
    footer_offset: u64,
    physical_len: u64,
    footer_present: bool,
) -> io::Result<Option<Recovery>> {
    if physical_len.saturating_sub(footer_offset) < FOOTER_BYTES as u64 {
        return Ok(None);
    }
    let mut footer = [0_u8; FOOTER_BYTES];
    read_exact_at(file, footer_offset, &mut footer)?;
    if footer[..FOOTER_MAGIC.len()] != FOOTER_MAGIC {
        return Ok(None);
    }
    let last_commit_offset = u64::from_le_bytes(read_array::<8>(&footer[8..16])?);
    let durable_len = u64::from_le_bytes(read_array::<8>(&footer[16..24])?);
    let sequence = u64::from_le_bytes(read_array::<8>(&footer[24..32])?);
    let checksum = &footer[32..64];
    if checksum != footer_checksum(last_commit_offset, durable_len, sequence).as_slice()
        || durable_len != footer_offset
        || last_commit_offset < VOLUME_MAGIC.len() as u64
        || last_commit_offset >= durable_len
    {
        return Ok(None);
    }
    let Some((header, payload)) = read_commit(file, last_commit_offset, durable_len, sequence)?
    else {
        return Ok(None);
    };
    let regions = decode_region_snapshot(&payload, last_commit_offset)?;
    debug_assert_eq!(header.operation, Operation::Commit);
    Ok(Some(Recovery {
        generation: 0,
        root_base: VOLUME_MAGIC.len() as u64,
        pointer_slot: false,
        regions,
        sequence,
        valid_len: durable_len,
        durable_len,
        last_commit_offset,
        last_commit_has_snapshot: true,
        footer_present,
        authority_len: physical_len,
    }))
}

fn recover_from_headers(file: &File) -> io::Result<Recovery> {
    let physical_len = file.metadata()?.len();
    let mut offset = VOLUME_MAGIC.len() as u64;
    let mut sequence = 0_u64;
    let mut regions = BTreeMap::new();
    let mut committed_regions = BTreeMap::new();
    let mut committed_sequence = 0_u64;
    let mut committed_offset = offset;
    let mut committed_has_snapshot = false;
    let mut last_commit_offset = 0_u64;
    while offset < physical_len {
        if physical_len.saturating_sub(offset) >= FOOTER_MAGIC.len() as u64 {
            let mut marker = [0_u8; FOOTER_MAGIC.len()];
            read_exact_at(file, offset, &mut marker)?;
            if marker == FOOTER_MAGIC {
                if let Some(mut recovery) = recover_footer_at(file, offset, physical_len, false)? {
                    recovery.footer_present = false;
                    return Ok(recovery);
                }
                // A recognizable but damaged footer is an uncommitted tail;
                // the last Commit already captured the durable namespace.
                break;
            }
        }
        let remaining = physical_len.saturating_sub(offset);
        if remaining < RECORD_FIXED_BYTES as u64 {
            break;
        }
        let header = match read_header(file, offset, physical_len) {
            Ok(Some(header)) => header,
            Ok(None) => break,
            Err(_error)
                if offset >= committed_offset
                    && !has_physically_valid_record_after(
                        file,
                        offset.saturating_add(1),
                        physical_len,
                    )? =>
            {
                break;
            },
            Err(error) => return Err(error),
        };
        if header.sequence != sequence.saturating_add(1) {
            return Err(invalid_transition(
                "Astrid volume record sequence is not contiguous",
            ));
        }
        let payload = match read_record_payload(file, &header) {
            Ok(payload) => payload,
            Err(_error)
                if !has_physically_valid_record_after(
                    file,
                    offset.saturating_add(1),
                    physical_len,
                )? =>
            {
                break;
            },
            Err(error) => return Err(error),
        };
        apply_record(&mut regions, &header, payload.as_deref())?;
        sequence = header.sequence;
        offset = offset
            .checked_add(header.total_len)
            .ok_or_else(|| io::Error::other("volume scan offset overflow"))?;
        if header.operation == Operation::Commit {
            committed_regions = regions.clone();
            committed_sequence = sequence;
            committed_offset = offset;
            committed_has_snapshot = payload.as_ref().is_some_and(|bytes| !bytes.is_empty());
            last_commit_offset = offset
                .checked_sub(header.total_len)
                .ok_or_else(|| io::Error::other("volume commit offset underflow"))?;
        }
    }
    Ok(Recovery {
        generation: 0,
        root_base: VOLUME_MAGIC.len() as u64,
        pointer_slot: false,
        regions: committed_regions,
        sequence: committed_sequence,
        valid_len: committed_offset,
        durable_len: committed_offset,
        last_commit_offset,
        last_commit_has_snapshot: committed_has_snapshot,
        footer_present: false,
        authority_len: committed_offset,
    })
}

fn apply_record(
    regions: &mut BTreeMap<VolumeRegion, RegionState>,
    header: &RecordHeader,
    payload: Option<&[u8]>,
) -> io::Result<()> {
    match header.operation {
        Operation::Commit => {
            if header.name.as_str() != COMMIT_REGION || header.logical_offset != 0 {
                return Err(invalid_transition("invalid volume commit boundary"));
            }
            if let Some(payload) = payload.filter(|payload| !payload.is_empty()) {
                *regions = decode_region_snapshot(payload, header_start(header)?)?;
            }
        },
        Operation::Write => {
            if payload.is_some() || header.payload_len == 0 {
                return Err(invalid_transition("write retained an unexpected payload"));
            }
            let region_state = regions
                .get_mut(&header.name)
                .ok_or_else(|| invalid_transition("write before create"))?;
            let end = header
                .logical_offset
                .checked_add(header.payload_len)
                .ok_or_else(|| invalid_transition("write range overflow"))?;
            overlay_extent(
                &mut region_state.extents,
                header.logical_offset,
                end,
                header.payload_offset,
            );
            region_state.length = region_state.length.max(end);
        },
        Operation::Create => {
            if payload.is_some_and(|payload| !payload.is_empty())
                || regions.contains_key(&header.name)
            {
                return Err(invalid_transition("invalid create"));
            }
            regions.insert(header.name.clone(), RegionState::default());
        },
        Operation::Truncate => {
            if payload.is_some_and(|payload| !payload.is_empty()) {
                return Err(invalid_transition("truncate has payload"));
            }
            let region_state = regions
                .get_mut(&header.name)
                .ok_or_else(|| invalid_transition("truncate before create"))?;
            truncate_extents(&mut region_state.extents, header.logical_offset);
            region_state.length = header.logical_offset;
        },
        Operation::Remove => {
            if payload.is_some_and(|payload| !payload.is_empty())
                || regions.remove(&header.name).is_none()
            {
                return Err(invalid_transition("invalid remove"));
            }
        },
        Operation::Rename | Operation::Replace => {
            let payload =
                payload.ok_or_else(|| invalid_transition("missing region transition payload"))?;
            let destination = String::from_utf8(payload.to_vec())
                .map_err(|_| invalid_transition("region transition destination is not UTF-8"))?;
            let destination = VolumeRegion::new(destination)?;
            if header.operation == Operation::Rename && regions.contains_key(&destination) {
                return Err(invalid_transition("rename destination exists"));
            }
            if header.operation == Operation::Replace && !regions.contains_key(&destination) {
                return Err(invalid_transition("replace destination is absent"));
            }
            let source = regions
                .remove(&header.name)
                .ok_or_else(|| invalid_transition("region transition source is absent"))?;
            regions.insert(destination, source);
        },
        Operation::MetadataTransaction => {
            if header.name.as_str() != METADATA_TRANSACTION_REGION || header.logical_offset != 0 {
                return Err(invalid_transition("invalid metadata transaction envelope"));
            }
            let payload = payload
                .ok_or_else(|| invalid_transition("missing metadata transaction payload"))?;
            let mutations = decode_metadata_mutations(payload)?;
            apply_metadata_mutations(regions, &mutations)?;
        },
    }
    Ok(())
}

fn read_header(file: &File, offset: u64, physical_len: u64) -> io::Result<Option<RecordHeader>> {
    let remaining = physical_len.saturating_sub(offset);
    if remaining < RECORD_FIXED_BYTES as u64 {
        return Ok(None);
    }
    #[cfg(test)]
    READ_HEADER_COUNT.with(|count| count.set(count.get().saturating_add(1)));
    let mut fixed = [0_u8; RECORD_FIXED_BYTES];
    read_exact_at(file, offset, &mut fixed)?;
    if fixed[..RECORD_MAGIC.len()] != RECORD_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Astrid volume record magic at {offset}"),
        ));
    }
    let total_len = u64::from_le_bytes(read_array::<8>(&fixed[8..16])?);
    let name_length = usize::from(u16::from_le_bytes(read_array::<2>(&fixed[25..27])?));
    let payload_len = u64::from_le_bytes(read_array::<8>(&fixed[35..43])?);
    let declared = (RECORD_FIXED_BYTES as u64)
        .checked_add(name_length as u64)
        .and_then(|value| value.checked_add(payload_len));
    if total_len < RECORD_FIXED_BYTES as u64
        || declared != Some(total_len)
        || name_length == 0
        || name_length > MAX_REGION_NAME_BYTES
    {
        return handle_bad_length(file, offset, physical_len, total_len, remaining);
    }
    if total_len > remaining {
        return handle_bad_length(file, offset, physical_len, total_len, remaining);
    }
    let operation = Operation::decode(fixed[24])?;
    let name_offset = offset
        .checked_add(RECORD_FIXED_BYTES as u64)
        .ok_or_else(|| io::Error::other("volume region name offset overflow"))?;
    let mut name = vec![0_u8; name_length];
    read_exact_at(file, name_offset, &mut name)?;
    let name = String::from_utf8(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 region name"))?;
    let name = VolumeRegion::new(name)?;
    let payload_offset = name_offset
        .checked_add(name_length as u64)
        .ok_or_else(|| io::Error::other("volume payload offset overflow"))?;
    Ok(Some(RecordHeader {
        total_len,
        sequence: u64::from_le_bytes(read_array::<8>(&fixed[16..24])?),
        operation,
        logical_offset: u64::from_le_bytes(read_array::<8>(&fixed[27..35])?),
        checksum: read_array::<32>(&fixed[43..75])?,
        name,
        payload_offset,
        payload_len,
    }))
}

fn handle_bad_length(
    file: &File,
    offset: u64,
    physical_len: u64,
    total_len: u64,
    remaining: u64,
) -> io::Result<Option<RecordHeader>> {
    if total_len > remaining
        && has_physically_valid_record_after(file, offset.saturating_add(1), physical_len)?
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid interior Astrid volume record length at {offset}"),
        ));
    }
    if total_len > remaining {
        return Ok(None);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid Astrid volume record length at {offset}"),
    ))
}

fn read_record_payload(file: &File, header: &RecordHeader) -> io::Result<Option<Vec<u8>>> {
    if header.operation == Operation::Write {
        return Ok(None);
    }
    let max_payload = if header.operation == Operation::Commit {
        MAX_COMMIT_SNAPSHOT_BYTES
    } else {
        MAX_METADATA_PAYLOAD_BYTES
    };
    if header.payload_len > max_payload {
        return Err(invalid_transition(
            "Astrid volume metadata payload exceeds the recovery bound",
        ));
    }
    let length = usize::try_from(header.payload_len)
        .map_err(|_| invalid_transition("volume metadata payload too large"))?;
    let mut payload = vec![0_u8; length];
    read_exact_at(file, header.payload_offset, &mut payload)?;
    verify_record_checksum(header, &payload)?;
    Ok(Some(payload))
}

fn verify_record_checksum(header: &RecordHeader, payload: &[u8]) -> io::Result<()> {
    let mut hasher = blake3::Hasher::new_derive_key("astrid volume record v1");
    hasher.update(&header.sequence.to_le_bytes());
    hasher.update(&[header.operation as u8]);
    let name = header.name.as_str().as_bytes();
    let name_len =
        u16::try_from(name.len()).map_err(|_| invalid_transition("region name too long"))?;
    hasher.update(&name_len.to_le_bytes());
    hasher.update(&header.logical_offset.to_le_bytes());
    hasher.update(&header.payload_len.to_le_bytes());
    hasher.update(name);
    hasher.update(payload);
    if hasher.finalize().as_bytes() != &header.checksum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Astrid volume record checksum mismatch",
        ));
    }
    Ok(())
}

fn read_commit(
    file: &File,
    offset: u64,
    durable_len: u64,
    sequence: u64,
) -> io::Result<Option<(RecordHeader, Vec<u8>)>> {
    let Some(header) = read_header(file, offset, durable_len)? else {
        return Ok(None);
    };
    if header.operation != Operation::Commit
        || header.name.as_str() != COMMIT_REGION
        || header.logical_offset != 0
        || header.sequence != sequence
        || header.total_len != durable_len.saturating_sub(offset)
    {
        return Ok(None);
    }
    let payload = read_record_payload(file, &header)?.unwrap_or_default();
    if payload.is_empty() {
        return Ok(None);
    }
    Ok(Some((header, payload)))
}

fn decode_region_snapshot(
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
            .insert(region, RegionState { length, extents })
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

fn has_physically_valid_record_after(file: &File, start: u64, end: u64) -> io::Result<bool> {
    let mut offset = start;
    while end.saturating_sub(offset) >= RECORD_MAGIC.len() as u64 {
        let mut magic = [0_u8; 8];
        let mut cursor = offset;
        while cursor < end {
            let remaining = usize::try_from(end.saturating_sub(cursor)).unwrap_or(0);
            if remaining < magic.len() {
                return Ok(false);
            }
            read_exact_at(file, cursor, &mut magic)?;
            if magic == RECORD_MAGIC && physically_valid_record_at(file, cursor, end)? {
                return Ok(true);
            }
            cursor = cursor.saturating_add(1);
            if cursor.saturating_sub(offset) >= RECOVERY_BUFFER_BYTES as u64 {
                break;
            }
        }
        offset = cursor;
    }
    Ok(false)
}

fn physically_valid_record_at(file: &File, offset: u64, end: u64) -> io::Result<bool> {
    let Some(header) = read_header_without_tail_scan(file, offset, end)? else {
        return Ok(false);
    };
    if header.operation == Operation::Write {
        return Ok(true);
    }
    let Some(payload) = read_record_payload(file, &header)? else {
        return Ok(false);
    };
    let _ = payload;
    Ok(true)
}

fn read_header_without_tail_scan(
    file: &File,
    offset: u64,
    physical_len: u64,
) -> io::Result<Option<RecordHeader>> {
    let remaining = physical_len.saturating_sub(offset);
    if remaining < RECORD_FIXED_BYTES as u64 {
        return Ok(None);
    }
    let mut fixed = [0_u8; RECORD_FIXED_BYTES];
    read_exact_at(file, offset, &mut fixed)?;
    if fixed[..RECORD_MAGIC.len()] != RECORD_MAGIC {
        return Ok(None);
    }
    let total_len = u64::from_le_bytes(read_array::<8>(&fixed[8..16])?);
    let name_length = usize::from(u16::from_le_bytes(read_array::<2>(&fixed[25..27])?));
    let payload_len = u64::from_le_bytes(read_array::<8>(&fixed[35..43])?);
    let declared = (RECORD_FIXED_BYTES as u64)
        .checked_add(name_length as u64)
        .and_then(|value| value.checked_add(payload_len));
    if total_len > remaining
        || declared != Some(total_len)
        || name_length == 0
        || name_length > MAX_REGION_NAME_BYTES
    {
        return Ok(None);
    }
    let name_offset = offset
        .checked_add(RECORD_FIXED_BYTES as u64)
        .ok_or_else(|| io::Error::other("volume region name offset overflow"))?;
    let mut name = vec![0_u8; name_length];
    read_exact_at(file, name_offset, &mut name)?;
    let Ok(name) = String::from_utf8(name) else {
        return Ok(None);
    };
    let Ok(name) = VolumeRegion::new(name) else {
        return Ok(None);
    };
    Ok(Some(RecordHeader {
        total_len,
        sequence: u64::from_le_bytes(read_array::<8>(&fixed[16..24])?),
        operation: match Operation::decode(fixed[24]) {
            Ok(operation) => operation,
            Err(_) => return Ok(None),
        },
        logical_offset: u64::from_le_bytes(read_array::<8>(&fixed[27..35])?),
        checksum: read_array::<32>(&fixed[43..75])?,
        name,
        payload_offset: name_offset
            .checked_add(name_length as u64)
            .ok_or_else(|| io::Error::other("volume payload offset overflow"))?,
        payload_len,
    }))
}

fn header_start(header: &RecordHeader) -> io::Result<u64> {
    let header_bytes = (RECORD_FIXED_BYTES as u64)
        .checked_add(header.name.as_str().len() as u64)
        .ok_or_else(|| io::Error::other("volume header length overflow"))?;
    header
        .payload_offset
        .checked_sub(header_bytes)
        .ok_or_else(|| io::Error::other("volume record header offset underflow"))
}

fn footer_checksum(last_commit_offset: u64, durable_len: u64, sequence: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("astrid volume footer v1");
    hasher.update(&FOOTER_MAGIC);
    hasher.update(&last_commit_offset.to_le_bytes());
    hasher.update(&durable_len.to_le_bytes());
    hasher.update(&sequence.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(read_array::<2>(take(
        bytes, cursor, 2,
    )?)?))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(read_array::<4>(take(
        bytes, cursor, 4,
    )?)?))
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(read_array::<8>(take(
        bytes, cursor, 8,
    )?)?))
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> io::Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| invalid_transition("snapshot cursor overflow"))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_transition("truncated commit snapshot"))?;
    *cursor = end;
    Ok(value)
}

fn read_array<const N: usize>(bytes: &[u8]) -> io::Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| invalid_transition("invalid volume record integer"))
}

fn read_exact_at(file: &File, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
    let mut done = 0_usize;
    while done < buffer.len() {
        let read_offset = offset
            .checked_add(done as u64)
            .ok_or_else(|| io::Error::other("volume positional read offset overflow"))?;
        let read = file_read_at(file, &mut buffer[done..], read_offset)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated Astrid volume record",
            ));
        }
        done = done
            .checked_add(read)
            .ok_or_else(|| io::Error::other("volume positional read length overflow"))?;
    }
    Ok(())
}

#[cfg(unix)]
fn file_read_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt as _;
    file.read_at(buffer, offset)
}

#[cfg(windows)]
fn file_read_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::windows::fs::FileExt as _;
    file.seek_read(buffer, offset)
}

#[cfg(not(any(unix, windows)))]
fn file_read_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::io::{Read, Seek};
    let mut clone = file.try_clone()?;
    clone.seek(SeekFrom::Start(offset))?;
    clone.read(buffer)
}

#[cfg(target_os = "linux")]
fn advise_random_access(file: &File) {
    use nix::fcntl::{PosixFadviseAdvice, posix_fadvise};
    let _ = posix_fadvise(file, 0, 0, PosixFadviseAdvice::POSIX_FADV_RANDOM);
}

#[cfg(target_vendor = "apple")]
fn advise_random_access(file: &File) {
    use nix::fcntl::{FcntlArg, fcntl};
    let _ = fcntl(file, FcntlArg::F_RDAHEAD(false));
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn advise_random_access(_file: &File) {}
