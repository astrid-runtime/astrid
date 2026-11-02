//! Restore the named checkpoint with the validation required by its source.

use std::collections::BTreeMap;
use std::fs::File;
use std::io;

use super::{
    COMMIT_REGION, MAX_COMMIT_SNAPSHOT_BYTES, Operation, RECORD_FIXED_BYTES, RECOVERY_BUFFER_BYTES,
    RecordHeader, Recovery, RegionState, VolumeRegion, apply_record, index, invalid_transition,
    read_header, read_record_payload, verify_tail_write_checksum,
};

/// Footer recovery authenticates newly interpreted write bytes. A completed
/// header scan already validated every transition and preserves the documented
/// legacy header-only contract: it is not a write-data integrity scrub.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Origin {
    Footer,
    HeaderScan,
}

pub(super) fn recover(
    file: &File,
    last_commit_offset: u64,
    durable_len: u64,
    sequence: u64,
    origin: Origin,
) -> io::Result<Option<Recovery>> {
    let Some((header, payload)) = read_checkpoint(file, last_commit_offset, durable_len)? else {
        return Ok(None);
    };
    let checkpoint_format = index::checkpoint_format(&payload);
    let mut regions =
        index::decode_checkpoint(file, &payload, last_commit_offset, header.sequence)?;
    let snapshot_end = last_commit_offset
        .checked_add(header.total_len)
        .ok_or_else(|| io::Error::other("volume checkpoint end overflow"))?;
    if snapshot_end > durable_len {
        return Err(invalid_transition(
            "volume checkpoint extends past durable length",
        ));
    }
    if snapshot_end == durable_len {
        if header.sequence != sequence {
            return Err(invalid_transition(
                "volume footer sequence does not match checkpoint",
            ));
        }
    } else {
        replay_checkpoint_tail(
            file,
            &mut regions,
            header.sequence,
            snapshot_end,
            durable_len,
            sequence,
            origin,
        )?;
    }
    Ok(Some(Recovery {
        checkpoint_format,
        regions,
        sequence,
        valid_len: durable_len,
        durable_len,
        last_commit_offset,
        last_snapshot_end: snapshot_end,
        footer_present: false,
    }))
}

fn read_checkpoint(
    file: &File,
    offset: u64,
    durable_len: u64,
) -> io::Result<Option<(RecordHeader, Vec<u8>)>> {
    let Some(header) = read_header(file, offset, durable_len)? else {
        return Ok(None);
    };
    if header.operation != Operation::Commit
        || header.name.as_str() != COMMIT_REGION
        || header.logical_offset != 0
    {
        return Ok(None);
    }
    let payload = read_record_payload(file, &header)?.unwrap_or_default();
    if payload.is_empty() {
        return Ok(None);
    }
    Ok(Some((header, payload)))
}

fn replay_checkpoint_tail(
    file: &File,
    regions: &mut BTreeMap<VolumeRegion, RegionState>,
    mut sequence: u64,
    mut offset: u64,
    durable_len: u64,
    footer_sequence: u64,
    origin: Origin,
) -> io::Result<()> {
    let tail = durable_len
        .checked_sub(offset)
        .ok_or_else(|| io::Error::other("volume checkpoint tail underflow"))?;
    if tail > MAX_COMMIT_SNAPSHOT_BYTES {
        return Err(invalid_transition(
            "volume checkpoint tail exceeds format bound",
        ));
    }
    let mut last_was_commit = false;
    let mut write_buffer = (origin == Origin::Footer).then(|| vec![0_u8; RECOVERY_BUFFER_BYTES]);
    while offset < durable_len {
        let remaining = durable_len.saturating_sub(offset);
        if remaining < RECORD_FIXED_BYTES as u64 {
            return Err(invalid_transition("truncated volume checkpoint tail"));
        }
        let Some(header) = read_header(file, offset, durable_len)? else {
            return Err(invalid_transition("truncated volume checkpoint tail"));
        };
        if header.sequence != sequence.saturating_add(1) {
            return Err(invalid_transition(
                "Astrid volume record sequence is not contiguous",
            ));
        }
        let record_end = offset
            .checked_add(header.total_len)
            .ok_or_else(|| io::Error::other("volume checkpoint tail overflow"))?;
        if record_end > durable_len {
            return Err(invalid_transition(
                "volume checkpoint tail record overruns durable length",
            ));
        }
        // Unlike snapshot extents, these headers are newly interpreted state.
        // Verify write bytes as well as metadata before trusting their offsets.
        // The enclosing tail bound limits I/O; hashing uses a fixed-size buffer.
        if header.operation == Operation::Write
            && let Some(buffer) = write_buffer.as_mut()
        {
            verify_tail_write_checksum(file, &header, buffer)?;
        }
        let payload = read_record_payload(file, &header)?;
        if header.operation == Operation::Commit
            && payload.as_ref().is_some_and(|bytes| !bytes.is_empty())
        {
            return Err(invalid_transition(
                "volume checkpoint tail contains a later snapshot",
            ));
        }
        apply_record(file, regions, &header, payload.as_deref())?;
        sequence = header.sequence;
        last_was_commit = header.operation == Operation::Commit;
        offset = record_end;
    }
    if !last_was_commit {
        return Err(invalid_transition(
            "volume checkpoint tail does not end at a commit",
        ));
    }
    if sequence != footer_sequence || offset != durable_len {
        return Err(invalid_transition(
            "volume footer sequence does not match recovered tail",
        ));
    }
    Ok(())
}
