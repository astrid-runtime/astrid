//! Sequential live and committed durable frame scanning.

use std::io::{Read as _, Seek as _};

use super::{
    CHECKSUM_START, DurableError, DurableFrameRange, DurableIo, FRAME_HEADER_LEN,
    FRAME_HEADER_LEN_USIZE, FRAME_VERSION, RecoveryLimits, SeekFrom, corrupt, decode_frame_header,
    frame_checksum, frame_checksum_hasher, io_error, read_exact_at, scan_frames_with_source,
    validate_positioned_header, validate_positioned_payload,
};

/// Successful scans leave the cursor at the current append boundary. After
/// an error the cursor is unspecified: callers must abandon or reposition the
/// handle before reuse. A rejected callback is never treated as tail damage.
pub(in crate::engine::durable) fn scan_frames<F: DurableIo>(
    file: &mut F,
    file_name: &'static str,
    magic: [u8; 8],
    limits: RecoveryLimits,
    mut accept: impl FnMut(u64, &[u8]) -> Result<(), DurableError>,
) -> Result<(), DurableError> {
    scan_frames_with_source(
        file,
        file_name,
        magic,
        limits,
        |location, payload, _source| accept(location.offset(), payload),
    )
}

pub(super) fn read_frame_preserving_cursor_within<F: DurableIo>(
    source: &mut F,
    file_name: &'static str,
    magic: [u8; 8],
    offset: u64,
    limits: RecoveryLimits,
    captured_end: u64,
) -> Result<Vec<u8>, DurableError> {
    // Reject before any media read so load_previous cannot observe bytes past
    // the captured fence, including a concurrent append tail.
    let header_end = offset
        .checked_add(FRAME_HEADER_LEN)
        .ok_or(DurableError::EncodingOverflow)?;
    if header_end > captured_end {
        return Err(corrupt(
            file_name,
            offset,
            "published frame header is truncated",
        ));
    }

    let position = if source.durable_read_at_preserves_cursor() {
        None
    } else {
        Some(
            source
                .stream_position()
                .map_err(|error| io_error("save durable scan read-ahead position", error))?,
        )
    };

    let restore = |source: &mut F, position: Option<u64>| -> Result<(), DurableError> {
        if let Some(position) = position {
            source
                .seek(SeekFrom::Start(position))
                .map_err(|error| io_error("restore durable scan read-ahead position", error))?;
        }
        Ok(())
    };

    let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
    if let Err(error) = read_exact_at(source, &mut header, offset) {
        restore(source, position)?;
        return Err(io_error("read durable scan source header", error));
    }
    let decoded = match validate_positioned_header(file_name, magic, offset, &header, limits) {
        Ok(decoded) => decoded,
        Err(error) => {
            restore(source, position)?;
            return Err(error);
        },
    };
    let Some(frame_len) = FRAME_HEADER_LEN.checked_add(decoded.payload_len) else {
        restore(source, position)?;
        return Err(DurableError::EncodingOverflow);
    };
    let Some(frame_end) = offset.checked_add(frame_len) else {
        restore(source, position)?;
        return Err(DurableError::EncodingOverflow);
    };
    if frame_end > captured_end {
        restore(source, position)?;
        return Err(corrupt(
            file_name,
            offset,
            "published frame payload is truncated",
        ));
    }

    let Ok(payload_usize) = usize::try_from(decoded.payload_len) else {
        restore(source, position)?;
        return Err(DurableError::EncodingOverflow);
    };
    let mut payload = Vec::new();
    if payload.try_reserve_exact(payload_usize).is_err() {
        restore(source, position)?;
        return Err(DurableError::EncodingOverflow);
    }
    payload.resize(payload_usize, 0);
    let Some(payload_offset) = offset.checked_add(FRAME_HEADER_LEN) else {
        restore(source, position)?;
        return Err(DurableError::EncodingOverflow);
    };
    if let Err(error) = read_exact_at(source, &mut payload, payload_offset) {
        restore(source, position)?;
        return Err(io_error("read durable scan source payload", error));
    }
    restore(source, position)?;
    validate_positioned_payload(file_name, magic, offset, decoded, &payload)?;
    Ok(payload)
}

/// Live recovery may truncate an unpublished torn tail; committed ranges never mutate.
#[derive(Clone, Copy, Debug)]
pub(super) enum FrameScanBound {
    LiveRepair { protected_len: u64 },
    Committed(DurableFrameRange),
}

pub(in crate::engine::durable) fn scan_frames_with_protected_prefix<F: DurableIo>(
    file: &mut F,
    file_name: &'static str,
    magic: [u8; 8],
    limits: RecoveryLimits,
    protected_len: u64,
    accept: impl FnMut(u64, &[u8], &mut F) -> Result<(), DurableError>,
) -> Result<(), DurableError> {
    scan_frames_with_bound(
        file,
        file_name,
        magic,
        limits,
        FrameScanBound::LiveRepair { protected_len },
        accept,
    )
}

/// Exact committed prefix `[0, end)` without truncation or reads past `end`.
#[cfg(test)]
pub(in crate::engine::durable) fn scan_frames_prefix<F: DurableIo>(
    file: &mut F,
    file_name: &'static str,
    magic: [u8; 8],
    limits: RecoveryLimits,
    end: super::DurablePrefixEnd,
    mut accept: impl FnMut(u64, &[u8]) -> Result<(), DurableError>,
) -> Result<(), DurableError> {
    scan_frames_with_bound(
        file,
        file_name,
        magic,
        limits,
        FrameScanBound::Committed(DurableFrameRange::prefix(end)),
        |offset, payload, _source| accept(offset, payload),
    )
}

/// Exact committed range `[start, end)` without truncation or reads past `end`.
pub(in crate::engine::durable) fn scan_frames_range<F: DurableIo>(
    file: &mut F,
    file_name: &'static str,
    magic: [u8; 8],
    limits: RecoveryLimits,
    range: DurableFrameRange,
    mut accept: impl FnMut(u64, &[u8]) -> Result<(), DurableError>,
) -> Result<(), DurableError> {
    scan_frames_with_bound(
        file,
        file_name,
        magic,
        limits,
        FrameScanBound::Committed(range),
        |offset, payload, _source| accept(offset, payload),
    )
}

#[derive(Clone, Copy)]
struct FrameScanPolicy {
    file_name: &'static str,
    magic: [u8; 8],
    limits: RecoveryLimits,
    protected_len: u64,
    file_len: u64,
}

pub(super) fn scan_frames_with_bound<F: DurableIo>(
    file: &mut F,
    file_name: &'static str,
    magic: [u8; 8],
    limits: RecoveryLimits,
    bound: FrameScanBound,
    mut accept: impl FnMut(u64, &[u8], &mut F) -> Result<(), DurableError>,
) -> Result<(), DurableError> {
    let physical_len = file
        .durable_metadata()
        .map_err(|source| io_error("read principal-store metadata", source))?
        .len();
    let (scan_start, scan_end, protected_len, restore_cursor) = match bound {
        FrameScanBound::LiveRepair { protected_len } => {
            if physical_len < protected_len {
                return Err(corrupt(
                    file_name,
                    physical_len,
                    "published durable prefix is truncated",
                ));
            }
            (0_u64, physical_len, protected_len, false)
        },
        FrameScanBound::Committed(range) => {
            let start = range.start().get();
            let end = range.end().get();
            if physical_len < end {
                return Err(corrupt(
                    file_name,
                    physical_len,
                    "published durable prefix is truncated",
                ));
            }
            // The whole committed window is protected: torn/cutoff bytes fail closed.
            (start, end, end, true)
        },
    };
    let policy = FrameScanPolicy {
        file_name,
        magic,
        limits,
        protected_len,
        file_len: scan_end,
    };
    let saved_cursor = if restore_cursor {
        Some(
            file.stream_position()
                .map_err(|source| io_error("save durable committed-range cursor", source))?,
        )
    } else {
        None
    };
    file.seek(SeekFrom::Start(scan_start))
        .map_err(|source| io_error("seek durable frame", source))?;

    // One grammar for live and committed scans. Committed mode wraps Take so
    // BufReader fill cannot sequentially read past end; live mode keeps a
    // direct BufReader so tail repair can still observe and truncate media.
    let result = match bound {
        FrameScanBound::LiveRepair { .. } => {
            let mut reader = std::io::BufReader::new(&mut *file);
            let scanned = scan_frames_grammar(
                &mut reader,
                |reader| reader.get_mut(),
                policy,
                scan_start,
                &mut accept,
            );
            if scanned.is_ok() {
                // Tail repair above is terminal: discard any read-ahead before
                // exposing the cursor again, including when repair shortened the
                // underlying file.
                reader
                    .seek(SeekFrom::End(0))
                    .map_err(|source| io_error("seek durable file tail", source))?;
            }
            scanned
        },
        FrameScanBound::Committed(_) => {
            let limit = scan_end
                .checked_sub(scan_start)
                .ok_or(DurableError::EncodingOverflow)?;
            let mut limited = (&mut *file).take(limit);
            let mut reader = std::io::BufReader::new(&mut limited);
            scan_frames_grammar(
                &mut reader,
                |reader| reader.get_mut().get_mut(),
                policy,
                scan_start,
                &mut accept,
            )
        },
    };
    if result.is_ok()
        && let Some(position) = saved_cursor
    {
        file.seek(SeekFrom::Start(position))
            .map_err(|source| io_error("restore durable committed-range cursor", source))?;
    }
    result
}

fn scan_frames_grammar<F, R, GetFile>(
    reader: &mut std::io::BufReader<R>,
    mut get_file: GetFile,
    policy: FrameScanPolicy,
    mut offset: u64,
    accept: &mut impl FnMut(u64, &[u8], &mut F) -> Result<(), DurableError>,
) -> Result<(), DurableError>
where
    F: DurableIo,
    R: std::io::Read,
    GetFile: FnMut(&mut std::io::BufReader<R>) -> &mut F,
{
    let file_name = policy.file_name;
    let magic = policy.magic;
    let limits = policy.limits;
    let file_len = policy.file_len;
    let protected_len = policy.protected_len;
    while offset < file_len {
        let remaining = file_len
            .checked_sub(offset)
            .ok_or(DurableError::EncodingOverflow)?;
        if remaining < FRAME_HEADER_LEN {
            if offset < protected_len {
                return Err(corrupt(
                    file_name,
                    offset,
                    "published frame header is truncated",
                ));
            }
            truncate_tail(get_file(reader), offset)?;
            break;
        }
        let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
        reader
            .read_exact(&mut header)
            .map_err(|source| io_error("read durable frame header", source))?;
        if header[..8] != magic {
            truncate_unpublished_tail_or_fail(
                get_file(reader),
                policy,
                offset,
                false,
                corrupt(file_name, offset, "frame magic mismatch"),
            )?;
            break;
        }
        let decoded = decode_frame_header(file_name, offset, &header)?;
        let payload_len = decoded.payload_len;
        if payload_len > limits.max_frame_bytes {
            let error = DurableError::FrameTooLarge {
                file: file_name,
                offset,
                declared: payload_len,
                limit: limits.max_frame_bytes,
            };
            if offset < protected_len {
                return Err(error);
            }
            let claimed_end = FRAME_HEADER_LEN
                .checked_add(payload_len)
                .and_then(|frame_len| offset.checked_add(frame_len));
            truncate_unpublished_tail_or_fail(
                get_file(reader),
                policy,
                offset,
                claimed_end.is_some_and(|end| end <= file_len),
                error,
            )?;
            break;
        }
        let frame_len = FRAME_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(DurableError::EncodingOverflow)?;
        let frame_end = offset
            .checked_add(frame_len)
            .ok_or(DurableError::EncodingOverflow)?;
        if frame_end > file_len {
            truncate_unpublished_tail_or_fail(
                get_file(reader),
                policy,
                offset,
                false,
                corrupt(file_name, offset, "published frame payload is truncated"),
            )?;
            break;
        }
        let payload = read_frame_payload(reader, payload_len)?;
        if frame_checksum(magic, payload_len, &payload) != decoded.checksum {
            truncate_unpublished_tail_or_fail(
                get_file(reader),
                policy,
                offset,
                false,
                corrupt(file_name, offset, "frame checksum mismatch"),
            )?;
            break;
        }
        accept(offset, &payload, get_file(reader))?;
        offset = frame_end;
    }
    Ok(())
}

fn read_frame_payload<F: std::io::Read>(
    file: &mut F,
    payload_len: u64,
) -> Result<Vec<u8>, DurableError> {
    let payload_usize = usize::try_from(payload_len).map_err(|_| DurableError::EncodingOverflow)?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(payload_usize)
        .map_err(|_| DurableError::EncodingOverflow)?;
    payload.resize(payload_usize, 0);
    file.read_exact(&mut payload)
        .map_err(|source| io_error("read durable frame payload", source))?;
    Ok(payload)
}

fn truncate_unpublished_tail_or_fail<F: DurableIo>(
    file: &mut F,
    policy: FrameScanPolicy,
    offset: u64,
    known_interior: bool,
    error: DurableError,
) -> Result<(), DurableError> {
    if offset < policy.protected_len
        || known_interior
        || valid_frame_follows(file, policy.magic, offset, policy.file_len, policy.limits)?
    {
        return Err(error);
    }
    truncate_tail(file, offset)
}

fn valid_frame_follows<F: DurableIo>(
    file: &mut F,
    magic: [u8; 8],
    invalid_offset: u64,
    file_len: u64,
    limits: RecoveryLimits,
) -> Result<bool, DurableError> {
    let Some(mut search_offset) = invalid_offset.checked_add(1) else {
        return Ok(false);
    };
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(65_543)
        .map_err(|_| DurableError::EncodingOverflow)?;
    buffer.resize(65_543, 0);
    while search_offset < file_len {
        file.seek(SeekFrom::Start(search_offset))
            .map_err(|source| io_error("seek durable tail recovery scan", source))?;
        let remaining = file_len
            .checked_sub(search_offset)
            .ok_or(DurableError::EncodingOverflow)?;
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| DurableError::EncodingOverflow)?;
        let read = file
            .read(&mut buffer[..wanted])
            .map_err(|source| io_error("read durable tail recovery scan", source))?;
        if read < magic.len() {
            return Ok(false);
        }
        for relative in 0..=read.saturating_sub(magic.len()) {
            let candidate_end = relative
                .checked_add(magic.len())
                .ok_or(DurableError::EncodingOverflow)?;
            if buffer.get(relative..candidate_end) != Some(magic.as_slice()) {
                continue;
            }
            let candidate = search_offset
                .checked_add(u64::try_from(relative).map_err(|_| DurableError::EncodingOverflow)?)
                .ok_or(DurableError::EncodingOverflow)?;
            if physical_frame_is_valid(file, magic, candidate, file_len, limits)? {
                return Ok(true);
            }
        }
        if read < wanted {
            return Ok(false);
        }
        let overlap = magic.len().saturating_sub(1);
        search_offset = search_offset
            .checked_add(
                u64::try_from(read.saturating_sub(overlap))
                    .map_err(|_| DurableError::EncodingOverflow)?,
            )
            .ok_or(DurableError::EncodingOverflow)?;
    }
    Ok(false)
}

fn physical_frame_is_valid<F: DurableIo>(
    file: &mut F,
    magic: [u8; 8],
    offset: u64,
    file_len: u64,
    limits: RecoveryLimits,
) -> Result<bool, DurableError> {
    let remaining = file_len
        .checked_sub(offset)
        .ok_or(DurableError::EncodingOverflow)?;
    if remaining < FRAME_HEADER_LEN {
        return Ok(false);
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| io_error("seek durable recovery candidate", source))?;
    let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
    file.read_exact(&mut header)
        .map_err(|source| io_error("read durable recovery candidate", source))?;
    if header[..8] != magic
        || u16::from_le_bytes([header[8], header[9]]) != FRAME_VERSION
        || header[10..12] != [0, 0]
    {
        return Ok(false);
    }
    let payload_len = u64::from_le_bytes(
        header[12..20]
            .try_into()
            .map_err(|_| DurableError::EncodingOverflow)?,
    );
    let frame_len = FRAME_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(DurableError::EncodingOverflow)?;
    if frame_len > remaining {
        return Ok(false);
    }
    if payload_len > limits.max_frame_bytes {
        return Ok(true);
    }
    let expected: [u8; 32] = header[CHECKSUM_START..]
        .try_into()
        .map_err(|_| DurableError::EncodingOverflow)?;
    // Reuse the process-wide LazyLock initial domain state from frame_checksum_hasher.
    let mut hasher = frame_checksum_hasher(magic, payload_len);
    let mut unread = payload_len;
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(65_536)
        .map_err(|_| DurableError::EncodingOverflow)?;
    buffer.resize(65_536, 0);
    while unread != 0 {
        let chunk = usize::try_from(unread.min(buffer.len() as u64))
            .map_err(|_| DurableError::EncodingOverflow)?;
        file.read_exact(&mut buffer[..chunk])
            .map_err(|source| io_error("read durable recovery candidate payload", source))?;
        hasher.update(&buffer[..chunk]);
        unread = unread
            .checked_sub(u64::try_from(chunk).map_err(|_| DurableError::EncodingOverflow)?)
            .ok_or(DurableError::EncodingOverflow)?;
    }
    Ok(hasher.finalize().as_bytes() == &expected)
}

fn truncate_tail<F: DurableIo>(file: &mut F, valid_len: u64) -> Result<(), DurableError> {
    file.durable_set_len(valid_len)
        .map_err(|source| io_error("truncate incomplete durable tail", source))?;
    file.durable_sync_data()
        .map_err(|source| io_error("flush durable tail truncation", source))
}
