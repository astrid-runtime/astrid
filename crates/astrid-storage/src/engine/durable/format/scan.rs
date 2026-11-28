//! Sequential live and committed durable frame scanning.

use std::io::{Read as _, Seek as _};

use super::{
    DurableError, DurableFrameRange, DurableIo, FRAME_HEADER_LEN, FRAME_HEADER_LEN_USIZE,
    FRAME_VERSION, RecoveryLimits, SeekFrom, arena_frame, corrupt, frame_checksum,
    frame_checksum_hasher, io_error, read_exact_at, scan_frames_with_source,
    validate_positioned_header, validate_positioned_payload,
};
use crate::engine::durable::frame_repair::{self, Damage, FrameReader};

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
    let mode = match bound {
        FrameScanBound::LiveRepair { protected_len } => frame_repair::Bound::Live(protected_len),
        FrameScanBound::Committed(range) => frame_repair::Bound::Committed {
            start: range.start().get(),
            end: range.end().get(),
        },
    };
    let frame_repair::Window {
        start: scan_start,
        end: scan_end,
        protected: protected_len,
        restore_cursor,
    } = frame_repair::window(physical_len, mode).ok_or_else(|| {
        corrupt(
            file_name,
            physical_len,
            "published durable prefix is truncated",
        )
    })?;
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
        FrameScanBound::LiveRepair { .. } => scan_live(file, |reader| {
            scan_frames_grammar(
                reader,
                |reader| reader.get_mut(),
                policy,
                scan_start,
                &mut accept,
            )
        }),
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

fn scan_live<F: DurableIo>(
    file: &mut F,
    run: impl FnOnce(&mut std::io::BufReader<&mut F>) -> Result<(), DurableError>,
) -> Result<(), DurableError> {
    let mut reader = std::io::BufReader::new(file);
    run(&mut reader)?;
    // Discard read-ahead after a repair, which can shorten the underlying file.
    reader
        .seek(SeekFrom::End(0))
        .map_err(|source| io_error("seek durable file tail", source))?;
    Ok(())
}

/// Run the verified root-history visitor directly on the live journal reader.
pub(in crate::engine::durable) fn scan_root_file<F: DurableIo, V, E>(
    file: &mut F,
    limits: RecoveryLimits,
    visitor: &mut V,
    report: impl FnOnce(u64, &[u8], E) -> DurableError,
) -> Result<(), DurableError>
where
    for<'a> V: super::super::frame_scan::Visitor<std::io::BufReader<&'a mut F>, Error = E>,
{
    let file_len = file
        .durable_metadata()
        .map_err(|source| io_error("read principal-store metadata", source))?
        .len();
    file.seek(SeekFrom::Start(0))
        .map_err(|source| io_error("seek durable frame", source))?;
    let policy = FrameScanPolicy {
        file_name: super::super::ROOT_FILE,
        magic: super::super::ROOT_MAGIC,
        limits,
        protected_len: 0,
        file_len,
    };
    scan_live(file, |reader| {
        let outcome = super::super::frame_scan::scan_root(
            reader,
            visitor,
            file_len,
            limits.max_frame_bytes,
            frame_checksum,
        );
        complete_scan(outcome, policy, || &mut **reader.get_mut(), report)
    })
}

impl FrameScanPolicy {
    fn window(self, start: u64) -> super::super::frame_scan::Window {
        super::super::frame_scan::Window {
            start,
            end: self.file_len,
            magic: self.magic,
            version: FRAME_VERSION,
            limit: self.limits.max_frame_bytes,
        }
    }
}

struct FrameCallback<T>(T);

impl<R, T, E> super::super::frame_scan::Visitor<R> for FrameCallback<T>
where
    R: FrameReader,
    T: FnMut(&mut R, u64, &[u8]) -> Result<(), E>,
{
    type Error = E;

    fn visit(&mut self, reader: &mut R, offset: u64, bytes: &[u8]) -> Result<(), E> {
        (self.0)(reader, offset, bytes)
    }
}

fn scan_frames_grammar<F, R, GetFile>(
    reader: &mut std::io::BufReader<R>,
    mut get_file: GetFile,
    policy: FrameScanPolicy,
    offset: u64,
    accept: &mut impl FnMut(u64, &[u8], &mut F) -> Result<(), DurableError>,
) -> Result<(), DurableError>
where
    F: DurableIo,
    R: std::io::Read,
    GetFile: FnMut(&mut std::io::BufReader<R>) -> &mut F,
{
    let mut visitor = FrameCallback(|r: &mut std::io::BufReader<R>, at, bytes: &[u8]| {
        accept(at, bytes, get_file(r))
    });
    let outcome =
        super::super::frame_scan::scan(reader, &mut visitor, policy.window(offset), frame_checksum);
    complete_scan(outcome, policy, || get_file(reader), |_, _, error| error)
}

fn complete_scan<'a, F: DurableIo + 'a, E>(
    outcome: Result<(), super::super::frame_scan::Stop<DurableError, E>>,
    policy: FrameScanPolicy,
    file: impl FnOnce() -> &'a mut F,
    report: impl FnOnce(u64, &[u8], E) -> DurableError,
) -> Result<(), DurableError> {
    use super::super::frame_scan::Stop;
    use frame_repair::{FrameError, TailError};
    let file_name = policy.file_name;
    let limits = policy.limits;
    match outcome {
        Ok(()) => Ok(()),
        Err(Stop::Visitor(at, body, error)) => Err(report(at, &body, error)),
        Err(Stop::Frame(_, FrameError::Io(error))) => Err(error),
        Err(Stop::Frame(_, FrameError::Overflow)) => Err(DurableError::EncodingOverflow),
        Err(Stop::Frame(at, FrameError::Header(error))) => {
            Err(super::frame_header_error(file_name, at, &error))
        },
        Err(Stop::Frame(offset, FrameError::Tail(error))) => {
            let damage = error.damage();
            let cause = match error {
                TailError::HeaderShort => {
                    corrupt(file_name, offset, "published frame header is truncated")
                },
                TailError::PayloadShort => {
                    corrupt(file_name, offset, "published frame payload is truncated")
                },
                TailError::Magic => corrupt(file_name, offset, "frame magic mismatch"),
                TailError::Oversize { size, .. } => DurableError::FrameTooLarge {
                    file: file_name,
                    offset,
                    declared: size,
                    limit: limits.max_frame_bytes,
                },
                TailError::Checksum => corrupt(file_name, offset, "frame checksum mismatch"),
            };
            repair_tail(file(), policy, offset, damage, cause)
        },
    }
}

impl<R: std::io::Read> FrameReader for std::io::BufReader<R> {
    type Error = DurableError;

    fn header(&mut self) -> Result<[u8; FRAME_HEADER_LEN_USIZE], DurableError> {
        let mut bytes = [0; FRAME_HEADER_LEN_USIZE];
        self.read_exact(&mut bytes)
            .map_err(|source| io_error("read durable frame header", source))?;
        Ok(bytes)
    }

    fn payload(&mut self, payload_len: u64) -> Result<Vec<u8>, DurableError> {
        let payload_usize =
            usize::try_from(payload_len).map_err(|_| DurableError::EncodingOverflow)?;
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(payload_usize)
            .map_err(|_| DurableError::EncodingOverflow)?;
        payload.resize(payload_usize, 0);
        self.read_exact(&mut payload)
            .map_err(|source| io_error("read durable frame payload", source))?;
        Ok(payload)
    }
}

struct RepairMedia<'a, F> {
    file: &'a mut F,
    policy: FrameScanPolicy,
}

impl<F: DurableIo> frame_repair::Medium for RepairMedia<'_, F> {
    type Error = DurableError;

    fn later_frame(&mut self, offset: u64) -> Result<bool, DurableError> {
        valid_frame_follows(
            self.file,
            self.policy.magic,
            offset,
            self.policy.file_len,
            self.policy.limits,
        )
    }

    fn resize(&mut self, offset: u64) -> Result<(), DurableError> {
        self.file
            .durable_set_len(offset)
            .map_err(|source| io_error("truncate incomplete durable tail", source))
    }

    fn flush(&mut self) -> Result<(), DurableError> {
        self.file
            .durable_sync_data()
            .map_err(|source| io_error("flush durable tail truncation", source))
    }
}

fn repair_tail<F: DurableIo>(
    file: &mut F,
    policy: FrameScanPolicy,
    offset: u64,
    damage: Damage,
    error: DurableError,
) -> Result<(), DurableError> {
    let mut media = RepairMedia { file, policy };
    match frame_repair::repair(
        &mut media,
        offset,
        policy.file_len,
        policy.protected_len,
        damage,
    ) {
        Ok(frame_repair::Outcome::Repaired) => Ok(()),
        Ok(frame_repair::Outcome::Reject) => Err(error),
        Err(
            frame_repair::Error::Probe(e)
            | frame_repair::Error::Resize(e)
            | frame_repair::Error::Flush(e),
        ) => Err(e),
    }
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
        // The measured extent bounds this window. Short reads are ordinary
        // progress. Premature EOF must fail before repair can resize the file.
        let window = &mut buffer[..wanted];
        file.read_exact(window)
            .map_err(|source| io_error("read durable tail recovery scan", source))?;
        for (relative, bytes) in window.windows(magic.len()).enumerate() {
            if bytes != magic.as_slice() {
                continue;
            }
            let candidate = search_offset
                .checked_add(u64::try_from(relative).map_err(|_| DurableError::EncodingOverflow)?)
                .ok_or(DurableError::EncodingOverflow)?;
            if physical_frame_is_valid(file, magic, candidate, file_len, limits)? {
                return Ok(true);
            }
        }
        if remaining <= buffer.len() as u64 {
            return Ok(false);
        }
        let overlap = magic.len().saturating_sub(1);
        search_offset = search_offset
            .checked_add(
                u64::try_from(wanted.saturating_sub(overlap))
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
    if !arena_frame::magic_matches(&header, magic) {
        return Ok(false);
    }
    let Ok(decoded) = arena_frame::decode_header(&header, FRAME_VERSION) else {
        return Ok(false);
    };
    let payload_len = decoded.payload_len;
    let frame_len = FRAME_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(DurableError::EncodingOverflow)?;
    if frame_len > remaining {
        return Ok(false);
    }
    if payload_len > limits.max_frame_bytes {
        return Ok(true);
    }
    let expected = decoded.checksum;
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
