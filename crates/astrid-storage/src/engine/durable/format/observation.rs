//! Bounded observation scans that retain malformed-evidence context.

use std::io::SeekFrom;

use super::{
    DurableError, DurableIo, FRAME_HEADER_LEN, FRAME_HEADER_LEN_USIZE, FRAME_VERSION,
    RecoveryLimits, corrupt, decode_frame_header, io_error, next_valid_frame_offset,
    read_frame_payload, validated_file_len,
};

/// Observe every recoverable frame without stopping at malformed evidence.
///
/// The first structural or model error is retained for fail-closed callers,
/// but scanning resynchronizes on each valid frame candidate so a malformed
/// prefix cannot hide a canonical owner in a later frame.
#[allow(
    clippy::too_many_lines,
    reason = "observation and bounded resynchronization share one cursor"
)]
pub(in crate::engine::durable) fn scan_frames_observing<F: DurableIo>(
    file: &mut F,
    file_name: &'static str,
    magic: [u8; 8],
    limits: RecoveryLimits,
    mut accept: impl FnMut(u64, &[u8]) -> Result<(), DurableError>,
) -> Result<Option<DurableError>, DurableError> {
    let file_len = validated_file_len(file, file_name, 0)?;
    let mut scan_error = None;
    let mut offset = 0_u64;
    let mut progress = 0_usize;
    while offset < file_len {
        progress = progress
            .checked_add(1)
            .ok_or(DurableError::EncodingOverflow)?;
        let remaining = file_len
            .checked_sub(offset)
            .ok_or(DurableError::EncodingOverflow)?;
        if remaining < FRAME_HEADER_LEN {
            scan_error.get_or_insert(corrupt(
                file_name,
                offset,
                "observed frame header is truncated",
            ));
            break;
        }
        file.seek(SeekFrom::Start(offset))
            .map_err(|source| io_error("seek durable frame observation", source))?;
        let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
        file.read_exact(&mut header)
            .map_err(|source| io_error("read durable frame observation", source))?;
        if header[..8] != magic {
            scan_error.get_or_insert(corrupt(
                file_name,
                offset,
                "observed frame magic does not match",
            ));
            offset = offset
                .checked_add(1)
                .ok_or(DurableError::EncodingOverflow)?;
            continue;
        }
        let decoded = match decode_frame_header(file_name, offset, &header) {
            Ok(decoded) => decoded,
            Err(error) => {
                scan_error.get_or_insert(error);
                offset = offset
                    .checked_add(1)
                    .ok_or(DurableError::EncodingOverflow)?;
                continue;
            },
        };
        let frame_len = FRAME_HEADER_LEN
            .checked_add(decoded.payload_len)
            .ok_or(DurableError::EncodingOverflow)?;
        if decoded.payload_len > limits.max_frame_bytes || frame_len > remaining {
            scan_error.get_or_insert(if decoded.payload_len > limits.max_frame_bytes {
                DurableError::FrameTooLarge {
                    file: file_name,
                    offset,
                    declared: decoded.payload_len,
                    limit: limits.max_frame_bytes,
                }
            } else {
                corrupt(file_name, offset, "observed frame payload is truncated")
            });
            offset = match next_valid_frame_offset(
                file,
                magic,
                offset
                    .checked_add(1)
                    .ok_or(DurableError::EncodingOverflow)?,
                file_len,
                limits,
            )? {
                Some(candidate) => candidate,
                None => break,
            };
            continue;
        }
        if !verify_frame_checksum_streaming(file, magic, &decoded)? {
            scan_error.get_or_insert(corrupt(file_name, offset, "frame checksum mismatch"));
            offset = match next_valid_frame_offset(
                file,
                magic,
                offset
                    .checked_add(1)
                    .ok_or(DurableError::EncodingOverflow)?,
                file_len,
                limits,
            )? {
                Some(candidate) => candidate,
                None => break,
            };
            continue;
        }
        file.seek(SeekFrom::Start(
            offset
                .checked_add(FRAME_HEADER_LEN)
                .ok_or(DurableError::EncodingOverflow)?,
        ))
        .map_err(|source| io_error("seek durable frame payload", source))?;
        let payload = read_frame_payload(file, decoded.payload_len)?;
        if let Err(error) = accept(offset, &payload) {
            scan_error.get_or_insert(error);
            offset = offset
                .checked_add(1)
                .ok_or(DurableError::EncodingOverflow)?;
            continue;
        }
        offset = offset
            .checked_add(frame_len)
            .ok_or(DurableError::EncodingOverflow)?;
    }
    Ok(scan_error)
}

/// Verify a durable frame checksum without reserving its declared payload.
///
/// A sparse hostile declaration is rejected by its checksum in fixed memory;
/// a checksum-valid frame is the only caller allowed to allocate its bytes.
fn verify_frame_checksum_streaming<F: DurableIo>(
    file: &mut F,
    magic: [u8; 8],
    decoded: &super::DecodedFrameHeader,
) -> Result<bool, DurableError> {
    let mut hasher = blake3::Hasher::new_derive_key("astrid durable physical frame checksum v1");
    hasher.update(&magic);
    hasher.update(&FRAME_VERSION.to_le_bytes());
    hasher.update(&decoded.payload_len.to_le_bytes());
    let mut unread = decoded.payload_len;
    let mut buffer = vec![0_u8; 65_536];
    while unread != 0 {
        let wanted = usize::try_from(unread.min(buffer.len() as u64))
            .map_err(|_| DurableError::EncodingOverflow)?;
        file.read_exact(&mut buffer[..wanted])
            .map_err(|source| io_error("read durable frame observation payload", source))?;
        hasher.update(&buffer[..wanted]);
        unread = unread
            .checked_sub(u64::try_from(wanted).map_err(|_| DurableError::EncodingOverflow)?)
            .ok_or(DurableError::EncodingOverflow)?;
    }
    Ok(hasher.finalize().as_bytes() == &decoded.checksum)
}
