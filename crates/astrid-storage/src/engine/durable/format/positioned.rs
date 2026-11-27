//! A positional frame retains the digest already checked against its header.
use std::fmt;

use super::{
    DurableError, DurableIo, FRAME_HEADER_LEN, FRAME_HEADER_LEN_USIZE, RecoveryLimits, io_error,
    read_exact_at, validate_positioned_header, validate_positioned_payload,
};

/// Only the validating reader in this module can construct this proof.
/// Payload bytes are immutable until the verified frame is consumed.
pub(in crate::engine::durable) struct ValidatedFrame {
    payload: Vec<u8>,
    checksum: [u8; 32],
}

impl fmt::Debug for ValidatedFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedFrame")
            .field("payload_bytes", &self.payload.len())
            .finish_non_exhaustive()
    }
}

impl ValidatedFrame {
    pub(super) const fn checksum(&self) -> [u8; 32] {
        self.checksum
    }
    pub(super) fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

// All positioned reads share framing, size, and checksum validation.
pub(in crate::engine::durable) fn read_frame_at<F: DurableIo>(
    file: &F,
    file_name: &'static str,
    magic: [u8; 8],
    offset: u64,
    limits: RecoveryLimits,
) -> Result<ValidatedFrame, DurableError> {
    let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
    read_exact_at(file, &mut header, offset)
        .map_err(|source| io_error("read indexed durable frame header", source))?;
    let decoded = validate_positioned_header(file_name, magic, offset, &header, limits)?;
    let payload_usize =
        usize::try_from(decoded.payload_len).map_err(|_| DurableError::EncodingOverflow)?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(payload_usize)
        .map_err(|_| DurableError::EncodingOverflow)?;
    payload.resize(payload_usize, 0);
    let payload_offset = offset
        .checked_add(FRAME_HEADER_LEN)
        .ok_or(DurableError::EncodingOverflow)?;
    read_exact_at(file, &mut payload, payload_offset)
        .map_err(|source| io_error("read indexed durable frame payload", source))?;
    let checksum = validate_positioned_payload(file_name, magic, offset, decoded, &payload)?;
    Ok(ValidatedFrame { payload, checksum })
}
