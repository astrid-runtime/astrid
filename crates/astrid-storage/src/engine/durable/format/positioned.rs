//! A positional frame retains the digest already checked against its header.
use std::fmt;

use super::{
    DurableError, DurableIo, RecoveryLimits, io_error, positional_error, positional_read,
    validate_positioned_header, validate_positioned_payload,
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
    use positional_read::FrameError;
    let (payload, checksum) = positional_read::frame(
        file,
        offset,
        |header| validate_positioned_header(file_name, magic, offset, header, limits),
        |decoded, payload| validate_positioned_payload(file_name, magic, offset, decoded, payload),
    )
    .map_err(|error| match error {
        FrameError::Header(e) => io_error("read indexed durable frame header", positional_error(e)),
        FrameError::Payload(e) => {
            io_error("read indexed durable frame payload", positional_error(e))
        },
        FrameError::Invalid(e) => e,
        FrameError::Capacity => DurableError::EncodingOverflow,
    })?;
    Ok(ValidatedFrame { payload, checksum })
}
