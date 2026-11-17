//! Shared ASTREG1 fixed-header encode for slice and stream append.
//!
//! Both producers emit the same 75-byte LE prefix; coalescing them into one
//! `write_append_bytes` call preserves grammar and checksum placement while
//! cutting the fixed-header syscall fan-out.

#[cfg(test)]
mod tests;

use super::{Operation, RECORD_FIXED_BYTES};

/// Absolute byte offset of the 32-byte checksum field inside the fixed header.
pub(super) const RECORD_CHECKSUM_OFFSET: u64 = 43;

const _: () = assert!(RECORD_CHECKSUM_OFFSET + 32 == RECORD_FIXED_BYTES as u64);

/// Encode the fixed ASTREG1 header exactly as both append paths historically
/// emitted field-by-field. `checksum` is the final digest for slice append, or
/// zeroes before the stream path patches the slot in place.
pub(super) fn encode_record_fixed_header(
    total_len: u64,
    sequence: u64,
    operation: Operation,
    name_len: u16,
    offset: u64,
    payload_len: u64,
    checksum: &[u8; 32],
) -> [u8; RECORD_FIXED_BYTES] {
    let mut header = [0_u8; RECORD_FIXED_BYTES];
    header[0..8].copy_from_slice(&super::RECORD_MAGIC);
    header[8..16].copy_from_slice(&total_len.to_le_bytes());
    header[16..24].copy_from_slice(&sequence.to_le_bytes());
    header[24] = operation as u8;
    header[25..27].copy_from_slice(&name_len.to_le_bytes());
    header[27..35].copy_from_slice(&offset.to_le_bytes());
    header[35..43].copy_from_slice(&payload_len.to_le_bytes());
    header[43..75].copy_from_slice(checksum);
    header
}
