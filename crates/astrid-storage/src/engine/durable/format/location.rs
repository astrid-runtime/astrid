//! Exact frame extents captured by validated immutable replay scans.

use super::{
    DurableError, DurableIo, FRAME_HEADER_LEN, FRAME_HEADER_LEN_USIZE, RecoveryLimits,
    check_frame_payload_limit, corrupt, io_error, read_exact_at, read_frame_preserving_cursor,
    scan_frames_with_protected_prefix, validate_positioned_header, validate_positioned_payload,
};

#[cfg(test)]
#[path = "location_tests.rs"]
mod tests;

/// A frame extent from this generation's successful framing scan. Full-width
/// lengths preserve process-addressable frames; this is not a payload cache.
/// The source generation must remain immutable between scanning and reading.
#[derive(Clone, Copy, Debug)]
pub(in crate::engine::durable) struct FrameLocation {
    offset: u64,
    payload_bytes: u64,
}

impl FrameLocation {
    // Only the format scanner can construct production locations. In
    // particular, untrusted manifests or caller hints are not extents.
    fn validated(offset: u64, payload: &[u8]) -> Result<Self, DurableError> {
        Ok(Self {
            offset,
            payload_bytes: u64::try_from(payload.len())
                .map_err(|_| DurableError::EncodingOverflow)?,
        })
    }

    pub(in crate::engine::durable) const fn offset(self) -> u64 {
        self.offset
    }

    /// Read exactly this extent, then revalidate the actual header and checksum.
    /// As with direct positional reads, providers may move the sequential cursor;
    /// subsequent sequential I/O must position it explicitly.
    pub(in crate::engine::durable) fn read<F: DurableIo>(
        self,
        source: &F,
        file_name: &'static str,
        magic: [u8; 8],
        limits: RecoveryLimits,
    ) -> Result<LocatedFrame, DurableError> {
        check_frame_payload_limit(file_name, self.offset, self.payload_bytes, limits)?;
        let frame_bytes = self
            .payload_bytes
            .checked_add(FRAME_HEADER_LEN)
            .ok_or(DurableError::EncodingOverflow)?;
        self.offset
            .checked_add(frame_bytes)
            .ok_or(DurableError::EncodingOverflow)?;
        let frame_bytes =
            usize::try_from(frame_bytes).map_err(|_| DurableError::EncodingOverflow)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(frame_bytes)
            .map_err(|_| DurableError::EncodingOverflow)?;
        bytes.resize(frame_bytes, 0);
        read_exact_at(source, &mut bytes, self.offset)
            .map_err(|source| io_error("read located durable frame", source))?;
        let header = bytes[..FRAME_HEADER_LEN_USIZE]
            .try_into()
            .map_err(|_| DurableError::EncodingOverflow)?;
        let decoded = validate_positioned_header(file_name, magic, self.offset, header, limits)?;
        if decoded.payload_len != self.payload_bytes {
            return Err(corrupt(
                file_name,
                self.offset,
                "frame length changed since recovery scan",
            ));
        }
        validate_positioned_payload(
            file_name,
            magic,
            self.offset,
            decoded,
            &bytes[FRAME_HEADER_LEN_USIZE..],
        )?;
        Ok(LocatedFrame { bytes })
    }

    #[cfg(test)]
    pub(in crate::engine::durable) const fn for_test(offset: u64, payload_bytes: u64) -> Self {
        Self {
            offset,
            payload_bytes,
        }
    }
}

/// Own the one frame allocation while canonical decoders borrow its payload.
/// No second full-payload allocation or prefix-removal copy is required.
pub(in crate::engine::durable) struct LocatedFrame {
    bytes: Vec<u8>,
}

impl LocatedFrame {
    pub(in crate::engine::durable) fn payload(&self) -> &[u8] {
        &self.bytes[FRAME_HEADER_LEN_USIZE..]
    }
}

/// Supply immutable replay extents captured only after the frame scan validates
/// each requested frame. The callback can reload earlier frames without
/// disturbing sequential read-ahead, including providers whose reads seek.
pub(in crate::engine::durable) fn scan_frames_with_source<F: DurableIo>(
    file: &mut F,
    file_name: &'static str,
    magic: [u8; 8],
    limits: RecoveryLimits,
    mut accept: impl FnMut(
        FrameLocation,
        &[u8],
        &mut dyn FnMut(u64) -> Result<Vec<u8>, DurableError>,
    ) -> Result<(), DurableError>,
) -> Result<(), DurableError> {
    scan_frames_with_protected_prefix(
        file,
        file_name,
        magic,
        limits,
        0,
        |offset, payload, source| {
            let location = FrameLocation::validated(offset, payload)?;
            accept(location, payload, &mut |position| {
                read_frame_preserving_cursor(source, file_name, magic, position, limits)
            })
        },
    )
}
