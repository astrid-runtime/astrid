//! Exact frame extents captured by validated immutable replay scans.

use super::{
    DurableError, DurableIo, FRAME_HEADER_LEN, FRAME_HEADER_LEN_USIZE, FrameScanBound,
    RecoveryLimits, check_frame_payload_limit, corrupt, io_error, read_exact_at,
    read_frame_preserving_cursor_within, scan_frames_with_bound, validate_positioned_header,
    validate_positioned_payload,
};

#[cfg(test)]
#[path = "location_tests.rs"]
mod tests;

/// Exclusive durable byte boundary used for committed prefix/range scans.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::engine::durable) struct DurablePrefixEnd {
    end: u64,
}

impl DurablePrefixEnd {
    #[must_use]
    pub(in crate::engine::durable) const fn exclusive(end: u64) -> Self {
        Self { end }
    }

    #[must_use]
    pub(in crate::engine::durable) const fn get(self) -> u64 {
        self.end
    }
}

/// Exact committed frame byte range `[start, end)`.
///
/// `start` and `end` must already be complete-frame boundaries for the scan to
/// succeed; a cutoff inside a frame fails closed without repairing media.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::engine::durable) struct DurableFrameRange {
    start: DurablePrefixEnd,
    end: DurablePrefixEnd,
}

impl DurableFrameRange {
    pub(in crate::engine::durable) fn try_new(
        start: DurablePrefixEnd,
        end: DurablePrefixEnd,
    ) -> Result<Self, DurableError> {
        if start.get() > end.get() {
            return Err(DurableError::InvalidRepresentationState(
                "durable frame range start exceeds end",
            ));
        }
        Ok(Self { start, end })
    }

    /// Committed prefix `[0, end)`.
    #[must_use]
    #[cfg(test)]
    pub(in crate::engine::durable) const fn prefix(end: DurablePrefixEnd) -> Self {
        Self {
            start: DurablePrefixEnd::exclusive(0),
            end,
        }
    }

    #[must_use]
    pub(in crate::engine::durable) const fn start(self) -> DurablePrefixEnd {
        self.start
    }

    #[must_use]
    pub(in crate::engine::durable) const fn end(self) -> DurablePrefixEnd {
        self.end
    }
}

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

    pub(in crate::engine::durable) fn end(self) -> Result<DurablePrefixEnd, DurableError> {
        let end = self
            .offset
            .checked_add(FRAME_HEADER_LEN)
            .and_then(|end| end.checked_add(self.payload_bytes))
            .ok_or(DurableError::EncodingOverflow)?;
        Ok(DurablePrefixEnd::exclusive(end))
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

/// Read one frame from a committed range using the shared bounded grammar.
/// This allows a cursor to stop after two CAS frames during writer-fence
/// preflight, without scanning or retaining the whole journal suffix.
pub(in crate::engine::durable) fn read_frame_in_range<F: DurableIo>(
    file: &mut F,
    file_name: &'static str,
    magic: [u8; 8],
    limits: RecoveryLimits,
    range: DurableFrameRange,
    offset: DurablePrefixEnd,
) -> Result<Option<(FrameLocation, Vec<u8>)>, DurableError> {
    if offset.get() < range.start().get() || offset.get() > range.end().get() {
        return Err(corrupt(
            file_name,
            offset.get(),
            "frame cursor escaped committed range",
        ));
    }
    let actual = file
        .durable_metadata()
        .map_err(|source| io_error("measure committed frame source", source))?
        .len();
    if actual < range.end().get() {
        return Err(corrupt(
            file_name,
            offset.get(),
            "committed frame range is truncated",
        ));
    }
    if offset == range.end() {
        return Ok(None);
    }
    let payload = read_frame_preserving_cursor_within(
        file,
        file_name,
        magic,
        offset.get(),
        limits,
        range.end().get(),
    )?;
    let location = FrameLocation::validated(offset.get(), &payload)?;
    Ok(Some((location, payload)))
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
    scan_frames_with_bound(
        file,
        file_name,
        magic,
        limits,
        FrameScanBound::LiveRepair { protected_len: 0 },
        |offset, payload, source| {
            let location = FrameLocation::validated(offset, payload)?;
            accept(location, payload, &mut |position| {
                // Live recovery may reload any prior frame in the scanned media.
                read_frame_preserving_cursor_within(
                    source,
                    file_name,
                    magic,
                    position,
                    limits,
                    u64::MAX,
                )
            })
        },
    )
}

/// Scan exact committed frames in `[range.start, range.end)` without truncation.
///
/// Sequential visitation starts at `range.start`. Source callback reloads may
/// address historical frames below `start`, but never load bytes past `end`.
pub(in crate::engine::durable) fn scan_frames_range_with_source<F: DurableIo>(
    file: &mut F,
    file_name: &'static str,
    magic: [u8; 8],
    limits: RecoveryLimits,
    range: DurableFrameRange,
    mut accept: impl FnMut(
        FrameLocation,
        &[u8],
        &mut dyn FnMut(u64) -> Result<Vec<u8>, DurableError>,
    ) -> Result<(), DurableError>,
) -> Result<(), DurableError> {
    let captured_end = range.end().get();
    scan_frames_with_bound(
        file,
        file_name,
        magic,
        limits,
        FrameScanBound::Committed(range),
        |offset, payload, source| {
            let location = FrameLocation::validated(offset, payload)?;
            accept(location, payload, &mut |position| {
                read_frame_preserving_cursor_within(
                    source,
                    file_name,
                    magic,
                    position,
                    limits,
                    captured_end,
                )
            })
        },
    )
}

/// Exact committed prefix `[0, end)` with source callback reloads capped at `end`.
#[cfg(test)]
pub(in crate::engine::durable) fn scan_frames_prefix_with_source<F: DurableIo>(
    file: &mut F,
    file_name: &'static str,
    magic: [u8; 8],
    limits: RecoveryLimits,
    end: DurablePrefixEnd,
    accept: impl FnMut(
        FrameLocation,
        &[u8],
        &mut dyn FnMut(u64) -> Result<Vec<u8>, DurableError>,
    ) -> Result<(), DurableError>,
) -> Result<(), DurableError> {
    scan_frames_range_with_source(
        file,
        file_name,
        magic,
        limits,
        DurableFrameRange::prefix(end),
        accept,
    )
}
