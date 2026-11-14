//! Bounded framed append stream for tip rewrites.
//!
//! Seeks once, then writes frame headers and payloads through a fixed-size
//! transfer buffer. This is an I/O coalescing mechanism (same class as the
//! object-index snapshot and WAL write buffers), not an operator retention or
//! admission limit.

use std::io::{BufWriter, SeekFrom, Write};

use super::{DurableError, DurableIo, frame_checksum, frame_header, io_error};

/// Transfer buffer for coalescing many small framed writes.
pub(in crate::engine::durable) const TRANSFER_BUFFER_BYTES: usize = 64 * 1024;

pub(in crate::engine::durable) struct FramedAppendStream<'a, F: DurableIo> {
    writer: BufWriter<&'a mut F>,
    magic: [u8; 8],
}

impl<'a, F: DurableIo> FramedAppendStream<'a, F> {
    /// Seek to end once and begin buffered framed appends.
    pub(in crate::engine::durable) fn begin(
        file: &'a mut F,
        magic: [u8; 8],
    ) -> Result<Self, DurableError> {
        file.seek(SeekFrom::End(0))
            .map_err(|source| io_error("seek framed append stream", source))?;
        Ok(Self {
            writer: BufWriter::with_capacity(TRANSFER_BUFFER_BYTES, file),
            magic,
        })
    }

    /// Append one already-encoded payload with the standard frame header/checksum.
    pub(in crate::engine::durable) fn append_payload(
        &mut self,
        payload: &[u8],
    ) -> Result<(), DurableError> {
        let payload_len =
            u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)?;
        let checksum = frame_checksum(self.magic, payload_len, payload);
        let header = frame_header(self.magic, payload_len, checksum);
        self.writer
            .write_all(&header)
            .map_err(|source| io_error("append framed stream header", source))?;
        self.writer
            .write_all(payload)
            .map_err(|source| io_error("append framed stream payload", source))?;
        Ok(())
    }

    /// Flush the transfer buffer before the caller syncs or re-reads the file.
    pub(in crate::engine::durable) fn finish(mut self) -> Result<(), DurableError> {
        self.writer
            .flush()
            .map_err(|source| io_error("flush framed append stream", source))
    }
}
