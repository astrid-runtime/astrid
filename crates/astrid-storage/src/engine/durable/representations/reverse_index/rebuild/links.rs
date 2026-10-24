//! Sequential private scratch emission with checked readback and publication flushes.
use super::{ArenaLocation, DurableError, MAGIC};
use crate::engine::durable::format::{frame_checksum, frame_header};
use crate::engine::durable::{FRAME_HEADER_LEN, io_error};
use std::io::{BufWriter, Seek, SeekFrom, Write};

pub(super) struct BufferedLinks<W: Write> {
    output: BufWriter<W>,
    offset: u64,
}

impl<W: Write + Seek> BufferedLinks<W> {
    pub(super) fn new(mut file: W, capacity: usize) -> Result<Self, DurableError> {
        let offset = file
            .seek(SeekFrom::End(0))
            .map_err(|source| io_error("seek reverse rebuild output", source))?;
        Ok(Self {
            output: BufWriter::with_capacity(capacity, file),
            offset,
        })
    }
}

impl<W: Write> BufferedLinks<W> {
    pub(super) fn append(&mut self, payload: &[u8]) -> Result<ArenaLocation, DurableError> {
        let payload_len =
            u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)?;
        let next = self
            .offset
            .checked_add(FRAME_HEADER_LEN)
            .and_then(|offset| offset.checked_add(payload_len))
            .ok_or(DurableError::EncodingOverflow)?;
        let checksum = frame_checksum(MAGIC, payload_len, payload);
        let location = ArenaLocation {
            offset: self.offset,
            payload_len,
            checksum,
        };
        self.output
            .write_all(&frame_header(MAGIC, payload_len, checksum))
            .map_err(|source| io_error("buffer reverse link header", source))?;
        self.output
            .write_all(payload)
            .map_err(|source| io_error("buffer reverse link payload", source))?;
        self.offset = next;
        Ok(location)
    }

    pub(super) fn flush(&mut self) -> Result<(), DurableError> {
        self.output
            .flush()
            .map_err(|source| io_error("flush reverse link readback", source))
    }

    pub(super) fn finish(self) -> Result<W, DurableError> {
        self.output
            .into_inner()
            .map_err(|error| io_error("flush reverse rebuild output", error.into_error()))
    }
}

#[cfg(test)]
mod tests;
