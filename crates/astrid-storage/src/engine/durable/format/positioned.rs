//! One bounded raw-byte window for immutable reconstruction reads.

use super::{
    DurableError, DurableIo, RecoveryLimits, TRANSFER_BUFFER_BYTES, io, read_exact_at,
    read_frame_with,
};

#[cfg(test)]
#[path = "positioned_tests.rs"]
mod tests;

/// Borrows a reconstruction source whose bytes must remain immutable until drop.
/// Positional I/O may move a provider's cursor; callers must position it before
/// subsequent sequential I/O, just as with `read_frame_at`.
///
/// The lazily allocated window reuses the existing transfer batch size. It is
/// transient I/O coalescing, not decoded-object retention or an admission limit.
/// Only requested frames pass through the authoritative frame validator.
pub(in crate::engine::durable) struct PositionalFrameReader<'a, F: DurableIo> {
    source: &'a F,
    buffer: Vec<u8>,
    start: u64,
    valid: usize,
}

impl<'a, F: DurableIo> PositionalFrameReader<'a, F> {
    pub(in crate::engine::durable) fn new(source: &'a F) -> Self {
        Self {
            source,
            buffer: Vec::new(),
            start: 0,
            valid: 0,
        }
    }

    pub(in crate::engine::durable) fn read_frame_at(
        &mut self,
        file_name: &'static str,
        magic: [u8; 8],
        offset: u64,
        limits: RecoveryLimits,
    ) -> Result<Vec<u8>, DurableError> {
        // Keep the frame-start window while parsing its header and payload.
        // A boundary-straddling request uses exact I/O without replacing that
        // window, so descending traversal does not reread adjacent blocks.
        if self.cached(offset, 1).is_none() && self.fill_window(offset).is_err() {
            self.valid = 0;
        }
        read_frame_with(file_name, magic, offset, limits, |bytes, position| {
            if let Some(cached) = self.cached(position, bytes.len()) {
                bytes.copy_from_slice(cached);
                Ok(())
            } else {
                // Optional prefetch failures and requests outside its valid
                // range are resolved by the original exact requested read.
                read_exact_at(self.source, bytes, position)
            }
        })
    }

    fn cached(&self, offset: u64, length: usize) -> Option<&[u8]> {
        let start = usize::try_from(offset.checked_sub(self.start)?).ok()?;
        let end = start.checked_add(length)?;
        if end > self.valid {
            return None;
        }
        self.buffer.get(start..end)
    }

    fn fill_window(&mut self, position: u64) -> io::Result<()> {
        self.valid = 0;
        let width = u64::try_from(TRANSFER_BUFFER_BYTES)
            .map_err(|_| io::Error::other("positional read length overflow"))?;
        self.start = position.strict_sub(position.strict_rem(width));
        if self.buffer.is_empty() {
            self.buffer
                .try_reserve_exact(TRANSFER_BUFFER_BYTES)
                .map_err(|_| io::Error::other("positional transfer allocation failed"))?;
            self.buffer.resize(TRANSFER_BUFFER_BYTES, 0);
        }
        let mut filled = 0;
        while filled < self.buffer.len() {
            let relative = u64::try_from(filled)
                .map_err(|_| io::Error::other("positional read offset overflow"))?;
            let offset = self
                .start
                .checked_add(relative)
                .ok_or_else(|| io::Error::other("positional read offset overflow"))?;
            let count = self
                .source
                .durable_read_at(&mut self.buffer[filled..], offset)?;
            if count == 0 {
                break;
            }
            filled = filled
                .checked_add(count)
                .ok_or_else(|| io::Error::other("positional read length overflow"))?;
        }
        // Publish only a completed fill (including an ordinary short EOF).
        self.valid = filled;
        Ok(())
    }
}
