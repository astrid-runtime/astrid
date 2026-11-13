//! Authenticated sequential reads for restoration without a full-file `Vec`.
//!
//! Borrows an existing [`PrincipalContentReadHandle`] so the compaction lease and
//! authorized root generation stay with the handle. Read batches use the same
//! soft I/O coalescing target as native content writers. Each range still follows the handle's complete authenticated read
//! path; no cache, admission, or content-format limit changes.

use std::io::{self, Read};
use std::ops::Range;

use crate::content::{
    NATIVE_CONTENT_BATCH_BYTES, PrincipalContentError, PrincipalContentReadHandle,
};
use crate::engine::PrincipalProjectionEngine;

/// Sequential `Read` over one opened principal-content handle.
pub(in crate::principal_state::runtime_tree) struct AuthenticatedContentReader<'a, P: Ord, E> {
    handle: &'a PrincipalContentReadHandle<P, E>,
    offset: u64,
    end: u64,
    window: u64,
    buffer: Vec<u8>,
    buffered: Range<usize>,
}

impl<'a, P, E> AuthenticatedContentReader<'a, P, E>
where
    P: Clone + Ord,
    E: PrincipalProjectionEngine<P>,
{
    /// Borrow `handle` for sequential authenticated reconstruction.
    #[must_use]
    pub(in crate::principal_state::runtime_tree) fn new(
        handle: &'a PrincipalContentReadHandle<P, E>,
    ) -> Self {
        let end = handle.descriptor().logical_bytes();
        // Coalesce ranges just as native content writes coalesce object batches.
        // Chunk boundaries remain authenticated by the existing read_range path.
        let window =
            u64::try_from(NATIVE_CONTENT_BATCH_BYTES).expect("native content batch size fits u64");
        Self {
            handle,
            offset: 0,
            end,
            window,
            buffer: Vec::new(),
            buffered: 0..0,
        }
    }

    /// Exact logical length captured when the handle was opened.
    #[must_use]
    pub(super) const fn logical_len(&self) -> u64 {
        self.end
    }

    /// Restart at offset zero without reopening or dropping the lease.
    pub(super) fn rewind(&mut self) {
        self.offset = 0;
        self.buffer.clear();
        self.buffered = 0..0;
    }
}

impl<P, E> Read for AuthenticatedContentReader<'_, P, E>
where
    P: Clone + Ord,
    E: PrincipalProjectionEngine<P>,
{
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.buffered.is_empty() {
            self.refill()?;
        }
        if self.buffered.is_empty() {
            return Ok(0);
        }
        let available = self.buffered.end.strict_sub(self.buffered.start);
        let count = available.min(output.len());
        let end = self.buffered.start.strict_add(count);
        output[..count].copy_from_slice(&self.buffer[self.buffered.start..end]);
        self.buffered.start = end;
        if self.buffered.is_empty() {
            self.buffer.clear();
            self.buffered = 0..0;
        }
        Ok(count)
    }
}

impl<P, E> AuthenticatedContentReader<'_, P, E>
where
    P: Clone + Ord,
    E: PrincipalProjectionEngine<P>,
{
    fn refill(&mut self) -> io::Result<()> {
        if self.offset >= self.end {
            self.buffer.clear();
            self.buffered = 0..0;
            return Ok(());
        }
        let want = self.end.strict_sub(self.offset).min(self.window);
        // The drained allocation must drop before reconstructing the next batch,
        // so peak transfer memory does not contain two live output windows.
        self.buffer = Vec::new();
        let bytes = self
            .handle
            .read_range(self.offset, want)
            .map_err(map_authenticated_read_error)?;
        let got = u64::try_from(bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "authenticated content range length exceeds u64",
            )
        })?;
        if got != want {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("authenticated content range length mismatch: got {got}, want {want}"),
            ));
        }
        self.offset = self.offset.checked_add(want).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "authenticated content read offset overflow",
            )
        })?;
        self.buffer = bytes;
        self.buffered = 0..self.buffer.len();
        Ok(())
    }
}

/// Map content/projection failures to IO without pretending the stream ended.
fn map_authenticated_read_error(error: PrincipalContentError) -> io::Error {
    // Verification, missing-object, and graph failures must not become
    // UnexpectedEof: write_from/compare treat EOF as short-stream/non-match.
    io::Error::new(io::ErrorKind::InvalidData, error)
}
