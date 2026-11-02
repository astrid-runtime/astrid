//! Test-only torn batch writes through the production frame encoder.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;

use crate::engine::durable::media::StoreMetadata;

use super::{DurableError, DurableFile, DurableIo, METADATA_MAGIC, append_frames};

std::thread_local! {
    static FAIL_AFTER: std::cell::Cell<Option<NonZeroUsize>> = const { std::cell::Cell::new(None) };
}

pub(super) fn fail_after(bytes: NonZeroUsize) {
    FAIL_AFTER.with(|fault| fault.set(Some(bytes)));
}

pub(super) fn append_if_armed(
    file: &mut DurableFile,
    payloads: &[Vec<u8>],
) -> Option<Result<(), DurableError>> {
    let remaining = FAIL_AFTER.with(std::cell::Cell::take)?.get();
    let mut file = PartialWrite { file, remaining };
    Some(append_frames(&mut file, METADATA_MAGIC, payloads).map(|_| ()))
}

struct PartialWrite<'a> {
    file: &'a mut DurableFile,
    remaining: usize,
}

impl Write for PartialWrite<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            return Err(io::Error::other("injected partial metadata batch write"));
        }
        let length = bytes.len().min(self.remaining);
        let written = self.file.write(&bytes[..length])?;
        self.remaining = self.remaining.strict_sub(written);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Read for PartialWrite<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file.read(bytes)
    }
}

impl Seek for PartialWrite<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

impl DurableIo for PartialWrite<'_> {
    fn durable_metadata(&self) -> io::Result<StoreMetadata> {
        self.file.durable_metadata()
    }

    fn durable_set_len(&self, length: u64) -> io::Result<()> {
        self.file.durable_set_len(length)
    }

    fn durable_sync_data(&self) -> io::Result<()> {
        self.file.durable_sync_data()
    }

    fn durable_read_at(&self, bytes: &mut [u8], offset: u64) -> io::Result<usize> {
        self.file.durable_read_at(bytes, offset)
    }

    fn durable_read_at_preserves_cursor(&self) -> bool {
        self.file.durable_read_at_preserves_cursor()
    }
}
