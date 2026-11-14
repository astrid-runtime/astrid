use crate::engine::durable::media::StoreMetadata;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::super::format::journal_digest;
use super::super::{DurableError, DurableIo};
use super::{TRANSFER_BUFFER_BYTES, digest_journal_file, digest_journal_prefix};

struct ProbeJournal {
    bytes: Vec<u8>,
    cursor: u64,
    max_read_request: AtomicUsize,
    interrupted_once: bool,
    total_read: usize,
}

impl ProbeJournal {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            cursor: 0,
            max_read_request: AtomicUsize::new(0),
            interrupted_once: false,
            total_read: 0,
        }
    }

    fn with_interrupt(mut self) -> Self {
        self.interrupted_once = true;
        self
    }

    fn max_read_request(&self) -> usize {
        self.max_read_request.load(Ordering::Relaxed)
    }
}

impl Read for ProbeJournal {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.max_read_request
            .fetch_max(buffer.len(), Ordering::Relaxed);
        if self.interrupted_once {
            self.interrupted_once = false;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let start = usize::try_from(self.cursor).unwrap();
        if start >= self.bytes.len() {
            return Ok(0);
        }
        let available = &self.bytes[start..];
        let take = available.len().min(buffer.len());
        buffer[..take].copy_from_slice(&available[..take]);
        self.cursor = self.cursor.strict_add(u64::try_from(take).unwrap());
        self.total_read = self.total_read.strict_add(take);
        Ok(take)
    }
}

impl Write for ProbeJournal {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for ProbeJournal {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let len = i64::try_from(self.bytes.len())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let current =
            i64::try_from(self.cursor).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let next = match position {
            SeekFrom::Start(offset) => {
                i64::try_from(offset).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?
            },
            SeekFrom::End(offset) => len
                .checked_add(offset)
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?,
            SeekFrom::Current(offset) => current
                .checked_add(offset)
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?,
        };
        if next < 0 {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        self.cursor = u64::try_from(next).unwrap();
        Ok(self.cursor)
    }
}

impl DurableIo for ProbeJournal {
    fn durable_metadata(&self) -> io::Result<StoreMetadata> {
        Err(io::Error::other("probe has no durable metadata"))
    }

    fn durable_set_len(&self, _length: u64) -> io::Result<()> {
        Err(io::Error::other("probe cannot set length"))
    }

    fn durable_sync_data(&self) -> io::Result<()> {
        Ok(())
    }

    fn durable_read_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
        let start = usize::try_from(offset).unwrap();
        if start >= self.bytes.len() {
            return Ok(0);
        }
        let available = &self.bytes[start..];
        let take = available.len().min(buffer.len());
        buffer[..take].copy_from_slice(&available[..take]);
        Ok(take)
    }
}

fn sample_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect()
}

#[test]
fn streamed_digest_matches_slice_digest_across_buffer_sizes() {
    for len in [
        0,
        1,
        63,
        TRANSFER_BUFFER_BYTES - 1,
        TRANSFER_BUFFER_BYTES,
        TRANSFER_BUFFER_BYTES + 1,
        TRANSFER_BUFFER_BYTES * 2 + 17,
    ] {
        let bytes = sample_bytes(len);
        let expected = journal_digest(&bytes);
        let mut file = ProbeJournal::new(bytes);
        let actual = digest_journal_file(&mut file, "parity").expect("digest");
        assert_eq!(actual, expected, "len={len}");
        assert!(
            file.max_read_request() <= TRANSFER_BUFFER_BYTES,
            "requested {} for len={len}",
            file.max_read_request()
        );
        assert_eq!(file.cursor, u64::try_from(len).unwrap());
    }
}

#[test]
fn streamed_digest_retries_interrupted_reads() {
    let bytes = sample_bytes(TRANSFER_BUFFER_BYTES + 9);
    let expected = journal_digest(&bytes);
    let mut file = ProbeJournal::new(bytes).with_interrupt();
    let actual = digest_journal_file(&mut file, "interrupt").expect("digest");
    assert_eq!(actual, expected);
}

#[test]
fn prefix_digest_ignores_changed_tail_bytes() {
    let prefix = sample_bytes(TRANSFER_BUFFER_BYTES + 5);
    let expected = journal_digest(&prefix);
    let mut with_tail = prefix.clone();
    with_tail.extend_from_slice(&[0xFF; 128]);
    let mut file = ProbeJournal::new(with_tail);
    let actual = digest_journal_prefix(&mut file, u64::try_from(prefix.len()).unwrap(), "prefix")
        .expect("prefix digest");
    assert_eq!(actual, expected);
    assert_eq!(file.total_read, prefix.len(), "the tail must not be read");
    assert!(file.max_read_request() <= TRANSFER_BUFFER_BYTES);
}

#[test]
fn truncated_prefix_fails_closed() {
    let bytes = sample_bytes(32);
    let mut file = ProbeJournal::new(bytes);
    let error = digest_journal_prefix(&mut file, 64, "truncated").expect_err("short");
    assert!(matches!(
        error,
        DurableError::InvalidRepresentationState(message)
            if message.contains("truncated")
    ));
}

#[test]
fn oversized_journal_never_requests_unbounded_read_buffer() {
    let bytes = sample_bytes(TRANSFER_BUFFER_BYTES * 4 + 3);
    assert!(bytes.len() > TRANSFER_BUFFER_BYTES);
    let mut file = ProbeJournal::new(bytes);
    let _ = digest_journal_file(&mut file, "bound").expect("digest");
    assert!(
        file.max_read_request() <= TRANSFER_BUFFER_BYTES,
        "max request {}",
        file.max_read_request()
    );
}
