use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};

use super::*;
use crate::engine::durable::format::append_frame;
use crate::engine::durable::media::StoreMetadata;

struct ObservedFile {
    file: File,
    largest_write: usize,
    short_writes: bool,
    fail_after: Option<usize>,
    written: usize,
}

impl ObservedFile {
    fn new() -> Self {
        Self {
            file: tempfile::tempfile().unwrap(),
            largest_write: 0,
            short_writes: false,
            fail_after: None,
            written: 0,
        }
    }
}

impl Read for ObservedFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file.read(bytes)
    }
}

impl Seek for ObservedFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

impl Write for ObservedFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.largest_write = self.largest_write.max(bytes.len());
        let mut count = if self.short_writes {
            bytes.len().min(7)
        } else {
            bytes.len()
        };
        if let Some(limit) = self.fail_after {
            if self.written >= limit {
                return Err(io::Error::other("injected streamed snapshot failure"));
            }
            count = count.min(limit.strict_sub(self.written));
        }
        let written = self.file.write(&bytes[..count])?;
        self.written = self.written.strict_add(written);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl DurableIo for ObservedFile {
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
}

fn state(count: u64) -> IndexState {
    let objects = (0..count)
        .rev()
        .map(|index| {
            let mut digest = [0; 32];
            digest[..8].copy_from_slice(&index.to_be_bytes());
            (
                ObjectId::new(digest),
                ArenaLocation {
                    offset: index.strict_mul(100),
                    payload_len: 48,
                    checksum: [0xa5; 32],
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    IndexState {
        arena_len: count.strict_mul(100),
        arena_tail: objects.values().next_back().copied(),
        objects,
    }
}

#[test]
fn streamed_snapshot_matches_frozen_bytes_with_bounded_writes_and_short_io() {
    let scheme = IdentityScheme::new(1, 1).unwrap();
    for count in [0, 1, 4096] {
        let state = state(count);
        let expected_payload = super::super::encode_snapshot(&state, scheme).unwrap();
        let mut expected = tempfile::tempfile().unwrap();
        append_frame(&mut expected, INDEX_MAGIC, &expected_payload).unwrap();
        for short_writes in [false, true] {
            let mut actual = ObservedFile::new();
            actual.short_writes = short_writes;
            Snapshot::new(&state, scheme)
                .unwrap()
                .append(&mut actual)
                .unwrap();
            assert!(actual.largest_write <= WRITE_BUFFER_BYTES);
            expected.rewind().unwrap();
            actual.rewind().unwrap();
            let mut expected_bytes = Vec::new();
            let mut actual_bytes = Vec::new();
            expected.read_to_end(&mut expected_bytes).unwrap();
            actual.read_to_end(&mut actual_bytes).unwrap();
            assert_eq!(
                actual_bytes, expected_bytes,
                "count={count}, short={short_writes}"
            );
        }
    }
}

#[test]
fn streamed_snapshot_reports_mid_payload_io_failure() {
    let state = state(4096);
    let mut file = ObservedFile::new();
    file.fail_after = Some(WRITE_BUFFER_BYTES + 123);
    assert!(
        Snapshot::new(&state, IdentityScheme::new(1, 1).unwrap())
            .unwrap()
            .append(&mut file)
            .is_err()
    );
    assert_eq!(file.written, WRITE_BUFFER_BYTES + 123);
}
