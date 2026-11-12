//! Positional reconstruction uses real framing and instrumented media reads.

use std::cell::{Cell, RefCell};
use std::io::{Read, Seek, Write};
use std::ops::Range;

use super::super::{
    ARENA_FILE, ARENA_MAGIC, CHECKSUM_START, FRAME_HEADER_LEN, FRAME_HEADER_LEN_USIZE, File,
    SeekFrom, append_frame, read_frame_at,
};
use super::*;
use crate::engine::durable::media::StoreMetadata;

struct ObservedSource {
    file: File,
    reads: RefCell<Vec<(u64, usize)>>,
    short_limit: usize,
    unreadable: Option<Range<u64>>,
    error_kind: io::ErrorKind,
    interrupt_once: Cell<bool>,
}

impl ObservedSource {
    fn new() -> Self {
        Self {
            file: File::native(tempfile::tempfile().unwrap()),
            reads: RefCell::new(Vec::new()),
            short_limit: usize::MAX,
            unreadable: None,
            error_kind: io::ErrorKind::Other,
            interrupt_once: Cell::new(false),
        }
    }

    fn read_frame(&self, offset: u64) -> Result<Vec<u8>, DurableError> {
        PositionalFrameReader::new(self).read_frame_at(
            ARENA_FILE,
            ARENA_MAGIC,
            offset,
            RecoveryLimits::process_addressable(),
        )
    }
}

impl Read for ObservedSource {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file.read(bytes)
    }
}
impl Write for ObservedSource {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.file.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
impl Seek for ObservedSource {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}
impl DurableIo for ObservedSource {
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
        self.reads.borrow_mut().push((offset, bytes.len()));
        if self.interrupt_once.replace(false) {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let length = bytes.len().min(self.short_limit);
        let end = offset.saturating_add(u64::try_from(length).unwrap());
        if self
            .unreadable
            .as_ref()
            .is_some_and(|range| offset < range.end && end > range.start)
        {
            return Err(io::Error::new(
                self.error_kind,
                "injected range read failure",
            ));
        }
        self.file.durable_read_at(&mut bytes[..length], offset)
    }
}

#[test]
fn descending_frames_share_aligned_reads_without_growing_the_window() {
    let mut source = ObservedSource::new();
    let locations: Vec<_> = (0_u64..4096)
        .map(|value| append_frame(&mut source, ARENA_MAGIC, &value.to_le_bytes()).unwrap())
        .collect();
    let mut reader = PositionalFrameReader::new(&source);
    assert_eq!(reader.buffer.capacity(), 0);
    for (value, location) in locations.iter().enumerate().rev() {
        let payload = reader
            .read_frame_at(
                ARENA_FILE,
                ARENA_MAGIC,
                location.offset,
                RecoveryLimits::process_addressable(),
            )
            .unwrap();
        assert_eq!(payload, u64::try_from(value).unwrap().to_le_bytes());
        assert_eq!(reader.buffer.len(), TRANSFER_BUFFER_BYTES);
    }
    assert!(source.reads.borrow().len() < locations.len() / 10);
    assert_eq!(reader.buffer.capacity(), TRANSFER_BUFFER_BYTES);
}

#[test]
fn boundary_headers_payloads_and_large_frames_use_the_same_validator() {
    for prefix in [
        TRANSFER_BUFFER_BYTES - 3,
        TRANSFER_BUFFER_BYTES - FRAME_HEADER_LEN_USIZE - 3,
    ] {
        for length in [0, 17, TRANSFER_BUFFER_BYTES - 1, TRANSFER_BUFFER_BYTES * 3] {
            let mut source = ObservedSource::new();
            source.write_all(&vec![0xa5; prefix]).unwrap();
            let expected = vec![0x39; length];
            let location = append_frame(&mut source, ARENA_MAGIC, &expected).unwrap();
            let mut reader = PositionalFrameReader::new(&source);
            assert_eq!(
                reader
                    .read_frame_at(
                        ARENA_FILE,
                        ARENA_MAGIC,
                        location.offset,
                        RecoveryLimits::process_addressable(),
                    )
                    .unwrap(),
                expected
            );
            assert_eq!(reader.buffer.capacity(), TRANSFER_BUFFER_BYTES);
            if length >= TRANSFER_BUFFER_BYTES {
                assert!(
                    source
                        .reads
                        .borrow()
                        .contains(&(location.offset + FRAME_HEADER_LEN, length,))
                );
            }
        }
    }
}

#[test]
fn short_reads_eof_and_sparse_offsets_terminate() {
    let mut source = ObservedSource::new();
    source.short_limit = 7;
    let far = u64::try_from(TRANSFER_BUFFER_BYTES).unwrap() * 1024 + 11;
    source.seek(SeekFrom::Start(far)).unwrap();
    // append_frame seeks to end, so extend the sparse file first.
    source.durable_set_len(far).unwrap();
    let location = append_frame(&mut source, ARENA_MAGIC, b"sparse frame").unwrap();
    assert_eq!(location.offset, far);
    assert_eq!(source.read_frame(far).unwrap(), b"sparse frame");
    let length = source.file.metadata().unwrap().len();
    for offset in [length - 1, length, length + 1, u64::MAX] {
        assert!(matches!(
            source.read_frame(offset),
            Err(DurableError::Io { .. })
        ));
    }
    source.durable_set_len(length - 1).unwrap();
    assert!(matches!(
        source.read_frame(far),
        Err(DurableError::Io { .. })
    ));
}

#[test]
fn sparse_active_frames_bound_prefetch_but_request_more_bytes_than_exact_reads() {
    let mut source = ObservedSource::new();
    let first = append_frame(&mut source, ARENA_MAGIC, b"first").unwrap();
    let width = u64::try_from(TRANSFER_BUFFER_BYTES).unwrap();
    let far = width * 1024 + 11;
    source.durable_set_len(far).unwrap();
    let last = append_frame(&mut source, ARENA_MAGIC, b"last").unwrap();
    source.durable_set_len((far / width + 1) * width).unwrap();
    let mut reader = PositionalFrameReader::new(&source);
    for (location, expected) in [(last, b"last".as_slice()), (first, b"first".as_slice())] {
        assert_eq!(
            reader
                .read_frame_at(
                    ARENA_FILE,
                    ARENA_MAGIC,
                    location.offset,
                    RecoveryLimits::process_addressable(),
                )
                .unwrap(),
            expected
        );
    }
    let reads = source.reads.borrow();
    assert_eq!(reads.len(), 2, "no scan of intervening historical bytes");
    let requested_bytes: usize = reads.iter().map(|(_, length)| length).sum();
    assert_eq!(requested_bytes, TRANSFER_BUFFER_BYTES * 2);
    assert_eq!(reader.buffer.capacity(), TRANSFER_BUFFER_BYTES);
}

#[test]
fn optional_prefix_and_suffix_errors_fall_back_to_exact_requested_bytes() {
    for blocked in [0..1, 4096..4097] {
        let mut source = ObservedSource::new();
        source.durable_set_len(1024).unwrap();
        let location = append_frame(&mut source, ARENA_MAGIC, b"requested").unwrap();
        source.unreadable = Some(blocked);
        assert_eq!(source.read_frame(location.offset).unwrap(), b"requested");
        assert!(
            source
                .reads
                .borrow()
                .contains(&(location.offset, FRAME_HEADER_LEN_USIZE))
        );
    }
}

#[test]
fn requested_range_failures_remain_io_errors_and_invalidate_partial_prefetch() {
    for kind in [io::ErrorKind::Other, io::ErrorKind::Interrupted] {
        let mut source = ObservedSource::new();
        let location = append_frame(&mut source, ARENA_MAGIC, b"requested").unwrap();
        source.short_limit = 7;
        source.unreadable = Some(FRAME_HEADER_LEN + 2..FRAME_HEADER_LEN + 3);
        source.error_kind = kind;
        let mut reader = PositionalFrameReader::new(&source);
        let error = reader
            .read_frame_at(
                ARENA_FILE,
                ARENA_MAGIC,
                location.offset,
                RecoveryLimits::process_addressable(),
            )
            .unwrap_err();
        assert!(matches!(error, DurableError::Io { source, .. } if source.kind() == kind));
        assert_eq!(reader.valid, 0);
    }
}

#[test]
fn optional_interrupt_is_retried_by_exact_read_without_retaining_partial_bytes() {
    let mut source = ObservedSource::new();
    append_frame(&mut source, ARENA_MAGIC, b"requested").unwrap();
    source.interrupt_once.set(true);
    assert_eq!(source.read_frame(0).unwrap(), b"requested");
}

#[test]
fn malformed_frames_and_limits_match_direct_reads() {
    for mutation in [0, 8, 10, CHECKSUM_START, FRAME_HEADER_LEN_USIZE] {
        let mut source = ObservedSource::new();
        append_frame(&mut source, ARENA_MAGIC, b"requested").unwrap();
        source
            .seek(SeekFrom::Start(u64::try_from(mutation).unwrap()))
            .unwrap();
        source.write_all(&[0xff]).unwrap();
        let direct = read_frame_at(
            &source,
            ARENA_FILE,
            ARENA_MAGIC,
            0,
            RecoveryLimits::process_addressable(),
        )
        .unwrap_err();
        let buffered = source.read_frame(0).unwrap_err();
        match (direct, buffered) {
            (
                DurableError::Corrupt { detail: left, .. },
                DurableError::Corrupt { detail: right, .. },
            ) => {
                assert_eq!(left, right);
            },
            pair => panic!("validation diverged: {pair:?}"),
        }
    }
    let mut source = ObservedSource::new();
    append_frame(&mut source, ARENA_MAGIC, b"requested").unwrap();
    let mut limits = RecoveryLimits::process_addressable();
    limits.max_frame_bytes = 1;
    let mut reader = PositionalFrameReader::new(&source);
    assert!(matches!(
        reader.read_frame_at(ARENA_FILE, ARENA_MAGIC, 0, limits),
        Err(DurableError::FrameTooLarge {
            declared: 9,
            limit: 1,
            ..
        })
    ));
}
