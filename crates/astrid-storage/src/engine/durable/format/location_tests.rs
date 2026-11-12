//! Exact scan extents share the direct reader's authoritative validation.

use super::super::positioned_tests::ObservedSource;
use super::super::{
    ARENA_FILE, ARENA_MAGIC, CHECKSUM_START, File, SeekFrom, append_frame, io,
    scan_frames_with_source,
};
use super::*;
use crate::volume::HostedFileVolume;
use std::io::{Seek, Write};

fn source(hosted: bool) -> (tempfile::TempDir, ObservedSource) {
    let dir = tempfile::tempdir().unwrap();
    let mut source = ObservedSource::new();
    if hosted {
        source.file = File::volume(
            HostedFileVolume::open(dir.path().join("frames.volume")).unwrap(),
            "frames",
            true,
        )
        .unwrap();
    }
    (dir, source)
}

fn locations(source: &mut ObservedSource) -> Vec<FrameLocation> {
    let mut locations = Vec::new();
    scan_frames_with_source(
        source,
        ARENA_FILE,
        ARENA_MAGIC,
        RecoveryLimits::process_addressable(),
        |location, _, _| {
            locations.push(location);
            Ok(())
        },
    )
    .unwrap();
    locations
}

#[test]
fn validated_extents_read_only_one_complete_frame_and_leave_appending_usable() {
    for hosted in [false, true] {
        let (_dir, mut source) = source(hosted);
        let payloads = [0, 7, 65_537].map(|length| vec![0x39; length]);
        for payload in &payloads {
            append_frame(&mut source, ARENA_MAGIC, payload).unwrap();
        }
        let locations = locations(&mut source);
        let append_offset = source.file.metadata().unwrap().len();
        source.seek(SeekFrom::Start(7)).unwrap();
        for (location, expected) in locations.into_iter().zip(payloads).rev() {
            source.reads.borrow_mut().clear();
            let frame = location
                .read(
                    &source,
                    ARENA_FILE,
                    ARENA_MAGIC,
                    RecoveryLimits::process_addressable(),
                )
                .unwrap();
            assert_eq!(frame.payload(), expected);
            assert_eq!(frame.bytes.len(), FRAME_HEADER_LEN_USIZE + expected.len());
            assert_eq!(
                *source.reads.borrow(),
                vec![(location.offset(), frame.bytes.len())]
            );
        }
        if source.file.durable_read_at_preserves_cursor() {
            assert_eq!(source.stream_position().unwrap(), 7);
        }
        assert_eq!(
            append_frame(&mut source, ARENA_MAGIC, b"next")
                .unwrap()
                .offset,
            append_offset
        );
    }
}

#[test]
fn exact_locations_handle_short_reads_and_truncation() {
    for hosted in [false, true] {
        let (_dir, mut source) = source(hosted);
        append_frame(&mut source, ARENA_MAGIC, b"requested payload").unwrap();
        let location = locations(&mut source)[0];
        source.short_limit = 7;
        assert_eq!(
            location
                .read(
                    &source,
                    ARENA_FILE,
                    ARENA_MAGIC,
                    RecoveryLimits::process_addressable(),
                )
                .unwrap()
                .payload(),
            b"requested payload"
        );
        let length = source.file.metadata().unwrap().len();
        for truncated in [length - 1, FRAME_HEADER_LEN - 1, 0] {
            source.durable_set_len(truncated).unwrap();
            let error = location
                .read(
                    &source,
                    ARENA_FILE,
                    ARENA_MAGIC,
                    RecoveryLimits::process_addressable(),
                )
                .err()
                .unwrap();
            assert!(matches!(error, DurableError::Io { source, .. }
                if source.kind() == io::ErrorKind::UnexpectedEof));
        }
    }
}

#[test]
fn exact_locations_revalidate_header_payload_and_declared_length() {
    for hosted in [false, true] {
        for mutation in [0, 8, 10, CHECKSUM_START, FRAME_HEADER_LEN_USIZE] {
            let (_dir, mut source) = source(hosted);
            append_frame(&mut source, ARENA_MAGIC, b"requested").unwrap();
            let location = locations(&mut source)[0];
            source
                .seek(SeekFrom::Start(u64::try_from(mutation).unwrap()))
                .unwrap();
            source.write_all(&[0xff]).unwrap();
            assert!(matches!(
                location.read(
                    &source,
                    ARENA_FILE,
                    ARENA_MAGIC,
                    RecoveryLimits::process_addressable(),
                ),
                Err(DurableError::Corrupt { .. })
            ));
        }
        for declared in [8_u64, 10, u64::MAX] {
            let (_dir, mut source) = source(hosted);
            append_frame(&mut source, ARENA_MAGIC, b"requested").unwrap();
            let location = locations(&mut source)[0];
            source.seek(SeekFrom::Start(12)).unwrap();
            source.write_all(&declared.to_le_bytes()).unwrap();
            let error = location
                .read(
                    &source,
                    ARENA_FILE,
                    ARENA_MAGIC,
                    RecoveryLimits::new(1024).unwrap(),
                )
                .err()
                .unwrap();
            if declared == u64::MAX {
                assert!(matches!(error, DurableError::FrameTooLarge { .. }));
            } else {
                assert!(matches!(
                    error,
                    DurableError::Corrupt {
                        detail: "frame length changed since recovery scan",
                        ..
                    }
                ));
            }
        }
    }
}

#[test]
fn exact_extent_limits_and_overflow_fail_before_any_read() {
    let (_dir, source) = source(false);
    for (location, limits) in [
        (
            FrameLocation::for_test(0, 2),
            RecoveryLimits::new(1).unwrap(),
        ),
        (
            FrameLocation::for_test(u64::MAX - 1, 8),
            RecoveryLimits::process_addressable(),
        ),
        (
            FrameLocation::for_test(0, u64::MAX),
            RecoveryLimits::process_addressable(),
        ),
    ] {
        assert!(
            location
                .read(&source, ARENA_FILE, ARENA_MAGIC, limits)
                .is_err()
        );
        assert!(source.reads.borrow().is_empty());
    }
}

#[test]
fn exact_extent_requested_range_io_errors_are_never_hidden() {
    for hosted in [false, true] {
        for kind in [io::ErrorKind::Other, io::ErrorKind::Interrupted] {
            let (_dir, mut source) = source(hosted);
            append_frame(&mut source, ARENA_MAGIC, b"requested").unwrap();
            let location = locations(&mut source)[0];
            source.short_limit = 7;
            source.unreadable = Some(FRAME_HEADER_LEN + 2..FRAME_HEADER_LEN + 3);
            source.error_kind = kind;
            let error = location
                .read(
                    &source,
                    ARENA_FILE,
                    ARENA_MAGIC,
                    RecoveryLimits::process_addressable(),
                )
                .err()
                .unwrap();
            assert!(matches!(error, DurableError::Io { source, .. } if source.kind() == kind));
        }
    }
}
