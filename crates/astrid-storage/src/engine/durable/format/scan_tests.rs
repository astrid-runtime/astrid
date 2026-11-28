//! Exercise the real sequential scanner over native files and volume regions.

use std::io::{Read, Seek, SeekFrom, Write};

use super::*;
use crate::engine::durable::media::StoreMetadata;
use crate::volume::HostedFileVolume;

struct ObservedStream {
    file: File,
    reads: usize,
    seeks: usize,
    short_reads: bool,
    fail_after_reads: Option<usize>,
    eof_after_reads: Option<usize>,
    move_cursor_on_read_at: bool,
    positional_reads: std::cell::RefCell<Vec<(u64, usize)>>,
}

impl Read for ObservedStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.fail_after_reads == Some(self.reads) {
            return Err(io::Error::other("injected scan read failure"));
        }
        if self.eof_after_reads == Some(self.reads) {
            return Ok(0);
        }
        self.reads = self.reads.strict_add(1);
        let length = if self.short_reads {
            bytes.len().min(7)
        } else {
            bytes.len()
        };
        self.file.read(&mut bytes[..length])
    }
}
impl Write for ObservedStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.file.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
impl Seek for ObservedStream {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.seeks = self.seeks.strict_add(1);
        self.file.seek(position)
    }
}
impl DurableIo for ObservedStream {
    fn durable_read_at_preserves_cursor(&self) -> bool {
        !self.move_cursor_on_read_at && self.file.durable_read_at_preserves_cursor()
    }

    fn durable_metadata(&self) -> io::Result<StoreMetadata> {
        self.file.durable_metadata()
    }
    fn durable_set_len(&self, len: u64) -> io::Result<()> {
        self.file.durable_set_len(len)
    }
    fn durable_sync_data(&self) -> io::Result<()> {
        self.file.durable_sync_data()
    }
    fn durable_read_at(&self, bytes: &mut [u8], offset: u64) -> io::Result<usize> {
        self.positional_reads
            .borrow_mut()
            .push((offset, bytes.len()));
        if self.move_cursor_on_read_at {
            // A cloned native handle shares its cursor, matching Windows
            // seek_read even when this regression runs on Unix.
            let mut reader = self.file.try_clone()?;
            reader.seek(SeekFrom::Start(offset))?;
            reader.read(bytes)
        } else {
            self.file.durable_read_at(bytes, offset)
        }
    }
}

fn stream(hosted: bool) -> (tempfile::TempDir, ObservedStream) {
    let dir = tempfile::tempdir().unwrap();
    let file = if hosted {
        File::volume(
            HostedFileVolume::open(dir.path().join("astrid.volume")).unwrap(),
            "frames",
            true,
        )
        .unwrap()
    } else {
        File::native(tempfile::tempfile().unwrap())
    };
    (
        dir,
        ObservedStream {
            file,
            reads: 0,
            seeks: 0,
            short_reads: false,
            fail_after_reads: None,
            eof_after_reads: None,
            move_cursor_on_read_at: false,
            positional_reads: std::cell::RefCell::new(Vec::new()),
        },
    )
}

#[test]
fn short_probe_reads_preserve_valid_frames_after_damage() {
    for hosted in [false, true] {
        let (_dir, mut stream) = self::stream(hosted);
        stream.write_all(&[0; FRAME_HEADER_LEN_USIZE]).unwrap();
        append_frame(&mut stream, ARENA_MAGIC, b"retained frame").unwrap();
        let mut original = Vec::new();
        stream.rewind().unwrap();
        stream.read_to_end(&mut original).unwrap();

        stream.short_reads = true;
        let error = scan_frames(
            &mut stream,
            "test frames",
            ARENA_MAGIC,
            RecoveryLimits::process_addressable(),
            |_, _| panic!("interior damage must stop the scan"),
        )
        .unwrap_err();
        assert!(matches!(error, DurableError::Corrupt { offset: 0, .. }));
        stream.rewind().unwrap();
        let mut preserved = Vec::new();
        stream.read_to_end(&mut preserved).unwrap();
        assert_eq!(preserved, original);
    }
}

#[test]
fn a_later_frame_crossing_probe_windows_prevents_truncation() {
    // The first window starts at 1 and ends at 65,544. Only three bytes
    // of the later frame's magic fit before that boundary.
    for hosted in [false, true] {
        let (_dir, mut stream) = self::stream(hosted);
        stream.write_all(&vec![0; 65_541]).unwrap();
        // The payload also crosses the independent 64 KiB checksum buffer.
        let mut payload = vec![0u8; 65_537];
        *payload.last_mut().unwrap() = 1;
        append_frame(&mut stream, ARENA_MAGIC, &payload).unwrap();
        let length = stream.file.metadata().unwrap().len();
        let error = scan_frames(
            &mut stream,
            "test frames",
            ARENA_MAGIC,
            RecoveryLimits::process_addressable(),
            |_, _| panic!("interior damage must stop the scan"),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            DurableError::Corrupt {
                offset: 0,
                detail: "frame magic mismatch",
                ..
            }
        ));
        assert_eq!(stream.file.metadata().unwrap().len(), length);

        // Change only the final chunk. No complete protective frame now follows.
        stream.seek(SeekFrom::End(-1)).unwrap();
        stream.write_all(&[0]).unwrap();
        scan_frames(
            &mut stream,
            "test frames",
            ARENA_MAGIC,
            RecoveryLimits::process_addressable(),
            |_, _| panic!("invalid frame must not be visited"),
        )
        .unwrap();
        assert_eq!(stream.file.metadata().unwrap().len(), 0);
    }
}

#[test]
fn probe_eof_before_the_measured_end_preserves_the_file() {
    for hosted in [false, true] {
        let (_dir, mut stream) = self::stream(hosted);
        stream.write_all(&[0; FRAME_HEADER_LEN_USIZE]).unwrap();
        // Header fetch succeeds, then the independent probe reads zero bytes.
        stream.eof_after_reads = Some(1);
        let error = scan_frames(
            &mut stream,
            "test frames",
            ARENA_MAGIC,
            RecoveryLimits::process_addressable(),
            |_, _| panic!("unreadable tail must stop the scan"),
        )
        .unwrap_err();
        assert!(
            matches!(error,DurableError::Io{operation:"read durable tail recovery scan",source} if source.kind()==io::ErrorKind::UnexpectedEof)
        );
        assert_eq!(stream.file.metadata().unwrap().len(), FRAME_HEADER_LEN);
    }
}

#[test]
fn callback_rejection_never_repairs_or_overwrites_the_stream() {
    for hosted in [false, true] {
        let (_dir, mut stream) = self::stream(hosted);
        for payload in [b"first".as_slice(), b"second"] {
            append_frame(&mut stream, ARENA_MAGIC, payload).unwrap();
        }
        let length = stream.file.metadata().unwrap().len();
        let error = scan_frames(
            &mut stream,
            "test frames",
            ARENA_MAGIC,
            RecoveryLimits::process_addressable(),
            |_, _| Err(DurableError::EncodingOverflow),
        )
        .unwrap_err();
        assert!(matches!(error, DurableError::EncodingOverflow));
        assert_eq!(stream.file.metadata().unwrap().len(), length);
        // Error-path cursor position is unspecified; a subsequent scan must
        // position itself and recover both original frames without mutation.
        let mut accepted = 0;
        scan_frames(
            &mut stream,
            "test frames",
            ARENA_MAGIC,
            RecoveryLimits::process_addressable(),
            |_, _| {
                accepted += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(accepted, 2);
    }
}

#[test]
fn incomplete_declared_payload_preserves_later_frames() {
    for hosted in [false, true] {
        for has_later_frame in [false, true] {
            let (_dir, mut stream) = self::stream(hosted);
            append_frame(&mut stream, ARENA_MAGIC, b"retained prefix").unwrap();
            let prefix_len = stream.stream_position().unwrap();
            stream
                .write_all(&frame_header(ARENA_MAGIC, 1024, [0; 32]))
                .unwrap();
            if has_later_frame {
                append_frame(&mut stream, ARENA_MAGIC, b"later frame").unwrap();
            }
            let mut original = Vec::new();
            stream.rewind().unwrap();
            stream.read_to_end(&mut original).unwrap();
            let mut visits = 0;
            let result = scan_frames(
                &mut stream,
                "test frames",
                ARENA_MAGIC,
                RecoveryLimits::process_addressable(),
                |at, body| {
                    assert_eq!(at, 0);
                    assert_eq!(body, b"retained prefix");
                    visits = usize::strict_add(visits, 1);
                    Ok(())
                },
            );
            assert_eq!(visits, 1);
            let expected = if has_later_frame {
                assert!(
                    matches!(result,Err(DurableError::Corrupt{offset,detail:"published frame payload is truncated",..}) if offset==prefix_len)
                );
                original.as_slice()
            } else {
                result.unwrap();
                &original[..usize::try_from(prefix_len).unwrap()]
            };
            stream.rewind().unwrap();
            let mut retained = Vec::new();
            stream.read_to_end(&mut retained).unwrap();
            assert_eq!(retained, expected);
        }
    }
}

#[test]
fn media_read_errors_do_not_become_repairable_tail_damage() {
    for hosted in [false, true] {
        for (fail_after, payload_len, operation) in [
            (0, 1, "read durable frame header"),
            (1, 32_769, "read durable frame payload"),
        ] {
            let (_dir, mut stream) = self::stream(hosted);
            append_frame(&mut stream, ARENA_MAGIC, &vec![0xa5; payload_len]).unwrap();
            let length = stream.file.metadata().unwrap().len();
            stream.fail_after_reads = Some(fail_after);
            let error = scan_frames(
                &mut stream,
                "test frames",
                ARENA_MAGIC,
                RecoveryLimits::process_addressable(),
                |_, _| panic!("failed frame must not be accepted"),
            )
            .unwrap_err();
            assert!(
                matches!(error, DurableError::Io { operation: actual, .. } if actual == operation)
            );
            assert_eq!(stream.file.metadata().unwrap().len(), length);
        }
    }
}

#[test]
fn sequential_scan_coalesces_small_frames_and_resets_the_append_cursor() {
    for hosted in [false, true] {
        let (_dir, mut stream) = self::stream(hosted);
        for index in 0_u64..256 {
            append_frame(&mut stream, ARENA_MAGIC, &index.to_le_bytes()).unwrap();
        }
        stream.reads = 0;
        stream.seeks = 0;
        let mut expected = 0_u64;
        scan_frames(
            &mut stream,
            "test frames",
            ARENA_MAGIC,
            RecoveryLimits::process_addressable(),
            |offset, payload| {
                assert_eq!(payload, expected.to_le_bytes());
                assert_eq!(offset, expected * (FRAME_HEADER_LEN + 8));
                expected += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(expected, 256);
        assert_eq!(
            stream.seeks, 2,
            "only initial positioning and final append positioning"
        );
        assert!(
            stream.reads < 256,
            "small headers/payloads must share media reads"
        );
        let length = stream.file.metadata().unwrap().len();
        assert_eq!(stream.file.stream_position().unwrap(), length);
        append_frame(&mut stream, ARENA_MAGIC, b"after recovery").unwrap();
    }
}

#[test]
fn buffered_scan_preserves_payloads_across_refills_and_short_reads() {
    for hosted in [false, true] {
        for short_reads in [false, true] {
            let (_dir, mut stream) = self::stream(hosted);
            let payloads = [0, 1, 8191, 8192, 8193, 32_769].map(|len| vec![0xa5; len]);
            for payload in &payloads {
                append_frame(&mut stream, ARENA_MAGIC, payload).unwrap();
            }
            stream.short_reads = short_reads;
            let mut index = 0;
            scan_frames(
                &mut stream,
                "test frames",
                ARENA_MAGIC,
                RecoveryLimits::process_addressable(),
                |_, payload| {
                    assert_eq!(payload, payloads[index]);
                    index += 1;
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(index, payloads.len());
        }
    }
}

#[test]
fn buffered_tail_repair_never_truncates_a_published_prefix_or_interior_frame() {
    for hosted in [false, true] {
        for (published, interior) in [(false, false), (true, false), (false, true)] {
            let (_dir, mut stream) = self::stream(hosted);
            append_frame(&mut stream, ARENA_MAGIC, b"valid prefix").unwrap();
            let prefix_len = stream.file.metadata().unwrap().len();
            let bad = append_frame(&mut stream, ARENA_MAGIC, b"bad checksum").unwrap();
            if interior {
                append_frame(&mut stream, ARENA_MAGIC, b"later complete frame").unwrap();
            }
            let original_len = stream.file.metadata().unwrap().len();
            stream
                .file
                .seek(SeekFrom::Start(bad.offset + CHECKSUM_START as u64))
                .unwrap();
            stream.file.write_all(&[0xff; 32]).unwrap();
            let mut accepted = 0;
            let result = scan_frames_with_protected_prefix(
                &mut stream,
                "test frames",
                ARENA_MAGIC,
                RecoveryLimits::process_addressable(),
                if published { original_len } else { prefix_len },
                |_, _, _source| {
                    accepted += 1;
                    Ok(())
                },
            );
            assert_eq!(accepted, 1);
            if published || interior {
                assert!(result.is_err());
                assert_eq!(stream.file.metadata().unwrap().len(), original_len);
            } else {
                result.unwrap();
                assert_eq!(stream.file.metadata().unwrap().len(), prefix_len);
                assert_eq!(stream.file.stream_position().unwrap(), prefix_len);
                append_frame(&mut stream, ARENA_MAGIC, b"replacement tail").unwrap();
            }
        }
    }
}

#[test]
fn positional_callback_reads_preserve_sequential_scan_read_ahead() {
    for hosted in [false, true] {
        let (_dir, mut source) = self::stream(hosted);
        let first = append_frame(&mut source, ARENA_MAGIC, b"first frame").unwrap();
        append_frame(&mut source, ARENA_MAGIC, b"second frame").unwrap();
        let length = source.file.metadata().unwrap().len();
        let limits = RecoveryLimits::process_addressable();
        let mut seen = Vec::new();
        scan_frames_with_source(
            &mut source,
            "test frames",
            ARENA_MAGIC,
            limits,
            |location, bytes, load_previous| {
                if location.offset() != first.offset {
                    assert_eq!(load_previous(first.offset)?, b"first frame");
                }
                seen.push(bytes.to_vec());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            seen,
            vec![b"first frame".to_vec(), b"second frame".to_vec()]
        );
        assert_eq!(source.file.stream_position().unwrap(), length);
        assert_eq!(source.file.metadata().unwrap().len(), length);
    }
}

#[test]
fn callback_rereads_preserve_read_ahead_across_refills_with_a_shared_cursor() {
    let (_dir, mut source) = stream(false);
    source.move_cursor_on_read_at = true;
    let mut expected = Vec::new();
    for marker in 0_u8..32 {
        let bytes = vec![marker; 1024];
        append_frame(&mut source, ARENA_MAGIC, &bytes).unwrap();
        expected.push(bytes);
    }
    let length = source.file.metadata().unwrap().len();
    let limits = RecoveryLimits::process_addressable();
    let mut seen = Vec::new();
    scan_frames_with_source(
        &mut source,
        "shared-cursor frames",
        ARENA_MAGIC,
        limits,
        |_, bytes, load_previous| {
            assert_eq!(load_previous(0)?, expected[0]);
            seen.push(bytes.to_vec());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        seen, expected,
        "rereads must not replace later frames with earlier ones"
    );
    assert_eq!(source.file.metadata().unwrap().len(), length);
    assert_eq!(source.file.stream_position().unwrap(), length);
}

#[test]
fn committed_prefix_ignores_appended_torn_tail_without_mutation() {
    for hosted in [false, true] {
        let (_dir, mut stream) = self::stream(hosted);
        let first = append_frame(&mut stream, ARENA_MAGIC, b"prefix-one").unwrap();
        let second = append_frame(&mut stream, ARENA_MAGIC, b"prefix-two").unwrap();
        let end = DurablePrefixEnd::exclusive(stream.file.metadata().unwrap().len());
        // Concurrent-style garbage past the captured fence.
        stream.file.write_all(&[0xA5; 17]).unwrap();
        stream.file.write_all(b"not-a-frame").unwrap();
        let physical = stream.file.metadata().unwrap().len();
        assert!(physical > end.get());

        let mut accepted = Vec::new();
        scan_frames_prefix(
            &mut stream,
            "prefix frames",
            ARENA_MAGIC,
            RecoveryLimits::process_addressable(),
            end,
            |offset, payload| {
                accepted.push((offset, payload.to_vec()));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            accepted,
            vec![
                (first.offset, b"prefix-one".to_vec()),
                (second.offset, b"prefix-two".to_vec()),
            ]
        );
        assert_eq!(stream.file.metadata().unwrap().len(), physical);
    }
}

#[test]
fn committed_prefix_rejects_mid_frame_cutoff_without_mutation() {
    for hosted in [false, true] {
        let (_dir, mut stream) = self::stream(hosted);
        append_frame(&mut stream, ARENA_MAGIC, b"complete").unwrap();
        let complete_end = stream.file.metadata().unwrap().len();
        append_frame(&mut stream, ARENA_MAGIC, b"cutoff-me").unwrap();
        let full = stream.file.metadata().unwrap().len();
        assert!(full > complete_end + FRAME_HEADER_LEN);

        for end in [complete_end + 1, complete_end + FRAME_HEADER_LEN, full - 1] {
            let before = stream.file.metadata().unwrap().len();
            let error = scan_frames_prefix(
                &mut stream,
                "cutoff frames",
                ARENA_MAGIC,
                RecoveryLimits::process_addressable(),
                DurablePrefixEnd::exclusive(end),
                |_, _| Ok(()),
            )
            .unwrap_err();
            assert!(
                matches!(
                    error,
                    DurableError::Corrupt {
                        detail: "published frame header is truncated"
                            | "published frame payload is truncated",
                        ..
                    }
                ),
                "{error:?} for end={end}"
            );
            assert_eq!(stream.file.metadata().unwrap().len(), before);
        }
    }
}

#[test]
fn committed_prefix_rejects_interior_magic_crc_and_size_without_mutation() {
    for hosted in [false, true] {
        let (_dir, mut stream) = self::stream(hosted);
        append_frame(&mut stream, ARENA_MAGIC, b"good").unwrap();
        let bad = append_frame(&mut stream, ARENA_MAGIC, b"tamper").unwrap();
        let end = DurablePrefixEnd::exclusive(stream.file.metadata().unwrap().len());

        // CRC tamper inside the committed prefix.
        stream
            .file
            .seek(SeekFrom::Start(bad.offset + CHECKSUM_START as u64))
            .unwrap();
        stream.file.write_all(&[0xff; 32]).unwrap();
        let length = stream.file.metadata().unwrap().len();
        let error = scan_frames_prefix(
            &mut stream,
            "crc frames",
            ARENA_MAGIC,
            RecoveryLimits::process_addressable(),
            end,
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            DurableError::Corrupt {
                detail: "frame checksum mismatch",
                ..
            }
        ));
        assert_eq!(stream.file.metadata().unwrap().len(), length);

        // Magic mismatch inside the committed prefix.
        let (_dir, mut stream) = self::stream(hosted);
        append_frame(&mut stream, ARENA_MAGIC, b"good").unwrap();
        let bad = append_frame(&mut stream, ARENA_MAGIC, b"magic").unwrap();
        let end = DurablePrefixEnd::exclusive(stream.file.metadata().unwrap().len());
        stream.file.seek(SeekFrom::Start(bad.offset)).unwrap();
        stream.file.write_all(b"BADMAGIC").unwrap();
        let length = stream.file.metadata().unwrap().len();
        let error = scan_frames_prefix(
            &mut stream,
            "magic frames",
            ARENA_MAGIC,
            RecoveryLimits::process_addressable(),
            end,
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            DurableError::Corrupt {
                detail: "frame magic mismatch",
                ..
            }
        ));
        assert_eq!(stream.file.metadata().unwrap().len(), length);

        // Declared size above RecoveryLimits inside the committed prefix.
        let (_dir, mut stream) = self::stream(hosted);
        append_frame(&mut stream, ARENA_MAGIC, b"good").unwrap();
        let bad = append_frame(&mut stream, ARENA_MAGIC, &[0_u8; 64]).unwrap();
        let end = DurablePrefixEnd::exclusive(stream.file.metadata().unwrap().len());
        let limits = RecoveryLimits::new(16).unwrap();
        let length = stream.file.metadata().unwrap().len();
        let error = scan_frames_prefix(
            &mut stream,
            "size frames",
            ARENA_MAGIC,
            limits,
            end,
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            DurableError::FrameTooLarge {
                offset,
                ..
            } if offset == bad.offset
        ));
        assert_eq!(stream.file.metadata().unwrap().len(), length);
    }
}

#[test]
fn committed_prefix_callback_rejection_never_mutates() {
    for hosted in [false, true] {
        let (_dir, mut stream) = self::stream(hosted);
        append_frame(&mut stream, ARENA_MAGIC, b"one").unwrap();
        append_frame(&mut stream, ARENA_MAGIC, b"two").unwrap();
        let end = DurablePrefixEnd::exclusive(stream.file.metadata().unwrap().len());
        stream.file.write_all(&[0x11; 9]).unwrap();
        let length = stream.file.metadata().unwrap().len();
        let error = scan_frames_prefix(
            &mut stream,
            "reject frames",
            ARENA_MAGIC,
            RecoveryLimits::process_addressable(),
            end,
            |_, _| Err(DurableError::EncodingOverflow),
        )
        .unwrap_err();
        assert!(matches!(error, DurableError::EncodingOverflow));
        assert_eq!(stream.file.metadata().unwrap().len(), length);
    }
}

#[test]
fn committed_range_scans_tail_only_and_allows_historical_source_loads() {
    for hosted in [false, true] {
        let (_dir, mut stream) = self::stream(hosted);
        let first = append_frame(&mut stream, ARENA_MAGIC, b"historical").unwrap();
        let start = DurablePrefixEnd::exclusive(stream.file.metadata().unwrap().len());
        let second = append_frame(&mut stream, ARENA_MAGIC, b"tail").unwrap();
        let end = DurablePrefixEnd::exclusive(stream.file.metadata().unwrap().len());
        stream.file.write_all(b"GGGGGGGGGGGGGGGG").unwrap();
        let physical = stream.file.metadata().unwrap().len();
        let range = DurableFrameRange::try_new(start, end).unwrap();

        let mut visited = Vec::new();
        scan_frames_range_with_source(
            &mut stream,
            "range frames",
            ARENA_MAGIC,
            RecoveryLimits::process_addressable(),
            range,
            |location, payload, load_previous| {
                assert_eq!(location.offset(), second.offset);
                assert_eq!(payload, b"tail");
                assert_eq!(load_previous(first.offset).unwrap(), b"historical");
                visited.push(payload.to_vec());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(visited, vec![b"tail".to_vec()]);
        assert_eq!(stream.file.metadata().unwrap().len(), physical);

        let error = scan_frames_range_with_source(
            &mut stream,
            "range frames",
            ARENA_MAGIC,
            RecoveryLimits::process_addressable(),
            range,
            |_location, _payload, load_previous| {
                // A fabricated extent past the captured end must fail closed.
                let _ = load_previous(end.get())?;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            DurableError::Corrupt {
                detail: "published frame header is truncated"
                    | "published frame payload is truncated"
                    | "frame magic mismatch"
                    | "unsupported frame version",
                ..
            } | DurableError::EncodingOverflow
                | DurableError::Io { .. }
        ));
        assert_eq!(stream.file.metadata().unwrap().len(), physical);
    }
}

#[test]
fn durable_frame_range_rejects_inverted_bounds() {
    let error = DurableFrameRange::try_new(
        DurablePrefixEnd::exclusive(8),
        DurablePrefixEnd::exclusive(4),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        DurableError::InvalidRepresentationState("durable frame range start exceeds end")
    ));
}

#[test]
fn source_callback_out_of_range_never_reads_past_bound_on_native_or_volume() {
    for hosted in [false, true] {
        for move_cursor in [false, true] {
            let (_dir, mut stream) = self::stream(hosted);
            stream.move_cursor_on_read_at = move_cursor;
            let first = append_frame(&mut stream, ARENA_MAGIC, b"keep-me").unwrap();
            let end = DurablePrefixEnd::exclusive(stream.file.metadata().unwrap().len());
            stream
                .file
                .write_all(&[0x5A; FRAME_HEADER_LEN_USIZE + 8])
                .unwrap();
            let physical = stream.file.metadata().unwrap().len();
            stream.positional_reads.borrow_mut().clear();

            let mut visited = Vec::new();
            scan_frames_prefix_with_source(
                &mut stream,
                "prefix frames",
                ARENA_MAGIC,
                RecoveryLimits::process_addressable(),
                end,
                |location, payload, load_previous| {
                    let error = load_previous(end.get()).expect_err("must reject exact end");
                    assert!(matches!(
                        error,
                        DurableError::Corrupt {
                            detail: "published frame header is truncated",
                            ..
                        } | DurableError::EncodingOverflow
                    ));
                    if end.get() >= FRAME_HEADER_LEN {
                        let interior = end.get() - (FRAME_HEADER_LEN - 1);
                        let error = load_previous(interior)
                            .expect_err("header crossing end must reject before read");
                        assert!(matches!(
                            error,
                            DurableError::Corrupt {
                                detail: "published frame header is truncated",
                                ..
                            } | DurableError::EncodingOverflow
                        ));
                    }
                    assert_eq!(load_previous(first.offset).unwrap(), b"keep-me");
                    visited.push((location.offset(), payload.to_vec()));
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(visited, vec![(first.offset, b"keep-me".to_vec())]);
            assert_eq!(stream.file.metadata().unwrap().len(), physical);
            for &(offset, len) in stream.positional_reads.borrow().iter() {
                let read_end = offset
                    .checked_add(u64::try_from(len).unwrap())
                    .expect("positional read extent");
                assert!(
                    read_end <= end.get(),
                    "source callback read [{offset}, {read_end}) past captured end {}",
                    end.get()
                );
            }
        }
    }
}

#[test]
fn live_source_load_preserves_header_extent_overflow_with_max_bound() {
    for hosted in [false, true] {
        let (_dir, mut stream) = self::stream(hosted);
        append_frame(&mut stream, ARENA_MAGIC, b"live").unwrap();
        let error = scan_frames_with_source(
            &mut stream,
            "live frames",
            ARENA_MAGIC,
            RecoveryLimits::process_addressable(),
            |_location, _payload, load_previous| {
                // Live path uses captured_end=MAX; overflowing the header extent
                // must fail closed as EncodingOverflow without inventing a fence.
                load_previous(u64::MAX - (FRAME_HEADER_LEN - 1)).map(|_| ())
            },
        )
        .unwrap_err();
        assert!(matches!(error, DurableError::EncodingOverflow));
    }
}
