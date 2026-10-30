//! Exercise the real sequential scanner over native files and volume regions.

use std::io::{Read, Seek, Write};

use super::*;
use crate::engine::durable::media::StoreMetadata;
use crate::volume::HostedFileVolume;

struct ObservedStream {
    file: File,
    reads: usize,
    seeks: usize,
    short_reads: bool,
    fail_after_reads: Option<usize>,
}

impl Read for ObservedStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.fail_after_reads == Some(self.reads) {
            return Err(io::Error::other("injected scan read failure"));
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
        self.file.durable_read_at(bytes, offset)
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
        },
    )
}

#[test]
fn callback_rejection_never_repairs_or_overwrites_the_stream() {
    for hosted in [false, true] {
        let (_dir, mut stream) = stream(hosted);
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
fn media_read_errors_do_not_become_repairable_tail_damage() {
    for hosted in [false, true] {
        for (fail_after, payload_len, operation) in [
            (0, 1, "read durable frame header"),
            (1, 32_769, "read durable frame payload"),
        ] {
            let (_dir, mut stream) = stream(hosted);
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
        let (_dir, mut stream) = stream(hosted);
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
            let (_dir, mut stream) = stream(hosted);
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
            let (_dir, mut stream) = stream(hosted);
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
                |_, _| {
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
