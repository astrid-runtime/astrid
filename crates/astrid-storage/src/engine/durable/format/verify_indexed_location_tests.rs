use std::cell::Cell;
use std::io::{Read, Seek, Write};

use super::*;
use crate::engine::durable::media::StoreMetadata;
use crate::volume::HostedFileVolume;

struct ObservedArena {
    file: File,
    positional_reads: Cell<usize>,
    sequential_reads: Cell<usize>,
    metadata_reads: Cell<usize>,
    seeks: Cell<usize>,
    max_read: usize,
}

impl Read for ObservedArena {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.sequential_reads
            .set(self.sequential_reads.get().strict_add(1));
        self.file.read(bytes)
    }
}

impl Write for ObservedArena {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.file.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for ObservedArena {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.seeks.set(self.seeks.get().strict_add(1));
        self.file.seek(position)
    }
}

impl DurableIo for ObservedArena {
    fn durable_metadata(&self) -> io::Result<StoreMetadata> {
        self.metadata_reads
            .set(self.metadata_reads.get().strict_add(1));
        self.file.durable_metadata()
    }

    fn durable_set_len(&self, length: u64) -> io::Result<()> {
        self.file.durable_set_len(length)
    }

    fn durable_sync_data(&self) -> io::Result<()> {
        self.file.durable_sync_data()
    }

    fn durable_read_at(&self, bytes: &mut [u8], offset: u64) -> io::Result<usize> {
        self.positional_reads
            .set(self.positional_reads.get().strict_add(1));
        let count = bytes.len().min(self.max_read);
        self.file.durable_read_at(&mut bytes[..count], offset)
    }
}

fn fixture(
    hosted: bool,
) -> (
    tempfile::TempDir,
    ObservedArena,
    ObjectId,
    ArenaLocation,
    u64,
) {
    let directory = tempfile::tempdir().unwrap();
    let mut file = if hosted {
        File::volume(
            HostedFileVolume::open(directory.path().join("astrid.volume")).unwrap(),
            "objects",
            true,
        )
        .unwrap()
    } else {
        File::native(tempfile::tempfile().unwrap())
    };
    let record = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"prefix verification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let id = ObjectId::new([7; 32]);
    let payload = encode_object_frame(IdentityScheme::new(1, 1).unwrap(), id, &record).unwrap();
    let location = append_frame(&mut file, ARENA_MAGIC, &payload).unwrap();
    let length = file.metadata().unwrap().len();
    file.seek(SeekFrom::Start(17)).unwrap();
    let observed = ObservedArena {
        file,
        positional_reads: Cell::new(0),
        sequential_reads: Cell::new(0),
        metadata_reads: Cell::new(0),
        seeks: Cell::new(0),
        max_read: usize::MAX,
    };
    (directory, observed, id, location, length)
}

fn verify(arena: &ObservedArena, id: ObjectId, location: ArenaLocation, length: u64) -> bool {
    verify_indexed_location(
        arena,
        id,
        location,
        IdentityScheme::new(1, 1).unwrap(),
        RecoveryLimits::process_addressable(),
        length,
    )
    .is_ok()
}

#[test]
fn index_prefix_uses_one_positional_read_without_metadata_or_cursor_io() {
    for hosted in [false, true] {
        let (_directory, mut arena, id, location, length) = fixture(hosted);
        assert!(verify(&arena, id, location, length));
        assert_eq!(arena.positional_reads.get(), 1);
        assert_eq!(arena.sequential_reads.get(), 0);
        assert_eq!(arena.metadata_reads.get(), 0);
        assert_eq!(arena.seeks.get(), 0);
        if hosted || cfg!(unix) {
            assert_eq!(arena.file.stream_position().unwrap(), 17);
        }
    }
}

#[test]
fn index_prefix_keeps_header_and_tagged_identity_authentication() {
    for hosted in [false, true] {
        for offset in [
            0,
            8,
            10,
            12,
            CHECKSUM_START,
            FRAME_HEADER_LEN_USIZE,
            FRAME_HEADER_LEN_USIZE + IDENTITY_PREFIX_BYTES,
        ] {
            let (_directory, mut arena, id, location, length) = fixture(hosted);
            let offset = u64::try_from(offset).unwrap();
            let mut byte = [0];
            arena.file.durable_read_at(&mut byte, offset).unwrap();
            byte[0] ^= 0xff;
            arena.file.seek(SeekFrom::Start(offset)).unwrap();
            arena.file.write_all(&byte).unwrap();
            assert!(
                !verify(&arena, id, location, length),
                "hosted={hosted} offset={offset}"
            );
        }
    }
}

#[test]
fn index_prefix_rejects_short_payload_and_out_of_bounds_without_reading() {
    for hosted in [false, true] {
        let (_directory, arena, id, location, length) = fixture(hosted);
        for invalid in [
            ArenaLocation {
                payload_len: 39,
                ..location
            },
            ArenaLocation {
                offset: u64::MAX,
                ..location
            },
            ArenaLocation {
                payload_len: length,
                ..location
            },
        ] {
            assert!(!verify(&arena, id, invalid, length));
        }
        assert!(!verify(&arena, id, location, length - 1));
        assert_eq!(arena.positional_reads.get(), 0);
    }
}

#[test]
fn index_prefix_does_not_complete_a_short_identity_from_the_next_frame() {
    for hosted in [false, true] {
        let (_directory, mut arena, id, _, _) = fixture(hosted);
        let mut payload = Vec::new();
        encode_identity(&mut payload, IdentityScheme::new(1, 1).unwrap(), id);
        let final_identity_byte = payload.pop().unwrap();
        arena.file.set_len(0).unwrap();
        let location = append_frame(&mut arena.file, ARENA_MAGIC, &payload).unwrap();
        // The next physical byte would complete the expected identity, but
        // it is outside this otherwise checksum-valid frame's payload.
        arena.file.write_all(&[final_identity_byte]).unwrap();
        let length = arena.file.metadata().unwrap().len();
        assert!(!verify(&arena, id, location, length));
        assert_eq!(arena.positional_reads.get(), 0);
    }
}

#[test]
fn index_prefix_handles_short_reads_and_rejects_truncation_or_wrong_identity() {
    for hosted in [false, true] {
        let (_directory, mut arena, id, location, length) = fixture(hosted);
        arena.max_read = 7;
        assert!(verify(&arena, id, location, length));
        assert!(arena.positional_reads.get() > 1);
        assert!(!verify(&arena, ObjectId::new([9; 32]), location, length));
        arena
            .file
            .set_len(u64::try_from(INDEXED_PREFIX_BYTES - 1).unwrap())
            .unwrap();
        assert!(!verify(&arena, id, location, length));
    }
}
