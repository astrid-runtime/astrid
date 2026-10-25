use super::*;
use std::io::{Seek, SeekFrom, Write};

fn location(offset: u64) -> ArenaLocation {
    ArenaLocation {
        offset,
        payload_len: 8,
        checksum: [7; 32],
    }
}
fn fixture() -> (RecoveredDirect, BTreeMap<ObjectId, ArenaLocation>) {
    let mut builder = Builder::new().unwrap();
    let first = ObjectId::new([1; 32]);
    builder.group(first, 2).unwrap();
    builder.location(location(1)).unwrap();
    builder.location(location(2)).unwrap();
    let second = ObjectId::new([2; 32]);
    builder.group(second, 1).unwrap();
    builder.location(location(3)).unwrap();
    (
        builder.finish().unwrap(),
        BTreeMap::from([(first, location(2)), (second, location(3))]),
    )
}

#[test]
fn accepts_matching_alternate_replica_and_rejects_cross_object_borrowing() {
    let (stream, index) = fixture();
    assert_eq!(stream.protected_len(), 3 + FRAME_HEADER_LEN + 8);
    stream.validate(&index).unwrap();
    let (stream, mut index) = fixture();
    index.insert(ObjectId::new([1; 32]), location(3));
    assert!(stream.validate(&index).is_err());
    let (stream, mut index) = fixture();
    index.remove(&ObjectId::new([2; 32]));
    assert!(stream.validate(&index).is_err());
}

#[test]
fn digest_rejects_well_formed_substitution_even_when_index_matches_forgery() {
    let (mut stream, mut index) = fixture();
    stream.file.seek(SeekFrom::Start(40)).unwrap();
    stream.file.write_all(&9_u64.to_le_bytes()).unwrap();
    index.insert(ObjectId::new([1; 32]), location(9));
    stream.file.seek(SeekFrom::Start(0)).unwrap();
    assert!(stream.validate(&index).is_err());
}

#[test]
fn truncated_and_extended_streams_fail_closed() {
    let (stream, index) = fixture();
    stream.file.set_len(stream.bytes - 1).unwrap();
    assert!(stream.validate(&index).is_err());
    let (mut stream, index) = fixture();
    stream.file.seek(SeekFrom::End(0)).unwrap();
    stream.file.write_all(b"junk").unwrap();
    stream.file.seek(SeekFrom::Start(0)).unwrap();
    assert!(stream.validate(&index).is_err());
}

#[test]
fn count_overflow_and_empty_groups_cannot_bypass_validation() {
    let (mut stream, index) = fixture();
    stream.file.seek(SeekFrom::Start(32)).unwrap();
    stream.file.write_all(&u64::MAX.to_le_bytes()).unwrap();
    stream.file.seek(SeekFrom::Start(0)).unwrap();
    assert!(stream.validate(&index).is_err());
    let mut builder = Builder::new().unwrap();
    assert!(builder.location(location(u64::MAX)).is_err());
    let mut builder = Builder::new().unwrap();
    builder.group(ObjectId::new([1; 32]), 0).unwrap();
    assert!(
        builder
            .finish()
            .unwrap()
            .validate(&BTreeMap::new())
            .is_err()
    );
}

#[test]
fn ten_thousand_groups_use_only_streaming_buffers_and_release_the_file() {
    let mut builder = Builder::new().unwrap();
    let mut index = BTreeMap::new();
    for ordinal in 0_u64..10_000 {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&ordinal.to_le_bytes());
        let object = ObjectId::new(bytes);
        builder.group(object, 1).unwrap();
        builder.location(location(ordinal)).unwrap();
        index.insert(object, location(ordinal));
    }
    let stream = builder.finish().unwrap();
    assert_eq!(stream.bytes, 10_000 * 88);
    assert_eq!(stream.groups, 10_000);
    assert_eq!(stream.protected_len(), 9_999 + FRAME_HEADER_LEN + 8);
    stream.validate(&index).unwrap();
    Builder::new()
        .unwrap()
        .finish()
        .unwrap()
        .validate(&BTreeMap::new())
        .unwrap();
}
