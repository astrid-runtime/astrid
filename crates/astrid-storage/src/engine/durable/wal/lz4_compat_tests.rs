use super::codec::{
    OBJECT_FLAG_LZ4, decode_object_storage_body, digest_record, digest_record_with_flags,
    encode_begin_body, encode_commit_body, encode_object_storage_body, encode_physical_record,
    encode_physical_record_with_flags, finish_digest, logical_record_length, new_digest,
};
use super::tests::{object_id, record, root, scan_events, scheme};
use super::types::{WalCount, WalEvent, WalOffset, WalOrdinal, WalRecordKind, WalSequence};
use crate::engine::durable::RecoveryLimits;
use crate::engine::durable::format::encode_object_frame;
use crate::engine::durable::roots::encode_root_record;

// Produced by lz4_flex 0.12.2 for `record(1, 4096)` and the storage crate's
// canonical ASTWAL2 object-frame construction.
const LZ4_FLEX_0_12_STORED_BODY: [u8; 66] = [
    69, 16, 0, 0, 0, 0, 0, 0, 101, 1, 0, 1, 0, 32, 0, 1, 0, 21, 1, 10, 0, 13, 2, 0, 0, 27, 0, 19,
    16, 22, 0, 4, 8, 0, 10, 2, 0, 0, 34, 0, 15, 2, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 235, 96, 0, 0, 0, 0, 0, 0,
];

#[test]
fn lz4_flex_zero_twelve_wal_bytes_decode_with_zero_fourteen() {
    let canonical = encode_object_frame(scheme(), object_id(1), &record(1, 4096)).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let decoded = decode_object_storage_body(
        &LZ4_FLEX_0_12_STORED_BODY,
        OBJECT_FLAG_LZ4,
        limits,
        WalOffset::new(0),
    )
    .unwrap();
    assert_eq!(decoded.as_ref(), canonical.as_slice());

    let (flags, current) = encode_object_storage_body(&canonical).unwrap();
    assert_eq!(flags, OBJECT_FLAG_LZ4);
    let current_decoded =
        decode_object_storage_body(current.as_ref(), flags, limits, WalOffset::new(0)).unwrap();
    assert_eq!(current_decoded.as_ref(), canonical.as_slice());

    let events = scan_events(compressed_transaction()).unwrap();
    assert_eq!(events.len(), 4);
    assert!(matches!(events.first(), Some(WalEvent::Begin(_))));
    assert!(matches!(
        events.get(1),
        Some(WalEvent::Object(object))
            if object.logical_bytes.get() == u64::try_from(canonical.len()).unwrap(),
    ));
    assert!(matches!(events.get(2), Some(WalEvent::Root(_))));
    assert!(matches!(events.get(3), Some(WalEvent::Commit(_))));
}

fn compressed_transaction() -> Vec<u8> {
    let sequence = WalSequence::new(1).unwrap();
    let stored = &LZ4_FLEX_0_12_STORED_BODY;
    let begin_body = encode_begin_body(scheme(), None).unwrap();
    let root_body = encode_root_record(scheme(), b"alice", None, root(100)).unwrap();
    let mut digest = new_digest();
    let mut logical_bytes = logical_record_length(&begin_body).unwrap();
    digest_record(
        &mut digest,
        WalRecordKind::Begin,
        sequence,
        WalOrdinal::new(0),
        &begin_body,
    )
    .unwrap();
    let mut bytes = encode_physical_record(
        WalRecordKind::Begin,
        sequence,
        WalOrdinal::new(0),
        &begin_body,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    digest_record_with_flags(
        &mut digest,
        WalRecordKind::Object,
        OBJECT_FLAG_LZ4,
        sequence,
        WalOrdinal::new(1),
        stored,
    )
    .unwrap();
    logical_bytes = logical_bytes
        .checked_add(logical_record_length(stored).unwrap())
        .unwrap();
    bytes.extend(
        encode_physical_record_with_flags(
            WalRecordKind::Object,
            OBJECT_FLAG_LZ4,
            sequence,
            WalOrdinal::new(1),
            stored,
            RecoveryLimits::process_addressable(),
        )
        .unwrap(),
    );
    digest_record(
        &mut digest,
        WalRecordKind::Root,
        sequence,
        WalOrdinal::new(2),
        &root_body,
    )
    .unwrap();
    logical_bytes = logical_bytes
        .checked_add(logical_record_length(&root_body).unwrap())
        .unwrap();
    bytes.extend(
        encode_physical_record(
            WalRecordKind::Root,
            sequence,
            WalOrdinal::new(2),
            &root_body,
            RecoveryLimits::process_addressable(),
        )
        .unwrap(),
    );
    let commit_body = encode_commit_body(
        sequence,
        WalCount::new(3),
        WalCount::new(1),
        WalCount::new(1),
        logical_bytes,
        finish_digest(&digest),
    );
    bytes.extend(
        encode_physical_record(
            WalRecordKind::Commit,
            sequence,
            WalOrdinal::new(3),
            &commit_body,
            RecoveryLimits::process_addressable(),
        )
        .unwrap(),
    );
    bytes
}
