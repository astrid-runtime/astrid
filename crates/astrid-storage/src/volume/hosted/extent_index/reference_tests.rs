use super::*;

fn reference(offset: u64, sequence: u64, start: u64, end: u64, count: u64, level: u8) -> PageRef {
    PageRef::new(
        RecordOffset::new(offset).unwrap(),
        RecordSequence::new(sequence).unwrap(),
        [37; 32],
        ExtentRange::new(start, end).unwrap(),
        ExtentCount::new(count).unwrap(),
        PageLevel::new(level).unwrap(),
    )
    .unwrap()
}

#[test]
fn typed_boundaries_reject_invalid_wire_values() {
    for offset in [0, 1, 7] {
        assert_eq!(
            RecordOffset::new(offset).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    for offset in [8, u64::MAX] {
        assert_eq!(RecordOffset::new(offset).unwrap().get(), offset);
    }
    assert!(RecordSequence::new(0).is_err());
    assert!(ExtentCount::new(0).is_err());
    for value in [1, u64::MAX] {
        assert_eq!(RecordSequence::new(value).unwrap().get(), value);
        assert_eq!(ExtentCount::new(value).unwrap().get(), value);
    }
    for (start, end) in [(0, 0), (1, 0), (u64::MAX, u64::MAX)] {
        assert!(ExtentRange::new(start, end).is_err());
    }
    assert_eq!(ExtentRange::new(0, u64::MAX).unwrap().end(), u64::MAX);
    assert!(PageLevel::new(63).is_ok());
    for level in [64, 65, u8::MAX] {
        assert!(PageLevel::new(level).is_err());
    }
}

#[test]
fn reference_round_trips_without_a_total_extent_ceiling() {
    for expected in [
        reference(8, 1, 0, 1, 1, 0),
        reference(4096, 900, 0, 1_000_000, 700_000, 1),
        reference(u64::MAX, u64::MAX, 0, u64::MAX, 1_u64 << 63, 63),
    ] {
        assert_eq!(PageRef::decode(&expected.encode()).unwrap(), expected);
    }
}

#[test]
fn encoded_layout_is_canonical_and_contains_the_record_identity() {
    let expected = reference(8192, 19, 32, 400, 12, 2);
    let bytes = expected.encode();
    assert_eq!(&bytes[..8], &8192_u64.to_le_bytes());
    assert_eq!(&bytes[8..16], &19_u64.to_le_bytes());
    assert_eq!(&bytes[16..48], &[37; 32]);
    assert_eq!(&bytes[48..56], &32_u64.to_le_bytes());
    assert_eq!(&bytes[56..64], &400_u64.to_le_bytes());
    assert_eq!(&bytes[64..72], &12_u64.to_le_bytes());
    assert_eq!(bytes[72], 2);
    assert_eq!(&bytes[73..], &[0; 7]);
    assert_eq!(expected.offset().get(), 8192);
    assert_eq!(expected.sequence().get(), 19);
    assert_eq!(expected.checksum(), &[37; 32]);
    assert_eq!(expected.range().start(), 32);
    assert_eq!(expected.extent_count().get(), 12);
    assert_eq!(expected.level().get(), 2);
}

#[test]
fn decoder_rejects_every_truncation_extension_and_reserved_byte() {
    let encoded = reference(8, 1, 0, 10, 3, 0).encode();
    for length in 0..PAGE_REFERENCE_BYTES {
        assert!(
            PageRef::decode(&encoded[..length]).is_err(),
            "length={length}"
        );
    }
    let mut extended = encoded.to_vec();
    extended.push(0);
    assert!(PageRef::decode(&extended).is_err());
    for index in 73..PAGE_REFERENCE_BYTES {
        let mut corrupt = encoded;
        corrupt[index] = 1;
        assert!(PageRef::decode(&corrupt).is_err(), "reserved byte={index}");
    }
}

#[test]
fn decoder_rejects_impossible_counts_ranges_and_depth() {
    let encoded = reference(8, 1, 0, 10, 3, 0).encode();
    for (offset, value) in [(0, 7_u64), (8, 0), (48, 10), (56, 0), (64, 0), (64, 11)] {
        let mut corrupt = encoded;
        corrupt[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        assert!(
            PageRef::decode(&corrupt).is_err(),
            "offset={offset} value={value}"
        );
    }
    for level in [2, 63, 64, 255] {
        let mut corrupt = encoded;
        corrupt[72] = level;
        assert!(PageRef::decode(&corrupt).is_err(), "level={level}");
    }
}

#[test]
fn complete_child_record_must_precede_parent_in_both_offset_and_sequence() {
    let child = reference(100, 10, 0, 10, 1, 0);
    let end = 100_u64.strict_add(super::super::INDEX_PAGE_RECORD_BYTES);
    for (offset, sequence, accepted) in [
        (end, 11, true),
        (end.strict_sub(1), 11, false),
        (101, 11, false),
        (100, 11, false),
        (99, 11, false),
        (end, 10, false),
        (end, 9, false),
    ] {
        assert_eq!(
            child
                .require_before(
                    RecordOffset::new(offset).unwrap(),
                    RecordSequence::new(sequence).unwrap()
                )
                .is_ok(),
            accepted,
            "offset={offset} sequence={sequence}"
        );
    }
}

#[test]
fn child_range_depth_and_count_must_fit_the_parent() {
    let parent = reference(10000, 100, 10, 100, 8, 1);
    for (child, accepted) in [
        (reference(100, 10, 10, 50, 4, 0), true),
        (reference(100, 10, 9, 50, 4, 0), false),
        (reference(100, 10, 50, 101, 4, 0), false),
        (reference(100, 10, 10, 50, 8, 0), false),
        (reference(100, 10, 10, 50, 4, 1), false),
        (reference(10000, 10, 10, 50, 4, 0), false),
        (reference(100, 100, 10, 50, 4, 0), false),
    ] {
        assert_eq!(parent.require_child(child).is_ok(), accepted, "{child:?}");
    }
    assert!(
        reference(10000, 100, 0, 10, 4, 0)
            .require_child(reference(100, 10, 0, 2, 1, 0))
            .is_err()
    );
}

#[test]
fn overflowing_complete_record_cannot_precede_a_parent() {
    let child = reference(u64::MAX.strict_sub(1), 1, 0, 1, 1, 0);
    assert!(
        child
            .require_before(
                RecordOffset::new(u64::MAX).unwrap(),
                RecordSequence::new(2).unwrap()
            )
            .is_err()
    );
}
