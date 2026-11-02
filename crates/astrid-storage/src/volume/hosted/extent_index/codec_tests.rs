use super::*;

fn leaf(count: usize) -> Page {
    Page::Leaf(
        (0..count)
            .map(|index| {
                IndexedExtent::new(
                    (index as u64).strict_mul(3),
                    (index as u64).strict_mul(3).strict_add(2),
                    8_u64.strict_add((index as u64).strict_mul(2)),
                )
                .unwrap()
            })
            .collect(),
    )
}

fn reference(page: &Page, offset: u64, sequence: u64) -> PageRef {
    page.reference(
        RecordOffset::new(offset).unwrap(),
        RecordSequence::new(sequence).unwrap(),
        [23; 32],
    )
    .unwrap()
}

#[test]
fn full_and_partial_leaves_round_trip_in_fixed_space() {
    for count in [1, 2, LEAF_CAPACITY - 1, LEAF_CAPACITY] {
        let page = leaf(count);
        let bytes = page.encode().unwrap();
        assert_eq!(bytes.len(), PAGE_BYTES);
        assert_eq!(Page::decode(&bytes).unwrap(), page);
        page.validate_reference(reference(&page, 8192, 10)).unwrap();
    }
    assert!(leaf(0).encode().is_err());
    assert!(leaf(LEAF_CAPACITY + 1).encode().is_err());
}

#[test]
fn branch_reference_binds_every_child_and_aggregate_summary() {
    let first = reference(&leaf(1), 8192, 1);
    let second_page = Page::Leaf(vec![IndexedExtent::new(10, 12, 100).unwrap()]);
    let second = reference(&second_page, 16384, 2);
    let page = Page::Branch(vec![first, second]);
    let descriptor = reference(&page, 24576, 3);
    assert_eq!(descriptor.extent_count().get(), 2);
    assert_eq!(descriptor.range(), ExtentRange::new(0, 12).unwrap());
    assert_eq!(descriptor.level().get(), 1);
    assert_eq!(Page::decode(&page.encode().unwrap()).unwrap(), page);
    assert!(
        page.reference(
            RecordOffset::new(2048).unwrap(),
            RecordSequence::new(3).unwrap(),
            [23; 32]
        )
        .is_err()
    );
    assert!(
        page.reference(
            RecordOffset::new(4096).unwrap(),
            RecordSequence::new(2).unwrap(),
            [23; 32]
        )
        .is_err()
    );
    assert!(Page::Branch(vec![first]).encode().is_err());
    assert!(Page::Branch(vec![second, first]).encode().is_err());
}

#[test]
fn rejects_truncations_padding_reserved_fields_and_impossible_counts() {
    let valid = leaf(1).encode().unwrap();
    for length in 0..PAGE_BYTES {
        assert!(Page::decode(&valid[..length]).is_err());
    }
    let mut extended = valid.to_vec();
    extended.push(0);
    assert!(Page::decode(&extended).is_err());
    for index in [0, 8, 9, 10, 11, 14, 15, 40, PAGE_BYTES - 1] {
        let mut corrupt = valid;
        corrupt[index] = 255;
        assert!(Page::decode(&corrupt).is_err(), "byte={index}");
    }
    for count in [0, LEAF_CAPACITY + 1, u16::MAX as usize] {
        let mut corrupt = valid;
        corrupt[12..14].copy_from_slice(&u16::try_from(count).unwrap().to_le_bytes());
        assert!(Page::decode(&corrupt).is_err());
    }
}

#[test]
fn physical_aliases_are_allowed_but_overflow_and_forward_data_are_not() {
    let first = IndexedExtent::new(0, 2, 100).unwrap();
    let second = IndexedExtent::new(10, 12, 100).unwrap();
    let page = Page::Leaf(vec![first, second]);
    assert_eq!(first.physical().get(), second.physical().get());
    assert_eq!(second.range().start(), 10);
    assert!(
        page.reference(
            RecordOffset::new(102).unwrap(),
            RecordSequence::new(1).unwrap(),
            [0; 32]
        )
        .is_ok()
    );
    assert!(
        page.reference(
            RecordOffset::new(101).unwrap(),
            RecordSequence::new(1).unwrap(),
            [0; 32]
        )
        .is_err()
    );
    for (start, end, physical) in [(0, 0, 8), (2, 1, 8), (0, 1, 7), (0, 2, u64::MAX)] {
        assert!(IndexedExtent::new(start, end, physical).is_err());
    }
}

#[test]
fn rejects_overlapping_extents_and_forged_reference_summaries() {
    let page = Page::Leaf(vec![
        IndexedExtent::new(0, 5, 8).unwrap(),
        IndexedExtent::new(4, 6, 13).unwrap(),
    ]);
    assert!(page.encode().is_err());
    let page = leaf(2);
    let expected = reference(&page, 8192, 10);
    let forged = PageRef::new(
        expected.offset(),
        expected.sequence(),
        *expected.checksum(),
        ExtentRange::new(0, 10).unwrap(),
        expected.extent_count(),
        expected.level(),
    )
    .unwrap();
    assert!(page.validate_reference(forged).is_err());
}
