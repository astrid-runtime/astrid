use super::*;
use std::collections::BTreeMap;
use std::num::NonZeroU64;

fn object(number: u64) -> ObjectId {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&number.to_be_bytes());
    ObjectId::new(bytes)
}
fn representation(number: u64) -> RepresentationRecordId {
    RepresentationRecordId::new(*object(number).as_bytes())
}
fn budget(rows: u64) -> LocationIndexMemoryBudget {
    LocationIndexMemoryBudget::new(
        NonZeroU64::new(LocationIndexMemoryBudget::MIN_BYTES.strict_mul(rows)).unwrap(),
    )
    .unwrap()
}

#[test]
fn ten_thousand_reverse_heads_preserve_all_ids_and_duplicates_with_bounded_residency() {
    let target = budget(128);
    let mut index = ReverseIndex::new(target).unwrap();
    let mut expected = BTreeMap::new();
    for number in 0..10000_u64 {
        index
            .insert(object(number), representation(number))
            .unwrap();
        expected.insert(object(number), vec![representation(number)]);
        assert!(index.resident_capacity_bytes() as u64 <= target.bytes().get() / 4);
    }
    for number in 0..512_u64 {
        let id = representation(number % 7);
        index.insert(object(0), id).unwrap();
        expected.get_mut(&object(0)).unwrap().push(id);
    }
    assert_eq!(index.len(), expected.len());
    assert_eq!(index.snapshot().unwrap(), expected);
    for (object, ids) in &expected {
        assert_eq!(index.first(*object).unwrap(), ids.first().copied());
    }
    assert_eq!(index.first(object(10001)).unwrap(), None);
    index.set_memory(budget(1)).unwrap();
    assert_eq!(index.resident_capacity_bytes(), 0);
    assert_eq!(index.snapshot().unwrap(), expected);
}

#[test]
fn reverse_chain_and_head_damage_are_errors_and_latch_recovery() {
    for head_damage in [false, true] {
        let mut index = ReverseIndex::new(budget(1)).unwrap();
        for number in 0..32 {
            index
                .insert(object(number), representation(number))
                .unwrap();
        }
        if head_damage {
            index.heads.truncate_test_run();
        } else {
            index.file.set_len(0).unwrap();
        }
        assert!(index.first(object(0)).is_err());
        assert!(index.failed());
        assert!(index.ids_newest_first(object(0)).is_err());
    }
}

#[test]
fn authenticated_wrong_object_and_forward_backlinks_are_rejected() {
    for wrong_object in [false, true] {
        let mut index = ReverseIndex::new(budget(1)).unwrap();
        index.insert(object(1), representation(1)).unwrap();
        if wrong_object {
            let location = index.heads.location(object(1)).unwrap().unwrap();
            index.heads.insert(object(2), location).unwrap();
        } else {
            let location = index.heads.location(object(1)).unwrap().unwrap();
            let mut link = index.link(object(1), location).unwrap();
            link.previous = Some(ArenaLocation {
                offset: u64::MAX - 1024,
                ..location
            });
            let location = append_frame(&mut index.file, MAGIC, &link.encode(object(2))).unwrap();
            index.heads.insert(object(2), location).unwrap();
        }
        assert!(index.first(object(2)).is_err());
        assert!(index.failed());
    }
}

#[test]
fn streamed_equivalence_checks_every_retained_id_and_order() {
    let mut first = ReverseIndex::new(budget(16)).unwrap();
    let mut second = ReverseIndex::new(budget(16)).unwrap();
    for number in [1, 2, 1] {
        first.insert(object(0), representation(number)).unwrap();
        second.insert(object(0), representation(number)).unwrap();
    }
    assert!(first.equivalent(&second).unwrap());
    second.insert(object(0), representation(1)).unwrap();
    assert!(!first.equivalent(&second).unwrap());
    first.insert(object(0), representation(1)).unwrap();
    assert!(first.equivalent(&second).unwrap());
    second.file.set_len(0).unwrap();
    assert!(first.equivalent(&second).is_err());
    assert!(second.failed());
}

#[test]
fn earliest_lookup_is_constant_but_full_enumeration_authenticates_old_links() {
    use std::io::{Seek, SeekFrom, Write};
    let mut index = ReverseIndex::new(budget(1)).unwrap();
    index.insert(object(7), representation(1)).unwrap();
    let old = index.heads.location(object(7)).unwrap().unwrap();
    for number in 2..64 {
        index.insert(object(7), representation(number)).unwrap();
    }
    // The newest frame carries authenticated earliest identity. A read need
    // not traverse later representations, as before this accelerator changed.
    index.file.seek(SeekFrom::Start(old.offset)).unwrap();
    index.file.write_all(&[0]).unwrap();
    assert_eq!(index.first(object(7)).unwrap(), Some(representation(1)));
    assert!(
        index
            .ids_newest_first(object(7))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .is_err()
    );
    assert!(index.failed());
}

#[test]
fn earliest_identity_is_authenticated_by_the_head_locator() {
    let mut index = ReverseIndex::new(budget(1)).unwrap();
    index.insert(object(3), representation(10)).unwrap();
    index.insert(object(3), representation(20)).unwrap();
    let original = index.heads.location(object(3)).unwrap().unwrap();
    let mut forged = index.link(object(3), original).unwrap();
    forged.first = representation(999);
    let replacement = append_frame(&mut index.file, MAGIC, &forged.encode(object(3))).unwrap();
    // This frame has a valid internal checksum but cannot replace the frame
    // authenticated by the existing head locator.
    index
        .heads
        .insert(
            object(3),
            ArenaLocation {
                checksum: original.checksum,
                ..replacement
            },
        )
        .unwrap();
    assert!(index.first(object(3)).is_err());
    assert!(index.failed());
}
