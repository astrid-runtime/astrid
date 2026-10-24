use super::super::tests::entry;
use super::*;
use crate::engine::durable::locations::LocationLookup;
use std::collections::BTreeMap;

#[test]
fn bulk_rebuild_selects_newest_duplicates_and_counts_unique_proofs() {
    let mut rebuild = RebuildLocations::new(NonZeroUsize::new(16).unwrap());
    let mut expected = BTreeMap::new();
    for ordinal in (0..1000_u64).rev() {
        let (id, location) = entry(ordinal);
        rebuild.push(id, location, ClosureProof::Unknown).unwrap();
        expected.insert(id, location);
    }
    for ordinal in 0..500_u64 {
        let (id, mut location) = entry(ordinal);
        location.offset = location.offset.strict_add(7);
        rebuild.push(id, location, ClosureProof::Complete).unwrap();
        expected.insert(id, location);
    }
    let (mut locations, complete) = rebuild.finish().unwrap();
    assert_eq!(complete, 500);
    assert_eq!(locations.len(), 1000);
    assert!(locations.resident.is_empty());
    assert_eq!(locations.runs.iter().flatten().count(), 1);
    assert_eq!(
        locations
            .locations()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        expected.into_iter().collect::<Vec<_>>()
    );
    for ordinal in 0..1000 {
        assert_eq!(
            locations.closure_proven(entry(ordinal).0).unwrap(),
            ordinal < 500
        );
    }
    let (id, location) = entry(1000);
    locations.insert(id, location).unwrap();
    assert_eq!(locations.len(), 1001);
    assert_eq!(locations.location(id).unwrap(), Some(location));
}

#[test]
fn bulk_rebuild_rejects_corrupt_older_input_even_with_a_newer_duplicate() {
    let mut rebuild = RebuildLocations::new(NonZeroUsize::new(8).unwrap());
    for ordinal in 0..8 {
        let (id, location) = entry(ordinal);
        rebuild.push(id, location, ClosureProof::Unknown).unwrap();
    }
    rebuild.locations.truncate_test_run();
    let (id, location) = entry(0);
    rebuild.push(id, location, ClosureProof::Complete).unwrap();
    assert!(
        rebuild.finish().is_err(),
        "superseded input still requires authentication"
    );
}

#[test]
fn small_rebuild_stays_resident_without_a_scratch_file_and_counts_replacements_once() {
    let mut rebuild = RebuildLocations::new(NonZeroUsize::new(8).unwrap());
    let (id, mut location) = entry(1);
    for _ in 0..100 {
        location.offset = location.offset.strict_add(1);
        rebuild.push(id, location, ClosureProof::Complete).unwrap();
    }
    let (locations, complete) = rebuild.finish().unwrap();
    assert_eq!(locations.len(), 1);
    assert_eq!(complete, 1);
    assert_eq!(locations.resident.len(), 1);
    assert!(locations.runs.is_empty());
    assert_eq!(locations.location(id).unwrap(), Some(location));
}

#[test]
fn checked_rebuild_validates_every_discarded_duplicate_including_resident_and_final_merge() {
    use std::cell::RefCell;
    use std::rc::Rc;
    for limit in [1, 2, 8, 64] {
        let observed = Rc::new(RefCell::new(Vec::new()));
        let checks = Rc::clone(&observed);
        let mut rebuild = RebuildLocations::checked(
            NonZeroUsize::new(limit).unwrap(),
            move |id, newer, older| {
                checks.borrow_mut().push((id, newer.offset, older.offset));
                Ok(())
            },
        );
        let mut expected = BTreeMap::new();
        for round in 0..4 {
            for ordinal in (0..29).rev() {
                let (id, mut location) = entry(ordinal);
                location.offset = round * 1000 + ordinal;
                rebuild.push(id, location, ClosureProof::Unknown).unwrap();
                expected.insert(id, location);
            }
        }
        let (locations, _) = rebuild.finish().unwrap();
        assert_eq!(
            observed.borrow().len(),
            29 * 3,
            "each discarded duplicate is checked exactly once at limit {limit}"
        );
        assert!(
            observed
                .borrow()
                .iter()
                .all(|(_, newer, older)| newer > older)
        );
        assert_eq!(
            locations
                .locations()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            expected.into_iter().collect::<Vec<_>>()
        );
        assert!(
            locations.resident_capacity_bytes()
                <= limit * std::mem::size_of::<(ObjectId, LocatorValue)>()
        );
    }
}

#[test]
fn checked_rebuild_error_fences_resident_spill_and_final_merge() {
    for limit in [1, 2, 8, 64] {
        let mut rebuild =
            RebuildLocations::checked(NonZeroUsize::new(limit).unwrap(), |_, _, _| {
                Err(DurableError::InvalidRepresentationState("test collision"))
            });
        for ordinal in 0..29 {
            let (id, location) = entry(ordinal);
            rebuild.push(id, location, ClosureProof::Unknown).unwrap();
        }
        let (id, mut location) = entry(0);
        location.offset += 1000;
        if rebuild.push(id, location, ClosureProof::Unknown).is_err() {
            assert!(
                rebuild
                    .push(entry(99).0, entry(99).1, ClosureProof::Unknown)
                    .is_err()
            );
        }
        assert!(
            rebuild.finish().is_err(),
            "a failed collision check must never publish a locator"
        );
    }
}

#[test]
fn checked_bulk_admission_avoids_per_frame_negative_point_probes() {
    use crate::engine::durable::locations::run::test_take_page_auth_count;
    let mut rebuild = RebuildLocations::checked(NonZeroUsize::new(16).unwrap(), |_, _, _| {
        panic!("unique identities must not trigger duplicate-body reads")
    });
    let _ = test_take_page_auth_count();
    for ordinal in 0..2048_u64 {
        let (id, location) = entry(ordinal);
        rebuild.push(id, location, ClosureProof::Unknown).unwrap();
    }
    let (locations, _) = rebuild.finish().unwrap();
    let pages = test_take_page_auth_count();
    assert_eq!(locations.len(), 2048);
    assert!(
        pages < 2048 / 2,
        "sorted admission should read pages sequentially, authenticated {pages} pages"
    );
}
