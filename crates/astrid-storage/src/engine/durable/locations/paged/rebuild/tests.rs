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
