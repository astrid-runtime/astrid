use super::super::tests::entry;
use super::super::{AuthenticatedPageMemo, LocationLookup, NonZeroUsize};
use super::*;

fn fixture() -> PagedLocations {
    let mut locations = PagedLocations::new(NonZeroUsize::new(8).unwrap());
    for index in 0..127 {
        let (id, location) = entry(index);
        locations.insert(id, location).unwrap();
    }
    assert!(locations.test_spilled_run_count() > 1);
    assert!(!locations.resident.is_empty());
    locations
}

#[test]
fn consolidation_keeps_latest_locations_proofs_absence_and_rebinds_memos() {
    let mut locations = fixture();
    for index in (0..127).step_by(2) {
        let (id, mut location) = entry(index);
        locations.mark_proven(id).unwrap();
        location.offset += 1;
        locations.insert(id, location).unwrap();
    }
    let expected = locations.rows().collect::<Result<Vec<_>, _>>().unwrap();
    let mut memo = AuthenticatedPageMemo::default();
    locations.location_memo(entry(0).0, &mut memo).unwrap();
    let epoch = locations.runs_epoch();
    locations.consolidate().unwrap();
    assert_ne!(locations.runs_epoch(), epoch);
    assert!(locations.resident.is_empty());
    assert_eq!(locations.test_spilled_run_count(), 1);
    assert_eq!(locations.len(), 127);
    assert_eq!(
        locations.rows().collect::<Result<Vec<_>, _>>().unwrap(),
        expected
    );
    for (id, row) in expected {
        assert_eq!(
            locations.location_memo(id, &mut memo).unwrap(),
            Some(row.location)
        );
        assert_eq!(
            locations.closure_proven_memo(id, &mut memo).unwrap(),
            row.proof == ClosureProof::Complete
        );
    }
    assert_eq!(
        locations.location_memo(entry(128).0, &mut memo).unwrap(),
        None
    );
    assert_eq!(memo.runs_epoch, locations.runs_epoch());
    for index in 127..256 {
        let (id, location) = entry(index);
        locations.insert_memo(id, location, &mut memo).unwrap();
    }
    locations.consolidate().unwrap();
    assert_eq!(locations.len(), 256);
    assert_eq!(
        locations
            .locations()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .len(),
        256
    );
    assert!(locations.closure_proven(entry(0).0).unwrap());
}

#[test]
fn failed_consolidation_preserves_input_owners_and_fences_instead_of_publishing() {
    let mut locations = fixture();
    let epoch = locations.runs_epoch();
    let count = locations.len();
    let resident = locations.resident.clone();
    let runs = locations.test_spilled_run_count();
    locations.truncate_test_run_without_epoch();
    assert!(locations.consolidate().is_err());
    assert!(locations.failed());
    assert_eq!(locations.runs_epoch(), epoch);
    assert_eq!(locations.len(), count);
    assert_eq!(locations.resident, resident);
    assert_eq!(locations.test_spilled_run_count(), runs);
    assert!(locations.consolidate().is_err());
}

#[test]
fn consolidation_checks_established_unique_count_before_publication() {
    let mut locations = fixture();
    locations.count += 1;
    let epoch = locations.runs_epoch();
    assert!(locations.consolidate().is_err());
    assert!(locations.failed());
    assert_eq!(locations.runs_epoch(), epoch);
    assert!(locations.test_spilled_run_count() > 1);
}
