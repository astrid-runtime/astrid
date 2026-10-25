use super::*;

pub(super) fn entry(index: u64) -> (ObjectId, ArenaLocation) {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&index.to_be_bytes());
    (
        ObjectId::new(bytes),
        ArenaLocation {
            offset: index.strict_mul(100),
            payload_len: 48,
            checksum: [5; 32],
        },
    )
}

#[test]
fn geometric_location_runs_bound_resident_rows_and_preserve_every_historical_location() {
    let limit = NonZeroUsize::new(32).unwrap();
    let mut paged = PagedLocations::new(limit);
    let mut expected = BTreeMap::new();
    for index in (0..10000_u64).rev() {
        let (id, location) = entry(index);
        paged.insert(id, location).unwrap();
        expected.insert(id, location);
        assert!(paged.resident.len() < limit.get());
        assert!(paged.runs.len() <= 16);
    }
    for (id, location) in &expected {
        assert_eq!(paged.location(*id).unwrap(), Some(*location));
    }
    assert_eq!(paged.location(entry(10000).0).unwrap(), None);
    for index in 0..256_u64 {
        let (id, mut location) = entry(index);
        location.offset = location.offset.strict_add(7);
        paged.insert(id, location).unwrap();
        expected.insert(id, location);
    }
    assert_eq!(paged.location_count(), expected.len());
    assert_eq!(
        paged.locations().collect::<Result<Vec<_>, _>>().unwrap(),
        expected.into_iter().collect::<Vec<_>>()
    );
    paged.clear();
    assert_eq!(paged.location_count(), 0);
    assert!(paged.locations().next().is_none());
}

#[test]
fn recovered_location_map_moves_into_anonymous_runs_without_a_second_full_map() {
    let map = (0..1000_u64).map(entry).collect::<BTreeMap<_, _>>();
    let expected = map.clone();
    let paged = PagedLocations::from_map(map, NonZeroUsize::new(16).unwrap()).unwrap();
    assert!(paged.resident.is_empty());
    assert_eq!(paged.runs.iter().flatten().count(), 1);
    assert_eq!(
        paged.runs.iter().flatten().next().unwrap().count,
        expected.len()
    );
    assert_eq!(
        paged.locations().collect::<Result<Vec<_>, _>>().unwrap(),
        expected.into_iter().collect::<Vec<_>>()
    );
}

#[test]
fn failed_geometric_merge_keeps_all_input_owners_and_rejects_the_prospective_update() {
    use std::io::{Read, Seek, SeekFrom, Write};

    let mut paged = PagedLocations::new(NonZeroUsize::new(2).unwrap());
    for index in 0..3 {
        let (id, location) = entry(index);
        paged.insert(id, location).unwrap();
    }
    let mut file = paged.runs[0]
        .as_ref()
        .unwrap()
        .test_file()
        .try_clone()
        .unwrap();
    let mut saved = Vec::new();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.read_to_end(&mut saved).unwrap();
    file.set_len(0).unwrap();
    let before_resident = paged.resident.clone();
    let (id, mut changed) = entry(2);
    changed.offset = 999;
    // The memtable answers this lookup, then the flush must authenticate the
    // older input. Failure cannot publish the newer value or drop that input.
    let (new_id, new_location) = entry(3);
    assert!(paged.insert(new_id, new_location).is_err());
    assert_eq!(paged.count, 3);
    assert_eq!(paged.resident, before_resident);
    assert!(paged.runs[0].is_some());
    assert!(paged.location(new_id).is_err());
    let mut entries = paged.locations();
    assert!(entries.next().unwrap().is_err());
    assert!(entries.next().is_none());
    drop(entries);

    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&saved).unwrap();
    assert_eq!(paged.location(new_id).unwrap(), None);
    assert_eq!(
        paged.locations().collect::<Result<Vec<_>, _>>().unwrap(),
        (0..3).map(entry).collect::<Vec<_>>()
    );
    paged.insert(id, changed).unwrap();
    paged.insert(new_id, new_location).unwrap();
    assert_eq!(paged.location_count(), 4);
    assert_eq!(paged.location(id).unwrap(), Some(changed));
    assert_eq!(paged.location(new_id).unwrap(), Some(new_location));
}

#[test]
fn repeated_location_replacements_do_not_accumulate_redundant_run_entries() {
    let mut paged = PagedLocations::new(NonZeroUsize::new(8).unwrap());
    let mut expected = BTreeMap::new();
    for generation in 0..100_u64 {
        for index in 0..32_u64 {
            let (id, mut location) = entry(index);
            location.offset = generation.strict_mul(10000).strict_add(index);
            paged.insert(id, location).unwrap();
            expected.insert(id, location);
            let physical = paged
                .runs
                .iter()
                .flatten()
                .map(|run| run.count)
                .sum::<usize>();
            assert!(physical <= paged.count.saturating_mul(2));
            assert!(paged.resident.capacity() <= paged.limit.get());
        }
    }
    assert_eq!(paged.location_count(), expected.len());
    assert_eq!(
        paged.locations().collect::<Result<Vec<_>, _>>().unwrap(),
        expected.into_iter().collect::<Vec<_>>()
    );
}

#[test]
fn proof_rows_survive_geometric_merges_without_another_history_sized_tree() {
    let limit = NonZeroUsize::new(32).unwrap();
    let mut paged = PagedLocations::new(limit);
    for index in 0..10000_u64 {
        let (id, location) = entry(index);
        paged.insert(id, location).unwrap();
        assert!(!paged.closure_proven(id).unwrap());
        if index % 2 == 0 {
            paged.mark_proven(id).unwrap();
        }
        assert!(
            paged.resident_capacity_bytes()
                <= limit
                    .get()
                    .strict_mul(std::mem::size_of::<(ObjectId, LocatorValue)>())
        );
        assert!(
            paged
                .runs
                .iter()
                .flatten()
                .map(|run| run.count)
                .sum::<usize>()
                <= paged.count.saturating_mul(2)
        );
    }
    for index in 0..10000 {
        let (id, mut location) = entry(index);
        assert_eq!(paged.closure_proven(id).unwrap(), index % 2 == 0);
        location.offset = location.offset.strict_add(1);
        paged.insert(id, location).unwrap();
        assert_eq!(paged.closure_proven(id).unwrap(), index % 2 == 0);
        assert_eq!(paged.location(id).unwrap(), Some(location));
    }
    assert!(!paged.closure_proven(entry(10000).0).unwrap());
    assert!(paged.mark_proven(entry(10000).0).is_err());
    assert_eq!(paged.len(), 10000);
}

#[test]
fn recovered_proofs_and_direct_spill_keep_the_same_locations_and_proof_membership() {
    let map = (0..256).map(entry).collect::<BTreeMap<_, _>>();
    let proven = (0..256)
        .filter(|index| index % 3 == 0)
        .map(|index| entry(index).0)
        .collect();
    for limit in [1, 1024] {
        let mut paged = PagedLocations::from_map_with_proofs(
            map.clone(),
            &proven,
            NonZeroUsize::new(limit).unwrap(),
        )
        .unwrap();
        paged.set_limit(NonZeroUsize::new(1).unwrap()).unwrap();
        assert_eq!(paged.resident_capacity_bytes(), 0);
        for index in 0..256 {
            assert_eq!(
                paged.closure_proven(entry(index).0).unwrap(),
                index % 3 == 0
            );
        }
        assert_eq!(
            paged
                .locations()
                .collect::<Result<BTreeMap<_, _>, _>>()
                .unwrap(),
            map
        );
        paged.truncate_test_run();
        assert!(paged.closure_proven(entry(0).0).is_err());
        assert!(paged.mark_proven(entry(0).0).is_err());
        assert!(paged.failed());
    }
}
