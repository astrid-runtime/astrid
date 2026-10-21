use super::*;

fn seeded_extents() -> BTreeMap<u64, Extent> {
    (0_u64..4096)
        .map(|index| {
            let start = index.strict_mul(8);
            (
                start,
                Extent {
                    logical_end: start.strict_add(4),
                    physical_offset: start,
                },
            )
        })
        .collect()
}

fn reset_visits() {
    MUTATION_EXTENT_VISITS.with(|count| count.set(0));
}

fn visits() -> usize {
    MUTATION_EXTENT_VISITS.with(Cell::get)
}

#[test]
fn append_does_not_scan_existing_extents() {
    let mut extents = seeded_extents();
    reset_visits();
    overlay_extent(&mut extents, 32768, 32772, 90000);
    assert_eq!(visits(), 0);
    assert_eq!(extents.len(), 4097);
}

#[test]
fn overwrite_visits_only_the_crossing_predecessor_and_overlaps() {
    let mut extents = seeded_extents();
    reset_visits();
    overlay_extent(&mut extents, 16002, 16018, 90000);
    assert_eq!(visits(), 3);
    assert_eq!(extents.get(&16000).unwrap().logical_end, 16002);
    assert_eq!(extents.get(&16018).unwrap().physical_offset, 16018);
    assert_eq!(extents.get(&16018).unwrap().logical_end, 16020);
}

#[test]
fn truncate_visits_only_the_removed_suffix() {
    let mut extents = seeded_extents();
    reset_visits();
    truncate_extents(&mut extents, 32770);
    assert_eq!(visits(), 0);
    reset_visits();
    truncate_extents(&mut extents, 32761);
    assert_eq!(visits(), 1);
    assert_eq!(extents.get(&32760).unwrap().logical_end, 32761);
}

#[test]
fn extent_mutations_match_a_byte_address_oracle() {
    let mut extents = BTreeMap::new();
    let mut expected = [None; 256];
    let mut seed = 42_u64;
    for operation in 0_u64..2000 {
        // Wrapping arithmetic belongs to this deterministic test generator,
        // never to the logical offset or physical address calculations.
        let mut next = || {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            usize::try_from((seed >> 32).checked_rem(256).unwrap()).unwrap()
        };
        let start = next();
        let end = next().max(start);
        if operation.checked_rem(7).unwrap() == 0 {
            truncate_extents(&mut extents, u64::try_from(start).unwrap());
            expected[start..].fill(None);
        } else {
            let physical = operation.strict_mul(1024);
            overlay_extent(
                &mut extents,
                u64::try_from(start).unwrap(),
                u64::try_from(end).unwrap(),
                physical,
            );
            for (offset, byte) in expected[start..end].iter_mut().enumerate() {
                *byte = Some(physical.strict_add(u64::try_from(offset).unwrap()));
            }
        }
        let mut actual = [None; 256];
        for (start, extent) in &extents {
            let range =
                usize::try_from(*start).unwrap()..usize::try_from(extent.logical_end).unwrap();
            for (offset, byte) in actual[range].iter_mut().enumerate() {
                assert!(byte.is_none(), "extents overlap at operation {operation}");
                *byte = Some(
                    extent
                        .physical_offset
                        .strict_add(u64::try_from(offset).unwrap()),
                );
            }
        }
        assert_eq!(actual, expected, "operation {operation}");
    }
}
