use super::*;

#[test]
fn consumed_canonical_tip_keeps_exact_visit_union_and_live_entry_borrows() {
    let (_directory, _volume, store, _limits) = super::super::adoption_tests::primed_volume();
    let maps = [
        store.profiles.as_canonical(),
        store.representations.as_canonical(),
        store.placement_entries.as_canonical(),
    ];
    let roots = [
        store.profiles.prove_root().unwrap(),
        store.representations.prove_root().unwrap(),
        store.placement_entries.prove_root().unwrap(),
    ];
    let expected_reachable: BTreeSet<_> = roots
        .iter()
        .flat_map(|proof| proof.visited().iter().copied())
        .collect();
    let expected_entries = roots.each_ref().map(|proof| proof.entries().to_vec());
    let canonical = CanonicalTip::from_root_proofs(roots);
    assert_eq!(canonical.reachable, expected_reachable);
    assert_eq!(canonical.entries, expected_entries);
    for (entries, map) in canonical.entries.iter().zip(maps) {
        for (key, value) in entries {
            assert!(core::ptr::eq(*value, map.get(*key).unwrap()));
        }
    }
}
