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

#[test]
fn live_semantic_comparison_does_not_retain_a_second_reverse_index() {
    use std::sync::atomic::AtomicBool;

    use crate::engine::durable::representations::recovery::{
        reset_retained_reverse_entries, retained_reverse_entries,
    };

    let (_directory, _volume, store, _limits) = super::super::adoption_tests::primed_volume();
    assert!(!store.reverse.is_empty());
    let tip = live_tip(&store);
    let canonical = tip.prove().unwrap();
    reset_retained_reverse_entries();
    tip.ensure_live_semantic_agreement(&canonical, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(
        retained_reverse_entries(),
        0,
        "semantic comparison must not retain a duplicate of the existing reverse index"
    );
}

fn live_tip(store: &RepresentationStore) -> LiveTipRefs<'_> {
    LiveTipRefs {
        profiles: &store.profiles,
        representations: &store.representations,
        placement_entries: &store.placement_entries,
        reverse: &store.reverse,
        catalogue: store.catalogue,
        placements: store.placements,
        state: store.state,
        active: store.active,
        direct_profile: store.direct_profile,
    }
}

#[test]
fn streamed_reverse_comparison_matches_owned_semantic_validation() {
    use std::sync::atomic::AtomicBool;

    use crate::engine::durable::representations::recovery::{
        reset_retained_reverse_entries, retained_reverse_entries, validate_representation_entries,
    };

    let (_directory, _volume, store, _limits) = super::super::adoption_tests::primed_volume();
    let canonical = live_tip(&store).prove().unwrap();
    reset_retained_reverse_entries();
    let owned = validate_representation_entries::<false, _>(
        store.profiles.as_canonical(),
        || Ok(canonical.entries[1].iter().copied()),
        canonical.entries[2].iter().copied(),
        store.direct_profile,
    )
    .unwrap();
    assert_eq!(owned.reverse, store.reverse);
    assert!(
        retained_reverse_entries() > 0,
        "recovery must still construct its independently validated reverse index"
    );
    let (&object, records) = owned.reverse.iter().next().unwrap();
    let id = records[0];
    let foreign_object = ObjectId::new([99; 32]);
    let foreign_id = RepresentationRecordId::new([99; 32]);
    assert!(!owned.reverse.contains_key(&foreign_object));
    assert_ne!(id, foreign_id);
    let mut cases = vec![owned.reverse.clone(), BTreeMap::new()];
    for replacement in [
        vec![],
        vec![id, id],
        vec![foreign_id],
        vec![id, foreign_id],
        vec![foreign_id, id],
    ] {
        let mut candidate = owned.reverse.clone();
        candidate.insert(object, smallvec::SmallVec::from_vec(replacement));
        cases.push(candidate);
    }
    let mut extra_empty = owned.reverse.clone();
    extra_empty.insert(foreign_object, smallvec::SmallVec::new());
    cases.push(extra_empty);
    let mut wrong_object = owned.reverse.clone();
    let moved = wrong_object.remove(&object).unwrap();
    wrong_object.insert(foreign_object, moved);
    cases.push(wrong_object);
    for reverse in cases {
        let tip = LiveTipRefs {
            reverse: &reverse,
            ..live_tip(&store)
        };
        assert_eq!(
            tip.ensure_live_semantic_agreement(&canonical, &AtomicBool::new(false))
                .is_ok(),
            reverse == owned.reverse,
            "streamed comparison changed owned equality for {reverse:?}"
        );
    }
}

#[test]
fn cancellation_precedes_a_streamed_reverse_mismatch() {
    use core::cell::Cell;

    struct CancelOnCheck {
        calls: Cell<usize>,
        at: usize,
    }
    impl CheckpointCancellation for CancelOnCheck {
        fn is_cancelled(&self) -> bool {
            let calls = self.calls.get().strict_add(1);
            self.calls.set(calls);
            calls >= self.at
        }
    }

    let (_directory, _volume, store, _limits) = super::super::adoption_tests::primed_volume();
    let canonical = live_tip(&store).prove().unwrap();
    let count_checks = CancelOnCheck {
        calls: Cell::new(0),
        at: usize::MAX,
    };
    live_tip(&store)
        .ensure_live_semantic_agreement(&canonical, &count_checks)
        .unwrap();
    let cancel = CancelOnCheck {
        calls: Cell::new(0),
        at: count_checks.calls.get(),
    };
    let empty = BTreeMap::new();
    let tip = LiveTipRefs {
        reverse: &empty,
        ..live_tip(&store)
    };
    let error = tip
        .ensure_live_semantic_agreement(&canonical, &cancel)
        .unwrap_err();
    assert!(is_checkpoint_cancelled(&error), "{error:?}");
}
