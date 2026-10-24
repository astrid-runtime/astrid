use super::*;
use crate::engine::durable::locations::test_take_page_auth_count;
use std::collections::BTreeMap;
use std::num::NonZeroU64;
fn object(n: u64) -> ObjectId {
    ObjectId::new(*blake3::hash(&n.to_le_bytes()).as_bytes())
}
fn id(n: u64) -> RepresentationRecordId {
    RepresentationRecordId::new(*object(n).as_bytes())
}
fn budget(bytes: u64) -> LocationIndexMemoryBudget {
    LocationIndexMemoryBudget::new(NonZeroU64::new(bytes).unwrap()).unwrap()
}

#[test]
fn sorted_reverse_rebuild_preserves_all_links_first_ids_and_avoids_negative_probes() {
    let budget = budget(LocationIndexMemoryBudget::MIN_BYTES * 128);
    let mut expected = BTreeMap::<_, Vec<_>>::new();
    let mut baseline = ReverseIndex::new(budget).unwrap();
    test_take_page_auth_count();
    for n in 0..2048 {
        let object = object(n % 1024);
        baseline.insert(object, id(n)).unwrap();
        expected.entry(object).or_default().push(id(n));
    }
    let baseline_auth = test_take_page_auth_count();
    let mut rebuild = Rebuild::new(budget);
    for n in 0..2048 {
        rebuild.push(object(n % 1024), id(n)).unwrap();
        assert!(
            std::mem::size_of::<Row>() * rebuild.rows.capacity()
                <= usize::try_from(budget.bytes().get()).unwrap() / 4
        );
    }
    let mut selected = BTreeMap::new();
    let index = rebuild
        .finish(|object, id| {
            assert!(selected.insert(object, id).is_none());
            Ok(())
        })
        .unwrap();
    let bulk_auth = test_take_page_auth_count();
    assert!(
        bulk_auth < baseline_auth,
        "sorted={bulk_auth}, prior={baseline_auth}"
    );
    assert!(
        bulk_auth < expected.len(),
        "grouped publication must avoid one point probe per object: {bulk_auth}"
    );
    eprintln!("reverse reconstruction: grouped={bulk_auth}, point_insert={baseline_auth}");
    assert!(index.equivalent(&baseline).unwrap());
    assert_eq!(index.snapshot().unwrap(), expected);
    assert_eq!(
        selected,
        expected
            .iter()
            .map(|(object, ids)| (*object, ids[0]))
            .collect()
    );
}
#[test]
fn minimal_reverse_sort_budget_spills_without_allocating_a_row_vector() {
    let budget = budget(LocationIndexMemoryBudget::MIN_BYTES);
    let mut rebuild = Rebuild::new(budget);
    for n in 0..32 {
        rebuild.push(object(n % 8), id(n)).unwrap();
        assert_eq!(rebuild.rows.capacity(), 0);
    }
    let index = rebuild.finish(|_, _| Ok(())).unwrap();
    assert_eq!(index.len(), 8);
    for n in 0..8 {
        assert_eq!(index.first(object(n)).unwrap(), Some(id(n)));
    }
    let empty = Rebuild::new(budget)
        .finish(|_, _| panic!("empty callback"))
        .unwrap();
    assert_eq!(empty.len(), 0);
}
#[test]
fn failed_reverse_rebuild_cannot_publish_partial_rows() {
    let mut rebuild = Rebuild::new(budget(LocationIndexMemoryBudget::MIN_BYTES));
    rebuild.push(object(0), id(0)).unwrap();
    rebuild.ordinal = u64::MAX;
    assert!(rebuild.push(object(1), id(1)).is_err());
    assert!(rebuild.finish(|_, _| Ok(())).is_err());
    let mut rebuild = Rebuild::new(budget(LocationIndexMemoryBudget::MIN_BYTES));
    rebuild.push(object(0), id(0)).unwrap();
    assert!(
        rebuild
            .finish(|_, _| Err(DurableError::InvalidRepresentationState(
                "test callback failure"
            )))
            .is_err()
    );
}
