use super::*;
use crate::engine::durable::ArenaLocation;
use std::num::NonZeroUsize;

fn id(n: u64) -> ObjectId {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&n.to_be_bytes());
    ObjectId::new(bytes)
}
fn table(values: impl IntoIterator<Item = u64>) -> PagedLocations {
    PagedLocations::from_map(
        values
            .into_iter()
            .map(|n| {
                (
                    id(n),
                    ArenaLocation {
                        offset: n,
                        payload_len: 1,
                        checksum: [0; 32],
                    },
                )
            })
            .collect(),
        NonZeroUsize::new(2).unwrap(),
    )
    .unwrap()
}

#[test]
fn missing_reference_does_not_hide_later_admitted_run_damage() {
    let source = table(1..130);
    let references = table([0]);
    assert!(!references_present(&source, &references).unwrap());
    source.corrupt_test_run_page_without_epoch(4096);
    assert!(references_present(&source, &references).is_err());
}

#[test]
fn missing_reference_does_not_hide_later_reference_run_damage() {
    let source = table([]);
    let references = table(0..130);
    assert!(!references_present(&source, &references).unwrap());
    references.corrupt_test_run_page_without_epoch(4096);
    assert!(references_present(&source, &references).is_err());
}

#[test]
fn reference_join_compares_full_identity_and_authenticates_both_streams() {
    let source = table(1..130);
    assert!(references_present(&source, &table(1..130)).unwrap());
    assert!(!references_present(&source, &table([0, 1, 2, 129, 130])).unwrap());
}
