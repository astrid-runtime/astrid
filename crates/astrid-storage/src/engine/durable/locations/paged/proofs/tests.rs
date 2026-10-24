use super::super::tests::entry;
use super::super::{AuthenticatedPageMemo, LocationLookup};
use super::*;

#[test]
fn proof_rewrite_preserves_latest_rows_and_replaces_every_flag() {
    for limit in [1, 8, 256] {
        for count in [0, 1, 7, 127] {
            let limit = NonZeroUsize::new(limit).unwrap();
            let mut source = PagedLocations::new(limit);
            for index in (0..count).rev() {
                let (id, location) = entry(index);
                source.insert(id, location).unwrap();
                source.mark_proven(id).unwrap();
            }
            for index in (0..count).step_by(3) {
                let (id, mut location) = entry(index);
                location.offset += 7;
                source.insert(id, location).unwrap();
            }
            let before = source.rows().collect::<Result<Vec<_>, _>>().unwrap();
            let (mut rewritten, complete) = source
                .rebuild_proofs(limit, |id| {
                    if id.as_bytes()[7] % 2 == 0 {
                        ClosureProof::Complete
                    } else {
                        ClosureProof::Unknown
                    }
                })
                .unwrap();
            assert_eq!(complete, usize::try_from(count.div_ceil(2)).unwrap());
            assert_eq!(rewritten.len(), usize::try_from(count).unwrap());
            assert!(rewritten.resident.capacity() <= limit.get());
            let after = rewritten.rows().collect::<Result<Vec<_>, _>>().unwrap();
            for ((id, old), (new_id, new)) in before.iter().zip(&after) {
                assert_eq!(id, new_id);
                assert_eq!(old.location, new.location);
                assert_eq!(
                    new.proof == ClosureProof::Complete,
                    id.as_bytes()[7] % 2 == 0
                );
            }
            assert_eq!(
                source.rows().collect::<Result<Vec<_>, _>>().unwrap(),
                before
            );
            let (id, location) = entry(count);
            rewritten.insert(id, location).unwrap();
            assert_eq!(rewritten.location(id).unwrap(), Some(location));
            assert_eq!(rewritten.len(), usize::try_from(count).unwrap() + 1);
            assert!(!rewritten.closure_proven(id).unwrap());
        }
    }
}

#[test]
fn proof_reset_rebinds_memos_and_does_not_reuse_authenticated_pages() {
    let mut source = PagedLocations::new(NonZeroUsize::new(8).unwrap());
    for index in 0..127 {
        let (id, location) = entry(index);
        source.insert(id, location).unwrap();
        source.mark_proven(id).unwrap();
    }
    let mut memo = AuthenticatedPageMemo::default();
    assert!(source.closure_proven_memo(entry(0).0, &mut memo).unwrap());
    let epoch = source.runs_epoch();
    source.clear_proofs().unwrap();
    assert_ne!(source.runs_epoch(), epoch);
    assert!(!source.closure_proven_memo(entry(0).0, &mut memo).unwrap());
    assert_eq!(memo.runs_epoch, source.runs_epoch());
    source.truncate_test_run_without_epoch();
    let epoch = source.runs_epoch();
    let runs = source.test_spilled_run_count();
    assert!(source.clear_proofs().is_err());
    assert!(source.failed());
    assert_eq!(source.runs_epoch(), epoch);
    assert_eq!(source.test_spilled_run_count(), runs);
    assert_eq!(source.len(), 127);
    assert!(
        source
            .rebuild_proofs(source.limit, |_| ClosureProof::Complete)
            .is_err()
    );
}

#[test]
fn proof_rewrite_checks_count_before_releasing_original_owners() {
    for count in [3, 127] {
        let mut source = PagedLocations::new(NonZeroUsize::new(8).unwrap());
        for index in 0..count {
            let (id, location) = entry(index);
            source.insert(id, location).unwrap();
        }
        source.count += 1;
        let resident = source.resident.clone();
        let runs = source.test_spilled_run_count();
        let epoch = source.runs_epoch();
        assert!(source.clear_proofs().is_err());
        assert!(source.failed());
        assert_eq!(source.resident, resident);
        assert_eq!(source.test_spilled_run_count(), runs);
        assert_eq!(source.runs_epoch(), epoch);
        assert_eq!(source.count, usize::try_from(count).unwrap() + 1);
    }
}
