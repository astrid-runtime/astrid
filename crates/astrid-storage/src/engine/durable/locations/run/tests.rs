use super::*;
use std::io::{Seek, SeekFrom};

fn pair(index: u64) -> (ObjectId, ArenaLocation) {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&index.to_be_bytes());
    (
        ObjectId::new(bytes),
        ArenaLocation {
            offset: index.strict_mul(100),
            payload_len: 48,
            checksum: [3; 32],
        },
    )
}

fn build(count: u64) -> Run {
    let mut builder = Builder::new().unwrap();
    for index in 0..count {
        let (id, location) = pair(index.strict_mul(2));
        builder.push(id, location).unwrap();
        assert!(builder.leaf.len() < LEAF_CAPACITY);
        assert!(
            builder
                .levels
                .iter()
                .all(|level| level.len() < BRANCH_CAPACITY)
        );
    }
    builder.finish().unwrap().unwrap()
}

#[test]
fn anonymous_run_preserves_complete_ordered_lookup_with_bounded_build_workspace() {
    for count in [1, 51, 52, 2856, 2857, 10000] {
        let run = build(count);
        assert_eq!(run.count, usize::try_from(count).unwrap());
        for index in 0..count {
            let (id, expected) = pair(index.strict_mul(2));
            assert_eq!(run.lookup(id).unwrap(), Some(expected));
            assert_eq!(
                run.lookup(pair(index.strict_mul(2).strict_add(1)).0)
                    .unwrap(),
                None
            );
        }
        let expected = (0..count)
            .map(|index| pair(index.strict_mul(2)))
            .collect::<Vec<_>>();
        let actual = run.entries().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn anonymous_run_corruption_cannot_turn_present_or_absent_lookup_into_success() {
    for query in [0, 1] {
        let mut run = build(1);
        run.file
            .seek(SeekFrom::Start(HEADER_BYTES.try_into().unwrap()))
            .unwrap();
        run.file.write_all(&[0xff]).unwrap();
        assert!(matches!(
            run.lookup(pair(query).0),
            Err(DurableError::Corrupt { .. })
        ));
        let mut entries = run.entries();
        assert!(entries.next().unwrap().is_err());
        assert!(entries.next().is_none());
    }
}

#[test]
fn anonymous_run_truncation_is_an_error_and_duplicate_input_is_rejected() {
    let run = build(100);
    run.file.set_len(0).unwrap();
    assert!(run.lookup(pair(0).0).is_err());
    let mut builder = Builder::new().unwrap();
    let (id, location) = pair(0);
    builder.push(id, location).unwrap();
    assert!(builder.push(id, location).is_err());
    assert!(Builder::new().unwrap().finish().unwrap().is_none());
}

#[test]
fn checksummed_invalid_proof_states_and_padding_are_rejected() {
    use std::io::Read as _;
    for (offset, byte) in [(80, 2), (81, 1)] {
        let mut run = build(1);
        let mut bytes = [0; PAGE_BYTES];
        run.file.rewind().unwrap();
        run.file.read_exact(&mut bytes).unwrap();
        bytes[HEADER_BYTES + offset] = byte;
        run.file.rewind().unwrap();
        run.file.write_all(&bytes).unwrap();
        run.root.digest = digest(0, &bytes);
        assert!(matches!(
            run.lookup_row(pair(0).0),
            Err(DurableError::Corrupt { .. })
        ));
    }
}


#[test]
fn page_memo_reuses_authenticated_ancestors_within_one_operation() {
    let run = build(5_000);
    let _ = super::test_take_page_auth_count();
    let mut memo = PageMemo::default();
    for index in 0_u64..5_000 {
        let (id, expected) = pair(index.strict_mul(2));
        assert_eq!(
            run.lookup_row_memoized(id, &mut memo)
                .unwrap()
                .map(|row| row.location),
            Some(expected)
        );
    }
    let auth = super::test_take_page_auth_count();
    let hits = memo.test_hits();
    let misses = memo.test_misses();
    assert!(hits > 0, "shared ancestors must hit the memo: misses={misses}");
    assert_eq!(auth, misses, "each miss authenticates exactly once");
    // Uncached control: fresh memo every lookup forces re-auth of the path.
    let _ = super::test_take_page_auth_count();
    for index in 0_u64..5_000 {
        let id = pair(index.strict_mul(2)).0;
        let mut uncached = PageMemo::default();
        assert!(run.lookup_row_memoized(id, &mut uncached).unwrap().is_some());
    }
    let uncached_auth = super::test_take_page_auth_count();
    assert!(
        uncached_auth > auth.strict_mul(2),
        "forced-uncached control must re-authenticate ancestors: memoized={auth} uncached={uncached_auth}"
    );
}

#[test]
fn page_memo_rebinds_after_run_replacement_and_still_fails_closed_on_corruption() {
    let run = build(2_000);
    let mut memo = PageMemo::default();
    assert!(run.lookup_row_memoized(pair(0).0, &mut memo).unwrap().is_some());
    let replaced = build(2_000);
    // Binding keys the exact incarnation so a replaced run re-authenticates.
    assert!(
        replaced
            .lookup_row_memoized(pair(0).0, &mut memo)
            .unwrap()
            .is_some()
    );
    assert!(memo.test_misses() >= 2);

    let corrupt = build(64);
    let mut memo = PageMemo::default();
    assert!(corrupt.lookup_row_memoized(pair(0).0, &mut memo).unwrap().is_some());
    corrupt.test_file().set_len(0).unwrap();
    // Run files are immutable for the life of an operation memo. A new operation
    // must authenticate again and fail closed on the damaged accelerator.
    let mut fresh = PageMemo::default();
    assert!(matches!(
        corrupt.lookup_row_memoized(pair(0).0, &mut fresh),
        Err(DurableError::Corrupt { .. })
    ));
}


#[test]
fn page_memo_rejects_wrong_upper_even_when_offset_digest_warm() {
    let run = build(256);
    let mut memo = PageMemo::default();
    assert!(run.lookup_row_memoized(pair(0).0, &mut memo).unwrap().is_some());
    assert!(memo.test_hits() > 0 || memo.test_misses() > 0);

    // Same offset/digest/level as the authenticated root, forged upper bound.
    // Memo must not serve the warmed page; decode must fail closed like uncached.
    let mut forged = run.root;
    forged.upper = ObjectId::new([0xff; 32]);
    assert_ne!(forged.upper, run.root.upper);
    assert!(matches!(
        run.page_memoized(forged, &mut memo),
        Err(DurableError::Corrupt { .. })
    ));

    let mut fresh = PageMemo::default();
    assert!(matches!(
        run.page_memoized(forged, &mut fresh),
        Err(DurableError::Corrupt { .. })
    ));
}
