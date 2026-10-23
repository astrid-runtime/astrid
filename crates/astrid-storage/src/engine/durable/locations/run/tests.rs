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
