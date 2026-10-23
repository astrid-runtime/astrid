use super::super::tests::{TEST_IDENTITY_SCHEME, Utf8Codec};
use super::*;

#[test]
fn root_removal_codec_is_canonical_and_duplicate_removal_fails_closed() {
    let root = RootState {
        generation: RootGeneration::INITIAL,
        commit: ObjectId::new([7; 32]),
    };
    let bytes = encode_root_removal(TEST_IDENTITY_SCHEME, b"alice", root).unwrap();
    assert_eq!(&bytes[..8], &u64::MAX.to_le_bytes());
    assert_eq!(bytes[8], 2);
    let decoded = decode_root_journal_record(&bytes, TEST_IDENTITY_SCHEME).unwrap();
    let mut recovered = BTreeMap::from([("alice".to_owned(), (root, 0))]);
    apply_root_journal_record(
        &mut recovered,
        &Utf8Codec,
        TEST_IDENTITY_SCHEME,
        1,
        &bytes,
        decoded,
    )
    .unwrap();
    assert!(recovered.is_empty());
    let decoded = decode_root_journal_record(&bytes, TEST_IDENTITY_SCHEME).unwrap();
    assert!(
        apply_root_journal_record(
            &mut recovered,
            &Utf8Codec,
            TEST_IDENTITY_SCHEME,
            2,
            &bytes,
            decoded
        )
        .is_err()
    );
    for len in 0..bytes.len() {
        assert!(decode_root_journal_record(&bytes[..len], TEST_IDENTITY_SCHEME).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_root_journal_record(&trailing, TEST_IDENTITY_SCHEME).is_err());
    let mut unknown = bytes;
    unknown[8] = 3;
    assert!(decode_root_journal_record(&unknown, TEST_IDENTITY_SCHEME).is_err());
}

#[test]
fn root_removal_extension_preserves_existing_transition_and_snapshot_bytes() {
    let root = RootState {
        generation: RootGeneration::INITIAL,
        commit: ObjectId::new([9; 32]),
    };
    let transition = encode_root_record(TEST_IDENTITY_SCHEME, b"alice", None, root).unwrap();
    assert_eq!(&transition[..8], &5_u64.to_le_bytes());
    assert_eq!(&transition[8..13], b"alice");
    assert_eq!(transition[13], 0);
    let entries = vec![(b"alice".to_vec(), root)];
    let snapshot = encode_root_snapshot(TEST_IDENTITY_SCHEME, &entries).unwrap();
    assert_eq!(snapshot[8], 1);
    let decoded = decode_root_journal_record(&snapshot, TEST_IDENTITY_SCHEME).unwrap();
    let mut recovered = BTreeMap::new();
    apply_root_journal_record(
        &mut recovered,
        &Utf8Codec,
        TEST_IDENTITY_SCHEME,
        0,
        &snapshot,
        decoded,
    )
    .unwrap();
    assert_eq!(recovered["alice"].0, root);
}
