//! Known-size reference decoding and unchanged canonical frame validation.
use super::*;
use crate::engine::durable::tests::TEST_IDENTITY_SCHEME;

fn references(count: usize) -> Vec<ObjectReference> {
    (0..count)
        .map(|index| {
            ObjectReference::owns(
                ReferenceLabel::new(u64::try_from(index).unwrap().to_be_bytes().to_vec()),
                ObjectId::new([7; 32]),
            )
        })
        .collect()
}

fn reference_bytes(references: &[ObjectReference]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for reference in references {
        let label = reference.label().as_bytes();
        bytes.extend_from_slice(&u64::try_from(label.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(label);
        encode_identity(&mut bytes, TEST_IDENTITY_SCHEME, reference.target());
        bytes.push(reference.kind().code());
    }
    bytes
}

#[test]
fn known_reference_counts_do_not_retain_vector_growth_slack() {
    for count in [0, 1, 2, 3, 4, 5, 8, 16] {
        let expected = references(count);
        let bytes = reference_bytes(&expected);
        let mut reader = SliceReader::new(&bytes);
        let decoded = decode_references(&mut reader, TEST_IDENTITY_SCHEME, count).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.capacity(), count);
        assert_eq!(reader.remaining(), 0);
        let record = ObjectRecord::new(
            ObjectKind::Chunk,
            ObjectFormatVersion::V1,
            vec![3; 96],
            decoded,
            96,
            ObjectClass::Data,
        )
        .unwrap();
        let id = ObjectId::new([9; 32]);
        let frame = encode_object_frame(TEST_IDENTITY_SCHEME, id, &record).unwrap();
        let (actual_id, actual) = decode_object_frame(&frame, TEST_IDENTITY_SCHEME).unwrap();
        assert_eq!(actual_id, id);
        assert_eq!(actual, record);
        assert_eq!(
            encode_object_frame(TEST_IDENTITY_SCHEME, actual_id, &actual).unwrap(),
            frame
        );
    }
}

#[test]
fn reference_decoder_keeps_bounds_tags_and_canonical_order_checks() {
    let mut bytes = reference_bytes(&references(2));
    assert!(
        decode_references(
            &mut SliceReader::new(&bytes),
            TEST_IDENTITY_SCHEME,
            usize::MAX
        )
        .is_err()
    );
    bytes.pop();
    assert!(decode_references(&mut SliceReader::new(&bytes), TEST_IDENTITY_SCHEME, 2).is_err());
    let mut bytes = reference_bytes(&references(1));
    *bytes.last_mut().unwrap() = u8::MAX;
    assert!(decode_references(&mut SliceReader::new(&bytes), TEST_IDENTITY_SCHEME, 1).is_err());

    let mut expected = references(2);
    expected.reverse();
    let mut frame = encode_object_frame(
        TEST_IDENTITY_SCHEME,
        ObjectId::new([9; 32]),
        &ObjectRecord::new(
            ObjectKind::Chunk,
            ObjectFormatVersion::V1,
            vec![],
            references(2),
            0,
            ObjectClass::Data,
        )
        .unwrap(),
    )
    .unwrap();
    let suffix = reference_bytes(&expected);
    let offset = frame.len() - suffix.len();
    frame[offset..].copy_from_slice(&suffix);
    assert_eq!(
        decode_object_frame(&frame, TEST_IDENTITY_SCHEME),
        Err("non-canonical object references")
    );
    let mut frame = encode_object_frame(
        TEST_IDENTITY_SCHEME,
        ObjectId::new([9; 32]),
        &ObjectRecord::new(
            ObjectKind::Chunk,
            ObjectFormatVersion::V1,
            vec![],
            vec![],
            0,
            ObjectClass::Data,
        )
        .unwrap(),
    )
    .unwrap();
    frame.push(0);
    assert_eq!(
        decode_object_frame(&frame, TEST_IDENTITY_SCHEME),
        Err("trailing object-frame bytes")
    );
}

#[test]
fn canonical_labels_follow_byte_order_across_long_shared_prefixes() {
    let mut labels = vec![vec![], vec![0], vec![255]];
    for len in [1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 127] {
        for last in [0, 1, 127, 255] {
            let mut value = vec![0x61; len];
            value.push(last);
            labels.push(value);
        }
    }
    for left in &labels {
        for right in &labels {
            let target = ObjectId::new([3; 32]);
            let refs = vec![
                ObjectReference::owns(ReferenceLabel::new(left.clone()), target),
                ObjectReference::owns(ReferenceLabel::new(right.clone()), target),
            ];
            let record = ObjectRecord::new(
                ObjectKind::Directory,
                ObjectFormatVersion::V1,
                vec![],
                refs,
                0,
                ObjectClass::Metadata,
            );
            assert_eq!(record.is_ok(), left < right);
        }
    }
}

#[test]
fn pending_wal_keeps_the_confirmed_frame_and_record_together() {
    use crate::engine::durable::tests::TestIdentity;
    use crate::storage_model::ObjectIdentity;
    use std::sync::Arc;

    let record = ObjectRecord::new(
        ObjectKind::Commit,
        ObjectFormatVersion::V1,
        vec![7, 5],
        references(3),
        312,
        ObjectClass::Metadata,
    )
    .unwrap();
    let id = TestIdentity.identify(&record);
    let bytes: Arc<[u8]> = encode_object_frame(TEST_IDENTITY_SCHEME, id, &record)
        .unwrap()
        .into();
    let (name, retained, decoded) = pending_object_frame(&bytes, id, &TestIdentity).unwrap();
    assert!(Arc::ptr_eq(&bytes, &retained));
    assert_eq!(name, id);
    assert_eq!(*decoded, record);
    let wrong = ObjectId::new([3; 32]);
    assert!(matches!(
        pending_object_frame(&bytes, wrong, &TestIdentity),
        Err(DurableError::Corrupt {
            detail: "WAL overlay object identity mismatch",
            ..
        })
    ));
    let wrong_frame = encode_object_frame(TEST_IDENTITY_SCHEME, wrong, &record)
        .unwrap()
        .into();
    assert!(matches!(
        pending_object_frame(&wrong_frame, wrong, &TestIdentity),
        Err(DurableError::Corrupt {
            detail: "WAL overlay object identity mismatch",
            ..
        })
    ));
    let mut trailing = bytes.to_vec();
    trailing.push(1);
    assert!(matches!(
        pending_object_frame(&trailing.into(), id, &TestIdentity),
        Err(DurableError::Corrupt {
            detail: "trailing object-frame bytes",
            ..
        })
    ));
}
