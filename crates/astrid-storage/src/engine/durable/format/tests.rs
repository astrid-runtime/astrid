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
