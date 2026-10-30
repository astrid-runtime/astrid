use super::*;

fn fields<W: EncodingSink>(encoder: &mut Encoder<W>) {
    encoder.u8(7);
    encoder.u16(1234);
    encoder.u32(56_789);
    encoder.u64(987_654_321);
    encoder.raw(&[1, 2, 3]);
    encoder.bytes(&[4, 5, 6]).unwrap();
    encoder.count(17).unwrap();
}

#[test]
fn comparison_matches_every_encoded_field_and_rejects_each_changed_byte() {
    let mut output = Encoder::new();
    fields(&mut output);
    let bytes = output.finish();
    let mut comparison = Encoder::comparing(&bytes);
    fields(&mut comparison);
    comparison.finish_comparison().unwrap();
    for offset in 0..bytes.len() {
        for bit in 0..8 {
            let mut changed = bytes.clone();
            changed[offset] ^= 1 << bit;
            let mut comparison = Encoder::comparing(&changed);
            fields(&mut comparison);
            assert_eq!(
                comparison.finish_comparison(),
                Err(PhysicalModelError::NonCanonicalEncoding)
            );
        }
        let mut comparison = Encoder::comparing(&bytes[..offset]);
        fields(&mut comparison);
        assert_eq!(
            comparison.finish_comparison(),
            Err(PhysicalModelError::NonCanonicalEncoding)
        );
    }
    let mut trailing = bytes;
    trailing.push(0);
    let mut comparison = Encoder::comparing(&trailing);
    fields(&mut comparison);
    assert_eq!(
        comparison.finish_comparison(),
        Err(PhysicalModelError::NonCanonicalEncoding)
    );
}

#[test]
fn comparison_handles_empty_fields_without_clearing_an_earlier_mismatch() {
    let mut empty = Encoder::comparing(&[]);
    empty.raw(&[]);
    empty.finish_comparison().unwrap();
    let mut mismatch = Encoder::comparing(&[1, 2]);
    mismatch.raw(&[0]);
    mismatch.raw(&[1, 2]);
    mismatch.raw(&[]);
    assert_eq!(
        mismatch.finish_comparison(),
        Err(PhysicalModelError::NonCanonicalEncoding)
    );
}

#[test]
fn reused_encoding_matches_owned_fields_and_clears_shorter_output() {
    let mut owned = Encoder::new();
    fields(&mut owned);
    let expected = owned.finish();
    let mut scratch = vec![0xff; 1_024];
    let original_pointer = scratch.as_ptr();
    let original_capacity = scratch.capacity();
    {
        let mut encoder = Encoder::reusing(&mut scratch);
        fields(&mut encoder);
    }
    assert_eq!(scratch, expected);
    assert_eq!(scratch.as_ptr(), original_pointer);
    assert_eq!(scratch.capacity(), original_capacity);
    Encoder::reusing(&mut scratch).bytes(&[]).unwrap();
    assert_eq!(scratch, 0_u64.to_le_bytes());
    // An empty next encoding must also discard the entire previous preimage.
    Encoder::reusing(&mut scratch);
    assert!(scratch.is_empty());
    assert_eq!(scratch.as_ptr(), original_pointer);
    assert_eq!(scratch.capacity(), original_capacity);
}
