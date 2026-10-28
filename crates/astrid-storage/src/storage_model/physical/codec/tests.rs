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
