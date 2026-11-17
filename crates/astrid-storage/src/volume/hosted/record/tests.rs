//! Frozen ASTREG1 header vector shared by slice and streamed records.

use super::super::Operation;
use super::{RECORD_CHECKSUM_OFFSET, encode_record_fixed_header};

#[test]
fn encode_record_fixed_header_matches_frozen_field_vector() {
    let checksum =
        hex::decode("00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210").unwrap();
    let checksum: [u8; 32] = checksum.try_into().unwrap();
    let expected = hex::decode("41535452454731005600000000000000efcdab89674523010204008070605040302010070000000000000000112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210").unwrap();
    let encoded = encode_record_fixed_header(
        86,
        0x0123_4567_89ab_cdef_u64,
        Operation::Write,
        4,
        0x1020_3040_5060_7080_u64,
        7,
        &checksum,
    );
    assert_eq!(encoded.as_slice(), expected);
    assert_eq!(RECORD_CHECKSUM_OFFSET, 43);
    assert_eq!(&encoded[43..], checksum);
}
