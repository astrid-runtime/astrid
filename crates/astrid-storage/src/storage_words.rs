//! Little-endian fixed-width words used in persisted storage formats.
use vstd::prelude::*;

verus! {
pub(crate) fn little_endian(value: u64) -> (bytes: [u8;8])
    ensures bytes@ == vstd::bytes::spec_u64_to_le_bytes(value),
{
    proof { vstd::bytes::spec_u64_to_le_bytes_to_open(value); }
    let bytes = [
        (value & 255) as u8, ((value >> 8) & 255) as u8,
        ((value >> 16) & 255) as u8, ((value >> 24) & 255) as u8,
        ((value >> 32) & 255) as u8, ((value >> 40) & 255) as u8,
        ((value >> 48) & 255) as u8, ((value >> 56) & 255) as u8,
    ];
    assert(bytes@ =~= vstd::bytes::spec_u64_to_le_bytes_open(value));
    bytes
}

pub(crate) open spec fn word32(value: u32) -> Seq<u8> {
    seq![(value & 255) as u8, ((value >> 8) & 255) as u8,
        ((value >> 16) & 255) as u8, ((value >> 24) & 255) as u8]
}

pub(crate) fn read_u32(bytes: [u8; 4]) -> (value: u32)
    ensures word32(value) == bytes@,
{
    let [a,b,c,d] = bytes;
    let value = u32::from(a) | (u32::from(b) << 8) | (u32::from(c) << 16) | (u32::from(d) << 24);
    assert(word32(value) =~= bytes@) by {
        assert(value & 255 == a as u32 && (value >> 8) & 255 == b as u32
            && (value >> 16) & 255 == c as u32 && (value >> 24) & 255 == d as u32)
            by (bit_vector) requires value == (a as u32 | (b as u32) << 8 | (c as u32) << 16 | (d as u32) << 24);
    }
    value
}

pub(crate) proof fn unique_word32(a: u32, b: u32)
    requires word32(a) == word32(b),
    ensures a == b,
{
    assert(a == b) by (bit_vector)
        requires (a & 255) as u8 == (b & 255) as u8,
            ((a >> 8) & 255) as u8 == ((b >> 8) & 255) as u8,
            ((a >> 16) & 255) as u8 == ((b >> 16) & 255) as u8,
            ((a >> 24) & 255) as u8 == ((b >> 24) & 255) as u8;
}

pub(crate) fn little_endian_u32(value: u32) -> (bytes: [u8;4])
    ensures bytes@ == word32(value),
{
    let bytes = [
        (value & 255) as u8, ((value >> 8) & 255) as u8,
        ((value >> 16) & 255) as u8, ((value >> 24) & 255) as u8,
    ];
    assert(bytes@ =~= word32(value));
    bytes
}
}
