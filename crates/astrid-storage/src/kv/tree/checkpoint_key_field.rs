//! Length-prefixed physical keys in checkpoint leaves and branch fences.
use crate::storage_fields::{ReadError, fixed, take};
use vstd::prelude::*;

verus! {
pub(super) enum KeyError { Field(ReadError), Length }

pub(super) open spec fn length(bytes: Seq<u8>, start: int) -> u32 {
    (bytes[start] as u32) | ((bytes[start+1] as u32) << 8) |
        ((bytes[start+2] as u32) << 16) | ((bytes[start+3] as u32) << 24)
}

pub(super) proof fn encoded_length(bytes: Seq<u8>, start: int, value: u32)
    requires crate::storage_fields::at(bytes,start,crate::storage_words::word32(value)),
    ensures length(bytes,start) == value,
{
    let (a,b,c,d) = (bytes[start],bytes[start+1],bytes[start+2],bytes[start+3]);
    assert(value == ((a as u32) | ((b as u32) << 8) |
        ((c as u32) << 16) | ((d as u32) << 24))) by (bit_vector)
        requires a == (value & 255) as u8, b == ((value>>8)&255) as u8,
            c == ((value>>16)&255) as u8, d == ((value>>24)&255) as u8;
}

pub(super) fn read<'a>(bytes: &'a [u8], cursor: &mut usize) -> (out: Result<&'a [u8],KeyError>)
    ensures ({
        let start = *old(cursor) as int;
        let size = length(bytes@,start) as int;
        &&& out.is_ok() == (start + 4 <= bytes.len() && start + 4 + size <= bytes.len())
        &&& out matches Ok(key) ==> *final(cursor) as int == start + 4 + size &&
            key@ == bytes@.subrange(start+4,start+4+size)
    }),
{
    let prefix = match fixed::<4>(bytes,cursor) {
        Ok(field) => field, Err(e) => return Err(KeyError::Field(e)),
    };
    let value = crate::storage_words::read_u32(prefix);
    proof { encoded_length(bytes@,*old(cursor) as int,value); }
    let Ok(len) = usize::try_from(value) else { return Err(KeyError::Length); };
    match take(bytes,cursor,len) {
        Ok(field) => Ok(field), Err(e) => Err(KeyError::Field(e)),
    }
}

pub(super) fn append(bytes: &mut Vec<u8>, key: &[u8]) -> (wrote: bool)
    ensures wrote == (key.len() <= u32::MAX),
        wrote ==> final(bytes)@ == old(bytes)@ +
            crate::storage_words::word32(key.len() as u32) + key@,
        !wrote ==> final(bytes)@ == old(bytes)@,
{
    let Ok(len) = u32::try_from(key.len()) else { return false; };
    let prefix = crate::storage_words::little_endian_u32(len);
    bytes.extend_from_slice(&prefix);
    bytes.extend_from_slice(key);
    true
}
}
