//! Length-prefixed LZ4 envelope for stored WAL object bodies.
use vstd::prelude::*;

verus! {

pub(super) const PREFIX:usize=8;

/// Return the allocation size only when the complete compressed envelope wins.
pub(super) fn allocation(canonical:usize,compressed:usize) -> (out:Result<Option<usize>,()>)
    ensures match out {
        Err(())=>compressed as int+PREFIX>usize::MAX,
        Ok(None)=>canonical<=compressed as int+PREFIX<=usize::MAX,
        Ok(Some(n))=>n==compressed as int+PREFIX && n<canonical,
    },
{
    let size=PREFIX.checked_add(compressed).ok_or(())?;
    Ok(if size<canonical {Some(size)} else {None})
}

/// The caller reserves the fallible allocation before writing either part.
pub(super) fn pack(stored:&mut Vec<u8>,length:u64,block:&[u8])
    requires old(stored).len()==0,block.len() as int+PREFIX<=usize::MAX,
    ensures final(stored)@==vstd::bytes::spec_u64_to_le_bytes(length)+block@,
{
    stored.extend_from_slice(&crate::storage_words::little_endian(length));
    stored.extend_from_slice(block);
}

/// Split the declared canonical size from the exact bytes passed to LZ4.
pub(super) fn split(body:&[u8]) -> (out:Option<(u64,&[u8])>)
    ensures out.is_some()==(body.len()>=PREFIX),
        out matches Some((n,block)) ==> n==vstd::bytes::spec_u64_from_le_bytes(body@.take(8)) &&
            block@==body@.skip(8),
{
    if body.len()<PREFIX {return None;}
    let mut word=[0u8;8];
    word.copy_from_slice(&body[..PREFIX]);
    Some((u64::from_le_bytes(word),&body[PREFIX..]))
}

}
