//! Address a single indexed frame inside a coalesced positional read.
use vstd::prelude::*;

verus! {

pub(super) const HEADER_BYTES: usize = 52;

/// Exact physical frame beginning at the absolute index offset. All arithmetic
/// is checked before taking the slice, including the physical header width.
pub(super) fn frame(span: &[u8], start: u64, offset: u64, payload_len: u64) -> (out: Option<&[u8]>)
    ensures out.is_some() == (start <= offset && payload_len as int + HEADER_BYTES <= u64::MAX &&
        offset as int - start + HEADER_BYTES + payload_len <= span.len()),
        out matches Some(bytes) ==> bytes@ == span@.subrange(offset as int - start,
            offset as int - start + HEADER_BYTES + payload_len),
{
    let relative = usize::try_from(offset.checked_sub(start)?).ok()?;
    let length = usize::try_from(payload_len.checked_add(HEADER_BYTES as u64)?).ok()?;
    let end = relative.checked_add(length)?;
    span.get(relative..end)
}

pub(super) enum Error {
    Truncated, Magic, Version, Reserved, Limit(u64), Length, Payload, Checksum,
}

pub(super) open spec fn declared(bytes: Seq<u8>) -> u64 {
    vstd::bytes::spec_u64_from_le_bytes(bytes.subrange(12,20))
}

/// Validate the physical envelope before handing the exact payload to both
/// the typed record decoder and the visitor.
pub(super) fn payload<H: FnOnce([u8;8],u64,&[u8])->[u8;32]>(
    bytes: &[u8], magic: [u8;8], version: u16, size: u64, checksum: [u8;32], limit: u64, hash: H,
) -> (out: Result<&[u8], Error>)
    requires forall|n:u64,p:&[u8]| #[trigger] hash.requires((magic,n,p)),
    ensures match out {
        Ok(p) => p@ == bytes@.skip(52) && bytes.len() == 52 + size as int &&
            size == declared(bytes@) && size <= limit && bytes@.take(8) == magic@ &&
            bytes@.subrange(8,10) == seq![version as u8,(version >> 8) as u8] &&
            bytes@[10] == 0 && bytes@[11] == 0 && bytes@.subrange(20,52) == checksum@ &&
            hash.ensures((magic,size,p),checksum),
        Err(Error::Truncated) => bytes.len() < 52,
        Err(Error::Magic) => bytes@.take(8) != magic@,
        Err(Error::Version) => bytes@.subrange(8,10) != seq![version as u8,(version >> 8) as u8],
        Err(Error::Reserved) => bytes@[10] != 0 || bytes@[11] != 0,
        Err(Error::Limit(n)) => n == declared(bytes@) && n > limit,
        Err(Error::Length) => size != declared(bytes@),
        Err(Error::Payload) => bytes.len() != 52 + size as int,
        Err(Error::Checksum) => bytes@.subrange(20,52) != checksum@ ||
            exists|p:&[u8],sum:[u8;32]| p@ == bytes@.skip(52) && sum != checksum && #[trigger] hash.ensures((magic,size,p),sum),
    },
{
    if bytes.len() < HEADER_BYTES {return Err(Error::Truncated);}
    assert(bytes@.take(8) =~= bytes@.subrange(0,8));
    if bytes[..8] != magic[..] {return Err(Error::Magic);}
    assert(((version & 255) as u8) == version as u8 && (version & 255) <= 255 && (version >> 8) <= 255) by(bit_vector);
    let v = [(version & 255) as u8,(version >> 8) as u8];
    if bytes[8..10] != v[..] {return Err(Error::Version);}
    if bytes[10] != 0 || bytes[11] != 0 {return Err(Error::Reserved);}
    let mut encoded = [0;8];
    encoded.copy_from_slice(&bytes[12..20]);
    let n = u64::from_le_bytes(encoded);
    if n > limit {return Err(Error::Limit(n));}
    if n != size {return Err(Error::Length);}
    let p = &bytes[HEADER_BYTES..];
    assert(p@ =~= bytes@.skip(52));
    if p.len() as u64 != size {return Err(Error::Payload);}
    let sum = hash(magic,size,p);
    if sum.as_slice() != &bytes[20..52] || sum.as_slice() != checksum.as_slice() {
        assert(bytes@.subrange(20,52) == checksum@ && sum == checksum ==> false);
        return Err(Error::Checksum);
    }
    assert(sum@ =~= checksum@);
    assert(sum == checksum);
    assert(bytes@.subrange(20,52) =~= checksum@);
    Ok(p)
}

pub(super) enum IndexedError<E> { Read(E), Placement }

/// Return the bytes from the read at this index offset only when the physical
/// envelope's size and validated checksum match the entry.
pub(super) fn at_location<E,F>(
    offset:u64, size:u64, checksum:[u8;32], read:F,
) -> (out:Result<Vec<u8>,IndexedError<E>>)
    where F:FnOnce(u64)->Result<(Vec<u8>,[u8;32]),E>,
    requires read.requires((offset,)),
    ensures match out {
        Ok(data) => data.len() == size && read.ensures((offset,),Ok((data,checksum))),
        Err(IndexedError::Read(e)) => read.ensures((offset,),Err(e)),
        Err(IndexedError::Placement) => exists|data:Vec<u8>,sum:[u8;32]| (data.len() != size || sum != checksum) &&
            #[trigger] read.ensures((offset,),Ok((data,sum))),
    },
{
    let (data,sum) = match read(offset) {
        Ok(frame) => frame,
        Err(error) => return Err(IndexedError::Read(error)),
    };
    if data.len() as u64 != size || sum.as_slice() != checksum.as_slice() {
        return Err(IndexedError::Placement);
    }
    assert(sum@ =~= checksum@);
    assert(sum == checksum);
    Ok(data)
}

}
