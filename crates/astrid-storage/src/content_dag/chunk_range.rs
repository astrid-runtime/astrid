//! Validate one immutable chunk and emit its requested file-offset interval.
use super::{ObjectClass, ObjectFormatVersion, ObjectKind, ObjectRecord};
use vstd::prelude::*;

verus! {
pub(super) struct Chunk<'a>(&'a [u8]);

pub(super) open spec fn valid(record: ObjectRecord, version: ObjectFormatVersion,
    length: u64, count: u64, depth: u32) -> bool {
    let r = record.contents();
    r.0 == ObjectKind::Chunk && r.1 == version.number() && r.5 == ObjectClass::Data
        && r.4 == 0 && r.3.len() == 0 && r.2.len() == length && count == 1 && depth == 0
}

impl<'a> Chunk<'a> {
    pub(super) closed spec fn payload(&self) -> Seq<u8> { self.0@ }

    pub(super) fn from_record(record: &'a ObjectRecord, version: ObjectFormatVersion,
        length: u64, count: u64, depth: u32) -> (out: Option<Self>)
        ensures out.is_some() == valid(*record,version,length,count,depth),
            out matches Some(c) ==> c.payload() == record.contents().2,
    {
        let bytes = record.canonical_bytes();
        if !matches!(record.kind(), ObjectKind::Chunk) || record.format_version().get() != version.get()
            || !matches!(record.class(), ObjectClass::Data) || record.logical_bytes() != 0
            || !record.references().is_empty() || bytes.len() as u64 != length
            || count != 1 || depth != 0 {
            return None;
        }
        Some(Self(bytes))
    }

    pub(super) fn bytes(&self) -> (out: &'a [u8])
        ensures out@ == self.payload(),
    { self.0 }
}

pub(super) enum RangeOutput<'a> { Buffer(&'a mut Vec<u8>), Count(usize) }

#[cfg(verus_keep_ghost)]
pub(super) ghost enum Output { Bytes(Seq<u8>), Count(nat) }

impl RangeOutput<'_> {
    pub(super) open spec fn snapshot(&self) -> Output {
        match self { Self::Buffer(buf) => Output::Bytes(buf@), Self::Count(n) => Output::Count(*n as nat) }
    }
}

pub(super) enum Error { Overflow, Outside }

pub(super) open spec fn begin(base:u64,start:u64) -> int {
    if start <= base { 0 } else { start - base }
}

pub(super) open spec fn limit(base:u64,end:u64,length:nat) -> int {
    if end <= base { 0 } else if end-base < length { end-base } else { length as int }
}

pub(super) open spec fn appended(before:Output,after:Output,s:Seq<u8>) -> bool {
    match (before,after) {
        (Output::Bytes(a),Output::Bytes(b)) => b == a+s,
        (Output::Count(a),Output::Count(b)) => b == a+s.len(),
        _ => false,
    }
}

pub(super) open spec fn count_fits(prior:Output,n:int) -> bool {
    match prior { Output::Count(k) => k+n <= usize::MAX, Output::Bytes(_) => true }
}

pub(super) fn emit(chunk: &Chunk, base:u64, start:u64, end:u64, output:&mut RangeOutput)
    -> (out:Result<usize,Error>)
    ensures ({
        let data = chunk.payload();
        let lo = begin(base,start);
        let hi = limit(base,end,data.len());
        &&& out.is_ok() == (base + data.len() <= u64::MAX && lo <= hi
            && count_fits(old(output).snapshot(),hi-lo))
        &&& match out {
            Ok(n) => base + data.len() <= u64::MAX && 0 <= lo <= hi <= data.len()
                && n == hi-lo && appended(old(output).snapshot(),final(output).snapshot(),data.subrange(lo,hi)),
            Err(_) => final(output).snapshot() == old(output).snapshot(),
        }
    }),
{
    let bytes = chunk.bytes();
    let length = u64::try_from(bytes.len()).map_err(|_| Error::Overflow)?;
    let extent = base.checked_add(length).ok_or(Error::Overflow)?;
    let lo = usize::try_from(start.saturating_sub(base)).map_err(|_| Error::Overflow)?;
    let hi = usize::try_from(end.min(extent).saturating_sub(base)).map_err(|_| Error::Overflow)?;
    if lo > hi || hi > bytes.len() { return Err(Error::Outside); }
    assert(lo == begin(base,start));
    assert(hi == limit(base,end,chunk.payload().len()));
    let selected = &bytes[lo..hi];
    let ghost prior = output.snapshot();
    match output {
        RangeOutput::Buffer(buffer) => {
            let ghost original = buffer@;
            assert(prior == Output::Bytes(original));
            buffer.extend_from_slice(selected);
            assert(buffer@ == original + selected@);
        },
        RangeOutput::Count(count) => {
            assert(prior == Output::Count(*count as nat));
            *count = count.checked_add(selected.len()).ok_or(Error::Overflow)?;
        }
    }
    assert(appended(prior, output.snapshot(),selected@));
    assert(selected@ =~= chunk.payload().subrange(lo as int,hi as int));
    Ok(selected.len())
}
}
