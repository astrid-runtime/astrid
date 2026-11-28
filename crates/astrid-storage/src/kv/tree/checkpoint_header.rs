//! Shared fixed headers for persisted KV leaf and branch pages.
use super::{
    ObjectId, ObjectReference,
    checkpoint_branch::{DecodeError, Header},
    checkpoint_page::Branch,
    checkpoint_totals::NodeTotals,
    encoding,
};
use crate::storage_fields::{ReadError, fixed, take};
use vstd::prelude::*;

verus! {
pub(super) const LEAF_MAGIC:&[u8;24] = b"astrid-kv-bplus-leaf-v1\0";
pub(super) const BRANCH_MAGIC:&[u8;26] = b"astrid-kv-bplus-branch-v1\0";

#[derive(Clone,Copy)]
pub(super) enum Kind { Leaf, Branch }
#[derive(Clone,Copy)]
pub(super) enum Error { Field(ReadError), Magic }

impl Kind {
    pub(super) open spec fn tag(self) -> Seq<u8> {
        match self { Self::Leaf => LEAF_MAGIC@, Self::Branch => BRANCH_MAGIC@ }
    }
    fn magic(self) -> (out:&'static [u8])
        ensures out@ == self.tag(),
    {
        match self { Self::Leaf => LEAF_MAGIC.as_slice(), Self::Branch => BRANCH_MAGIC.as_slice() }
    }
}

pub(super) open spec fn word(n:u16) -> Seq<u8> {
    seq![(n & 255) as u8,(n >> 8) as u8]
}

fn append_word(bytes:&mut Vec<u8>,n:u16)
    ensures final(bytes)@ == old(bytes)@ + word(n),
{
    let field = [(n & 255) as u8,(n >> 8) as u8];
    assert(field@ =~= word(n));
    bytes.extend_from_slice(&field);
}

fn read_word(bytes:&[u8],cursor:&mut usize) -> (out:Result<u16,ReadError>)
    ensures out.is_ok() == (*old(cursor) as int + 2 <= bytes.len()),
        (out matches Err(ReadError::Overflow(_))) == (*old(cursor) as int+2 > usize::MAX),
        out matches Ok(n) ==> *final(cursor) as int == *old(cursor) as int + 2 &&
            crate::storage_fields::at(bytes@,*old(cursor) as int,word(n)),
{
    let [lo,hi] = fixed::<2>(bytes,cursor)?;
    let n = u16::from(lo) | (u16::from(hi) << 8);
    assert((n & 255) as u8 == lo && (n>>8) as u8 == hi) by (bit_vector)
        requires n == (lo as u16 | (hi as u16) << 8);
    assert(word(n) =~= bytes@.subrange(*old(cursor) as int,*cursor as int));
    Ok(n)
}

pub(super) open spec fn wire(kind:Kind,h:Header) -> Seq<u8> {
    kind.tag() + (if kind is Branch { word(h.level) } else { Seq::empty() }) +
        word(h.count as u16) + h.totals.wire()
}

pub(super) fn append(bytes:&mut Vec<u8>,kind:Kind,h:Header) -> (out:bool)
    ensures out == (h.count <= u16::MAX), out ==> final(bytes)@ == old(bytes)@ + wire(kind,h),
        !out ==> final(bytes)@ == old(bytes)@,
{
    let Ok(count) = u16::try_from(h.count) else {return false;};
    bytes.extend_from_slice(kind.magic());
    if let Kind::Branch = kind { append_word(bytes,h.level); }
    append_word(bytes,count);
    h.totals.append(bytes);
    assert(bytes@ =~= old(bytes)@ + wire(kind,h));
    true
}

pub(super) fn read(bytes:&[u8],kind:Kind) -> (out:Result<(usize,Header),Error>)
    ensures match out {
        Ok(pair) => present(bytes@,kind,pair.1,pair.0),
        Err(e) => prefix_error(bytes@,kind,e),
    },
{
    let mut cursor = 0usize;
    let magic = kind.magic();
    assert(magic.len() <= 32);
    let tag = match take(bytes,&mut cursor,magic.len()) { Ok(t) => t, Err(e) => return Err(Error::Field(e)) };
    if !matches!(encoding::bytewise_cmp(tag,magic),std::cmp::Ordering::Equal) {return Err(Error::Magic);}
    let level = match kind {
        Kind::Leaf => 0, Kind::Branch => match read_word(bytes,&mut cursor) {Ok(n)=>n,Err(e)=>return Err(Error::Field(e))},
    };
    let count = match read_word(bytes,&mut cursor) {Ok(n)=>n,Err(e)=>return Err(Error::Field(e))};
    let totals = match NodeTotals::read(bytes,&mut cursor) {Ok(t)=>t,Err(e)=>return Err(Error::Field(e))};
    let h = Header {level,count:usize::from(count),totals};
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(totals.wire().len() == 24);
        assert(bytes@.subrange(0,cursor as int) =~= wire(kind,h));
    }
    Ok((cursor,h))
}

pub(super) enum RecordError<E> { Prefix(Error), Body(DecodeError<E>) }

pub(super) open spec fn present(bytes:Seq<u8>,kind:Kind,h:Header,end:usize) -> bool {
    &&& h.count <= u16::MAX && (kind is Leaf ==> h.level == 0)
    &&& end == wire(kind,h).len() && crate::storage_fields::at(bytes,0,wire(kind,h))
}

pub(super) open spec fn prefix_error(bytes:Seq<u8>,kind:Kind,e:Error) -> bool {
    match e {
        Error::Magic => kind.tag().len() <= bytes.len() && bytes.take(kind.tag().len() as int) != kind.tag(),
        Error::Field(reason) => reason == ReadError::Truncated &&
            (bytes.len() < kind.tag().len() || crate::storage_fields::at(bytes,0,kind.tag())) &&
            bytes.len() < kind.tag().len() + (if kind is Branch {2int} else {0int}) + 26,
    }
}

pub(super) fn branch<E,F:Fn(&[u8])->Result<(),E>+Copy>(bytes:&[u8],refs:&[ObjectReference],validate:F)
    -> (out:Result<Branch<ObjectId,NodeTotals>,RecordError<E>>)
    requires forall|k:&[u8]| #[trigger] validate.requires((k,)),
    ensures match out {
        Err(RecordError::Prefix(e)) => prefix_error(bytes@,Kind::Branch,e),
        Err(RecordError::Body(e)) => exists|h:Header,s:usize| #[trigger] present(bytes@,Kind::Branch,h,s) &&
            h.outcome(bytes,refs,s,validate,Err(e)),
        Ok(b) => exists|h:Header,s:usize| #[trigger] present(bytes@,Kind::Branch,h,s) &&
            h.outcome(bytes,refs,s,validate,Ok(b)),
    },
{
    let (s,h) = match read(bytes,Kind::Branch) {Ok(pair)=>pair,Err(e)=>return Err(RecordError::Prefix(e))};
    assert(present(bytes@,Kind::Branch,h,s));
    match h.decode(bytes,refs,s,validate) {
        Ok(b) => Ok(b),
        Err(e) => Err(RecordError::Body(e)),
    }
}
}
