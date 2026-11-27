//! Position-labelled owning edges in persistent KV leaf and branch pages.
use super::{ObjectId, ObjectReference, ReferenceLabel, encoding};
use vstd::prelude::*;

verus! {

pub(super) const CHILD:[u8;6] = [b'c',b'h',b'i',b'l',b'd',b'/'];
pub(super) const VALUE:[u8;6] = [b'v',b'a',b'l',b'u',b'e',b'/'];

#[derive(Clone,Copy)]
pub(super) enum Relation { Child, Value }

impl Relation {
    pub(super) open spec fn tag(&self) -> Seq<u8> {
        match self {
            Self::Child => CHILD@,
            Self::Value => VALUE@,
        }
    }
    fn prefix(self) -> (out:&'static [u8])
        ensures out@ == self.tag(),
    {
        let prefix:&[u8;6] = match self { Self::Child => &CHILD, Self::Value => &VALUE };
        assert(prefix@ =~= self.tag());
        prefix.as_slice()
    }
}

pub(super) open spec fn wire(rel:Relation,slot:usize) -> Seq<u8> {
    rel.tag() + seq![(slot/256) as u8,(slot%256) as u8]
}

fn suffix(slot:usize) -> (out:Option<[u8;2]>)
    ensures out.is_some() == (slot <= u16::MAX), out matches Some(bytes) ==>
        bytes@ == seq![(slot/256) as u8,(slot%256) as u8],
{
    let high = u8::try_from(slot/256).ok()?;
    let low = u8::try_from(slot%256).ok()?;
    let bytes = [high,low];
    assert(bytes@ =~= seq![(slot/256) as u8,(slot%256) as u8]);
    Some(bytes)
}

pub(super) fn label(rel:Relation,slot:usize) -> (out:Option<ReferenceLabel>)
    ensures out.is_some() == (slot <= u16::MAX), out matches Some(l) ==> l.value()@ == wire(rel,slot),
{
    let bytes = suffix(slot)?;
    let prefix = rel.prefix();
    let mut encoded = Vec::with_capacity(prefix.len().saturating_add(bytes.len()));
    encoded.extend_from_slice(prefix);
    encoded.extend_from_slice(&bytes);
    Some(ReferenceLabel::new(encoded))
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) enum Rejection { Missing, IndexOverflow, Mismatch }

pub(super) fn target(refs:&[ObjectReference],position:usize,rel:Relation,slot:usize)
    -> (out:Result<ObjectId,Rejection>)
    ensures out == if position >= refs.len() { Err(Rejection::Missing) }
        else if slot > u16::MAX { Err(Rejection::IndexOverflow) }
        else {
            let fields = refs@[position as int].fields();
            if fields.0 == wire(rel,slot) && fields.2 is Owns { Ok(fields.1) } else { Err(Rejection::Mismatch) }
        },
{
    let Some(edge) = refs.get(position) else { return Err(Rejection::Missing); };
    let Some(bytes) = suffix(slot) else { return Err(Rejection::IndexOverflow); };
    let prefix = rel.prefix();
    let actual = edge.label_bytes();
    if actual.len() != prefix.len().saturating_add(bytes.len()) { return Err(Rejection::Mismatch); }
    let (tag,index) = actual.split_at(prefix.len());
    if !matches!(encoding::bytewise_cmp(tag,prefix),std::cmp::Ordering::Equal) ||
        !matches!(encoding::bytewise_cmp(index,&bytes),std::cmp::Ordering::Equal) {
        assert(actual@ != wire(rel,slot)) by {
            if actual@ == wire(rel,slot) {
                assert(tag@ =~= prefix@); assert(index@ =~= bytes@);
            }
        }
        return Err(Rejection::Mismatch);
    }
    assert(actual@ =~= wire(rel,slot));
    edge.owning_target().ok_or(Rejection::Mismatch)
}
}
