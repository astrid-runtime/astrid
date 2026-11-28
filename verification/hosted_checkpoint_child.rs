//! Connect the checked field encoders and the actual indexed owning edge to a decoded child.
use crate::{ObjectId,ObjectReference,checkpoint_child::{self,ChildError},checkpoint_key_field as key,
    checkpoint_reference as edge,checkpoint_totals::NodeTotals,storage_fields::at,storage_words::word32};
use vstd::prelude::*;

verus! {

fn read_written(bytes: &mut Vec<u8>, fence: &[u8], totals: NodeTotals, suffix: &[u8],
    refs: &mut Vec<ObjectReference>, id:ObjectId) -> (out: Result<(Vec<u8>,ObjectId,NodeTotals),ChildError<()>>)
    requires totals.entries > 0, old(refs).len() <= u16::MAX, fence.len() <= u32::MAX,
        old(bytes).len() as int + 4 + fence.len() + 24 + suffix.len() <= usize::MAX,
    ensures out matches Ok(row) && row.0@ == fence@ && row.1 == id && row.2 == totals,
{
    let mut cursor = bytes.len();
    let ghost start = cursor as int;
    let index = refs.len();
    key::append(bytes,fence);
    totals.append(bytes);
    bytes.extend_from_slice(suffix);
    let label = edge::label(edge::Relation::Child,index).unwrap();
    refs.push(ObjectReference::owns(label,id));
    let ghost pos = start+4+fence.len();
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(bytes@.subrange(start,start+4) =~= word32(fence.len() as u32));
        key::encoded_length(bytes@,start,fence.len() as u32);
        assert(bytes@.subrange(start+4,pos) =~= fence@);
        assert(bytes@.subrange(pos,pos+24) =~= totals.wire());
    }
    let accept = |_:&[u8]| -> (r:Result<(),()>) ensures r is Ok { Ok(()) };
    let out = checkpoint_child::read(bytes,&mut cursor,refs,index,accept);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        if let Err(ChildError::Empty) = out {
            let empty = choose|t:NodeTotals| t.entries == 0 && at(bytes@,pos,#[trigger] t.wire());
            crate::hosted_checkpoint_totals::same(empty,totals);
        }
        if out is Ok {
            assert(cursor as int == pos+24);
            crate::hosted_checkpoint_totals::same(out->Ok_0.2,totals);
        }
    }
    out
}

fn refused(bytes:&[u8],start:usize,refs:&[ObjectReference],index:usize) -> (rejected:bool)
    ensures rejected,
{
    let mut cursor = start;
    let deny = |_:&[u8]| -> (r:Result<(),()>) ensures r is Err { Err(()) };
    checkpoint_child::read(bytes,&mut cursor,refs,index,deny).is_err()
}

fn refused_complete(bytes:&[u8],start:usize,refs:&[ObjectReference],index:usize)
    -> (out:(usize,Result<(Vec<u8>,ObjectId,NodeTotals),ChildError<()>>))
    requires start as int + 4 + key::length(bytes@,start as int) <= bytes.len(),
    ensures out.0 as int == start as int + 4 + key::length(bytes@,start as int),
        out.1 matches Err(ChildError::InvalidKey(_)),
{
    let mut cursor = start;
    let deny = |_:&[u8]| -> (r:Result<(),()>) ensures r is Err { Err(()) };
    let out = checkpoint_child::read(bytes,&mut cursor,refs,index,deny);
    (cursor,out)
}

fn short_child_totals(bytes:&[u8],start:usize,refs:&[ObjectReference],index:usize)
    -> (out:(usize,Result<(Vec<u8>,ObjectId,NodeTotals),ChildError<()>>))
    requires ({
        let pos = start as int + 4 + key::length(bytes@,start as int);
        pos <= bytes.len() && pos+24 > bytes.len()
    }),
    ensures ({
        let pos = start as int + 4 + key::length(bytes@,start as int);
        let last = if pos+8 > bytes.len() { pos } else if pos+16 > bytes.len() { pos+8 } else { pos+16 };
        &&& out.0 as int == last
        &&& out.1 == Err(ChildError::Totals(if last+8 > usize::MAX { crate::storage_fields::ReadError::Overflow(8) }
            else { crate::storage_fields::ReadError::Truncated }))
    }),
{
    let mut cursor = start;
    let accept = |_:&[u8]| -> (r:Result<(),()>) ensures r is Ok { Ok(()) };
    let out = checkpoint_child::read(bytes,&mut cursor,refs,index,accept);
    proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }
    (cursor,out)
}

fn short_child_key(bytes:&[u8],start:usize,refs:&[ObjectReference],index:usize)
    -> (out:(usize,Result<(Vec<u8>,ObjectId,NodeTotals),ChildError<()>>))
    requires start as int+4 > bytes.len() || start as int+4+key::length(bytes@,start as int) > bytes.len(),
    ensures out.1 matches Err(ChildError::Key(e)) && key::failure(bytes@,start as int,out.0 as int,e),
{
    let mut cursor = start;
    let accept = |_:&[u8]| -> (r:Result<(),()>) ensures r is Ok { Ok(()) };
    let out = checkpoint_child::read(bytes,&mut cursor,refs,index,accept);
    proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }
    (cursor,out)
}
}
