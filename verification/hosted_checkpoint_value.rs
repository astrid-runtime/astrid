//! Round trip the native leaf value field with independently varying physical and logical indices.
use crate::{ObjectReference,checkpoint_value::{self as value,ValueSlot,Error},checkpoint_reference as edge};
use vstd::prelude::*;

verus! {

fn roundtrip(bytes:&mut Vec<u8>,refs:&mut Vec<ObjectReference>,v:ValueSlot,slot:usize,tail:&[u8])
    -> (out:Result<ValueSlot,Error>)
    requires old(bytes).len()+value::wire(v).len()+tail.len() <= usize::MAX,
        match v {ValueSlot::Inline(d) => d.len() <= 1024,
            ValueSlot::Spilled {length,..} => length > 1024 && slot <= u16::MAX && old(refs).len() < usize::MAX},
    ensures (match v {
            ValueSlot::Inline(data) => out matches Ok(ValueSlot::Inline(got)) && got@ == data@,
            ValueSlot::Spilled {object,length} => out == Ok(ValueSlot::Spilled {object,length}),
        }), final(bytes)@ == old(bytes)@ + value::wire(v) + tail@,
        match v {ValueSlot::Inline(_) => final(refs)@ == old(refs)@,
            ValueSlot::Spilled {object,..} => final(refs)@.drop_last() == old(refs)@ &&
                final(refs)@.last().fields() == (edge::wire(edge::Relation::Value,slot),object,crate::ReferenceKind::Owns)},
{
    let mut cursor = bytes.len();
    let mut reference = refs.len();
    let ghost start = cursor as int;
    let wrote = value::append(bytes,refs,slot,&v);
    assert(wrote is Ok);
    bytes.extend_from_slice(tail);
    let out = value::read(bytes,&mut cursor,refs,&mut reference,slot);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        match &v {
            ValueSlot::Inline(data) => {
                assert(bytes@.subrange(start,start+8) =~= vstd::bytes::spec_u64_to_le_bytes(data.len() as u64));
                assert(bytes@[start+8] == 0);
                assert(bytes@.subrange(start+9,start+9+data.len()) =~= data@);
                assert(out is Ok);
                assert(out matches Ok(ValueSlot::Inline(got)) && got@ == data@);
                assert(reference == old(refs).len());
                assert(cursor as int == start+9+data.len());
            },
            ValueSlot::Spilled {object,length} => {
                assert(bytes@.subrange(start,start+8) =~= vstd::bytes::spec_u64_to_le_bytes(*length));
                assert(bytes@[start+8] == 1);
                assert(refs@[old(refs).len() as int] == refs@.last());
                assert(out is Ok);
                assert(out == Ok(ValueSlot::Spilled {object:*object,length:*length}));
                assert(reference as int == old(refs).len()+1);
                assert(cursor as int == start+9);
            },
        }
    }
    out
}

fn invalid_tag(bytes:&[u8],refs:&[ObjectReference],start:usize,first:usize,slot:usize)
    -> (out:(usize,usize,Result<ValueSlot,Error>))
    requires start as int+9 <= bytes.len(), bytes@[start as int+8] != 0, bytes@[start as int+8] != 1,
    ensures out.0 as int == start as int+9 && out.1 == first && out.2 == Err(Error::Tag),
{
    let mut cursor = start;
    let mut pos = first;
    let out = value::read(bytes,&mut cursor,refs,&mut pos,slot);
    (cursor,pos,out)
}

fn spilled_rejection(bytes:&[u8],refs:&[ObjectReference],start:usize,first:usize,slot:usize)
    -> (out:(usize,usize,Result<ValueSlot,Error>))
    requires start as int+9 <= bytes.len(), bytes@[start as int+8] == 1,
        value::value_length(bytes@,start as int) <= 1024 || first >= refs.len() || slot > u16::MAX ||
        refs@[first as int].fields().0 != edge::wire(edge::Relation::Value,slot) || !(refs@[first as int].fields().2 is Owns),
    ensures out.0 as int == start as int+9 && out.1 == first &&
        out.2 == Err(if value::value_length(bytes@,start as int) <= 1024 {Error::SmallSpill}
            else if first >= refs.len() { Error::Reference(edge::Rejection::Missing) }
            else if slot > u16::MAX { Error::Reference(edge::Rejection::IndexOverflow) }
            else {Error::Reference(edge::Rejection::Mismatch)}),
{
    let mut cursor = start;
    let mut pos = first;
    let out = value::read(bytes,&mut cursor,refs,&mut pos,slot);
    (cursor,pos,out)
}
}
