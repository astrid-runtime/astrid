//! Physical reference positions and encoded logical slots are distinct for spilled leaf values.
use crate::{ObjectId,ObjectReference,ReferenceKind,checkpoint_reference::{self,Relation,Rejection,wire}};
use vstd::prelude::*;

verus! {

proof fn unique_slot(rel:Relation,first:usize,second:usize)
    requires first <= u16::MAX,second <= u16::MAX,wire(rel,first) == wire(rel,second),
    ensures first == second,
{
    let n = rel.tag().len() as int;
    assert(wire(rel,first)[n] == (first/256) as u8);
    assert(wire(rel,second)[n] == (second/256) as u8);
    assert(wire(rel,first)[n+1] == (first%256) as u8);
    assert(wire(rel,second)[n+1] == (second%256) as u8);
}

// Place a spilled value behind an unrelated owning reference. Only the
// correct physical reference at the correct stored entry index can recover it.
fn spilled(slot:usize,other:usize,peer:ObjectId,body:ObjectId)
    -> (out:(Option<ObjectId>,Option<ObjectId>,Option<ObjectId>,Option<ObjectId>))
    requires slot <= u16::MAX, other <= u16::MAX, slot != other,
    ensures out == (Some(body),None,None,None),
{
    let label = checkpoint_reference::label(Relation::Value,slot).unwrap();
    let mut refs = Vec::new();
    let child = checkpoint_reference::label(Relation::Child,slot).unwrap();
    refs.push(ObjectReference::owns(child,peer));
    refs.push(ObjectReference::owns(label,body));
    assert(wire(Relation::Child,slot)[0] != wire(Relation::Value,slot)[0]);
    proof { if wire(Relation::Value,slot) == wire(Relation::Value,other) { unique_slot(Relation::Value,slot,other); } }
    let selected = checkpoint_reference::target(&refs,1,Relation::Value,slot).ok();
    let wrong_position = checkpoint_reference::target(&refs,0,Relation::Value,slot).ok();
    let wrong_slot = checkpoint_reference::target(&refs,1,Relation::Value,other).ok();
    let absent = checkpoint_reference::target(&refs,2,Relation::Value,slot).ok();
    (selected,wrong_position,wrong_slot,absent)
}

fn non_owning(slot:usize,kind:ReferenceKind,id:ObjectId) -> (out:Result<ObjectId,Rejection>)
    requires slot <= u16::MAX, !(kind is Owns),
    ensures out == Err(Rejection::Mismatch),
{
    let label = checkpoint_reference::label(Relation::Child,slot).unwrap();
    let mut refs = Vec::new();
    refs.push(ObjectReference::new(label,id,kind));
    checkpoint_reference::target(&refs,0,Relation::Child,slot)
}

fn branch(refs:&[ObjectReference],slot:usize) -> (out:Result<ObjectId,Rejection>)
    ensures out == if slot >= refs.len() { Err(Rejection::Missing) }
        else if slot > u16::MAX { Err(Rejection::IndexOverflow) }
        else {
            let row = refs@[slot as int].fields();
            if row.0 == wire(Relation::Child,slot) && row.2 is Owns { Ok(row.1) } else { Err(Rejection::Mismatch) }
        },
{
    checkpoint_reference::target(refs,slot,Relation::Child,slot)
}
}
