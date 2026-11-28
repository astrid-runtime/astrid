//! Values in persisted checkpoint leaves. Inline bytes consume no owning edge.
use super::{
    ObjectId, ObjectReference,
    checkpoint_reference::{self as edge, Rejection, Relation},
};
use crate::storage_fields::{ReadError, fixed, take};
use vstd::prelude::*;

verus! {
pub(super) const INLINE_VALUE_MAX:usize = 1_024;
pub(super) const INLINE_VALUE:u8 = 0;
pub(super) const SPILLED_VALUE:u8 = 1;

#[derive(Clone,Debug,PartialEq,Eq)]
pub(super) enum ValueSlot {
    Inline(Vec<u8>), Spilled {object:ObjectId,length:u64},
}

pub(super) enum Error { Field(ReadError), Length, Oversized, SmallSpill, Tag, Reference(Rejection) }

pub(super) open spec fn value_length(bytes:Seq<u8>,start:int) -> u64 {
    if start < 0 || start+8 > bytes.len() {0}
    else {vstd::bytes::spec_u64_from_le_bytes(bytes.subrange(start,start+8))}
}

pub(super) open spec fn decoded(bytes:Seq<u8>,start:int,end:int,refs:Seq<ObjectReference>,position:usize,
    next:usize,slot:usize,v:ValueSlot) -> bool {
    let n = value_length(bytes,start);
    &&& 0 <= start && start+9 <= bytes.len()
    &&& match v {
        ValueSlot::Inline(data) => bytes[start+8] == INLINE_VALUE && n <= INLINE_VALUE_MAX &&
            end == start+9+n && end <= bytes.len() && next == position && data@ == bytes.subrange(start+9,end),
        ValueSlot::Spilled {object,length} => bytes[start+8] == SPILLED_VALUE && length == n && n > INLINE_VALUE_MAX &&
            end == start+9 && next as int == position as int+1 && position < refs.len() && slot <= u16::MAX &&
            refs[position as int].fields() == (edge::wire(Relation::Value,slot),object,super::ReferenceKind::Owns),
    }
}

// Native readers leave the cursor immediately after the last whole field.
pub(super) open spec fn field_error(start:int,width:int) -> ReadError {
    if start+width > usize::MAX {ReadError::Overflow(width as usize)} else {ReadError::Truncated}
}

pub(super) open spec fn failure(bytes:Seq<u8>,start:int,end:int,refs:Seq<ObjectReference>,position:usize,slot:usize,e:Error) -> bool {
    let n = value_length(bytes,start) as int;
    if start+8 > bytes.len() {end == start && e == Error::Field(field_error(start,8))}
    else if start+9 > bytes.len() {end == start+8 && e == Error::Field(field_error(start+8,1))}
    else {
        &&& end == start+9
        &&& if bytes[start+8] == INLINE_VALUE {
            if n > usize::MAX {e == Error::Length}
            else if n > INLINE_VALUE_MAX {e == Error::Oversized}
            else {start+9+n > bytes.len() && e == Error::Field(field_error(start+9,n))}
        } else if bytes[start+8] == SPILLED_VALUE {
            if n <= INLINE_VALUE_MAX {e == Error::SmallSpill}
            else if position >= refs.len() {e == Error::Reference(Rejection::Missing)}
            else if slot > u16::MAX {e == Error::Reference(Rejection::IndexOverflow)}
            else {
                let row = refs[position as int].fields();
                (row.0 != edge::wire(Relation::Value,slot) || !(row.2 is Owns)) && e == Error::Reference(Rejection::Mismatch)
            }
        } else {e == Error::Tag}
    }
}

pub(super) fn read(bytes:&[u8],cursor:&mut usize,refs:&[ObjectReference],position:&mut usize,slot:usize)
    -> (out:Result<ValueSlot,Error>)
    ensures match out {
        Ok(v) => decoded(bytes@,*old(cursor) as int,*final(cursor) as int,refs@,*old(position),*final(position),slot,v),
        Err(e) => *final(position) == *old(position) && failure(bytes@,*old(cursor) as int,*final(cursor) as int,refs@,*old(position),slot,e),
    },
{
    let ghost start = *cursor as int;
    let ghost first = *position;
    let raw = match fixed::<8>(bytes,cursor) {Ok(f)=>f,Err(e)=>return Err(Error::Field(e))};
    let n = u64::from_le_bytes(raw);
    assert(n == value_length(bytes@,start));
    let [tag] = match fixed::<1>(bytes,cursor) {Ok(f)=>f,Err(e)=>return Err(Error::Field(e))};
    assert(tag == bytes@[start+8]);
    match tag {
        INLINE_VALUE => {
            let Ok(len) = usize::try_from(n) else {return Err(Error::Length);};
            if len > INLINE_VALUE_MAX {return Err(Error::Oversized);}
            let data = match take(bytes,cursor,len) {Ok(d)=>d,Err(e)=>return Err(Error::Field(e))};
            let mut value = Vec::with_capacity(len);
            value.extend_from_slice(data);
            assert(value@ =~= bytes@.subrange(start+9,*cursor as int));
            assert(*cursor as int == start + 9 + n);
            assert(*position == first);
            assert(bytes@[start+8] == INLINE_VALUE);
            let v = ValueSlot::Inline(value);
            assert(decoded(bytes@,start,*cursor as int,refs@,first,*position,slot,v));
            Ok(v)
        },
        SPILLED_VALUE => {
            if n <= INLINE_VALUE_MAX as u64 {return Err(Error::SmallSpill);}
            let object = match edge::target(refs,*position,Relation::Value,slot) {
                Ok(id)=>id,Err(e)=>return Err(Error::Reference(e))
            };
            *position = position.saturating_add(1);
            let v = ValueSlot::Spilled {object,length:n};
            assert(decoded(bytes@,start,*cursor as int,refs@,first,*position,slot,v));
            Ok(v)
        },
        _ => Err(Error::Tag),
    }
}

pub(super) enum WriteError { Overflow, Oversized, SmallSpill }

pub(super) open spec fn wire(v:ValueSlot) -> Seq<u8> {
    match v {
        ValueSlot::Inline(data) => vstd::bytes::spec_u64_to_le_bytes(data.len() as u64) + seq![INLINE_VALUE] + data@,
        ValueSlot::Spilled {length,..} => vstd::bytes::spec_u64_to_le_bytes(length) + seq![SPILLED_VALUE],
    }
}

pub(super) fn append(bytes:&mut Vec<u8>,refs:&mut Vec<ObjectReference>,slot:usize,value:&ValueSlot)
    -> (out:Result<(),WriteError>)
    ensures out.is_err() ==> final(bytes)@ == old(bytes)@ && final(refs)@ == old(refs)@,
        out.is_ok() ==> final(bytes)@ == old(bytes)@ + wire(*value),
        match value {
            ValueSlot::Inline(data) => out == (if data.len() > u64::MAX { Err(WriteError::Overflow) }
                else if data.len() > INLINE_VALUE_MAX {Err(WriteError::Oversized)} else {Ok(())}) &&
                final(refs)@ == old(refs)@,
            ValueSlot::Spilled {object,length} => ({
                &&& out == (if *length <= INLINE_VALUE_MAX {Err(WriteError::SmallSpill)} else if slot > u16::MAX {Err(WriteError::Overflow)} else {Ok(())})
                &&& out.is_ok() ==> final(refs).len() == old(refs).len()+1 &&
                    final(refs)@.drop_last() == old(refs)@ &&
                    final(refs)@.last().fields() == (edge::wire(Relation::Value,slot),*object,super::ReferenceKind::Owns)
            }),
        },
{
    match value {
        ValueSlot::Inline(data) => {
            let Ok(n) = u64::try_from(data.len()) else { return Err(WriteError::Overflow); };
            if data.len() > INLINE_VALUE_MAX {return Err(WriteError::Oversized);}
            bytes.extend_from_slice(&crate::storage_words::little_endian(n));
            bytes.push(INLINE_VALUE);
            bytes.extend_from_slice(data);
        },
        ValueSlot::Spilled {object,length} => {
            if *length <= INLINE_VALUE_MAX as u64 {return Err(WriteError::SmallSpill);}
            let Some(label) = edge::label(Relation::Value,slot) else {return Err(WriteError::Overflow);};
            bytes.extend_from_slice(&crate::storage_words::little_endian(*length));
            bytes.push(SPILLED_VALUE);
            refs.push(ObjectReference::owns(label,*object));
            assert(refs@.drop_last() =~= old(refs)@);
        },
    }
    assert(bytes@ =~= old(bytes)@ + wire(*value));
    Ok(())
}
}
