//! One operation in a persisted KV delta.
use super::checkpoint_value::{INLINE_VALUE_MAX, ValueSlot};
use super::{ObjectId, ObjectReference, ReferenceLabel, checkpoint_reference};
use crate::storage_words::{little_endian, little_endian_u32};
use vstd::prelude::*;

verus! {
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Mutation {
    pub(super) key: Vec<u8>,
    pub(super) value: Option<ValueSlot>,
}

pub(super) const DELETE:u8 = 0;
pub(super) const INLINE:u8 = 1;
pub(super) const SPILLED:u8 = 2;

pub(super) open spec fn label_bytes(index:u32) -> Seq<u8> {
    let le = crate::storage_words::word32(index);
    checkpoint_reference::VALUE@ + seq![le[3],le[2],le[1],le[0]]
}

pub(super) fn value_label(index:usize) -> (out:Option<ReferenceLabel>)
    ensures out.is_some() == (index <= u32::MAX),
        out matches Some(label) ==> label.value()@ == label_bytes(index as u32),
{
    let ordinal = u32::try_from(index).ok()?;
    let [low,lower_mid,upper_mid,high] = little_endian_u32(ordinal);
    let mut label = Vec::with_capacity(10);
    label.extend_from_slice(&checkpoint_reference::VALUE);
    label.extend_from_slice(&[high,upper_mid,lower_mid,low]);
    assert(label@ =~= label_bytes(ordinal));
    Some(ReferenceLabel::new(label))
}

pub(super) enum WriteError { Overflow, Oversized, SmallSpill }

impl Mutation {
    pub(super) open spec fn payload(&self) -> Seq<u8> {
        crate::storage_words::word32(self.key.len() as u32) + self.key@ + match self.value {
            None => seq![DELETE],
            Some(ValueSlot::Inline(data)) => seq![INLINE] + vstd::bytes::spec_u64_to_le_bytes(data.len() as u64) + data@,
            Some(ValueSlot::Spilled {length,..}) => seq![SPILLED] + vstd::bytes::spec_u64_to_le_bytes(length),
        }
    }

    pub(super) fn append(&self,index:usize,bytes:&mut Vec<u8>,refs:&mut Vec<ObjectReference>)
        -> (out:Result<(),WriteError>)
        ensures out.is_err() ==> final(bytes)@ == old(bytes)@ && final(refs)@ == old(refs)@,
            out.is_ok() ==> final(bytes)@ == old(bytes)@ + self.payload(),
            self.key.len() > u32::MAX ==> out == Err(WriteError::Overflow),
            self.key.len() <= u32::MAX ==> match self.value {
                None => out.is_ok() && final(refs)@ == old(refs)@,
                Some(ValueSlot::Inline(data)) => out == (if data.len() > INLINE_VALUE_MAX {Err(WriteError::Oversized)} else {Ok(())}) &&
                    final(refs)@ == old(refs)@,
                Some(ValueSlot::Spilled {object,length}) => {
                    &&& out == (if length <= INLINE_VALUE_MAX {Err(WriteError::SmallSpill)} else if index > u32::MAX {Err(WriteError::Overflow)} else {Ok(())})
                    &&& out.is_ok() ==> final(refs).len() == old(refs).len()+1 &&
                        final(refs)@.drop_last() == old(refs)@ &&
                        final(refs)@.last().fields() == (label_bytes(index as u32),object,super::ReferenceKind::Owns)
                }
            },
    {
        let Ok(width) = u32::try_from(self.key.len()) else {return Err(WriteError::Overflow);};
        match &self.value {
            Some(ValueSlot::Inline(data)) if data.len() > INLINE_VALUE_MAX => return Err(WriteError::Oversized),
            Some(ValueSlot::Spilled {object,length}) => {
                if *length <= INLINE_VALUE_MAX as u64 {return Err(WriteError::SmallSpill);}
                let Some(label) = value_label(index) else {return Err(WriteError::Overflow);};
                refs.push(ObjectReference::owns(label,*object));
                assert(refs@.drop_last() =~= old(refs)@);
            },
            _ => {},
        }
        bytes.extend_from_slice(&little_endian_u32(width));
        bytes.extend_from_slice(&self.key);
        match &self.value {
            None => bytes.push(DELETE),
            Some(ValueSlot::Inline(data)) => {
                bytes.push(INLINE);
                bytes.extend_from_slice(&little_endian(data.len() as u64));
                bytes.extend_from_slice(data);
            },
            Some(ValueSlot::Spilled {length,..}) => {
                bytes.push(SPILLED);
                bytes.extend_from_slice(&little_endian(*length));
            },
        }
        assert(bytes@ =~= old(bytes)@ + self.payload());
        Ok(())
    }
}

pub(super) enum Operation<'a> { Delete, Inline(&'a [u8]), Spill(u64) }
pub(super) enum ReadError { Field(crate::storage_fields::ReadError), Length, Oversized, SmallSpill, Tag }

pub(super) open spec fn valid(bytes:Seq<u8>,start:int) -> bool {
    let n = super::checkpoint_value::value_length(bytes,start+1) as int;
    0 <= start < bytes.len() && (bytes[start] == DELETE ||
        (start+9 <= bytes.len() && ((bytes[start] == INLINE && n <= INLINE_VALUE_MAX && start+9+n <= bytes.len()) ||
            (bytes[start] == SPILLED && n > INLINE_VALUE_MAX))))
}

pub(super) fn read<'a>(bytes:&'a [u8],cursor:&mut usize) -> (out:Result<Operation<'a>,ReadError>)
    ensures out.is_ok() == valid(bytes@,*old(cursor) as int),
        out matches Ok(op) ==> {
            let start = *old(cursor) as int;
            let n = super::checkpoint_value::value_length(bytes@,start+1);
            match op {
                Operation::Delete => bytes@[start] == DELETE && *final(cursor) as int == start+1,
                Operation::Inline(data) => bytes@[start] == INLINE && *final(cursor) as int == start+9+n &&
                    data@ == bytes@.subrange(start+9,*final(cursor) as int),
                Operation::Spill(length) => bytes@[start] == SPILLED && *final(cursor) as int == start+9 && length == n,
            }
        },
{
    let ghost start = *cursor as int;
    let [tag] = match crate::storage_fields::fixed::<1>(bytes,cursor) {
        Ok(field) => field, Err(e) => return Err(ReadError::Field(e)),
    };
    assert(tag == bytes@[start]);
    if tag == DELETE {return Ok(Operation::Delete);}
    if tag != INLINE && tag != SPILLED {return Err(ReadError::Tag);}
    let field = match crate::storage_fields::fixed::<8>(bytes,cursor) {
        Ok(field) => field, Err(e) => return Err(ReadError::Field(e)),
    };
    let n = u64::from_le_bytes(field);
    assert(n == super::checkpoint_value::value_length(bytes@,start+1));
    if tag == SPILLED {
        if n <= INLINE_VALUE_MAX as u64 {return Err(ReadError::SmallSpill);}
        return Ok(Operation::Spill(n));
    }
    let Ok(len) = usize::try_from(n) else {return Err(ReadError::Length);};
    if len > INLINE_VALUE_MAX {return Err(ReadError::Oversized);}
    match crate::storage_fields::take(bytes,cursor,len) {
        Ok(data) => Ok(Operation::Inline(data)), Err(e) => Err(ReadError::Field(e)),
    }
}

pub(super) enum EdgeError { Index, Missing, NonOwning }

pub(super) fn spill_object(refs:&[ObjectReference],index:usize) -> (out:Result<ObjectId,EdgeError>)
    ensures ({
        let label = label_bytes(index as u32);
        let selected = super::reference_lookup::selected(refs@,label,0,refs.len() as int);
        if index > u32::MAX {out == Err(EdgeError::Index)} else {match selected {
            None => out == Err(EdgeError::Missing),
            Some(edge) => out == if edge.fields().2 == super::ReferenceKind::Owns {Ok(edge.fields().1)} else {Err(EdgeError::NonOwning)},
        }}
    }),
        out matches Ok(id) ==> (super::reference_lookup::selected(refs@,label_bytes(index as u32),0,refs.len() as int)
            matches Some(edge) && edge.fields() == (label_bytes(index as u32),id,super::ReferenceKind::Owns)),
        out matches Ok(id) ==> exists|r:ObjectReference| refs@.contains(r) &&
            #[trigger] r.fields() == (label_bytes(index as u32),id,super::ReferenceKind::Owns),
        forall|i:int| index <= u32::MAX && #[trigger] super::reference_lookup::positioned(refs@,label_bytes(index as u32),i) &&
            refs@[i].fields().2 == super::ReferenceKind::Owns ==> out == Ok(refs@[i].fields().1),
{
    let Some(label) = value_label(index) else {return Err(EdgeError::Index);};
    let bytes = label.into_inner();
    let Some(r) = super::reference_lookup::find(refs,bytes.as_slice()) else {return Err(EdgeError::Missing);};
    r.owning_target().ok_or(EdgeError::NonOwning)
}

pub(super) enum DecodeError<E> {
    Key(super::checkpoint_key_field::KeyError),
    InvalidKey(E),
    Operation(ReadError),
    Edge(EdgeError),
}

pub(super) open spec fn validated<E,F:FnOnce(&[u8])->Option<E>>(validate:F,key:Seq<u8>,decision:Option<E>) -> bool {
    exists|field:&[u8]| field@ == key && #[trigger] validate.ensures((field,),decision)
}

impl Mutation {
    /// Recover one complete mutation, preserving validation and error order.
    pub(super) fn decode<E,F:FnOnce(&[u8])->Option<E>>(bytes:&[u8],cursor:&mut usize,
        refs:&[ObjectReference],index:usize,validate:F) -> (out:Result<Self,DecodeError<E>>)
        requires forall|k:&[u8]| #[trigger] validate.requires((k,)),
        ensures ({
            let start = *old(cursor) as int;
            let key_end = start + 4 + super::checkpoint_key_field::length(bytes@,start);
            let has_key = start+4 <= bytes.len() && key_end <= bytes.len();
            let key = if has_key {bytes@.subrange(start+4,key_end)} else {Seq::empty()};
            let length = super::checkpoint_value::value_length(bytes@,key_end+1);
            let label = if index <= u32::MAX {label_bytes(index as u32)} else {Seq::empty()};
            let edge = super::reference_lookup::selected(refs@,label,0,refs.len() as int);
            match out {
                Err(DecodeError::Key(_)) => !has_key,
                Err(DecodeError::InvalidKey(e)) => has_key && validated(validate,key,Some(e)),
                Err(DecodeError::Operation(_)) => has_key && validated(validate,key,None) && !valid(bytes@,key_end),
                Err(DecodeError::Edge(_)) => has_key && validated(validate,key,None) && valid(bytes@,key_end) && bytes@[key_end] == SPILLED &&
                    (index > u32::MAX || edge.is_none() || edge.unwrap().fields().2 != super::ReferenceKind::Owns),
                Ok(row) => {
                    &&& has_key && row.key@ == key && valid(bytes@,key_end)
                    &&& validated(validate,key,None)
                    &&& match row.value {
                        None => bytes@[key_end] == DELETE && *final(cursor) as int == key_end+1,
                        Some(ValueSlot::Inline(data)) => bytes@[key_end] == INLINE && *final(cursor) as int == key_end+9+length &&
                            data@ == bytes@.subrange(key_end+9,*final(cursor) as int),
                        Some(ValueSlot::Spilled {object,length:n}) => bytes@[key_end] == SPILLED && *final(cursor) as int == key_end+9 &&
                            n == length && index <= u32::MAX && (edge matches Some(r) && r.fields() == (label,object,super::ReferenceKind::Owns)),
                    }
                },
            }
        }),
    {
        let ghost start = *cursor as int;
        let k = match super::checkpoint_key_field::read(bytes,cursor) {
            Ok(k) => k, Err(e) => return Err(DecodeError::Key(e)),
        };
        let ghost key_end = start + 4 + super::checkpoint_key_field::length(bytes@,start);
        assert(k@ == bytes@.subrange(start+4,key_end));
        let decision = validate(k);
        assert(validated(validate,k@,decision)) by {assert(validate.ensures((k,),decision));}
        if let Some(e) = decision {return Err(DecodeError::InvalidKey(e));}
        assert(decision.is_none());
        assert(*cursor as int == key_end);
        let op = match read(bytes,cursor) {Ok(o) => o, Err(e) => return Err(DecodeError::Operation(e))};
        let value = match op {
            Operation::Delete => None,
            Operation::Inline(data) => {
                let mut value = Vec::with_capacity(data.len());
                value.extend_from_slice(data);
                assert(value@ =~= data@);
                Some(ValueSlot::Inline(value))
            },
            Operation::Spill(length) => {
                let object = match spill_object(refs,index) {Ok(id) => id, Err(e) => return Err(DecodeError::Edge(e))};
                Some(ValueSlot::Spilled {object,length})
            },
        };
        let mut key = Vec::with_capacity(k.len());
        key.extend_from_slice(k);
        assert(key@ =~= k@);
        assert(validated(validate,key@,None));
        Ok(Self {key,value})
    }
}

/// Resolve borrowed mutation bytes without duplicating a spilled payload.
pub(super) fn encode<E,F:FnOnce(&[u8],u64)->Result<ObjectId,E>>(data:&[u8],spill:F)
    -> (out:Result<ValueSlot,E>)
    requires data.len() > INLINE_VALUE_MAX ==> spill.requires((data,data.len() as u64)),
    ensures match out {
        Ok(ValueSlot::Inline(v)) => data.len() <= INLINE_VALUE_MAX && v@ == data@,
        Ok(ValueSlot::Spilled {object,length}) => data.len() > INLINE_VALUE_MAX &&
            length == data.len() && spill.ensures((data,length),Ok(object)),
        Err(e) => data.len() > INLINE_VALUE_MAX && spill.ensures((data,data.len() as u64),Err(e)),
    },
{
    if data.len() <= INLINE_VALUE_MAX {
        let mut bytes = Vec::with_capacity(data.len());
        bytes.extend_from_slice(data);
        assert(bytes@ =~= data@);
        return Ok(ValueSlot::Inline(bytes));
    }
    let length = data.len() as u64;
    let object = spill(data,length)?;
    Ok(ValueSlot::Spilled {object,length})
}
}
