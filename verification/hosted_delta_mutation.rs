//! A row begins after an arbitrary byte prefix and ends before an arbitrary suffix.
use crate::{ObjectId,ObjectRecord,ObjectReference,ReferenceKind,checkpoint_key_field as key,
    checkpoint_value::{ValueSlot,INLINE_VALUE_MAX},delta_mutation::{self as delta,Mutation,Operation},
    reference_lookup,storage_fields,storage_words};
use vstd::prelude::*;

verus! {

fn roundtrip(row:Mutation,index:usize,bytes:&mut Vec<u8>,refs:&mut Vec<ObjectReference>,tail:&[u8])
    requires row.key.len() <= u32::MAX, index <= u32::MAX,
        old(bytes).len()+row.payload().len()+tail.len() <= usize::MAX,
        match row.value {None => true,Some(ValueSlot::Inline(data)) => data.len() <= INLINE_VALUE_MAX,
            Some(ValueSlot::Spilled {length,..}) => length > INLINE_VALUE_MAX},
        forall|i:int| 0 <= i < old(refs).len() ==> {
            let label = (#[trigger] old(refs)@[i]).fields().0;
            label != delta::label_bytes(index as u32) && ObjectRecord::label_before(label,delta::label_bytes(index as u32))
        },
    ensures final(bytes)@ == old(bytes)@ + row.payload() + tail@,
{
    let start = bytes.len();
    let mut cursor = start;
    let first = refs.len();
    let wrote = row.append(index,bytes,refs);
    assert(wrote.is_ok());
    bytes.extend_from_slice(tail);
    assert(bytes@ =~= old(bytes)@ + row.payload() + tail@);
    let ghost tag = start as int+4+row.key.len();
    assert(bytes@.subrange(start as int,start as int+4) =~= storage_words::word32(row.key.len() as u32));
    assert(storage_fields::at(bytes@,start as int,storage_words::word32(row.key.len() as u32)));
    proof {key::encoded_length(bytes@,start as int,row.key.len() as u32);}
    let read_key = key::read(bytes,&mut cursor);
    assert(read_key matches Ok(k) && k@ == row.key@) by {
        assert(bytes@.subrange(start as int+4,tag) =~= row.key@);
    }
    assert(cursor == tag);
    let decoded = delta::read(bytes,&mut cursor);
    proof {vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();}
    match &row.value {
        None => {
            assert(bytes@[tag] == 0);
            assert(decoded matches Ok(Operation::Delete));
            assert(refs@ == old(refs)@);
        },
        Some(ValueSlot::Inline(data)) => {
            assert(bytes@[tag] == 1);
            assert(bytes@.subrange(tag+1,tag+9) =~= vstd::bytes::spec_u64_to_le_bytes(data.len() as u64));
            assert(bytes@.subrange(tag+9,tag+9+data.len()) =~= data@);
            assert(decoded matches Ok(Operation::Inline(got)) && got@ == data@);
            assert(refs@ == old(refs)@);
        },
        Some(ValueSlot::Spilled {object,length}) => {
            assert(bytes@[tag] == 2);
            assert(bytes@.subrange(tag+1,tag+9) =~= vstd::bytes::spec_u64_to_le_bytes(*length));
            assert(decoded matches Ok(Operation::Spill(n)) && n == *length);
            let ghost label = delta::label_bytes(index as u32);
            assert(refs@[first as int].fields() == (label,*object,ReferenceKind::Owns));
            assert(reference_lookup::positioned(refs@,label,first as int)) by {
                assert forall|i:int| 0 <= i < first implies (#[trigger] refs@[i]).fields().0 != label &&
                    ObjectRecord::label_before(refs@[i].fields().0,label) by {
                    assert(refs@[i] == refs@.drop_last()[i]);
                }
            }
            let target = delta::spill_object(refs,index);
            assert(target == Ok(*object));
        },
    }
    assert(cursor as int == start as int+row.payload().len());
    let mut consumed = start;
    let parsed = Mutation::decode(bytes,&mut consumed,refs,index,|_:&[u8]| -> (error:Option<()>)
        ensures error == None, {None});
    let Ok(actual) = parsed else {assert(false);return;};
    assert(actual.key@ == row.key@);
    match &row.value {
        None => assert(actual.value.is_none()),
        Some(ValueSlot::Inline(data)) => assert(actual.value matches Some(ValueSlot::Inline(got)) && got@ == data@),
        Some(ValueSlot::Spilled {object,length}) => assert(actual.value == Some(ValueSlot::Spilled {object:*object,length:*length})),
    }
    assert(consumed == cursor);

}

fn malformed_operation(bytes:&[u8],start:usize)
    requires !delta::valid(bytes@,start as int),
{
    let mut cursor = start;
    let decoded = delta::read(bytes,&mut cursor);
    assert(decoded.is_err());
}

/// A rejected key cannot produce a recovered mutation.
fn refused_key(bytes:&[u8],start:usize,refs:&[ObjectReference],index:usize,error:u64)
    requires start as int+4 <= bytes.len() && start as int+4+key::length(bytes@,start as int) <= bytes.len(),
{
    let mut cursor = start;
    let out = Mutation::decode(bytes,&mut cursor,refs,index,|_:&[u8]| -> (decision:Option<u64>)
        ensures decision == Some(error), {Some(error)});
    assert(out matches Err(delta::DecodeError::InvalidKey(e)) && e == error);
}

fn wrong_relation(refs:&[ObjectReference],index:usize)
    requires index <= u32::MAX, forall|i:int| 0 <= i < refs.len() ==>
        (#[trigger] refs@[i]).fields().0 != delta::label_bytes(index as u32) ||
        refs@[i].fields().2 != ReferenceKind::Owns,
{
    let result = delta::spill_object(refs,index);
    if let Ok(id) = result {
        let ghost edge = choose|r:ObjectReference| refs@.contains(r) &&
            #[trigger] r.fields() == (delta::label_bytes(index as u32),id,ReferenceKind::Owns);
        let ghost i = refs@.index_of(edge);
        assert(0 <= i < refs.len() && refs@[i] == edge);
        assert(false);
    }
}

fn label_layout(index:u32) {
    let result = delta::value_label(index as usize);
    let Some(label) = result else {assert(false);return;};
    let encoded = label.into_inner();
    assert(encoded@ =~= seq![b'v',b'a',b'l',b'u',b'e',b'/',(index >> 24) as u8,
        (index >> 16) as u8,(index >> 8) as u8,index as u8]) by {
        assert(((index >> 24) & 255) as u8 == (index >> 24) as u8 &&
            ((index >> 16) & 255) as u8 == (index >> 16) as u8 &&
            ((index >> 8) & 255) as u8 == (index >> 8) as u8 && (index & 255) as u8 == index as u8) by (bit_vector);
    }
}
}
