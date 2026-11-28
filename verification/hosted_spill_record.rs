//! Recover the bytes or the owning file of the exact spill selected by a KV slot.
use crate::{ObjectFormatVersion,ObjectId,ObjectRecord,checkpoint_value::{ValueSlot,INLINE_VALUE_MAX},spill_record as spill};
use vstd::prelude::*;

verus! {
fn opaque_slot(data:Vec<u8>,id:ObjectId,declared:u64,available:bool,version:ObjectFormatVersion,chunked:ObjectFormatVersion)
    requires version.number() != chunked.number(),
{
    let record = spill::opaque(version,data);
    let ghost fields = record.contents();
    let slot = ValueSlot::Spilled {object:id,length:declared};
    let load = |key:ObjectId| -> (out:Result<ObjectRecord,u8>)
        ensures if available && key == id {out matches Ok(r) && r.contents() == fields} else {out == Err(1u8)} {
        if available && key.same(&id) {Ok(record)} else {Err(1u8)}
    };
    let chunk = |_id:ObjectId,_n:u64,_r:&ObjectRecord| -> (out:Result<Vec<u8>,u8>) ensures out == Err(2u8) {Err(2u8)};
    let out = spill::resolve(&slot,version,chunked,load,chunk);
    assert(if !available {out == Err(spill::ResolveError::Source(1u8))}
        else if data.len() != declared || declared <= INLINE_VALUE_MAX {out == Err(spill::ResolveError::Invalid(id))}
        else {out matches Ok(v) && v@ == data@});
}

fn chunk_slot(id:ObjectId,file:ObjectId,stored:u64,declared:u64,maximum:u32,body:Vec<u8>)
{
    let plain = ObjectFormatVersion::new(4).unwrap();
    let chunked = ObjectFormatVersion::new(5).unwrap();
    let record = spill::wrapper(chunked,file,stored);
    let ghost fields = record.contents();
    let slot = ValueSlot::Spilled {object:id,length:declared};
    let load = |key:ObjectId| -> (out:Result<ObjectRecord,u8>)
        ensures if key == id {out matches Ok(r) && r.contents() == fields} else {out == Err(1u8)} {
        if key.same(&id) {Ok(record)} else {Err(1u8)}
    };
    let chunk = |key:ObjectId,n:u64,r:&ObjectRecord| -> (out:Result<Vec<u8>,u8>)
        ensures r.contents() == fields ==> (if key == id && n == stored && n > maximum {out matches Ok(v) && v@ == body@}
            else {out == Err(2u8)}) {
        proof {vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();}
        match spill::file(r,n,maximum) {
            Ok(target) if key.same(&id) && target.same(&file) => Ok(body),
            _ => Err(2u8),
        }
    };
    let out = spill::resolve(&slot,plain,chunked,load,chunk);
    assert(if declared == stored && declared > maximum {out matches Ok(v) && v@ == body@}
        else {out == Err(spill::ResolveError::Source(2u8))});
}

fn inline_slot(data:Vec<u8>,version:ObjectFormatVersion) {
    let slot = ValueSlot::Inline(data);
    let load = |_key:ObjectId| -> (out:Result<ObjectRecord,u8>) ensures out == Err(1u8) {Err(1u8)};
    let chunk = |_key:ObjectId,_n:u64,_r:&ObjectRecord| -> (out:Result<Vec<u8>,u8>) ensures out == Err(2u8) {Err(2u8)};
    let out = spill::resolve(&slot,version,version,load,chunk);
    assert(out matches Ok(v) && v@ == data@);
}

fn wrapper_reference(target:ObjectId,kind:crate::ReferenceKind,wrong:bool) {
    let version = ObjectFormatVersion::new(5).unwrap();
    let mut label = Vec::new();
    label.extend_from_slice(&spill::CONTENT);
    assert(label@ =~= spill::CONTENT@);
    if wrong {label.push(0);}
    assert((label@ == spill::CONTENT@) == !wrong);
    let edge = crate::ObjectReference::new(crate::ReferenceLabel::new(label),target,kind);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&crate::storage_words::little_endian(2048));
    assert(bytes@ =~= vstd::bytes::spec_u64_to_le_bytes(2048));
    let record = ObjectRecord::from_fields(crate::ObjectKind::KvLeaf,version,bytes,vec![edge],0,crate::ObjectClass::Data).unwrap();
    let out = spill::file(&record,2048,1024);
    assert(out == if !wrong && kind is Owns { Ok(target) } else { Err(spill::Error::Reference) });
}
}
