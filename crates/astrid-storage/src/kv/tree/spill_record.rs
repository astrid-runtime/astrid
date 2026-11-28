//! Persisted KV spill payloads and their owning content-DAG links.
use super::checkpoint_value::{INLINE_VALUE_MAX, ValueSlot};
use super::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, ObjectReference,
    ReferenceLabel,
};
use crate::storage_words::little_endian;
use vstd::prelude::*;

verus! {
pub(super) const CONTENT:[u8;7] = [b'c',b'o',b'n',b't',b'e',b'n',b't'];

pub(super) fn opaque(version:ObjectFormatVersion,data:Vec<u8>) -> (r:ObjectRecord)
    ensures r.contents() == (ObjectKind::KvLeaf,version.number(),data@,Seq::empty(),0u64,ObjectClass::Data),
{
    ObjectRecord::from_fields(ObjectKind::KvLeaf,version,data,Vec::new(),0,ObjectClass::Data).expect("an empty reference list is ordered")
}

pub(super) open spec fn valid_payload(record:&ObjectRecord,version:ObjectFormatVersion,length:u64) -> bool {
    let r = record.contents();
    r.0 is KvLeaf && r.1 == version.number() && r.5 is Data && r.4 == 0 &&
        r.3.len() == 0 && r.2.len() == length && length > INLINE_VALUE_MAX
}

pub(super) fn payload(record:&ObjectRecord,version:ObjectFormatVersion,length:u64) -> (out:Option<&[u8]>)
    ensures out.is_some() == valid_payload(record,version,length),
        out matches Some(b) ==> b@ == record.contents().2,
{
    let data = record.canonical_bytes();
    if !matches!(record.kind(),ObjectKind::KvLeaf) || record.format_version().get() != version.get() ||
        !matches!(record.class(),ObjectClass::Data) || record.logical_bytes() != 0 ||
        !record.references().is_empty() || u64::try_from(data.len()).ok() != Some(length) ||
        length <= INLINE_VALUE_MAX as u64 {None} else {Some(data)}
}

pub(super) fn wrapper(version:ObjectFormatVersion,file:ObjectId,length:u64) -> (r:ObjectRecord)
    ensures ({
        let fields = r.contents();
        fields.0 is KvLeaf && fields.1 == version.number() && fields.5 is Data && fields.4 == 0 &&
        fields.2 == vstd::bytes::spec_u64_to_le_bytes(length) && fields.3.len() == 1 &&
        fields.3[0].fields() == (CONTENT@,file,super::ReferenceKind::Owns)
    }),
{
    let mut bytes = Vec::with_capacity(8);
    bytes.extend_from_slice(&little_endian(length));
    let mut label = Vec::with_capacity(CONTENT.len());
    label.extend_from_slice(&CONTENT);
    let refs = vec![ObjectReference::owns(ReferenceLabel::new(label),file)];
    ObjectRecord::from_fields(ObjectKind::KvLeaf,version,bytes,refs,0,ObjectClass::Data).expect("one owning reference is ordered")
}

pub(super) enum Error { Wrapper, Reference }

pub(super) fn file(record:&ObjectRecord,length:u64,maximum:u32) -> (out:Result<ObjectId,Error>)
    ensures ({
        let r = record.contents();
        out == if !(r.0 is KvLeaf) || !(r.5 is Data) || r.4 != 0 || r.2 != vstd::bytes::spec_u64_to_le_bytes(length) ||
            r.3.len() != 1 || length <= maximum {Err(Error::Wrapper)}
        else if r.3[0].fields().0 != CONTENT@ || !(r.3[0].fields().2 is Owns) {Err(Error::Reference)}
        else {Ok(r.3[0].fields().1)}
    }),
{
    let bytes = little_endian(length);
    let data = record.canonical_bytes();
    if !matches!(record.kind(),ObjectKind::KvLeaf) || !matches!(record.class(),ObjectClass::Data) ||
        record.logical_bytes() != 0 || data != bytes.as_slice() || record.references().len() != 1 ||
        length <= u64::from(maximum) {return Err(Error::Wrapper);}
    assert(data@ =~= bytes@);
    let edge = &record.references()[0];
    let label = edge.label_bytes();
    if label != CONTENT.as_slice() {return Err(Error::Reference);}
    assert(label@ =~= CONTENT@);
    edge.owning_target().ok_or(Error::Reference)
}

pub(super) enum ResolveError<E> { Source(E), Invalid(ObjectId) }

pub(super) fn resolve<E,L:FnOnce(ObjectId)->Result<ObjectRecord,E>,
    C:FnOnce(ObjectId,u64,&ObjectRecord)->Result<Vec<u8>,E>>(
    value:&ValueSlot,plain:ObjectFormatVersion,chunked:ObjectFormatVersion,load:L,chunk:C,
) -> (out:Result<Vec<u8>,ResolveError<E>>)
    requires forall|id:ObjectId| #[trigger] load.requires((id,)),
        forall|id:ObjectId,n:u64,r:&ObjectRecord| #[trigger] chunk.requires((id,n,r)),
    ensures match *value {
        ValueSlot::Inline(data) => out matches Ok(v) && v@ == data@,
        ValueSlot::Spilled {object,length} => match out {
            Ok(v) => exists|r:ObjectRecord| #[trigger] load.ensures((object,),Ok(r)) &&
                if r.contents().1 == chunked.number() {chunk.ensures((object,length,&r),Ok(v))}
                else {valid_payload(&r,plain,length) && v@ == r.contents().2},
            Err(ResolveError::Invalid(id)) => id == object &&
                exists|r:ObjectRecord| #[trigger] load.ensures((object,),Ok(r)) &&
                    r.contents().1 != chunked.number() && !valid_payload(&r,plain,length),
            Err(ResolveError::Source(e)) => load.ensures((object,),Err(e)) ||
                exists|r:ObjectRecord| #[trigger] load.ensures((object,),Ok(r)) &&
                    r.contents().1 == chunked.number() && chunk.ensures((object,length,&r),Err(e)),
        },
    },
{
    let (object,length) = match value {
        ValueSlot::Inline(data) => {
            let mut copy = Vec::with_capacity(data.len());
            copy.extend_from_slice(data);
            assert(copy@ =~= data@);
            return Ok(copy);
        },
        ValueSlot::Spilled {object,length} => (*object,*length),
    };
    let record = match load(object) {Ok(r)=>r,Err(e)=>return Err(ResolveError::Source(e))};
    if record.format_version().get() == chunked.get() {
        return match chunk(object,length,&record) { Ok(v)=>Ok(v), Err(e)=>Err(ResolveError::Source(e)) };
    }
    let Some(bytes) = payload(&record,plain,length) else {return Err(ResolveError::Invalid(object));};
    let mut copy = Vec::with_capacity(bytes.len());
    copy.extend_from_slice(bytes);
    assert(copy@ =~= record.contents().2);
    Ok(copy)
}
}
