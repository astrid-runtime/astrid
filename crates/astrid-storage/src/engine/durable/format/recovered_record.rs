//! Decode the arena scan's declared name, authenticate its record and require canonical frame bytes.
use super::ArenaLocation;
use super::{ObjectId, ObjectRecord, root_wire::Scheme, verified_record as wire};
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

verus! {
pub(super) fn unpack(payload:&[u8],scheme:Scheme) -> (out:Result<(ObjectId,ObjectRecord),wire::DecodeError<wire::BodyError>>)
    ensures match out {
        Ok((id,r)) => wire::tag(payload@,0,scheme) && id.digest() == payload@.subrange(8,40) &&
            wire::record_at(payload@,40,scheme,r),
        Err(wire::DecodeError::Tag(_)) => !wire::tag(payload@,0,scheme),
        Err(wire::DecodeError::Record(e)) => wire::tag(payload@,0,scheme) && !wire::leaf_body(payload@,40) &&
            (wire::complete_body(payload@,40,scheme) ==> e is Allocation),
    },
{
    let decoder = |b:&[u8],start:usize| -> (out:Result<ObjectRecord,wire::BodyError>)
        ensures out matches Ok(r) ==> wire::record_at(b@,start as int,scheme,r),
            wire::leaf_body(b@,start as int) ==> out.is_ok(),
            wire::complete_body(b@,start as int,scheme) ==> out.is_ok() || (out matches Err(wire::BodyError::Allocation)),
    { wire::body(b,start,scheme) };
    let (name,r) = wire::decode(payload,scheme,decoder)?;
    Ok((ObjectId::new(name),r))
}

pub(super) open spec fn encoding(scheme:Scheme,id:ObjectId,r:ObjectRecord) -> Seq<u8> {
    let f = r.contents();
    scheme.algorithm@ + scheme.construction@ + seq![32u8,0u8,0u8,0u8] + id.digest() +
        wire::header_wire(f.0,f.1,f.5) + wire::payload_wire(f.4,f.2,f.3.len() as usize) +
        wire::reference_prefix(f.3,f.3.len(),scheme)
}

pub(super) enum Error { Decode(wire::DecodeError<wire::BodyError>), Identity, Overflow, Canonical }

pub(super) open spec fn refused<F:FnOnce(&ObjectRecord)->ObjectId>(payload:Seq<u8>,scheme:Scheme,identify:F,e:Error) -> bool {
    match e {
        Error::Decode(wire::DecodeError::Tag(_)) => !wire::tag(payload,0,scheme),
        Error::Decode(wire::DecodeError::Record(e)) => wire::tag(payload,0,scheme) && !wire::leaf_body(payload,40) &&
            (wire::complete_body(payload,40,scheme) ==> e is Allocation),
        Error::Identity => exists|r:ObjectRecord,actual:ObjectId| wire::record_at(payload,40,scheme,r) &&
            #[trigger] identify.ensures((&r,),actual) && actual.digest() != payload.subrange(8,40),
        Error::Canonical => exists|r:ObjectRecord,id:ObjectId| wire::record_at(payload,40,scheme,r) &&
            id.digest() == payload.subrange(8,40) && #[trigger] identify.ensures((&r,),id) && payload != encoding(scheme,id,r),
        Error::Overflow => false,
    }
}

pub(super) fn recover<F:FnOnce(&ObjectRecord)->ObjectId>(payload:&[u8],scheme:Scheme,identify:F)
    -> (out:Result<(ObjectId,ObjectRecord),Error>)
    requires forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),
    ensures match out {
        Ok((id,r)) => wire::tag(payload@,0,scheme) && id.digest() == payload@.subrange(8,40) &&
            wire::record_at(payload@,40,scheme,r) && identify.ensures((&r,),id) && payload@ == encoding(scheme,id,r),
        Err(e) => refused(payload@,scheme,identify,e),
    },
{
    let (id,r) = match unpack(payload,scheme) {Ok(pair)=>pair,Err(e)=>return Err(Error::Decode(e))};
    let actual = identify(&r);
    if !actual.same(&id) {
        proof { if actual.digest() == id.digest() { ObjectId::same_digest(actual,id); } }
        return Err(Error::Identity);
    }
    let Ok(canonical) = wire::encode(scheme,id,&r) else {return Err(Error::Overflow);};
    if canonical.as_slice() != payload {return Err(Error::Canonical);}
    Ok((id,r))
}
pub(super) enum IndexError { Record(Error), Collision(ObjectId) }

pub(super) open spec fn agrees(a:ArenaLocation,b:ArenaLocation) -> bool {
    a.payload_len == b.payload_len && a.checksum == b.checksum
}

pub(super) open spec fn authenticated<F:FnOnce(&ObjectRecord)->ObjectId>(
    payload:Seq<u8>, scheme:Scheme, id:ObjectId, identify:F,
) -> bool {
    wire::tag(payload,0,scheme) && id.digest() == payload.subrange(8,40) &&
    exists|r:ObjectRecord| #[trigger] wire::record_at(payload,40,scheme,r) &&
        identify.ensures((&r,),id) && payload == encoding(scheme,id,r)
}

/// Preserve the first placement for a matching duplicate. A successful scan
/// still advances its physical tail to the frame just visited.
pub(super) fn index<F,H>(map:&mut BTreeMap<ObjectId,ArenaLocation>,offset:u64,payload:&[u8],
    scheme:Scheme,identify:F,checksum:H) -> (out:Result<ArenaLocation,IndexError>)
    where F:FnOnce(&ObjectRecord)->ObjectId,H:FnOnce(u64,&[u8])->[u8;32],
    requires btree_map_inv(old(map)),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),checksum.requires((payload.len() as u64,payload)),
    ensures btree_map_inv(final(map)), match out {
        Ok(loc) => loc.offset == offset && loc.payload_len == payload.len() &&
            checksum.ensures((loc.payload_len,payload),loc.checksum) &&
            exists|id:ObjectId| #[trigger] authenticated(payload@,scheme,id,identify) &&
                if old(map)@.contains_key(id) {agrees(old(map)@[id],loc) && final(map)@ == old(map)@}
                else { final(map)@ == old(map)@.insert(id,loc) },
        Err(IndexError::Collision(id)) => final(map)@ == old(map)@ && old(map)@.contains_key(id) &&
            authenticated(payload@,scheme,id,identify) &&
            exists|sum:[u8;32]| #[trigger] checksum.ensures((payload.len() as u64,payload),sum) &&
                (old(map)@[id].payload_len != payload.len() || old(map)@[id].checksum != sum),
        Err(IndexError::Record(e)) => final(map)@ == old(map)@ && refused(payload@,scheme,identify,e),
    },
{
    let (id,_record) = match recover(payload,scheme,identify) {Ok(pair)=>pair,Err(e)=>return Err(IndexError::Record(e))};
    assert(authenticated(payload@,scheme,id,identify));
    let Ok(len) = u64::try_from(payload.len()) else {return Err(IndexError::Record(Error::Overflow));};
    let sum = checksum(len,payload);
    let loc = ArenaLocation {offset,payload_len:len,checksum:sum};
    if let Some(prior) = map.get(&id) {
        if prior.payload_len != len || prior.checksum.as_slice() != sum.as_slice() {return Err(IndexError::Collision(id));}
        assert(prior.checksum =~= sum);
    } else {map.insert(id,loc);}
    Ok(loc)
}

}
