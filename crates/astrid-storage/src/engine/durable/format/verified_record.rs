//! Bind the canonical record returned by a decoder to the requested object.
use super::ReferenceKind;
use super::root_wire::{self, ReadError, Scheme};
use vstd::prelude::*;

verus! {

pub(super) enum TagError { Read(ReadError), LengthOverflow, Zero, Scheme, DigestLength }

pub(super) open spec fn tag(bytes:Seq<u8>,start:int,scheme:Scheme) -> bool {
    &&& 0 <= start && start + 40 <= bytes.len()
    &&& (scheme.algorithm[0] != 0 || scheme.algorithm[1] != 0) && (scheme.construction[0] != 0 || scheme.construction[1] != 0)
    &&& bytes.subrange(start,start+2) == scheme.algorithm@
    &&& bytes.subrange(start+2,start+4) == scheme.construction@
    &&& bytes.subrange(start+4,start+8) == seq![32u8,0u8,0u8,0u8]
}

/// Decode the tagged identity at the caller's cursor. A frame can have
/// additional fields after this identity.
#[expect(clippy::redundant_closure, reason = "Verus requires an explicit closure for enum constructors")]
pub(super) fn identity(bytes:&[u8],cursor:&mut usize,scheme:Scheme) -> (out:Result<[u8;32],TagError>)
    ensures out.is_ok() == tag(bytes@,*old(cursor) as int,scheme),
        out matches Ok(id) ==> *final(cursor) as int == *old(cursor) as int + 40 &&
            id@ == bytes@.subrange(*old(cursor) as int+8,*final(cursor) as int),
{
    let ghost start = *cursor as int;
    let algorithm = root_wire::fixed::<2>(bytes,cursor).map_err(|e| TagError::Read(e))?;
    let construction = root_wire::fixed::<2>(bytes,cursor).map_err(|e| TagError::Read(e))?;
    let length = root_wire::fixed::<4>(bytes,cursor).map_err(|e| TagError::Read(e))?;
    let width = [32u8,0,0,0];
    assert(width@ =~= seq![32u8,0u8,0u8,0u8]);
    let supported = length.as_slice() == width.as_slice();
    let size = if supported {32usize} else {
        let Ok(other) = usize::try_from(u32::from_le_bytes(length)) else {return Err(TagError::LengthOverflow);};
        other
    };
    assert(algorithm@ == bytes@.subrange(start,start+2));
    assert(construction@ == bytes@.subrange(start+2,start+4));
    assert(length@ == bytes@.subrange(start+4,start+8));
    if (algorithm[0] == 0 && algorithm[1] == 0) || (construction[0] == 0 && construction[1] == 0) || size == 0 {
        return Err(TagError::Zero);
    }
    let digest = root_wire::take(bytes,cursor,size).map_err(|e| TagError::Read(e))?;
    if algorithm.as_slice() != scheme.algorithm.as_slice() || construction.as_slice() != scheme.construction.as_slice() {
        return Err(TagError::Scheme);
    }
    assert(algorithm@ =~= scheme.algorithm@);
    assert(construction@ =~= scheme.construction@);
    if !supported {return Err(TagError::DigestLength);}
    assert(length@ =~= width@);
    let mut id = [0u8;32];
    id.copy_from_slice(digest);
    Ok(id)
}

pub(super) open spec fn wire(scheme:Scheme,id:[u8;32]) -> Seq<u8> {
    scheme.algorithm@ + scheme.construction@ + seq![32u8,0u8,0u8,0u8] + id@
}

pub(super) fn append_identity(bytes:&mut Vec<u8>,scheme:Scheme,id:[u8;32])
    ensures final(bytes)@ == old(bytes)@ + wire(scheme,id),
{
    bytes.extend_from_slice(&scheme.algorithm);
    bytes.extend_from_slice(&scheme.construction);
    bytes.extend_from_slice(&[32u8,0,0,0]);
    bytes.extend_from_slice(&id);
    assert(bytes@ =~= old(bytes)@ + wire(scheme,id));
}

pub(super) proof fn tag_written(bytes:Seq<u8>,at:int,scheme:Scheme,id:[u8;32])
    requires at >= 0,at+40 <= bytes.len(),bytes.subrange(at,at+40) == wire(scheme,id),
        scheme.algorithm@ != seq![0u8,0u8],scheme.construction@ != seq![0u8,0u8],
    ensures tag(bytes,at,scheme),bytes.subrange(at+8,at+40) == id@,
{
    root_wire::subfield(bytes,at,wire(scheme,id),0,2);
    root_wire::subfield(bytes,at,wire(scheme,id),2,2);
    root_wire::subfield(bytes,at,wire(scheme,id),4,4);
    root_wire::subfield(bytes,at,wire(scheme,id),8,32);
    assert(bytes.subrange(at,at+2) =~= scheme.algorithm@);
    assert(bytes.subrange(at+2,at+4) =~= scheme.construction@);
    assert(bytes.subrange(at+4,at+8) =~= seq![32u8,0u8,0u8,0u8]);
    assert(bytes.subrange(at+8,at+40) =~= id@);
    if scheme.algorithm[0]==0 && scheme.algorithm[1]==0 {assert(scheme.algorithm@ =~= seq![0u8,0u8]);}
    if scheme.construction[0]==0 && scheme.construction[1]==0 {assert(scheme.construction@ =~= seq![0u8,0u8]);}

}

pub(super) fn append_reference(bytes:&mut Vec<u8>,label:&[u8],scheme:Scheme,id:[u8;32],kind:ReferenceKind)
    -> (out:Result<(),()>)
    ensures out.is_ok(), final(bytes)@ == old(bytes)@ + vstd::bytes::spec_u64_to_le_bytes(label.len() as u64) +
        label@ + wire(scheme,id) + seq![match kind {ReferenceKind::Owns=>0u8,ReferenceKind::Evidence=>1u8,
            ReferenceKind::Lineage=>2u8,ReferenceKind::Derived=>3u8}],
{
    let length = u64::try_from(label.len()).map_err(|_| ())?;
    let field = root_wire::little_endian(length);
    bytes.extend_from_slice(&field);
    bytes.extend_from_slice(label);
    append_identity(bytes,scheme,id);
    let code = kind.code();
    bytes.push(code);
    assert(bytes@ =~= old(bytes)@ + field@ + label@ + wire(scheme,id) + seq![code]);
    Ok(())
}

pub(super) enum ReferenceError { Read(ReadError), Length, Target(TagError), Kind }

pub(super) open spec fn target_offset(bytes:Seq<u8>,start:int) -> int {
    start + 8 + vstd::bytes::spec_u64_from_le_bytes(bytes.subrange(start,start+8))
}

pub(super) open spec fn complete_reference(bytes:Seq<u8>,start:int,scheme:Scheme) -> bool {
    let target = target_offset(bytes,start);
    &&& 0 <= start && start+8 <= bytes.len()
    &&& tag(bytes,target,scheme)
    &&& target+40 < bytes.len()
    &&& bytes[target+40] <= 3
}

pub(super) open spec fn meaning(code:u8,kind:ReferenceKind) -> bool {
    match kind {ReferenceKind::Owns => code == 0,ReferenceKind::Evidence => code == 1,
        ReferenceKind::Lineage => code == 2,ReferenceKind::Derived => code == 3}
}

/// An object reference is a length-prefixed label, one typed identity and
/// one reachability code. The next reference starts at the returned cursor.
#[expect(clippy::redundant_closure, reason = "Verus requires explicit closures for enum constructors")]
pub(super) fn reference<'a>(bytes:&'a [u8],cursor:&mut usize,scheme:Scheme)
    -> (out:Result<(&'a [u8],[u8;32],ReferenceKind),ReferenceError>)
    ensures out.is_ok() == complete_reference(bytes@,*old(cursor) as int,scheme),
        out matches Ok((label,id,kind)) ==> {
            let target = target_offset(bytes@,*old(cursor) as int);
            &&& label@ == bytes@.subrange(*old(cursor) as int+8,target)
            &&& id@ == bytes@.subrange(target+8,target+40)
            &&& meaning(bytes@[target+40],kind)
            &&& *final(cursor) as int == target+41
        },
{
    let length = root_wire::fixed::<8>(bytes,cursor).map_err(|e| ReferenceError::Read(e))?;
    let size = usize::try_from(u64::from_le_bytes(length)).map_err(|_| ReferenceError::Length)?;
    let label = root_wire::take(bytes,cursor,size).map_err(|e| ReferenceError::Read(e))?;
    let target = identity(bytes,cursor,scheme).map_err(|e| ReferenceError::Target(e))?;
    let [code] = root_wire::fixed::<1>(bytes,cursor).map_err(|e| ReferenceError::Read(e))?;
    let kind = ReferenceKind::from_code(code).ok_or(ReferenceError::Kind)?;
    Ok((label,target,kind))
}

/// Position reached after the first i variable-size references.
pub(super) open spec fn position(bytes:Seq<u8>,start:int,i:nat) -> int
    decreases i,
{
    if i == 0 {start} else { target_offset(bytes,position(bytes,start,(i-1) as nat))+41 }
}

pub(super) open spec fn entry<R,F:Fn(&[u8],[u8;32],ReferenceKind)->R>(
    bytes:Seq<u8>,at:int,scheme:Scheme,pack:F,result:R) -> bool
{
    let target = target_offset(bytes,at);
    complete_reference(bytes,at,scheme) && exists|label:&[u8],id:[u8;32],kind:ReferenceKind|
        label@ == bytes.subrange(at+8,target) && id@ == bytes.subrange(target+8,target+40) &&
        meaning(bytes[target+40],kind) && #[trigger] pack.ensures((label,id,kind),result)
}

/// Fill the caller's reserved vector in physical order. No unconsumed
/// reference can be skipped by advancing directly to a later cursor.
pub(super) fn read_many<R,F>(bytes:&[u8],cursor:&mut usize,scheme:Scheme,count:usize,
    mut rows:Vec<R>,pack:F) -> (out:Result<Vec<R>,ReferenceError>)
    where F:Fn(&[u8],[u8;32],ReferenceKind)->R,
    requires rows.len() == 0, forall|l:&[u8],id:[u8;32],k:ReferenceKind| #[trigger] pack.requires((l,id,k)),
    ensures out.is_ok() == (forall|i:nat| i < count ==> complete_reference(bytes@,#[trigger] position(bytes@,*old(cursor) as int,i),scheme)),
        out matches Ok(v) ==> v.len() == count && *final(cursor) as int == position(bytes@,*old(cursor) as int,count as nat) &&
            forall|i:nat| i < count ==> #[trigger] entry(bytes@,position(bytes@,*old(cursor) as int,i),scheme,pack,v@[i as int]),
{
    let ghost start = *cursor as int;
    while rows.len() < count
        invariant rows.len() <= count,*cursor as int == position(bytes@,start,rows.len() as nat),
            start == *old(cursor) as int,
            forall|l:&[u8],id:[u8;32],k:ReferenceKind| #[trigger] pack.requires((l,id,k)),
            forall|i:nat| i < rows.len() ==> #[trigger] entry(bytes@,position(bytes@,start,i),scheme,pack,rows@[i as int]),
        decreases count - rows.len(),
    {
        let ghost i = rows.len() as nat;
        let ghost at = *cursor as int;
        let (label,id,kind) = match reference(bytes,cursor,scheme) {
            Ok(fields) => fields,
            Err(e) => {assert(!complete_reference(bytes@,position(bytes@,start,i),scheme));return Err(e);}
        };
        let value = pack(label,id,kind);
        assert(entry(bytes@,at,scheme,pack,value));
        rows.push(value);
    }
    assert forall|i:nat| i < count implies complete_reference(bytes@,#[trigger] position(bytes@,start,i),scheme) by {
        assert(entry(bytes@,position(bytes@,start,i),scheme,pack,rows@[i as int]));
    }
    Ok(rows)
}

pub(super) enum DecodeError<E> { Tag(TagError), Record(E) }

/// The body decoder receives the original frame and the offset immediately
/// following its embedded object name.
pub(super) fn decode<R,E,D>(payload:&[u8],scheme:Scheme,body:D) -> (out:Result<([u8;32],R),DecodeError<E>>)
    where D:FnOnce(&[u8],usize)->Result<R,E>,
    requires tag(payload@,0,scheme) ==> body.requires((payload,40usize)),
    ensures match out {
        Ok((id,r)) => tag(payload@,0,scheme) && id@ == payload@.subrange(8,40) && body.ensures((payload,40usize),Ok(r)),
        Err(DecodeError::Tag(_)) => !tag(payload@,0,scheme),
        Err(DecodeError::Record(e)) => tag(payload@,0,scheme) && body.ensures((payload,40usize),Err(e)),
    },
{
    let mut cursor = 0;
    let id = match identity(payload,&mut cursor,scheme) {
        Ok(id) => id, Err(e) => return Err(DecodeError::Tag(e)),
    };
    match body(payload,cursor) {
        Ok(record) => Ok((id,record)), Err(e) => Err(DecodeError::Record(e)),
    }
}

pub(super) enum Error<E> { Decode(DecodeError<E>), Identifier, Identity }

/// Check the embedded name before invoking the identity algorithm on the
/// decoded record. Both indexed arena readers use this return value.
pub(super) fn read<R,E,D,H>(payload:&[u8],scheme:Scheme,expected:[u8;32],body:D,identify:H)
    -> (out:Result<R,Error<E>>)
    where D:FnOnce(&[u8],usize)->Result<R,E>, H:FnOnce(&R)->[u8;32],
    requires tag(payload@,0,scheme) ==> body.requires((payload,40usize)),
        forall|r:&R| #[trigger] identify.requires((r,)),
    ensures match out {
        Ok(r) => tag(payload@,0,scheme) && expected@ == payload@.subrange(8,40) &&
            body.ensures((payload,40usize),Ok(r)) && identify.ensures((&r,),expected),
        Err(Error::Decode(DecodeError::Tag(_))) => !tag(payload@,0,scheme),
        Err(Error::Decode(DecodeError::Record(e))) => tag(payload@,0,scheme) && body.ensures((payload,40usize),Err(e)),
        Err(Error::Identifier) => tag(payload@,0,scheme) && expected@ != payload@.subrange(8,40) &&
            exists|r:R| #[trigger] body.ensures((payload,40usize),Ok(r)),
        Err(Error::Identity) => tag(payload@,0,scheme) && expected@ == payload@.subrange(8,40) &&
            exists|r:R,actual:[u8;32]| actual@ != expected@ &&
            body.ensures((payload,40usize),Ok(r)) && #[trigger] identify.ensures((&r,),actual),
    },
{
    let (tag,record) = match decode(payload,scheme,body) {
        Ok(pair) => pair, Err(e) => return Err(Error::Decode(e)),
    };
    if tag.as_slice() != expected.as_slice() {return Err(Error::Identifier);}
    assert(tag =~= expected);
    let computed = identify(&record);
    if computed.as_slice() != expected.as_slice() {return Err(Error::Identity);}
    assert(computed =~= expected);
    Ok(record)
}

}
