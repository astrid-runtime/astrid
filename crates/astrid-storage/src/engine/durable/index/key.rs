//! Decode the scheme and object name carried by an index checkpoint.
use super::root_wire::{self, ReadError, Scheme};
use super::{ArenaLocation, ObjectId};
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

verus! {

#[derive(Clone, Copy)]
pub(super) enum Error {
    Read(ReadError),
    ZeroScheme,
    WrongScheme,
    LengthOverflow,
    ZeroLength,
    WrongLength,
    Order,
    Capacity,
}

fn read_error(error: ReadError) -> Error { Error::Read(error) }

pub(super) open spec fn scheme_at(bytes:Seq<u8>, start:int, expected:Scheme) -> bool {
    &&& root_wire::at(bytes,start,expected.algorithm@ + expected.construction@)
    &&& (expected.algorithm[0] != 0 || expected.algorithm[1] != 0)
    &&& (expected.construction[0] != 0 || expected.construction[1] != 0)
}

pub(super) fn read_scheme(bytes:&[u8], cursor:&mut usize, expected:Scheme) -> (out:Result<(),Error>)
    ensures out.is_ok() == scheme_at(bytes@,*old(cursor) as int,expected),
        out.is_ok() ==> *final(cursor) as int == *old(cursor) as int + 4,
{
    let ghost start = *cursor as int;
    let algorithm = root_wire::fixed::<2>(bytes,cursor).map_err(read_error)?;
    let construction = root_wire::fixed::<2>(bytes,cursor).map_err(read_error)?;
    proof {
        assert(bytes@.subrange(start,start+4) =~= algorithm@ + construction@);
        if scheme_at(bytes@,start,expected) {
            root_wire::subfield(bytes@,start,expected.algorithm@ + expected.construction@,0,2);
            root_wire::subfield(bytes@,start,expected.algorithm@ + expected.construction@,2,2);
            assert(algorithm@ =~= expected.algorithm@);
            assert(construction@ =~= expected.construction@);
        }
    }
    if (algorithm[0] == 0 && algorithm[1] == 0) || (construction[0] == 0 && construction[1] == 0) {
        return Err(Error::ZeroScheme);
    }
    if algorithm.as_slice() != expected.algorithm.as_slice() ||
        construction.as_slice() != expected.construction.as_slice() {
        return Err(Error::WrongScheme);
    }
    assert(algorithm@ =~= expected.algorithm@);
    assert(construction@ =~= expected.construction@);
    Ok(())
}

pub(super) open spec fn key_at(bytes:Seq<u8>, start:int, scheme:Scheme) -> bool {
    scheme_at(bytes,start,scheme) && start+40 <= bytes.len() &&
        bytes.subrange(start+4,start+8) == seq![32u8,0u8,0u8,0u8]
}

pub(super) fn decode(bytes:&[u8], cursor:&mut usize, scheme:Scheme) -> (out:Result<ObjectId,Error>)
    ensures out.is_ok() == key_at(bytes@,*old(cursor) as int,scheme),
        out matches Ok(id) ==> *final(cursor) as int == *old(cursor) as int + 40 &&
            id.digest() == bytes@.subrange(*old(cursor) as int+8,*final(cursor) as int),
{
    read_scheme(bytes,cursor,scheme)?;
    let field = root_wire::fixed::<4>(bytes,cursor).map_err(read_error)?;
    let width = [32u8,0,0,0];
    assert(width@ =~= seq![32u8,0u8,0u8,0u8]);
    let supported = field.as_slice() == width.as_slice();
    let size = if supported {32usize} else {
        let Ok(length) = usize::try_from(u32::from_le_bytes(field)) else {return Err(Error::LengthOverflow);};
        length
    };
    if size == 0 {return Err(Error::ZeroLength);}
    let digest = root_wire::take(bytes,cursor,size).map_err(read_error)?;
    if !supported {return Err(Error::WrongLength);}
    assert(field@ =~= width@);
    let mut id = [0;32];
    id.copy_from_slice(digest);
    Ok(ObjectId::new(id))
}

/// Check the key before consuming its location, preserving the checkpoint error order.
pub(super) fn row(bytes:&[u8], cursor:&mut usize, scheme:Scheme, previous:Option<ObjectId>)
    -> (out:Result<(ObjectId,ArenaLocation),Error>)
    ensures
        out matches Ok((id,loc)) ==> {
            let start = *old(cursor) as int;
            &&& *final(cursor) as int == start + 88
            &&& key_at(bytes@,start,scheme) && id.digest() == bytes@.subrange(start+8,start+40)
            &&& previous matches Some(prior) ==> ObjectId::digest_before(prior.digest(),id.digest())
            &&& loc.wire() == bytes@.subrange(start+40,start+88)
        },
        out.is_ok() == ({
            let start = *old(cursor) as int;
            &&& key_at(bytes@,start,scheme) && start + 88 <= bytes.len()
            &&& previous matches Some(prior) ==> ObjectId::digest_before(prior.digest(),bytes@.subrange(start+8,start+40))
        }),
{
    let id = decode(bytes,cursor,scheme)?;
    let ordered = match previous {
        Some(prior) => prior.strictly_before(&id),
        None => true,
    };
    if !ordered {return Err(Error::Order);}
    let field = root_wire::take(bytes,cursor,ArenaLocation::ENCODED_LEN).map_err(read_error)?;
    let Some(loc) = ArenaLocation::decode(field) else {return Err(Error::Read(ReadError::Truncated));};
    Ok((id,loc))
}

/// Each checkpoint entry consists of a tagged name followed by its location.
pub(super) const ROW_LEN:usize = 40 + ArenaLocation::ENCODED_LEN;

pub(super) open spec fn mapped(bytes:Seq<u8>,start:int,count:nat,map:Map<ObjectId,ArenaLocation>) -> bool
    decreases count,
{
    if count == 0 { map == Map::<ObjectId,ArenaLocation>::empty() } else {
        let at = start + (count-1)*ROW_LEN;
        exists|prior:Map<ObjectId,ArenaLocation>,id:ObjectId,loc:ArenaLocation|
            mapped(bytes,start,(count-1) as nat,prior) &&
            id.digest() == bytes.subrange(at+8,at+40) && loc.wire() == bytes.subrange(at+40,at+88) &&
            map == #[trigger] prior.insert(id,loc)
    }
}

pub(super) open spec fn ordered_row(bytes:Seq<u8>,start:int,i:int,scheme:Scheme) -> bool {
    let at = start+i*ROW_LEN;
    &&& key_at(bytes,at,scheme) && at + ROW_LEN <= bytes.len()
    &&& i > 0 ==> ObjectId::digest_before(bytes.subrange(at-80,at-48),bytes.subrange(at+8,at+40))
}

pub(super) fn rows(bytes:&[u8], cursor:&mut usize, count:usize, scheme:Scheme)
    -> (out:Result<BTreeMap<ObjectId,ArenaLocation>,Error>)
    requires *old(cursor) <= bytes.len(), obeys_cmp::<ObjectId>(), obeys_cmp_concrete_eq::<ObjectId>(),
    ensures
        out matches Ok(map) ==> btree_map_inv(&map) && *final(cursor)<=bytes.len() &&
            *final(cursor) as int == *old(cursor) as int + count as int*ROW_LEN &&
            mapped(bytes@,*old(cursor) as int,count as nat,map@) &&
            (forall|i:int| 0 <= i < count ==> #[trigger] ordered_row(bytes@,*old(cursor) as int,i,scheme)),
        (forall|i:int| 0 <= i < count ==> #[trigger] ordered_row(bytes@,*old(cursor) as int,i,scheme)) ==> out.is_ok(),
{
    let start = *cursor;
    if count > bytes.len().saturating_sub(start)/ROW_LEN {
        proof {
            if count > 0 {
                let last = count as int-1;
                assert(start as int + last*88 + 88 > bytes.len()) by(nonlinear_arith)
                    requires last == count as int-1, start <= bytes.len(),
                        count > (bytes.len()-start)/88;
                assert(!ordered_row(bytes@,start as int,last,scheme));
            }
        }
        return Err(Error::Capacity);
    }
    let mut map = BTreeMap::new();
    let mut previous:Option<ObjectId> = None;
    let mut i = 0usize;
    while i < count
        invariant
            ROW_LEN == 88, i <= count, *cursor<=bytes.len(), start == *old(cursor), start <= bytes.len(), *cursor as int == start as int + i as int*ROW_LEN,
            btree_map_inv(&map), obeys_cmp::<ObjectId>(), obeys_cmp_concrete_eq::<ObjectId>(),
            previous.is_some() == (i > 0),
            previous matches Some(id) ==> id.digest() == bytes@.subrange(*cursor as int-80,*cursor as int-48),
            mapped(bytes@,start as int,i as nat,map@),
            forall|j:int| 0 <= j < i ==> #[trigger] ordered_row(bytes@,start as int,j,scheme),
        decreases count-i,
    {
        let ghost prior = map@;
        let ghost at = *cursor as int;
        let parsed = row(bytes,cursor,scheme,previous);
        let (id,loc) = match parsed {
            Ok(pair) => pair,
            Err(error) => {
                proof {
                    if ordered_row(bytes@,start as int,i as int,scheme) {
                        if let Some(prior) = previous {
                            assert(ObjectId::digest_before(prior.digest(),bytes@.subrange(at+8,at+40)));
                        }
                        assert(false);
                    }
                }
                return Err(error);
            },
        };
        assert(*cursor as int == at+88);
        assert(*cursor as int == start as int + (i as int+1)*88);
        proof {
            assert(ordered_row(bytes@,start as int,i as int,scheme));
        }
        map.insert(id,loc);
        proof {
            assert(exists|p:Map<ObjectId,ArenaLocation>,k:ObjectId,l:ArenaLocation|
                mapped(bytes@,start as int,i as nat,p) &&
                k.digest() == bytes@.subrange(at+8,at+40) && l.wire() == bytes@.subrange(at+40,at+88) &&
                map@ == #[trigger] p.insert(k,l)) by {assert(map@ == prior.insert(id,loc));}
            assert(mapped(bytes@,start as int,(i+1) as nat,map@));
        }
        previous = Some(id);
        i = i.saturating_add(1);
    }
    Ok(map)
}

}
