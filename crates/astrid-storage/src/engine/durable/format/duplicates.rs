//! Verify unindexed arena intervals as exact copies of earlier indexed frames.
use super::{ArenaLocation, ObjectId, root_wire::Scheme, verified_record};
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

verus! {

pub(crate) open spec fn fits(frames:vstd::imap::IMap<u64,Seq<u8>>,at:u64,end:u64) -> bool {
    frames.contains_key(at) && at as int + 52 + frames[at].len() <= end
}

pub(crate) trait Media {
    spec fn frames(&self) -> vstd::imap::IMap<u64,Seq<u8>>;
    spec fn dependable(&self) -> bool;
    fn bounded(&mut self,at:u64,end:u64) -> (out:Option<Vec<u8>>)
        ensures final(self).frames() == old(self).frames(), final(self).dependable() == old(self).dependable(),
            out matches Some(v) ==> fits(old(self).frames(),at,end) && v@ == old(self).frames()[at],
            old(self).dependable() && fits(old(self).frames(),at,end) ==> out.is_some();
}

pub(crate) open spec fn named(bytes:Seq<u8>,scheme:Scheme,id:ObjectId) -> bool {
    verified_record::tag(bytes,0,scheme) && id.digest() == bytes.subrange(8,40)
}

pub(crate) open spec fn copy_of(frames:vstd::imap::IMap<u64,Seq<u8>>,map:Map<ObjectId,ArenaLocation>,
    scheme:Scheme,at:u64,id:ObjectId) -> bool {
    let loc = map[id];
    &&& frames.contains_key(at) && named(frames[at],scheme,id) && map.contains_key(id)
    &&& loc.offset < at && loc.payload_len == frames[at].len()
    &&& fits(frames,loc.offset,at) && frames[loc.offset] == frames[at]
}

pub(crate) open spec fn tiled(frames:vstd::imap::IMap<u64,Seq<u8>>,map:Map<ObjectId,ArenaLocation>,
    scheme:Scheme,at:u64,end:u64) -> bool
    decreases (end as int - at as int) as nat
{
    if at == end {true} else if at > end || !fits(frames,at,end) {false}
    else {(exists|id:ObjectId| #[trigger] copy_of(frames,map,scheme,at,id)) &&
        tiled(frames,map,scheme,(at as int+52+frames[at].len()) as u64,end)}
}

/// Object ids are injective in their complete digest; a different map key
/// cannot witness the same tagged bytes at this physical offset.
proof fn only_key(frames:vstd::imap::IMap<u64,Seq<u8>>,map:Map<ObjectId,ArenaLocation>,scheme:Scheme,at:u64,id:ObjectId)
    requires named(frames[at],scheme,id),
    ensures (exists|k:ObjectId| #[trigger] copy_of(frames,map,scheme,at,k)) ==> copy_of(frames,map,scheme,at,id),
{
    if exists|k:ObjectId| #[trigger] copy_of(frames,map,scheme,at,k) {
        let k = choose|k:ObjectId| #[trigger] copy_of(frames,map,scheme,at,k);
        ObjectId::same_digest(id,k);
    }
}

pub(crate) fn check<R:Media>(arena:&mut R,map:&BTreeMap<ObjectId,ArenaLocation>,scheme:Scheme,start:u64,end:u64)
    -> (ok:bool)
    requires btree_map_inv(map),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
    ensures ok ==> tiled(old(arena).frames(),map@,scheme,start,end),
        old(arena).dependable() && tiled(old(arena).frames(),map@,scheme,start,end) ==> ok,
        final(arena).frames() == old(arena).frames(), final(arena).dependable() == old(arena).dependable(),
{
    if start > end {return false;}
    let mut cursor = start;
    while cursor < end
        invariant btree_map_inv(map),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
            start <= cursor <= end, arena.frames() == old(arena).frames(), arena.dependable() == old(arena).dependable(),
            tiled(arena.frames(),map@,scheme,start,end) == tiled(arena.frames(),map@,scheme,cursor,end),
        decreases end-cursor,
    {
        let Some(copy) = arena.bounded(cursor,end) else {return false;};
        let mut pos = 0usize;
        let Ok(name) = verified_record::identity(&copy,&mut pos,scheme) else {return false;};
        let id = ObjectId::new(name);
        proof {only_key(arena.frames(),map@,scheme,cursor,id);}
        let Some(first) = map.get(&id) else {return false;};
        let length = copy.len() as u64;
        if first.offset >= cursor || first.payload_len != length {return false;}
        let Some(original) = arena.bounded(first.offset,cursor) else {return false;};
        if original.as_slice() != copy.as_slice() {return false;}
        assert(original@ =~= copy@);
        assert(copy_of(arena.frames(),map@,scheme,cursor,id));
        let Some(body) = cursor.checked_add(52) else {return false;};
        let Some(next) = body.checked_add(length) else {return false;};
        cursor = next;
    }
    true
}

}
