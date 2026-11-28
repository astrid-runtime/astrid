//! Publish arena placements to the live lookup and checkpoint delta together.
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

verus! {

pub(super) fn publish<K:Ord+Copy,L:Copy>(
    index:&mut BTreeMap<K,L>, delta:&mut Vec<(K,L)>, key:K, location:L,
)
    requires btree_map_inv(old(index)), obeys_cmp::<K>(), obeys_cmp_concrete_eq::<K>(),
    ensures btree_map_inv(final(index)), final(index)@ == old(index)@.insert(key,location),
        final(delta)@ == old(delta)@.push((key,location)),
{
    index.insert(key,location);
    delta.push((key,location));
}

/// Repeated ids retain the last placement in the lookup. The delta records
/// each append in order, including earlier placements for a repeated id.
pub(super) open spec fn applied<K,L>(initial:Map<K,L>, keys:Seq<K>, locations:Seq<L>, n:nat) -> Map<K,L>
    decreases n,
{
    if n == 0 { initial } else {
        applied(initial,keys,locations,(n-1) as nat).insert(keys[n-1],locations[n-1])
    }
}

pub(super) fn publish_batch<K:Ord+Copy,L:Copy>(
    index:&mut BTreeMap<K,L>, delta:&mut Vec<(K,L)>, keys:&[K], locations:&[L],
) -> (ok:bool)
    requires btree_map_inv(old(index)), obeys_cmp::<K>(), obeys_cmp_concrete_eq::<K>(),
    ensures btree_map_inv(final(index)), ok == (keys.len() == locations.len()),
        if ok {
            &&& final(index)@ == applied(old(index)@,keys@,locations@,keys@.len())
            &&& final(delta)@ == old(delta)@ + Seq::new(keys@.len(),|i:int| (keys@[i],locations@[i]))
        } else {final(index)@ == old(index)@ && final(delta)@ == old(delta)@},
{
    if keys.len() != locations.len() {return false;}
    let mut i = 0usize;
    while i < keys.len()
        invariant obeys_cmp::<K>(), obeys_cmp_concrete_eq::<K>(), i <= keys.len() == locations.len(), btree_map_inv(index),
            index@ == applied(old(index)@,keys@,locations@,i as nat),
            delta@ == old(delta)@ + Seq::new(i as nat,|j:int| (keys@[j],locations@[j])),
        decreases keys.len()-i,
    {
        publish(index,delta,keys[i],locations[i]);
        assert(delta@ =~= old(delta)@ + Seq::new((i+1) as nat,|j:int| (keys@[j],locations@[j])));
        i = i.saturating_add(1);
    }
    true
}

/// A replayed checkpoint delta may repeat a mapping but cannot move an existing name.
pub(super) fn restore_location<K:Ord+Copy>(
    index:&mut BTreeMap<K,super::arena_frame::ArenaLocation>, key:K, loc:super::arena_frame::ArenaLocation,
) -> (accepted:bool)
    requires btree_map_inv(old(index)), obeys_cmp::<K>(), obeys_cmp_concrete_eq::<K>(),
    ensures btree_map_inv(final(index)),
        accepted == (!old(index)@.contains_key(key) || old(index)@[key] == loc),
        final(index)@ == if accepted {old(index)@.insert(key,loc)} else {old(index)@},
{
    if let Some(previous) = index.get(&key) {
        if previous.offset != loc.offset || previous.payload_len != loc.payload_len ||
            previous.checksum.as_slice() != loc.checksum.as_slice() {
            return false;
        }
        assert(previous.checksum@ =~= loc.checksum@);
        assert(previous.checksum == loc.checksum);
        assert(*previous == loc);
        assert(index@ =~= old(index)@.insert(key,loc));
        true
    } else {
        index.insert(key,loc);
        true
    }
}

/// Resolve both placement fields for the same immutable object name.
pub(super) fn placement<'a,K:Ord+Copy,L:Copy,D>(
    key:K,index:&BTreeMap<K,L>,direct:&'a BTreeMap<K,D>,
) -> (out:Option<(L,Option<&'a D>)>)
    requires obeys_cmp::<K>(),obeys_cmp_concrete_eq::<K>(),btree_map_inv(index),btree_map_inv(direct),
    ensures out.is_some() == index@.contains_key(key),
        out matches Some((location,metadata)) ==> location == index@[key] &&
            metadata.is_some() == direct@.contains_key(key) &&
            (metadata matches Some(d) ==> *d == direct@[key]),
{
    let location = *index.get(&key)?;
    Some((location,direct.get(&key)))
}

}
