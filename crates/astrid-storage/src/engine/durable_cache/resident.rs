//! Retain the physical record and principal entry together while updating their recency.
use super::{ObjectId, ObjectRecord};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::{btree_map_inv, btree_set_inv},
};

verus! {
pub(super) struct CachedObject<M> {
    pub(super) record:Arc<ObjectRecord>,
    pub(super) weight:u64,
    pub(super) last_access:u64,
    pub(super) principals:M,
}

pub(super) struct PrincipalEntry<V> {
    pub(super) last_access:u64,
    pub(super) projections:V,
}

pub(super) struct Partition<V> {
    pub(super) entries:BTreeMap<ObjectId,PrincipalEntry<V>>,
    pub(super) lru:BTreeSet<(u64,ObjectId)>,
    pub(super) charged_bytes:u64,
}

fn partition<'a,P:Ord,V>(map:&'a mut BTreeMap<Arc<P>,V>,p:&P) -> (out:Option<&'a mut V>)
    requires btree_map_inv(old(map)),obeys_cmp::<Arc<P>>(),obeys_cmp::<&P>(),obeys_cmp_concrete_eq::<&P>(),obeys_cmp_concrete_eq::<P>(),
        vstd::std_specs::cmp::borrowed_key_ordering_matches::<Arc<P>,P>(),
    ensures btree_map_inv(final(map)),match out {
        None => final(map)@ == old(map)@ && forall|key:Arc<P>| #[trigger] old(map)@.contains_key(key) ==> *key != *p,
        Some(v) => exists|key:Arc<P>| #[trigger] old(map)@.contains_key(key) && *key == *p &&
            *v == old(map)@[key] && final(map)@ == old(map)@.insert(key,*final(v)),
    },
{
    map.get_mut(p)
}

pub(super) fn install<M>(objects:&mut BTreeMap<ObjectId,CachedObject<M>>,id:ObjectId,
    record:Arc<ObjectRecord>,weight:u64,tick:u64,members:M)
    requires btree_map_inv(old(objects)),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
    ensures btree_map_inv(final(objects)),final(objects)@ == old(objects)@.insert(id,
        CachedObject {record,weight,last_access:tick,principals:members}),
{
    objects.insert(id,CachedObject {record,weight,last_access:tick,principals:members});
}

type Recency = BTreeSet<(u64,ObjectId)>;

pub(super) open spec fn next(tick:u64) -> u64 { if tick == u64::MAX {tick} else {(tick+1) as u64} }

fn touch<M,V,F>(id:ObjectId,objects:&mut BTreeMap<ObjectId,CachedObject<M>>,
    owner:&mut BTreeMap<ObjectId,PrincipalEntry<V>>,clock:&mut u64,global_lru:&mut Recency,
    owner_lru:&mut Recency,check:F) -> (out:Option<Arc<ObjectRecord>>)
    where F:FnOnce(&M),
    requires btree_map_inv(old(objects)),btree_map_inv(old(owner)),btree_set_inv(old(global_lru)),btree_set_inv(old(owner_lru)),
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        obeys_cmp::<(u64,ObjectId)>(),obeys_cmp_concrete_eq::<(u64,ObjectId)>(),
        old(objects)@.contains_key(id) && old(owner)@.contains_key(id) ==> check.requires((&old(objects)@[id].principals,)),
    ensures btree_map_inv(final(objects)),btree_map_inv(final(owner)),btree_set_inv(final(global_lru)),btree_set_inv(final(owner_lru)),
        ({
            if old(objects)@.contains_key(id) && old(owner)@.contains_key(id) {
                let entry = old(objects)@[id]; let account = old(owner)@[id]; let tick = next(*old(clock));
                &&& out == Some(entry.record) && *final(clock) == tick
                &&& final(objects)@ == old(objects)@.insert(id,CachedObject {last_access:tick,..entry})
                &&& final(owner)@ == old(owner)@.insert(id,PrincipalEntry {last_access:tick,..account})
                &&& final(global_lru)@ == old(global_lru)@.remove((entry.last_access,id)).insert((tick,id))
                &&& final(owner_lru)@ == old(owner_lru)@.remove((account.last_access,id)).insert((tick,id))
            } else {
                &&& out.is_none() && *final(clock) == *old(clock)
                &&& final(objects)@ == old(objects)@ && final(owner)@ == old(owner)@
                &&& final(global_lru)@ == old(global_lru)@ && final(owner_lru)@ == old(owner_lru)@
            }
        }),
{
    let account = owner.get_mut(&id)?;
    let entry = objects.get_mut(&id)?;
    check(&entry.principals);
    let tick = clock.saturating_add(1);
    *clock = tick;
    let old_tick = entry.last_access;
    entry.last_access = tick;
    global_lru.remove(&(old_tick,id));
    global_lru.insert((tick,id));
    let old_tick = account.last_access;
    account.last_access = tick;
    owner_lru.remove(&(old_tick,id));
    owner_lru.insert((tick,id));
    Some(Arc::clone(&entry.record))
}

pub(super) open spec fn member<P,V>(partitions:Map<Arc<P>,Partition<V>>,owner:P,id:ObjectId) -> bool {
    exists|key:Arc<P>| #[trigger] partitions.contains_key(key) && *key == owner &&
        partitions[key].entries@.contains_key(id)
}

pub(super) open spec fn account_after<V>(before:Partition<V>,after:Partition<V>,id:ObjectId,tick:Option<u64>) -> bool {
    &&& after.charged_bytes == before.charged_bytes
    &&& match tick {
        None => after.entries@ == before.entries@ && after.lru@ == before.lru@,
        Some(t) => before.entries@.contains_key(id) && ({
            let old = before.entries@[id];
            &&& after.entries@ == before.entries@.insert(id,PrincipalEntry {last_access:t,..old})
            &&& after.lru@ == before.lru@.remove((old.last_access,id)).insert((t,id))
        }),
    }
}

pub(super) fn visit<P:Ord,M,V,F>(owner:&P,id:ObjectId,partitions:&mut BTreeMap<Arc<P>,Partition<V>>,
    objects:&mut BTreeMap<ObjectId,CachedObject<M>>,clock:&mut u64,global_lru:&mut Recency,check:F)
    -> (out:Option<Arc<ObjectRecord>>)
    where F:FnOnce(&M),
    requires btree_map_inv(old(partitions)),btree_map_inv(old(objects)),btree_set_inv(old(global_lru)),
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),obeys_cmp::<(u64,ObjectId)>(),
        obeys_cmp_concrete_eq::<(u64,ObjectId)>(),obeys_cmp::<Arc<P>>(),obeys_cmp::<&P>(),obeys_cmp_concrete_eq::<&P>(),
        obeys_cmp_concrete_eq::<P>(),vstd::std_specs::cmp::borrowed_key_ordering_matches::<Arc<P>,P>(),
        forall|key:Arc<P>| #[trigger] old(partitions)@.contains_key(key) && *key == *owner ==>
            btree_map_inv(&old(partitions)@[key].entries) && btree_set_inv(&old(partitions)@[key].lru),
        old(objects)@.contains_key(id) && member(old(partitions)@,*owner,id) ==> check.requires((&old(objects)@[id].principals,)),
    ensures btree_map_inv(final(partitions)),btree_map_inv(final(objects)),btree_set_inv(final(global_lru)),
        out == if old(objects)@.contains_key(id) && member(old(partitions)@,*owner,id) {
            Some(old(objects)@[id].record)
        } else { None },
        final(objects)@.dom() == old(objects)@.dom(),
        forall|k:ObjectId| #[trigger] final(objects)@.contains_key(k) ==> final(objects)@[k].record == old(objects)@[k].record,
        out.is_none() ==> final(objects)@ == old(objects)@ &&
            *final(clock) == *old(clock) && final(global_lru)@ == old(global_lru)@,
        out.is_some() ==> *final(clock) == next(*old(clock)),
        final(partitions)@.dom() == old(partitions)@.dom(),
        forall|peer:Arc<P>| #[trigger] old(partitions)@.contains_key(peer) ==> (
            if *peer != *owner { final(partitions)@[peer] == old(partitions)@[peer] }
            else {account_after(old(partitions)@[peer],final(partitions)@[peer],id,
                if out.is_some() {Some(*final(clock))} else {None})}
        ),
{
    let Some(part) = partition(partitions,owner) else {
        assert(!member(old(partitions)@,*owner,id));
        return None;
    };
    let ghost key = choose|k:Arc<P>| #[trigger] old(partitions)@.contains_key(k) && *k == *owner && *part == old(partitions)@[k];
    proof { if part.entries@.contains_key(id) {assert(member(old(partitions)@,*owner,id));} }
    let ghost before = *part;
    let result = touch(id,objects,&mut part.entries,clock,global_lru,&mut part.lru,check);
    assert(account_after(before,*part,id,if result.is_some() {Some(*clock)} else {None}));
    assert(partitions@.dom() =~= old(partitions)@.dom());
    result
}

}

impl<V> Default for Partition<V> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            lru: BTreeSet::new(),
            charged_bytes: 0,
        }
    }
}
