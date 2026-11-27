//! Reconcile every candidate mapping and the tail with the authoritative arena.
use super::{ArenaLocation, ObjectId};
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::{btree::btree_map_inv, iter::IteratorSpec},
};

verus! {

/// Recovered disposable object-location state.
pub(super) struct IndexState<M = BTreeMap<ObjectId, ArenaLocation>> {
    pub(super) arena_len: u64,
    pub(super) arena_tail: Option<ArenaLocation>,
    pub(super) objects: M,
}

impl IndexState {
    pub(super) fn validated<A:Arena>(candidate:Option<Self>, complete:bool, measured:u64, arena:&mut A)
        -> (out:Option<Self>)
        requires candidate matches Some(s) ==> btree_map_inv(&s.objects),
            obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        ensures out matches Some(s) ==> complete && candidate == Some(s) &&
                consistent(s.objects@,s.arena_tail,s.arena_len,measured,old(arena).entries(),old(arena).tails()),
            complete && old(arena).reliable() && (candidate matches Some(s) &&
                consistent(s.objects@,s.arena_tail,s.arena_len,measured,old(arena).entries(),old(arena).tails())) ==> out.is_some(),
    {
        if !complete {return None;}
        let state = candidate?;
        if accept(&state.objects,state.arena_tail,state.arena_len,measured,arena) {Some(state)} else {None}
    }
}

pub(super) trait Arena {
    spec fn entries(&self) -> vstd::iset::ISet<(ObjectId,ArenaLocation)>;
    spec fn tails(&self) -> Set<ArenaLocation>;
    spec fn reliable(&self) -> bool;
    fn entry(&mut self, id:ObjectId, loc:ArenaLocation) -> (ok:bool)
        ensures final(self).entries() == old(self).entries(), final(self).tails() == old(self).tails(),
            final(self).reliable() == old(self).reliable(), ok ==> old(self).entries().contains((id,loc)),
            old(self).reliable() && old(self).entries().contains((id,loc)) ==> ok;
    fn tail(&mut self, loc:ArenaLocation) -> (ok:bool)
        ensures ok ==> old(self).tails().contains(loc),
            old(self).reliable() && old(self).tails().contains(loc) ==> ok;
}

fn offset(pair:&(ObjectId,ArenaLocation)) -> (at:u64)
    ensures at == pair.1.offset,
{ pair.1.offset }

/// Physically ordered validation keeps recovery reads sequential. Sorting must
/// retain every (object, location) pair obtained from the checkpoint map.
fn physical_order(map:&BTreeMap<ObjectId,ArenaLocation>) -> (out:Vec<(ObjectId,ArenaLocation)>)
    requires btree_map_inv(map),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
    ensures out@.to_set() == map@.kv_pairs(), out.len() == map.len(),
{
    let mut it = map.iter();
    let ghost sequence = it.remaining();
    let mut items = Vec::with_capacity(map.len());
    while items.len() < map.len()
        invariant sequence.len() == map.len(), items.len() <= map.len(),
            it.remaining() == sequence.skip(items.len() as int),
            items@ == sequence.unref().take(items.len() as int),
            sequence.unref().to_set() == map@.kv_pairs(),
        decreases map.len()-items.len(),
    {
        let ghost i = items.len() as int;
        let Some((id,loc)) = it.next() else {unreachable!()};
        items.push((*id,*loc));
        assert(it.remaining() =~= sequence.skip(i+1));
        assert(items@ =~= sequence.unref().take(i+1));
    }
    assert(items@ =~= sequence.unref());
    let ghost before = items@;
    assert(vstd::std_specs::slice::key_fn_deterministic_on(offset,before));
    items.as_mut_slice().sort_by_key(offset);
    proof {
        broadcast use vstd::seq_lib::to_multiset_contains;
        items@.to_set_ensures();
        before.to_set_ensures();
        assert forall|p:(ObjectId,ArenaLocation)| #[trigger] items@.to_set().contains(p) == before.to_set().contains(p) by {
            assert(items@.to_multiset().count(p) == before.to_multiset().count(p));
        }
        assert(items@.to_set() =~= before.to_set());
    }
    items
}

pub(super) open spec fn consistent(map:Map<ObjectId,ArenaLocation>, tail:Option<ArenaLocation>,
    covered:u64, measured:u64, entries:vstd::iset::ISet<(ObjectId,ArenaLocation)>, tails:Set<ArenaLocation>) -> bool {
    &&& covered == measured
    &&& forall|p:(ObjectId,ArenaLocation)| #[trigger] map.kv_pairs().contains(p) ==> entries.contains(p)
    &&& match tail {Some(loc) => tails.contains(loc),None => covered == 0}
}

pub(super) fn accept<A:Arena>(map:&BTreeMap<ObjectId,ArenaLocation>, tail:Option<ArenaLocation>,
    covered:u64, measured:u64, arena:&mut A) -> (ok:bool)
    requires btree_map_inv(map),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
    ensures
        ok ==> consistent(map@,tail,covered,measured,old(arena).entries(),old(arena).tails()),
        old(arena).reliable() && consistent(map@,tail,covered,measured,old(arena).entries(),old(arena).tails()) ==> ok,
{
    if covered != measured {return false;}
    let rows = physical_order(map);
    let mut i = 0usize;
    while i < rows.len()
        invariant i <= rows.len(), rows@.to_set() == map@.kv_pairs(),
            arena.entries() == old(arena).entries(), arena.tails() == old(arena).tails(), arena.reliable() == old(arena).reliable(),
            forall|j:int| 0 <= j < i ==> arena.entries().contains(#[trigger] rows@[j]),
        decreases rows.len()-i,
    {
        let (id,loc) = rows[i];
        assert(rows@.to_set().contains((id,loc)));
        if !arena.entry(id,loc) {return false;}
        i = i.saturating_add(1);
    }
    proof {
        assert forall|p:(ObjectId,ArenaLocation)| rows@.to_set().contains(p) implies #[trigger] arena.entries().contains(p) by {
            let j = choose|j:int| 0 <= j < rows.len() && rows@[j] == p;
        }
    }
    match tail {Some(loc) => arena.tail(loc),None => covered == 0}
}

}
