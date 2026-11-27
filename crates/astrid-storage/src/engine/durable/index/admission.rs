//! Reconcile every candidate mapping and the tail with the authoritative arena.
#[cfg(verus_keep_ghost)]
use super::arena_frame::WIDTH;
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
                consistent(s.objects@,s.arena_tail,s.arena_len,measured,old(arena).entries(),old(arena).tails()) && can_cover(s.objects@,measured),
            complete && old(arena).reliable() && (candidate matches Some(s) && can_cover(s.objects@,measured) &&
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
    ensures out@.to_set() == map@.kv_pairs(), out.len() == map.len(), ordered(out@,map@),
{
    let mut it = map.iter();
    let ghost sequence = it.remaining();
    let mut items = Vec::with_capacity(map.len());
    while items.len() < map.len()
        invariant forall|pair:(ObjectId,ArenaLocation)| #[trigger] items@.to_set().contains(pair) ==> call_ensures(offset,(&pair,),pair.1.offset),
            sequence.len() == map.len(), items.len() <= map.len(),
            it.remaining() == sequence.skip(items.len() as int),
            items@ == sequence.unref().take(items.len() as int),
            sequence.unref().to_set() == map@.kv_pairs(),
        decreases map.len()-items.len(),
    {
        let ghost i = items.len() as int;
        let Some((id,loc)) = it.next() else {unreachable!("iterator length matches the checked map length")};
        // Instantiate the key-function contract for each concrete row.
        let key = offset;
        let pair = (*id,*loc);
        let _ = key(&pair);
        assert(call_ensures(offset,(&pair,),pair.1.offset));
        proof {items@.lemma_push_to_set_commute(pair);}
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
    assert forall|i:int,j:int| 0 <= i < j < items.len() implies
        (#[trigger] items@[i]).1.offset <= (#[trigger] items@[j]).1.offset by {
        assert(vstd::std_specs::slice::key_le(offset,items@[i],items@[j]));
        assert(items@.to_set().contains(items@[i]));
        assert(items@.to_set().contains(items@[j]));
        assert(call_ensures(offset,(&items@[i],),items@[i].1.offset));
        assert(call_ensures(offset,(&items@[j],),items@[j].1.offset));
    }
    items
}

#[cfg(verus_keep_ghost)]
type Rows = Seq<(ObjectId,ArenaLocation)>;

pub(super) open spec fn ordered(rows:Rows, map:Map<ObjectId,ArenaLocation>) -> bool {
    &&& rows.to_set() == map.kv_pairs() && rows.len() == map.dom().len()
    &&& forall|i:int,j:int| 0 <= i < j < rows.len() ==> (#[trigger] rows[i]).1.offset <= (#[trigger] rows[j]).1.offset
}

pub(super) open spec fn frontier(rows:Rows,i:int) -> int {
    if i == 0 {0} else {let loc = rows[i-1].1; loc.offset as int + WIDTH + loc.payload_len}
}

pub(super) open spec fn partition(rows:Rows, measured:u64) -> bool {
    &&& frontier(rows,rows.len() as int) == measured
    &&& forall|i:int| 0 <= i < rows.len() ==> (#[trigger] rows[i]).1.offset == frontier(rows,i)
}

pub(super) open spec fn can_cover(map:Map<ObjectId,ArenaLocation>,measured:u64) -> bool {
    exists|rows:Rows| #[trigger] ordered(rows,map) && partition(rows,measured)
}

/// A contiguous physical ordering is unique, even if the sorting contract
/// permits arbitrary ordering among equal keys on malformed input.
proof fn unique_partition(map:Map<ObjectId,ArenaLocation>, actual:Rows, measured:u64)
    requires ordered(actual,map), can_cover(map,measured),
    ensures partition(actual,measured),
{
    let witness = choose|w:Rows| #[trigger] ordered(w,map) && partition(w,measured);
    assert forall|i:int,j:int| 0 <= i < j < witness.len() implies
        (#[trigger] witness[i]).1.offset < (#[trigger] witness[j]).1.offset by {
        assert(witness[i+1].1.offset == frontier(witness,i+1));
        if i+1 < j {assert(witness[i+1].1.offset <= witness[j].1.offset);}
    }
    assert(witness.no_duplicates());
    witness.unique_seq_to_set();
    actual.lemma_no_dup_set_cardinality();
    witness.to_set_ensures();
    actual.to_set_ensures();
    match_prefix(actual,witness,actual.len() as int);
    assert(actual =~= witness);
}

proof fn match_prefix(actual:Rows,witness:Rows,n:int)
    requires 0 <= n <= actual.len() == witness.len(), actual.to_set() == witness.to_set(),
        actual.no_duplicates(),witness.no_duplicates(),
        forall|i:int,j:int| 0 <= i < j < actual.len() ==> (#[trigger] actual[i]).1.offset <= (#[trigger] actual[j]).1.offset,
        forall|i:int,j:int| 0 <= i < j < witness.len() ==> (#[trigger] witness[i]).1.offset < (#[trigger] witness[j]).1.offset,
    ensures forall|k:int| 0 <= k < n ==> #[trigger] actual[k] == witness[k],
    decreases n,
{
    if n > 0 {
        let i = n-1;
        match_prefix(actual,witness,i);
        witness.to_set_ensures();
        actual.to_set_ensures();
        assert(witness.to_set().contains(actual[i]));
        assert(actual.to_set().contains(witness[i]));
        let j = choose|j:int| 0 <= j < witness.len() && #[trigger] witness[j] == actual[i];
        let k = choose|k:int| 0 <= k < actual.len() && #[trigger] actual[k] == witness[i];
        if j < i {assert(actual[j] == witness[j]);}
        if k < i {assert(witness[k] == actual[k]);}
        assert(i <= j && i <= k);
        if j > i {assert(witness[i].1.offset < witness[j].1.offset);}
        if k > i {assert(actual[i].1.offset <= actual[k].1.offset);}
        assert(actual[i] == witness[i]);
    }
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
        ok ==> can_cover(map@,measured) && consistent(map@,tail,covered,measured,old(arena).entries(),old(arena).tails()),
        old(arena).reliable() && can_cover(map@,measured) && consistent(map@,tail,covered,measured,old(arena).entries(),old(arena).tails()) ==> ok,
{
    if covered != measured {return false;}
    let rows = physical_order(map);
    proof {if can_cover(map@,measured) {unique_partition(map@,rows@,measured);}}
    let mut i = 0usize;
    let mut end = 0u64;
    while i < rows.len()
        invariant end == frontier(rows@,i as int), ordered(rows@,map@),
            can_cover(map@,measured) ==> partition(rows@,measured),
            forall|j:int| 0 <= j < i ==> (#[trigger] rows@[j]).1.offset == frontier(rows@,j),
            i <= rows.len(), rows@.to_set() == map@.kv_pairs(),
            arena.entries() == old(arena).entries(), arena.tails() == old(arena).tails(), arena.reliable() == old(arena).reliable(),
            forall|j:int| 0 <= j < i ==> arena.entries().contains(#[trigger] rows@[j]),
        decreases rows.len()-i,
    {
        let (id,loc) = rows[i];
        assert(rows@.to_set().contains((id,loc)));
        if loc.offset != end {return false;}
        let Some(next) = loc.end() else {
            assert(frontier(rows@,i as int+1) > u64::MAX);
            assert(!partition(rows@,measured)) by {if i+1 < rows.len() {assert(rows@[i as int+1].1.offset <= u64::MAX);}}
            return false;
        };
        end = next;
        if !arena.entry(id,loc) {return false;}
        i = i.saturating_add(1);
    }
    proof {
        assert forall|p:(ObjectId,ArenaLocation)| rows@.to_set().contains(p) implies #[trigger] arena.entries().contains(p) by {
            let j = choose|j:int| 0 <= j < rows.len() && rows@[j] == p;
        }
    }
    if end != measured {return false;}
    assert(partition(rows@,measured));
    match tail {Some(loc) => arena.tail(loc),None => covered == 0}
}

}
