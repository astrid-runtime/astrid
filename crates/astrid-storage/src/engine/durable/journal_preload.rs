//! Install one indexed object and schedule its unresolved owning references.
#[cfg(verus_keep_ghost)]
use super::closure_walk::{Edge, children};
use super::{ArenaLocation, ObjectId, ObjectRecord};
use std::collections::{BTreeMap, BTreeSet};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::{
        btree::{btree_map_inv, btree_set_inv},
        iter::IteratorSpec,
    },
};

verus! {
/// Resolve every still-unloaded frontier member against this recovery index.
pub(super) fn requests(frontier: &BTreeSet<ObjectId>, loaded: &BTreeMap<ObjectId,ObjectRecord>,
    index: &BTreeMap<ObjectId,ArenaLocation>) -> (out: Result<Vec<(ObjectId,ArenaLocation)>,ObjectId>)
    requires btree_set_inv(frontier), btree_map_inv(loaded), btree_map_inv(index),
        obeys_cmp::<ObjectId>(), obeys_cmp_concrete_eq::<ObjectId>(),
    ensures match out {
        Ok(rows) => rows@.map(|_, row:(ObjectId,ArenaLocation)| row.0).to_set() ==
            frontier@.difference(loaded@.dom()) &&
            forall|i:int| 0 <= i < rows.len() ==> index@.contains_key(#[trigger] rows@[i].0) &&
                index@[rows@[i].0] == rows@[i].1,
        Err(id) => frontier@.contains(id) && !loaded@.contains_key(id) && !index@.contains_key(id),
    },
{
    let mut requested = Vec::new();
    let mut iter = frontier.iter();
    let ghost mut left = frontier@.len() as int;
    loop
        invariant
            left == iter.remaining().len(),
            btree_map_inv(loaded), btree_map_inv(index), obeys_cmp::<ObjectId>(), obeys_cmp_concrete_eq::<ObjectId>(),
            iter.remaining().unref().to_set().subset_of(frontier@),
            requested@.map(|_,row:(ObjectId,ArenaLocation)| row.0).to_set().union(
                iter.remaining().unref().to_set().difference(loaded@.dom())) == frontier@.difference(loaded@.dom()),
            forall|i:int| 0 <= i < requested.len() ==> index@.contains_key(#[trigger] requested@[i].0) &&
                index@[requested@[i].0] == requested@[i].1,
        decreases left,
    {
        let ghost remaining = iter.remaining();
        let ghost prefix = requested@;
        let Some(&id) = iter.next() else { return Ok(requested); };
        proof { left = left - 1; }
        assert(remaining.unref() =~= seq![id] + iter.remaining().unref());
        proof {
            let one = seq![id];
            one.to_set_ensures();
            assert(one[0] == id);
            assert forall|k:ObjectId| one.to_set().contains(k) == (k == id) by {
                if one.contains(k) { let i = choose|i:int| 0 <= i < one.len() && one[i] == k; assert(i == 0); }
            }
            assert(one.to_set() =~= Set::empty().insert(id));
        }
        proof { vstd::seq_lib::seq_to_set_distributes_over_add(seq![id],iter.remaining().unref()); }
        assert(remaining.unref().to_set() =~= iter.remaining().unref().to_set().insert(id));
        if !loaded.contains_key(&id) {
            let Some(&location) = index.get(&id) else { return Err(id); };
            requested.push((id,location));
            assert(requested@.map(|_,row:(ObjectId,ArenaLocation)| row.0) =~=
                prefix.map(|_,row:(ObjectId,ArenaLocation)| row.0) + seq![id]);
            proof { vstd::seq_lib::seq_to_set_distributes_over_add(prefix.map(|_,row:(ObjectId,ArenaLocation)| row.0),seq![id]); };
        }
        assert(requested@.map(|_,row:(ObjectId,ArenaLocation)| row.0).to_set().union(
            iter.remaining().unref().to_set().difference(loaded@.dom())) =~= frontier@.difference(loaded@.dom()));
    }
}

pub(super) fn accept(loaded:&mut BTreeMap<ObjectId,ObjectRecord>,next:&mut BTreeSet<ObjectId>,
    id:ObjectId,record:ObjectRecord)
    requires btree_map_inv(old(loaded)),btree_set_inv(old(next)),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
    ensures btree_map_inv(final(loaded)),btree_set_inv(final(next)),
        final(loaded)@ == old(loaded)@.insert(id,record),
        final(next)@ == old(next)@.union(children(record.contents().3).difference(old(loaded)@.dom())),
{
    let refs = record.references();
    assert(refs@.skip(0) =~= refs@);
    let mut i = 0;
    while i < refs.len()
        invariant i <= refs.len(), btree_map_inv(loaded),btree_set_inv(next),
            obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
            next@.union(children(refs@.skip(i as int)).difference(loaded@.dom())) ==
                old(next)@.union(children(refs@).difference(loaded@.dom())),
        decreases refs.len()-i,
    {
        let ghost before = next@;
        let ghost suffix = refs@.skip(i as int);
        assert(suffix.skip(1) =~= refs@.skip(i as int+1));
        assert(suffix.first() == refs@[i as int]);
        let k = refs[i].owning_target();
        match k { Some(child) if !loaded.contains_key(&child) => {next.insert(child);}, _ => {} }
        assert(k == Edge::<ObjectId>::target(&suffix.first()));
        assert(next@.union(children(suffix.skip(1)).difference(loaded@.dom())) =~=
            before.union(children(suffix).difference(loaded@.dom())));
        i = i.saturating_add(1);
    }
    assert(refs@.skip(i as int) =~= Seq::empty());
    assert(next@ =~= old(next)@.union(children(refs@).difference(loaded@.dom())));
    loaded.insert(id,record);
}
type Table = BTreeMap<ObjectId,ObjectRecord>;
type Frontier = BTreeSet<ObjectId>;
type Row = (ObjectId,ArenaLocation);
pub(super) enum Error<E> { Missing(ObjectId), Read(E) }

pub(super) open spec fn selected(rows:Seq<Row>) -> Set<ObjectId> {
    rows.map(|_,row:Row| row.0).to_set()
}

pub(super) open spec fn outgoing(table:Map<ObjectId,ObjectRecord>,id:ObjectId) -> Set<ObjectId> {
    children(table[id].contents().3)
}

pub(super) open spec fn wave(before:Map<ObjectId,ObjectRecord>,keys:Set<ObjectId>,
    after:Map<ObjectId,ObjectRecord>,next:Set<ObjectId>) -> bool {
    &&& before.submap_of(after)
    &&& after.dom() == before.dom().union(keys)
    &&& forall|k:ObjectId| keys.contains(k) ==> #[trigger] outgoing(after,k).subset_of(after.dom().union(next))
    &&& forall|c:ObjectId| #[trigger] next.contains(c) ==> exists|k:ObjectId|
        keys.contains(k) && #[trigger] outgoing(after,k).contains(c)
}

pub(super) open spec fn closed_on(table:Map<ObjectId,ObjectRecord>,scope:Set<ObjectId>) -> bool {
    forall|k:ObjectId| table.contains_key(k) && scope.contains(k) ==> #[trigger] outgoing(table,k).subset_of(scope)
}

pub(super) open spec fn reachable_only(roots:Set<ObjectId>,table:Map<ObjectId,ObjectRecord>,next:Set<ObjectId>) -> bool {
    forall|scope:Set<ObjectId>| roots.subset_of(scope) && #[trigger] closed_on(table,scope) ==>
        table.dom().union(next).subset_of(scope)
}

pub(super) open spec fn covered(roots:Set<ObjectId>,table:Map<ObjectId,ObjectRecord>,next:Set<ObjectId>) -> bool {
    &&& roots.subset_of(table.dom().union(next))
    &&& forall|k:ObjectId| table.contains_key(k) ==> #[trigger] outgoing(table,k).subset_of(table.dom().union(next))
}

proof fn advance(roots:Set<ObjectId>,before:Map<ObjectId,ObjectRecord>,current:Set<ObjectId>,
    after:Map<ObjectId,ObjectRecord>,next:Set<ObjectId>)
    requires covered(roots,before,current), reachable_only(roots,before,current),
        wave(before,current.difference(before.dom()),after,next),
    ensures covered(roots,after,next), reachable_only(roots,after,next),
{
    let keys = current.difference(before.dom());
    assert(before.dom().union(current) =~= after.dom());
    assert forall|k:ObjectId| after.contains_key(k) implies #[trigger] outgoing(after,k).subset_of(after.dom().union(next)) by {
        if before.contains_key(k) { assert(before[k] == after[k]); assert(outgoing(before,k).subset_of(after.dom())); }
        else { assert(keys.contains(k)); }
    }
    assert forall|scope:Set<ObjectId>| roots.subset_of(scope) && #[trigger] closed_on(after,scope)
        implies after.dom().union(next).subset_of(scope) by {
        assert forall|k:ObjectId| before.contains_key(k) && scope.contains(k) implies #[trigger] outgoing(before,k).subset_of(scope) by {
            assert(after.contains_key(k) && after[k] == before[k]);
            assert(outgoing(after,k).subset_of(scope));
        }
        assert(closed_on(before,scope));
        assert(after.dom().subset_of(scope));
        assert forall|c:ObjectId| next.contains(c) implies scope.contains(c) by {
            let k = choose|k:ObjectId| keys.contains(k) && #[trigger] outgoing(after,k).contains(c);
            assert(outgoing(after,k).subset_of(scope));
        }
    }
}

pub(super) open spec fn pending_failure(roots:Set<ObjectId>,index:Map<ObjectId,ArenaLocation>,
    t:Map<ObjectId,ObjectRecord>,frontier:Set<ObjectId>) -> bool {
    t.dom().subset_of(index.dom()) && covered(roots,t,frontier) && reachable_only(roots,t,frontier)
}

pub(super) open spec fn read_failure<E,V:Fn(Table,&[Row])->Result<(Table,Frontier),E>>(
    roots:Set<ObjectId>,index:Map<ObjectId,ArenaLocation>,read:V,e:E) -> bool {
    exists|t:Table,r:&[Row],f:Set<ObjectId>| #[trigger] pending_failure(roots,index,t@,f) && r.len()>0 &&
        selected(r@) == f.difference(t@.dom()) &&
        (forall|i:int| 0 <= i < r.len() ==> index.contains_key(#[trigger] r@[i].0) && index[r@[i].0] == r@[i].1) &&
        #[trigger] read.ensures((t,r),Err(e))
}

/// Continue until every owning edge is resident. A successful read of a
/// nonempty frontier must strictly increase the resident subset of the index.
pub(super) fn preload<E,V:Fn(Table,&[Row])->Result<(Table,Frontier),E>>(
    index:&BTreeMap<ObjectId,ArenaLocation>,roots:Frontier,read:V) -> (out:Result<Table,Error<E>>)
    requires btree_map_inv(index), btree_set_inv(&roots), obeys_cmp::<ObjectId>(), obeys_cmp_concrete_eq::<ObjectId>(),
        forall|t:Table,r:&[Row]| btree_map_inv(&t) && t@.dom().disjoint(selected(r@)) ==> #[trigger] read.requires((t,r)),
        forall|t:Table,r:&[Row],u:Table,n:Frontier| #[trigger] read.ensures((t,r),Ok((u,n))) ==>
            btree_map_inv(&u) && btree_set_inv(&n) && wave(t@,selected(r@),u@,n@),
    ensures match out {
        Ok(t) => btree_map_inv(&t) && t@.dom().subset_of(index@.dom()) &&
            covered(roots@,t@,Set::empty()) && reachable_only(roots@,t@,Set::empty()),
        Err(Error::Missing(k)) => !index@.contains_key(k),
        Err(Error::Read(e)) => read_failure(roots@,index@,read,e),
    },
{
    let mut table = Table::new();
    let mut pending = roots;
    loop
        invariant btree_map_inv(index),btree_map_inv(&table),btree_set_inv(&pending),
            obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
            table@.dom().subset_of(index@.dom()),covered(roots@,table@,pending@),reachable_only(roots@,table@,pending@),
            forall|t:Table,r:&[Row]| btree_map_inv(&t) && t@.dom().disjoint(selected(r@)) ==> #[trigger] read.requires((t,r)),
            forall|t:Table,r:&[Row],u:Table,n:Frontier| #[trigger] read.ensures((t,r),Ok((u,n))) ==>
                btree_map_inv(&u) && btree_set_inv(&n) && wave(t@,selected(r@),u@,n@),
        decreases index@.dom().len() as int - table@.dom().len(),
    {
        let ghost frontier = pending@;
        let rows = {
            let current = pending;
            match requests(&current,&table,index) {Ok(r)=>r,Err(k)=>return Err(Error::Missing(k))}
        };
        let ghost keys = selected(rows@);
        let ghost earlier = table@;
        assert(keys == frontier.difference(earlier.dom()));
        assert(earlier.dom().disjoint(keys));
        if rows.is_empty() {
            assert(keys =~= Set::empty());
            assert(frontier.subset_of(earlier.dom())) by {
                assert forall|k:ObjectId| frontier.contains(k) implies earlier.contains_key(k) by {
                    if !earlier.contains_key(k) {assert(keys.contains(k));}
                }
            }
            assert(earlier.dom().union(frontier) =~= earlier.dom().union(Set::empty()));
            assert(covered(roots@,earlier,Set::empty()));
            assert(reachable_only(roots@,earlier,Set::empty()));
            return Ok(table);
        }
        let batch = rows.as_slice();
        let (updated,next) = match read(table,batch) {
            Ok(pair)=>pair,
            Err(e)=>{
                assert(read.ensures((table,batch),Err(e)) && batch.len()>0);
                assert(pending_failure(roots@,index@,table@,frontier));
                assert(read_failure(roots@,index@,read,e));
                return Err(Error::Read(e));
            },
        };
        table = updated;
        pending = next;
        proof {
            let ids = rows@.map(|_,r:Row| r.0);
            ids.to_set_ensures();
            assert forall|k:ObjectId| keys.contains(k) implies index@.contains_key(k) by {
                assert(ids.contains(k));
                let j = choose|j:int| 0 <= j < ids.len() && ids[j]==k;
                assert(index@.contains_key(rows@[j].0));
            }
            assert(wave(earlier,keys,table@,pending@));
            advance(roots@,earlier,frontier,table@,pending@);
            assert(ids[0] == rows@[0].0 && ids.contains(rows@[0].0));
            assert(keys.contains(rows@[0].0));
            earlier.dom().lemma_subset_not_in_lt(table@.dom(),rows@[0].0);
            vstd::set_lib::lemma_len_subset(table@.dom(),index@.dom());
        };
    }
}

}
