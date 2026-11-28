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
            proof { vstd::seq_lib::seq_to_set_distributes_over_add(prefix.map(|_,row:(ObjectId,ArenaLocation)| row.0),seq![id]); }
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
}
