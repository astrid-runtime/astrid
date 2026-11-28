//! Install one indexed object and schedule its unresolved owning references.
#[cfg(verus_keep_ghost)]
use super::closure_walk::{Edge, children};
use super::{ObjectId, ObjectRecord};
use std::collections::{BTreeMap, BTreeSet};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::{btree_map_inv, btree_set_inv},
};

verus! {
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
