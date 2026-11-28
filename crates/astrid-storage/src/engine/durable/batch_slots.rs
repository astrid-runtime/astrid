//! Keep each cached or fetched object in its original request slots.
use super::ObjectId;
use std::{collections::BTreeMap, sync::Arc};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

verus! {
pub(super) struct Batch<R> {
    pub(super) records: Vec<Option<Arc<R>>>,
    pub(super) missing: BTreeMap<ObjectId,Vec<usize>>,
}

pub(super) open spec fn waiting(map:Map<ObjectId,Vec<usize>>,key:ObjectId,i:int) -> bool {
    map.contains_key(key) && 0 <= i <= usize::MAX && map[key]@.contains(i as usize)
}

pub(super) open spec fn indexed(map:Map<ObjectId,Vec<usize>>,ids:Seq<ObjectId>) -> bool {
    forall|key:ObjectId,j:int| #[trigger] waiting(map,key,j) ==> 0 <= j < ids.len() && ids[j] == key
}

fn remember(map:&mut BTreeMap<ObjectId,Vec<usize>>,key:ObjectId,i:usize)
    requires btree_map_inv(old(map)),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
    ensures btree_map_inv(final(map)), forall|k:ObjectId,j:int| #[trigger] waiting(final(map)@,k,j) ==
        (waiting(old(map)@,k,j) || (k == key && j == i)),
{
    broadcast use vstd::seq_lib::lemma_seq_contains_after_push;
    if let Some(indices) = map.get_mut(&key) { indices.push(i); }
    else { map.insert(key,vec![i]); }
    assert forall|k:ObjectId,j:int| #[trigger] waiting(map@,k,j) ==
        (waiting(old(map)@,k,j) || (k == key && j == i)) by {
        if k == key && old(map)@.contains_key(key) {
            assert(map@[key]@ == old(map)@[key]@.push(i));
        }
    };
}

pub(super) fn prepare<P,R,F>(owner:&P,ids:&[ObjectId],lookup:F) -> (out:Batch<R>)
    where F:Fn(&P,ObjectId)->Option<Arc<R>>,
    requires obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|id:ObjectId| #[trigger] lookup.requires((owner,id)),
    ensures out.records.len() == ids.len(), btree_map_inv(&out.missing), indexed(out.missing@,ids@),
        forall|i:int| 0 <= i < ids.len() ==> #[trigger] lookup.ensures((owner,ids@[i]),out.records@[i])
            && (out.records@[i].is_none() == waiting(out.missing@,ids@[i],i)),
{
    let mut missing = BTreeMap::new();
    let mut records = Vec::with_capacity(ids.len());
    let mut i = 0usize;
    while i < ids.len()
        invariant i <= ids.len(), records.len() == i, btree_map_inv(&missing),
            obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
            forall|id:ObjectId| #[trigger] lookup.requires((owner,id)),
            forall|k:ObjectId,j:int| #[trigger] waiting(missing@,k,j) ==> 0 <= j < i && ids@[j] == k,
            forall|j:int| 0 <= j < i ==> #[trigger] lookup.ensures((owner,ids@[j]),records@[j])
                && (records@[j].is_none() == waiting(missing@,ids@[j],j)),
        decreases ids.len()-i,
    {
        let id = ids[i];
        let record = lookup(owner,id);
        if record.is_none() { remember(&mut missing,id,i); }
        let ghost prior = records@;
        records.push(record);
        assert forall|j:int| 0 <= j <= i implies #[trigger] lookup.ensures((owner,ids@[j]),records@[j])
            && (records@[j].is_none() == waiting(missing@,ids@[j],j)) by {
            if j < i { assert(lookup.ensures((owner,ids@[j]),prior[j])); }
        }
        i = i.saturating_add(1);
    }
    Batch { records, missing }
}

/// Install the cache result in every requested position missing this exact key.
fn install<R>(records:&mut [Option<Arc<R>>],missing:&BTreeMap<ObjectId,Vec<usize>>,
    id:ObjectId,record:&Arc<R>)
    requires btree_map_inv(missing),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|j:int| #[trigger] waiting(missing@,id,j) ==> j < old(records).len(),
    ensures final(records).len() == old(records).len(),
        forall|j:int| 0 <= j < old(records).len() ==> #[trigger] final(records)@[j] ==
            if waiting(missing@,id,j) { Some(*record) } else { old(records)@[j] },
{
    let Some(indices) = missing.get(&id) else { return; };
    let mut i = 0usize;
    while i < indices.len()
        invariant i <= indices.len(), records.len() == old(records).len(), missing@.contains_key(id),
            missing@[id] == *indices,
            forall|j:int| #[trigger] waiting(missing@,id,j) ==> j < old(records).len(),
            forall|j:int| 0 <= j < records.len() ==> #[trigger] records@[j] ==
                if indices@.take(i as int).contains(j as usize) { Some(*record) } else { old(records)@[j] },
        decreases indices.len()-i,
    {
        let index = indices[i];
        assert(indices@.contains(index));
        assert(waiting(missing@,id,index as int));
        broadcast use vstd::seq_lib::lemma_seq_contains_after_push;
        records[index] = Some(Arc::clone(record));
        assert(indices@.take(i as int+1) =~= indices@.take(i as int).push(index));
        i = i.saturating_add(1);
    }
    assert(indices@.take(i as int) =~= indices@);
}

pub(super) fn publish<P,R,F>(batch:&mut Batch<R>,owner:&P,id:ObjectId,loaded:R,insert:F)
    where F:FnOnce(&P,ObjectId,R)->Arc<R>,
    requires btree_map_inv(&old(batch).missing),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        insert.requires((owner,id,loaded)),
        forall|j:int| #[trigger] waiting(old(batch).missing@,id,j) ==> j < old(batch).records.len(),
    ensures final(batch).missing == old(batch).missing, final(batch).records.len() == old(batch).records.len(),
        exists|cached:Arc<R>| #[trigger] insert.ensures((owner,id,loaded),cached) &&
            forall|j:int| 0 <= j < old(batch).records.len() ==> #[trigger] final(batch).records@[j] ==
                if waiting(old(batch).missing@,id,j) { Some(cached) } else { old(batch).records@[j] },
{
    let cached = insert(owner,id,loaded);
    install(batch.records.as_mut_slice(),&batch.missing,id,&cached);
}
}
