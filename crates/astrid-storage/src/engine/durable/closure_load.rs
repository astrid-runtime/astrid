//! Select the record used by a closure walk from the live transaction layers.
use super::closure_walk::{self as walk, Edge, Source};
use super::{ObjectId, ObjectRecord, ObjectReference};
use std::collections::{BTreeMap, BTreeSet};
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::{
        btree::{btree_map_inv, increasing_seq},
        iter::IteratorSpec,
    },
};

verus! {

impl Edge<ObjectId> for ObjectReference {
    open spec fn target(&self) -> Option<ObjectId> {
        if self.fields().2 is Owns {Some(self.fields().1)} else {None}
    }

    fn owned_target(&self) -> Option<ObjectId> {
        self.owning_target()
    }
}

pub(super) struct Layers<'a,K,I,P,L> {
    pub(super) incoming:&'a BTreeMap<K,I>,
    pub(super) pending:Option<&'a BTreeMap<K,P>>,
    pub(super) index:&'a BTreeMap<K,L>,
}

/// Select a preloaded record. Only the caller decides how to handle a miss.
fn incoming<'a,K:Ord,I>(id:&K,table:&'a BTreeMap<K,I>) -> (out:Option<&'a I>)
    requires btree_map_inv(table),obeys_cmp::<K>(),obeys_cmp_concrete_eq::<K>(),
    ensures out.is_some() == table@.contains_key(*id),
        out matches Some(record) ==> *record == table@[*id],
{
    table.get(id)
}

/// Immutable object table populated by the recovery arena reader.
pub(super) struct Preload<'a>(pub(super) &'a BTreeMap<ObjectId,ObjectRecord>);

impl Source<ObjectId> for Preload<'_> {
    type Error = ObjectId;

    open spec fn valid(&self) -> bool {
        btree_map_inv(self.0) && obeys_cmp::<ObjectId>() && obeys_cmp_concrete_eq::<ObjectId>()
    }

    open spec fn edges(&self) -> Map<ObjectId,Set<ObjectId>> {
        self.0@.map_values(|record:ObjectRecord| walk::children(record.contents().3))
    }

    open spec fn failed(graph:Map<ObjectId,Set<ObjectId>>,id:ObjectId,error:ObjectId) -> bool {
        !graph.contains_key(id) && error == id
    }

    // The caller validates the commit after collecting its complete owning closure.
    open spec fn commit(&self,_root:ObjectId) -> bool {true}
    open spec fn root_failed(&self,_root:ObjectId,_error:ObjectId) -> bool {false}

    fn check_root(&mut self,_root:ObjectId) -> Result<(),ObjectId> {Ok(())}

    fn expand(&mut self,id:ObjectId,stack:&mut Vec<walk::Work<ObjectId>>) -> Result<(),ObjectId> {
        match incoming(&id,self.0) {
            Some(record) => {
                walk::schedule(record.references(),stack);
                Ok(())
            },
            None => Err(id),
        }
    }
}

/// Recovery has no pending WAL object table or index fallback after preloading.
pub(super) fn preloaded<K:Ord+Copy,I,R,E,F:FnOnce(&I)->R,M:FnOnce(K)->E>(
    id:K,table:&BTreeMap<K,I>,copy:F,missing:M) -> (out:Result<R,E>)
    requires btree_map_inv(table),obeys_cmp::<K>(),obeys_cmp_concrete_eq::<K>(),
        forall|v:&I| #[trigger] copy.requires((v,)),missing.requires((id,)),
    ensures match out {
        Ok(r) => table@.contains_key(id) && copy.ensures((&table@[id],),r),
        Err(e) => !table@.contains_key(id) && missing.ensures((id,),e),
    },
{
    match incoming(&id,table) {Some(record) => Ok(copy(record)),None => Err(missing(id))}
}

pub(super) open spec fn in_id_order(ids:Seq<ObjectId>) -> bool {
    exists|ordered:Seq<&ObjectId>| #[trigger] increasing_seq(ordered) && ids == ordered.unref()
}

pub(super) open spec fn row_ids(rows:Seq<(ObjectId,ObjectRecord)>) -> Seq<ObjectId> {
    rows.map_values(|row:(ObjectId,ObjectRecord)| row.0)
}

/// Materialize the least owning closure in the ordered set's iteration order.
pub(super) fn materialize<F:Fn(&ObjectRecord)->ObjectRecord>(
    table:&BTreeMap<ObjectId,ObjectRecord>,root:ObjectId,copy:F)
    -> (out:Result<Vec<(ObjectId,ObjectRecord)>,walk::Failure<ObjectId,ObjectId>>)
    requires Preload(table).valid(),
        forall|v:&ObjectRecord| #[trigger] copy.requires((v,)),
        forall|v:&ObjectRecord,r:ObjectRecord| #[trigger] copy.ensures((v,),r) ==> r.contents() == v.contents(),
    ensures match out {
        Ok(rows) => {
            let ids = row_ids(rows@).to_set();
            let graph = Preload(table).edges();
            &&& in_id_order(row_ids(rows@))
            &&& walk::closed(root,Set::empty(),graph,ids)
            &&& forall|nodes:Set<ObjectId>| #[trigger] walk::closed(root,Set::empty(),graph,nodes) ==> ids.subset_of(nodes)
            &&& exists|rank:Map<ObjectId,nat>| rank.dom() == ids && #[trigger] walk::ranked(graph,Set::empty(),rank)
            &&& forall|i:int| 0 <= i < rows.len() ==> table@.contains_key(rows@[i].0) &&
                (#[trigger] rows@[i]).1.contents() == table@[rows@[i].0].contents()
        },
        Err(walk::Failure::Cycle(id)) => walk::reaches(Preload(table).edges(),Set::empty(),id,id) &&
            forall|nodes:Set<ObjectId>| #[trigger] walk::closed(root,Set::empty(),Preload(table).edges(),nodes) ==> nodes.contains(id),
        Err(walk::Failure::Source(id,e)) => id == e && !table@.contains_key(id) &&
            forall|nodes:Set<ObjectId>| #[trigger] walk::closed(root,Set::empty(),Preload(table).edges(),nodes) ==> nodes.contains(id),
        Err(walk::Failure::Root(_)) => false,
    },
{
    let mut source = Preload(table);
    let seen = walk::walk(&mut source,&BTreeSet::new(),root)?;
    let mut it = seen.iter();
    let ghost sequence = it.remaining();
    let mut rows = Vec::with_capacity(seen.len());
    while rows.len() < seen.len()
        invariant
            forall|v:&ObjectRecord| #[trigger] copy.requires((v,)),
            forall|v:&ObjectRecord,r:ObjectRecord| #[trigger] copy.ensures((v,),r) ==> r.contents() == v.contents(),
            Preload(table).valid(),sequence.len() == seen.len(), rows.len() <= seen.len(),
            increasing_seq(sequence),sequence.unref().to_set() == seen@,it.remaining() == sequence.skip(rows.len() as int),
            row_ids(rows@) == sequence.unref().take(rows.len() as int),
            forall|k:ObjectId| seen@.contains(k) ==> table@.contains_key(k),
            forall|i:int| 0 <= i < rows.len() ==> table@.contains_key(rows@[i].0) &&
                (#[trigger] rows@[i]).1.contents() == table@[rows@[i].0].contents(),
        decreases seen.len()-rows.len(),
    {
        let ghost i = rows.len() as int;
        let Some(id) = it.next() else {unreachable!("iterator length matches the closure size")};
        assert(sequence.unref()[i] == *id);
        assert(seen@.contains(*id));
        let record = preloaded(*id,table,|v:&ObjectRecord| -> (r:ObjectRecord)
            ensures r.contents() == v.contents(), {copy(v)}, |key:ObjectId| key);
        let Ok(record) = record else {unreachable!("visited object is present in the immutable preload")};
        rows.push((*id,record));
        assert(it.remaining() =~= sequence.skip(i+1));
        assert(row_ids(rows@) =~= sequence.unref().take(i+1));
    }
    assert(row_ids(rows@) =~= sequence.unref());
    assert(increasing_seq(sequence));
    assert(seen@.difference(Set::empty()) =~= seen@);
    Ok(rows)
}

/// Incoming records shadow the committed WAL overlay. A media error for the
/// selected index entry is returned to the walk at that same object identity.
pub(super) fn load<K:Ord+Copy,I,P,L,R,E,FI,FP,FL,FM>(
    id:K,layers:&Layers<K,I,P,L>,
    from_incoming:FI,from_pending:FP,from_index:FL,missing:FM,
) -> (out:Result<R,E>)
    where FI:FnOnce(&I)->R,FP:FnOnce(&P)->R,FL:FnOnce(K,&L)->Result<R,E>,FM:FnOnce(K)->E,
    requires obeys_cmp::<K>(),obeys_cmp_concrete_eq::<K>(),
        btree_map_inv(layers.incoming),btree_map_inv(layers.index),
        layers.pending matches Some(table) ==> btree_map_inv(table),
        forall|value:&I| #[trigger] from_incoming.requires((value,)),
        forall|value:&P| #[trigger] from_pending.requires((value,)),
        forall|location:&L| #[trigger] from_index.requires((id,location)),
        missing.requires((id,)),
    ensures
        if layers.incoming@.contains_key(id) {
            out matches Ok(record) && from_incoming.ensures((&layers.incoming@[id],),record)
        } else if layers.pending matches Some(table) && table@.contains_key(id) {
            out matches Ok(record) && from_pending.ensures((&layers.pending.unwrap()@[id],),record)
        } else if layers.index@.contains_key(id) {
            from_index.ensures((id,&layers.index@[id]),out)
        } else {
            out matches Err(error) && missing.ensures((id,),error)
        },
{
    if let Some(record) = incoming(&id,layers.incoming) {
        return Ok(from_incoming(record));
    }
    let pending = match layers.pending {Some(table) => table.get(&id), None => None};
    if let Some(record) = pending {
        return Ok(from_pending(record));
    }
    match layers.index.get(&id) {
        Some(location) => from_index(id,location),
        None => Err(missing(id)),
    }
}

}
