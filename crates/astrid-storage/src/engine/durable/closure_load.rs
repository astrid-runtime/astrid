//! Select the record used by a closure walk from the live transaction layers.
use super::closure_walk::Edge;
use super::{ObjectId, ObjectReference};
use std::collections::BTreeMap;
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

verus! {

impl Edge<ObjectId> for ObjectReference {
    open spec fn target(&self) -> Option<ObjectId> {
        if self.fields().2 is Owns {Some(self.fields().1)} else {None}
    }

    fn owned_target(&self) -> Option<ObjectId> {
        self.kind().owned_target(self.target())
    }
}

/// Check the digest computed over this exact record before it enters an
/// externally supplied transaction or restore snapshot.
pub(super) fn check_identity<R,F>(declared:ObjectId,record:&R,identify:&F)
    -> (out:Result<(),(ObjectId,ObjectId)>)
    where F:Fn(&R)->ObjectId,
    requires identify.requires((record,)),
    ensures match out {
        Ok(()) => exists|computed:ObjectId| #[trigger] identify.ensures((record,),computed) && computed.digest() == declared.digest(),
        Err((name,computed)) => name == declared && identify.ensures((record,),computed) && computed.digest() != declared.digest(),
    },
{
    let computed = identify(record);
    if computed.as_bytes().as_slice() == declared.as_bytes().as_slice() {Ok(())}
    else {Err((declared,computed))}
}

pub(super) open spec fn authentic<R,F:Fn(&R)->ObjectId>(row:(ObjectId,R),identify:F) -> bool {
    exists|computed:ObjectId| #[trigger] identify.ensures((&row.1,),computed) && computed.digest() == row.0.digest()
}

/// Preserve the first mismatched declaration and check every earlier row.
pub(super) fn check_transaction<R,F>(records:&[(ObjectId,R)],identify:F)
    -> (out:Result<(),(ObjectId,ObjectId)>)
    where F:Fn(&R)->ObjectId,
    requires forall|r:&R| #[trigger] identify.requires((r,)),
    ensures match out {
        Ok(()) => forall|i:int| 0 <= i < records.len() ==> #[trigger] authentic(records@[i],identify),
        Err((name,computed)) => exists|i:int| 0 <= i < records.len() && name == records@[i].0 &&
            #[trigger] identify.ensures((&records@[i].1,),computed) && computed.digest() != name.digest() &&
            forall|j:int| 0 <= j < i ==> #[trigger] authentic(records@[j],identify),
    },
{
    let mut i = 0;
    while i < records.len()
        invariant i <= records.len(),
            forall|r:&R| #[trigger] identify.requires((r,)),
            forall|j:int| 0 <= j < i ==> #[trigger] authentic(records@[j],identify),
        decreases records.len()-i,
    {
        let row = &records[i];
        if let Err((name,computed)) = check_identity(row.0,&row.1,&identify) {
            assert(identify.ensures((&records@[i as int].1,),computed));
            return Err((name,computed));
        }
        i = i.saturating_add(1);
    }
    Ok(())
}

pub(super) struct Layers<'a,K,I,P,L> {
    pub(super) incoming:&'a BTreeMap<K,I>,
    pub(super) pending:Option<&'a BTreeMap<K,P>>,
    pub(super) index:&'a BTreeMap<K,L>,
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
    if let Some(record) = layers.incoming.get(&id) {
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
