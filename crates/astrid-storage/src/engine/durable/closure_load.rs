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
        self.owning_target()
    }
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
