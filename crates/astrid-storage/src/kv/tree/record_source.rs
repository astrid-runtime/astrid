//! Resolve an object from the current transaction or its owner's engine reader.
use super::{ObjectId, ObjectRecord};
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

verus! {
pub(super) fn shared(record:&ObjectRecord) -> (out:std::sync::Arc<ObjectRecord>)
    ensures out.same_contents(record),
{ std::sync::Arc::new(record.owned_record()) }

pub(super) enum Error<E> { Source(E), Missing(ObjectId) }

pub(super) fn load<P,T,E,C:FnOnce(&ObjectRecord)->T,L:FnOnce(&P,ObjectId)->Result<Option<T>,E>>(
    staged:&BTreeMap<ObjectId,ObjectRecord>,owner:&P,id:ObjectId,copy:C,engine:L) -> (out:Result<T,Error<E>>)
    requires btree_map_inv(staged),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        staged@.contains_key(id) ==> copy.requires((&staged@[id],)),engine.requires((owner,id)),
    ensures if staged@.contains_key(id) {
        out matches Ok(t) && copy.ensures((&staged@[id],),t)
    } else {
        match out {
            Ok(t) => engine.ensures((owner,id),Ok(Some(t))),
            Err(Error::Missing(k)) => k == id && engine.ensures((owner,id),Ok(None)),
            Err(Error::Source(e)) => engine.ensures((owner,id),Err(e)),
        }
    },
{
    if let Some(record) = staged.get(&id) {return Ok(copy(record));}
    match engine(owner,id) {
        Ok(Some(t)) => Ok(t),
        Ok(None) => Err(Error::Missing(id)),
        Err(e) => Err(Error::Source(e)),
    }
}
}
