//! Merge repeated WAL declarations without replacing an immutable record.
use std::collections::BTreeMap;
use std::sync::Arc;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

verus! {

#[derive(Debug)]
pub(crate) struct Object<R,L,D> {
    pub(super) payload:Arc<[u8]>,
    pub(super) record:R,
    pub(super) location:Option<L>,
    pub(super) direct:Option<D>,
}

impl<R,L,D> Object<R,L,D> {
    pub(super) fn staged(payload: Arc<[u8]>, record: R, location: L, direct: Option<D>) -> (out: Self)
        ensures out.payload == payload && out.record == record,
            out.location == Some(location) && out.direct == direct,
    {
        Self { payload, record, location: Some(location), direct }
    }

    pub(super) fn prepared(payload: Arc<[u8]>, record: R) -> (out: Self)
        ensures out.payload == payload && out.record == record,
            out.location.is_none() && out.direct.is_none(),
    {
        Self { payload, record, location: None, direct: None }
    }

    /// The only permitted update to an existing object upgrades a missing
    /// physical location using an identical frame and its paired direct metadata.
    pub(super) fn merge(&mut self,incoming:Self) -> (out:Result<(),()>)
        ensures out.is_ok() == ((*old(self).payload)@ == (*incoming.payload)@),
            final(self).payload == old(self).payload && final(self).record == old(self).record,
            if out.is_ok() && old(self).location.is_none() && incoming.location.is_some() {
                final(self).location == incoming.location && final(self).direct == incoming.direct
            } else { *final(self) == *old(self) },
    {
        let before:&[u8] = &self.payload;
        let after:&[u8] = &incoming.payload;
        if before != after {return Err(());}
        assert(before@ =~= after@);
        if self.location.is_none() && incoming.location.is_some() {
            self.location = incoming.location;
            self.direct = incoming.direct;
        }
        Ok(())
    }
}

/// Install the first declaration or merge a repeated declaration for the same name.
pub(super) fn install<K: Ord + Copy, R, L, D>(
    objects: &mut BTreeMap<K, Object<R, L, D>>, id: K, candidate: Object<R, L, D>,
) -> (out: Result<(), ()>)
    requires obeys_cmp::<K>(), obeys_cmp_concrete_eq::<K>(), btree_map_inv(old(objects)),
    ensures btree_map_inv(final(objects)),
        if old(objects)@.contains_key(id) {
            let prior = old(objects)@[id];
            let retained = final(objects)@[id];
            &&& out.is_ok() == ((*prior.payload)@ == (*candidate.payload)@)
            &&& final(objects)@ == old(objects)@.insert(id, retained)
            &&& retained.record == prior.record && retained.payload == prior.payload
            &&& if out.is_ok() && prior.location.is_none() && candidate.location.is_some() {
                retained.location == candidate.location && retained.direct == candidate.direct
            } else { retained == prior }
        } else {
            out.is_ok() && final(objects)@ == old(objects)@.insert(id, candidate)
        },
{
    if let Some(retained) = objects.get_mut(&id) {
        retained.merge(candidate)
    } else {
        objects.insert(id, candidate);
        Ok(())
    }
}

}
