//! Select a point-read snapshot by owner and consult its key only at the sampled root.
use super::RootState;
use std::{collections::BTreeMap, sync::Arc};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

verus! {
pub(super) enum CachedValue {
    Present(Arc<[u8]>),
    Missing,
}

impl Clone for CachedValue {
    fn clone(&self) -> (copy:Self)
        ensures copy == *self,
    {
        match self {
            Self::Present(bytes) => Self::Present(Arc::clone(bytes)),
            Self::Missing => Self::Missing,
        }
    }
}

impl CachedValue {
    pub(super) open spec fn bytes_view(&self) -> Option<Seq<u8>> {
        match self {Self::Present(bytes) => Some((**bytes)@),Self::Missing => None}
    }

    pub(super) fn to_vec(&self) -> (out:Option<Vec<u8>>)
        ensures match out {Some(v) => self.bytes_view() == Some(v@), None => self.bytes_view().is_none()},
    {
        match self {
            Self::Present(bytes) => {
                let mut value = Vec::with_capacity(bytes.len());
                value.extend_from_slice(bytes);
                Some(value)
            },
            Self::Missing => None,
        }
    }
}

/// The payload can itself represent an absent value cached at this root.
pub(super) fn at_root<V,F>(observed:Option<RootState>,requested:Option<RootState>,key:&[u8],read:F)
    -> (out:Option<V>) where F:FnOnce(&[u8])->Option<V>,
    requires observed == requested ==> read.requires((key,)),
    ensures if observed == requested {read.ensures((key,),out)} else {out.is_none()},
{
    let same = match (observed,requested) {
        (Some(a),Some(b)) => a.same(b),
        (None,None) => true,
        _ => false,
    };
    if same {read(key)} else {None}
}

pub(super) fn lookup<P:Ord,S,V,F>(owners:&BTreeMap<P,S>,owner:&P,requested:Option<RootState>,
    key:&[u8],snapshot:F) -> (out:Option<V>) where F:FnOnce(&S,Option<RootState>,&[u8])->Option<V>,
    requires btree_map_inv(owners),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        owners@.contains_key(*owner) ==> snapshot.requires((&owners@[*owner],requested,key)),
    ensures if owners@.contains_key(*owner) {snapshot.ensures((&owners@[*owner],requested,key),out)}
        else {out.is_none()},
{
    let selected = owners.get(owner)?;
    snapshot(selected,requested,key)
}
}
