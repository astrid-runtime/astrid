//! Select a point-read snapshot by owner and consult its key only at the sampled root.
use super::RootState;
use std::{collections::BTreeMap, sync::Arc};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq, obeys_cmp_deep_eq},
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

impl DeepView for CachedValue {
    type V = Option<Seq<u8>>;
    closed spec fn deep_view(&self) -> Self::V { self.bytes_view() }
}

pub(super) fn store_row(rows:&mut BTreeMap<Vec<u8>,CachedValue>,key:Vec<u8>,value:CachedValue)
    requires btree_map_inv(old(rows)),obeys_cmp::<Vec<u8>>(),obeys_cmp_deep_eq::<Vec<u8>>(),
    ensures btree_map_inv(final(rows)),final(rows).deep_view() == old(rows).deep_view().insert(key@,value.bytes_view()),
{
    broadcast use vstd::std_specs::btree::group_btree_axioms;
    assert(key.deep_view() =~= key@);
    rows.insert(key,value);
}

pub(super) fn row<'a>(rows:&'a BTreeMap<Vec<u8>,CachedValue>,key:&Vec<u8>) -> (out:Option<&'a CachedValue>)
    requires btree_map_inv(rows),obeys_cmp::<Vec<u8>>(),obeys_cmp_deep_eq::<Vec<u8>>(),
    ensures match out {
        Some(v) => rows.deep_view().get(key@) == Some(v.bytes_view()),
        None => !rows.deep_view().contains_key(key@),
    },
{
    broadcast use vstd::std_specs::btree::group_btree_axioms;
    assert(key.deep_view() =~= key@);
    rows.get::<Vec<u8>>(key)
}

/// The payload can itself represent an absent value cached at this root.
pub(super) fn at_root<V,F>(observed:Option<RootState>,requested:Option<RootState>,key:&Vec<u8>,read:F)
    -> (out:Option<V>) where F:FnOnce(&Vec<u8>)->Option<V>,
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
    key:&Vec<u8>,snapshot:F) -> (out:Option<V>) where F:FnOnce(&S,Option<RootState>,&Vec<u8>)->Option<V>,
    requires btree_map_inv(owners),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        owners@.contains_key(*owner) ==> snapshot.requires((&owners@[*owner],requested,key)),
    ensures if owners@.contains_key(*owner) {snapshot.ensures((&owners@[*owner],requested,key),out)}
        else {out.is_none()},
{
    let selected = owners.get(owner)?;
    snapshot(selected,requested,key)
}

/// One successful point read, held until its optional cache fill.
pub(super) struct PointRead<P> {
    owner:P,
    key:Vec<u8>,
    root:Option<RootState>,
    value:Option<Vec<u8>>,
}

impl<P:Clone> PointRead<P> {
    pub(super) closed spec fn binding(&self) -> (P,Vec<u8>,Option<RootState>,Option<Vec<u8>>) {
        (self.owner,self.key,self.root,self.value)
    }

    pub(super) fn load<E,L>(owner:P,key:Vec<u8>,read:L) -> (out:Result<Self,E>)
        where L:FnOnce(P,&Vec<u8>)->Result<(Option<RootState>,Option<Vec<u8>>),E>,
        requires vstd::pervasive::obeys_clone_eq::<P>(),read.requires((owner,&key)),
        ensures match out {
            Ok(row) => row.binding().0 == owner && row.binding().1 == key &&
                read.ensures((owner,&key),Ok((row.binding().2,row.binding().3))),
            Err(e) => read.ensures((owner,&key),Err(e)),
        },
    {
        proof { reveal(vstd::pervasive::obeys_clone_eq); }
        let read_owner = P::clone(&owner);
        assert(vstd::pervasive::cloned(owner,read_owner));
        assert(read_owner == owner);
        let (root,value) = read(read_owner,&key)?;
        Ok(Self {owner,key,root,value})
    }

    /// Return the observed value after offering it to the cache, including negative entries.
    pub(super) fn retain<C>(self,cache:C) -> (out:Option<Vec<u8>>)
        where C:FnOnce(&P,Vec<u8>,Option<RootState>,&Option<Vec<u8>>),
        requires cache.requires((&self.binding().0,self.binding().1,self.binding().2,&self.binding().3)),
        ensures out == self.binding().3,
            cache.ensures((&self.binding().0,self.binding().1,self.binding().2,&out),()),
    {
        cache(&self.owner,self.key,self.root,&self.value);
        self.value
    }
}
}
