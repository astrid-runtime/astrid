//! Lazy enumeration of the reservations in one immutable ownership snapshot.
use std::collections::{BTreeMap, btree_map::Iter};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::{
    btree::{btree_map_wf, key_obeys_cmp_spec},
    iter::IteratorSpec,
};

verus! {
#[cfg_attr(not(verus_keep_ghost), derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize))]
#[cfg_attr(not(verus_keep_ghost), serde(rename = "PrincipalDeletionReservation", deny_unknown_fields, bound(deserialize = "A: serde::Deserialize<'de>, F: serde::Deserialize<'de>")))]
pub(super) struct Reservation<A,F> {
    pub(super) alias: Option<A>,
    #[cfg_attr(not(verus_keep_ghost), serde(default, skip_serializing_if = "Option::is_none"))]
    pub(super) fleet: Option<F>,
}

pub(super) fn scan<K: Ord,V>(map: &BTreeMap<K,V>) -> (cursor: Iter<'_,K,V>)
    requires key_obeys_cmp_spec::<K>(), btree_map_wf(map),
    ensures cursor.decrease().is_some(), cursor.remaining().len() == map@.dom().len(),
        cursor.remaining().no_duplicates(),
        forall|k: K, v: V| #[trigger] cursor.remaining().contains((&k,&v)) == (map@.get(k) == Some(v)),
{
    let cursor = map.iter();
    assert forall|k: K, v: V| #[trigger] cursor.remaining().contains((&k,&v)) == (map@.get(k) == Some(v)) by {
        if cursor.remaining().contains((&k,&v)) {
            let i = cursor.remaining().index_of((&k,&v));
            assert(cursor.remaining()[i] == (&k,&v));
            assert(map@.contains_key(*cursor.remaining()[i].0));
            assert(map@[*cursor.remaining()[i].0] == *cursor.remaining()[i].1);
        }
    }
    cursor
}

pub(super) fn next<'a,K: Copy,A,F>(
    cursor: &mut Iter<'a,K,Reservation<A,F>>,
) -> (out: Option<(K,Option<&'a A>)>)
    requires (*old(cursor)).decrease().is_some(),
    ensures ({
        let before = (*old(cursor)).remaining();
        if before.len() == 0 {
            out.is_none() && (*final(cursor)).remaining() == before
        } else {
            &&& (*final(cursor)).decrease().is_some()
            &&& (*final(cursor)).decrease().unwrap() < (*old(cursor)).decrease().unwrap()
            &&& (*final(cursor)).remaining() == before.drop_first()
            &&& out matches Some((key,name)) && key == *before[0].0 && name == match before[0].1.alias { Some(a) => Some(&a), None => None }
        }
    }),
{
    let (uid,value) = cursor.next()?;
    Some((*uid,value.alias.as_ref()))
}
}
