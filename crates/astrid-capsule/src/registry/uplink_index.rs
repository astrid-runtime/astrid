//! Select uplink descriptors by ID and withdraw exactly one package's registrations.
use std::{collections::HashMap, hash::Hash};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_eq::obeys_concrete_eq,
    std_specs::{
        hash::{hash_map_inv, obeys_key_model},
        iter::IteratorSpec,
    },
};

verus! {
broadcast use {vstd::std_specs::hash::group_hash_axioms, vstd::seq_lib::group_seq_properties};

pub(super) fn descriptor<'a,K:Eq+Hash,O,D>(entries:&'a HashMap<K,(O,D)>, id:&K) -> (out:Option<&'a D>)
    requires hash_map_inv(entries), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
    ensures out == if entries@.contains_key(*id) { Some(&entries@[*id].1) } else { None },
{
    match entries.get(id) { Some((_,d)) => Some(d), None => None }
}

pub(super) fn withdraw<K:Eq+Hash+Copy,O:Eq,D>(entries:&mut HashMap<K,(O,D)>, owner:&O)
    requires hash_map_inv(old(entries)), obeys_key_model::<K>(), obeys_concrete_eq::<K>(), obeys_concrete_eq::<O>(),
    ensures hash_map_inv(final(entries)), final(entries)@ == old(entries)@.restrict(
        old(entries)@.dom().filter(|id:K| old(entries)@[id].0 != *owner)),
{
    proof { reveal(obeys_concrete_eq); }
    let ghost before = entries@;
    let keys = crate::registry_keys::keys_for(entries,
        |row:&(O,D)| -> (matches:bool) ensures matches == (row.0 == *owner), { O::eq(&row.0,owner) },
        |id:&K| -> (copied:K) ensures copied == *id, { *id });
    crate::registry_keys::remove(entries,keys.as_slice());
    assert(entries@ =~= before.restrict(before.dom().filter(|id:K| before[id].0 != *owner)));
}

/// Keep package registrations while any principal still has that package in its view.
pub(super) fn prune_unviewed<P:Eq+Hash,O:Eq+Hash,V,D,K:Eq+Hash+Copy>(
    views:&HashMap<P,HashMap<O,V>>, entries:&mut HashMap<K,(O,D)>, package:&O)
    requires hash_map_inv(views), hash_map_inv(old(entries)), obeys_key_model::<P>(),
        obeys_key_model::<O>(), obeys_concrete_eq::<O>(), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
        forall|p:P| views@.contains_key(p) ==> hash_map_inv(&views@[p]),
    ensures hash_map_inv(final(entries)), final(entries)@ == if exists|p:P| views@.contains_key(p) &&
        (#[trigger] views@[p])@.contains_key(*package) { old(entries)@ }
        else { old(entries)@.restrict(old(entries)@.dom().filter(|id:K| old(entries)@[id].0 != *package)) },
{
    let mut rows = views.iter();
    let ghost all = rows.remaining();
    let ghost mut n:int = 0;
    loop
        invariant hash_map_inv(entries), entries@ == old(entries)@, 0 <= n <= all.len(), rows.remaining() == all.skip(n),
            all.len() == views@.dom().len(), obeys_key_model::<O>(), obeys_concrete_eq::<O>(), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
            forall|p:P| views@.contains_key(p) ==> all.contains((&p,&views@[p])) && hash_map_inv(&views@[p]),
            forall|i:int| 0 <= i < all.len() ==> views@.contains_key(*all[i].0) && #[trigger] views@[*all[i].0] == *all[i].1,
            forall|i:int| 0 <= i < n ==> !(#[trigger] all[i].1)@.contains_key(*package),
        decreases views@.dom().len() - n,
    {
        let Some((principal,view)) = rows.next() else {
            assert(n == all.len());
            assert forall|p:P| views@.contains_key(p) implies !(#[trigger] views@[p])@.contains_key(*package) by {
                let i = all.index_of((&p,&views@[p]));
                assert(0 <= i < n);
                assert(all[i] == (&p,&views@[p]));
                assert(!all[i].1@.contains_key(*package));
            }
            withdraw(entries,package);
            return;
        };
        assert(all[n] == (principal,view));
        assert(views@.contains_key(*principal));
        assert(views@[*principal] == *view);
        if view.contains_key(package) { return; }
        assert(rows.remaining() =~= all.skip(n+1));
        proof { n = n+1; }
    }
}
}
