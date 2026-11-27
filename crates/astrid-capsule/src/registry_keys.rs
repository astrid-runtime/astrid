//! Select distinct registry keys from the complete map under its caller’s lock.
use std::{collections::HashMap, hash::Hash};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::{
    hash::{hash_map_inv, obeys_key_model},
    iter::IteratorSpec,
};

verus! {
broadcast use {vstd::std_specs::hash::group_hash_axioms, vstd::seq_lib::group_seq_properties};
pub(super) fn owned_by(principal: &[u8], creator: &[u8]) -> (yes: bool)
    ensures yes == (principal@ == creator@),
{
    if principal != creator { return false; }
    assert(principal@ =~= creator@);
    true
}

// Scan under the registry lock. The iterator covers the initial map in arbitrary order.
pub(super) fn keys_for<K: Eq + Hash, V, F: Fn(&V) -> bool, C: Fn(&K) -> K>(
    entries: &HashMap<K, V>, matches: F, key_for: C,
) -> (keys: Vec<K>)
    requires hash_map_inv(entries), obeys_key_model::<K>(),
        forall|k:K| entries@.contains_key(k) ==> matches.requires((&entries@[k],)),
        forall|k:&K| key_for.requires((k,)),
        forall|k:&K,c:K| key_for.ensures((k,),c) ==> c == *k,
    ensures keys@.no_duplicates(), forall|k:K| entries@.contains_key(k) ==> matches.ensures((&entries@[k],),keys@.contains(k)),
        forall|k:K| keys@.contains(k) ==> entries@.contains_key(k),
{
    let mut iter = entries.iter();
    let ghost initial = iter.remaining();
    // The processed prefix determines membership. No key in the suffix has been selected.
    let mut keys = Vec::new();
    loop
        invariant
            keys@.no_duplicates(),
            iter.decrease().is_some(),
            iter.remaining().len() <= initial.len(),
            iter.remaining() == initial.skip(initial.len() - iter.remaining().len()),
            forall|k:K| entries@.contains_key(k) ==> matches.requires((&entries@[k],)),
            forall|k:&K| key_for.requires((k,)),
            forall|k:&K,c:K| key_for.ensures((k,),c) ==> c == *k,
            forall|i:int| 0 <= i < initial.len() ==> entries@.contains_key(*initial[i].0) && entries@[*initial[i].0] == *initial[i].1,
            forall|k:K| entries@.contains_key(k) ==> initial.contains((&k,&entries@[k])),
            initial.no_duplicates(),
            forall|k:K| keys@.contains(k) ==> entries@.contains_key(k),
            forall|i:int| 0 <= i < initial.len() - iter.remaining().len() ==> matches.ensures((initial[i].1,),keys@.contains(*initial[i].0)),
            forall|i:int| initial.len() - iter.remaining().len() <= i < initial.len() ==> !keys@.contains(*initial[i].0),
        decreases iter.decrease().unwrap(),
    {
        let ghost n = initial.len() - iter.remaining().len();
        let Some((k,v)) = iter.next() else {
            assert forall|key:K| entries@.contains_key(key) implies matches.ensures((&entries@[key],),keys@.contains(key)) by {
                let i = initial.index_of((&key,&entries@[key]));
                assert(initial[i] == (&key,&entries@[key]));
                assert(matches.ensures((initial[i].1,),keys@.contains(*initial[i].0)));
            }
            return keys;
        };
        assert(initial[n] == (k,v));
        assert forall|j:int| 0 <= j < initial.len() && j != n implies *initial[j].0 != *k by {
            if *initial[j].0 == *k { assert(initial[j] == initial[n]); }
        }
        let ghost prior = keys@;
        assert(entries@[*initial[n].0] == *initial[n].1);
        let yes = matches(v);
        if yes { keys.push(key_for(k)); }
        assert(entries@.contains_key(*k));
        assert forall|key:K| keys@.contains(key) implies entries@.contains_key(key) by {
            if key != *k { assert(prior.contains(key)); }
        }
        assert forall|i:int| 0 <= i < n + 1 implies matches.ensures((initial[i].1,),keys@.contains(*initial[i].0)) by {
            if i < n {
                assert(*initial[i].0 != *k);
                assert(keys@.contains(*initial[i].0) == prior.contains(*initial[i].0));
                assert(matches.ensures((initial[i].1,),prior.contains(*initial[i].0)));
            } else { assert(keys@.contains(*k) == yes); }
        }
    }
}

/// Remove exactly the selected keys while preserving the other entries and values.
pub(super) fn remove<K:Eq+Hash,V>(entries:&mut HashMap<K,V>, keys:&[K])
    requires hash_map_inv(old(entries)), obeys_key_model::<K>(), vstd::laws_eq::obeys_concrete_eq::<K>(),
    ensures hash_map_inv(final(entries)), final(entries)@ == old(entries)@.remove_keys(keys@.to_set()),
{
    let ghost before = entries@;
    let mut i = 0usize;
    while i < keys.len()
        invariant i <= keys.len(), hash_map_inv(entries), obeys_key_model::<K>(), vstd::laws_eq::obeys_concrete_eq::<K>(),
            entries@ == before.remove_keys(keys@.take(i as int).to_set()),
        decreases keys.len() - i,
    {
        entries.remove(&keys[i]);
        assert(keys@.take(i+1) =~= keys@.take(i as int).push(keys@[i as int]));
        assert(keys@.take(i+1).to_set() =~= keys@.take(i as int).to_set().insert(keys@[i as int]));
        i += 1;
    }
    assert(keys@.take(i as int) =~= keys@);
}
}
