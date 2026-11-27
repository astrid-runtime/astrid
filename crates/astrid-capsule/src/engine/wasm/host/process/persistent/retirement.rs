//! Remove one principal’s entries from the persistent process registry.
use std::collections::HashMap;
use std::hash::Hash;
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
fn keys_for<K: Copy + Eq + Hash, V, F: Fn(&V) -> bool>(
    entries: &HashMap<K, V>, matches: F,
) -> (keys: Vec<K>)
    requires hash_map_inv(entries), obeys_key_model::<K>(),
        forall|v:&V| matches.requires((v,)),
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
            forall|v:&V| matches.requires((v,)),
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
        let yes = matches(v);
        if yes { keys.push(*k); }
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

// The witness pairs each removed entry with its unique original registry key.
pub(super) open spec fn retired<K, V, F: Fn(&V) -> bool>(
    before: Map<K, V>, after: Map<K, V>, keys: Seq<K>, removed: Seq<V>, matches: F,
) -> bool {
    keys.no_duplicates() && keys.len() == removed.len()
            && (forall|k:K| #[trigger] before.contains_key(k) ==> matches.ensures((&before[k],),keys.contains(k)))
            && (forall|i:int| 0 <= i < keys.len() ==> before.contains_key(#[trigger] keys[i]) && removed[i] == before[keys[i]])
            && after == before.remove_keys(keys.to_set())
}
pub(super) fn drain_for<K: Copy + Eq + Hash, V, F: Fn(&V) -> bool>(
    entries: &mut HashMap<K, V>, matches: F,
) -> (removed: Vec<V>)
    requires hash_map_inv(old(entries)), obeys_key_model::<K>(), vstd::laws_eq::obeys_concrete_eq::<K>(),
        forall|v:&V| matches.requires((v,)),
    ensures hash_map_inv(final(entries)), ({
        let before = old(entries)@;
        exists|keys:Seq<K>| retired(before,final(entries)@,keys,removed@,matches)
    }),
{
    let ghost before = entries@;
    let keys = keys_for(entries,matches);
    let mut removed = Vec::new();
    let mut i = 0usize;
    // The registry loses exactly the processed prefix. The output retains its original values.
    while i < keys.len()
        invariant
            obeys_key_model::<K>(), vstd::laws_eq::obeys_concrete_eq::<K>(),
            i <= keys@.len(), keys@.no_duplicates(), removed@.len() == i,
            forall|k:K| #[trigger] before.contains_key(k) ==> matches.ensures((&before[k],),keys@.contains(k)),
            forall|k:K| keys@.contains(k) ==> before.contains_key(k),
            hash_map_inv(entries), entries@ == before.remove_keys(keys@.take(i as int).to_set()),
            forall|j:int| 0 <= j < i ==> removed@[j] == before[keys@[j]],
        decreases keys.len() - i,
    {
        let key = keys[i];
        assert(keys@.contains(key));
        assert(!keys@.take(i as int).contains(key));
        assert(before.contains_key(key));
        let ghost seen = keys@.take(i as int);
        assert(!seen.to_set().contains(key));
        assert(entries@.contains_key(key));
        if let Some(entry) = entries.remove(&key) {
            removed.push(entry);
        }
        assert(keys@.take(i as int + 1) =~= keys@.take(i as int).push(key));
        assert(keys@.take(i as int + 1).to_set() =~= seen.to_set().insert(key));
        assert(entries@ =~= before.remove_keys(keys@.take(i as int + 1).to_set()));
        i += 1;
    }
    assert(keys@.take(i as int) =~= keys@);
    assert forall|j:int| 0 <= j < keys@.len() implies before.contains_key(#[trigger] keys@[j]) && removed@[j] == before[keys@[j]] by { assert(keys@.contains(keys@[j])); }
    assert(entries@ == before.remove_keys(keys@.to_set()));
    assert(keys@.len() == removed@.len());
    assert(forall|k:K| #[trigger] before.contains_key(k) ==> matches.ensures((&before[k],),keys@.contains(k)));
    assert(retired(before,entries@,keys@,removed@,matches));
    removed
}
}
