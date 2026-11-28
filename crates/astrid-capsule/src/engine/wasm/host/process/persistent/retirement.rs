//! Remove one principal’s entries from the persistent process registry.
use super::registry_keys;
use std::collections::HashMap;
use std::hash::Hash;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::hash::{hash_map_inv, obeys_key_model};
verus! {
broadcast use {vstd::std_specs::hash::group_hash_axioms, vstd::seq_lib::group_seq_properties};
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
    let keys = registry_keys::keys_for(entries,matches,|k:&K| -> (out:K) ensures out == *k, { *k });
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
