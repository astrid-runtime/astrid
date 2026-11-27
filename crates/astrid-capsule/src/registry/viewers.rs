//! Identify the principal views attached to one exact runtime generation.
use std::{collections::HashMap, hash::Hash};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_eq::obeys_concrete_eq,
    pervasive::obeys_clone_eq,
    std_specs::hash::{hash_map_inv, obeys_key_model},
    std_specs::iter::IteratorSpec,
};

verus! {
broadcast use vstd::std_specs::hash::group_hash_axioms;

pub(super) fn attached<K: Eq + Hash, V: Eq>(view: &HashMap<K,V>, runtime: &V) -> (found: bool)
    requires hash_map_inv(view), obeys_key_model::<K>(), obeys_concrete_eq::<V>(),
    ensures found == view@.values().contains(*runtime),
{
    proof { reveal(obeys_concrete_eq); }
    let mut values = view.values();
    let ghost all = values.remaining();
    let found = values.any(|v: &V| -> (hit: bool)
        ensures hit == (*v == *runtime),
        { V::eq(v,runtime) });
    proof {
        if found {
            let i = all.len() - values.remaining().len() - 1;
            assert(*all[i] == *runtime);
            assert(all.unref()[i] == *runtime);
            assert(all.unref().contains(*runtime));
        } else if view@.values().contains(*runtime) {
            let i = choose|i:int| 0 <= i < all.unref().len() && all.unref()[i] == *runtime;
            assert(*all[i] == *runtime);
        }
    }
    found
}

pub(super) fn viewers<P: Eq + Hash + Clone, K: Eq + Hash, V: Eq>(
    views: &HashMap<P, HashMap<K,V>>, runtime: &V) -> (out: Vec<P>)
    requires hash_map_inv(views), obeys_key_model::<P>(), obeys_key_model::<K>(),
        obeys_clone_eq::<P>(), obeys_concrete_eq::<V>(),
        forall|p:P| views@.contains_key(p) ==> hash_map_inv(&views@[p]),
    ensures out@.no_duplicates(),
        forall|p:P| #[trigger] out@.contains(p) <==>
        views@.contains_key(p) && views@[p]@.values().contains(*runtime),
{
    let mut out = Vec::new();
    let mut entries = views.iter();
    // Capture the iterator domain once. The loop consumes exactly its prefix.
    let ghost all = entries.remaining();
    let ghost mut n:int = 0;
    loop
        invariant all.no_duplicates(), out@.no_duplicates(), all.len() == views@.dom().len(), 0 <= n <= all.len(),
            obeys_key_model::<K>(), obeys_concrete_eq::<V>(), obeys_clone_eq::<P>(), entries.remaining() == all.skip(n),
            forall|i:int| 0 <= i < all.len() ==> views@.contains_key(*all[i].0)
                && #[trigger] views@[*all[i].0] == *all[i].1,
            forall|p:P| views@.contains_key(p) ==> all.contains((&p, &views@[p])),
            forall|p:P| views@.contains_key(p) ==> hash_map_inv(&views@[p]),
            forall|p:P| #[trigger] out@.contains(p) <==>
                exists|i:int| 0 <= i < n && *all[i].0 == p && all[i].1@.values().contains(*runtime),
        decreases views@.dom().len() - n,
    {
        let Some((principal,view)) = entries.next() else {
            assert(n == all.len());
            assert forall|p:P| views@.contains_key(p) && views@[p]@.values().contains(*runtime)
                implies #[trigger] out@.contains(p) by {
                let i = choose|i:int| 0 <= i < all.len() && all[i] == (&p,&views@[p]);
            }
            assert forall|p:P| #[trigger] out@.contains(p) implies
                views@.contains_key(p) && views@[p]@.values().contains(*runtime) by {
                let i = choose|i:int| 0 <= i < n && *all[i].0 == p && all[i].1@.values().contains(*runtime);
                assert(views@[p] == *all[i].1);
            }
            return out;
        };
        assert((principal,view) == all[n]);
        assert(views@[*principal] == *view);
        assert(views@.contains_key(*principal));
        let ghost prior = out@;
        let hit = attached(view,runtime);
        if hit {
            // The outer map yields one entry per principal even when several slots match.
            let selected = principal.clone();
            assert(vstd::pervasive::cloned(*principal,selected));
            assert(selected == *principal);
            assert(!prior.contains(*principal)) by {
                if prior.contains(*principal) {
                    let i = choose|i:int| 0 <= i < n && *all[i].0 == *principal && all[i].1@.values().contains(*runtime);
                    assert(views@[*all[i].0] == *all[i].1);
                    assert(all[i] == all[n]);
                }
            }
            out.push(selected);
            assert forall|i:int,j:int| 0 <= i < j < out@.len() implies out@[i] != out@[j] by {
                if j == prior.len() { assert(prior.contains(out@[i])); }
            }
        }
        assert(entries.remaining() =~= all.skip(n+1));
        assert forall|p:P| #[trigger] out@.contains(p) ==
            (prior.contains(p) || (hit && p == *principal)) by {
            if hit { vstd::seq_lib::lemma_seq_contains_after_push(prior, *principal, p); }
        }
        assert forall|p:P| #[trigger] out@.contains(p) <==>
            (exists|i:int| 0 <= i < n+1 && *all[i].0 == p && all[i].1@.values().contains(*runtime)) by {
            if out@.contains(p) && !prior.contains(p) {
                assert(*all[n].0 == p && all[n].1@.values().contains(*runtime));
            } else if prior.contains(p) {
                let i = choose|i:int| 0 <= i < n && *all[i].0 == p && all[i].1@.values().contains(*runtime);
                assert(0 <= i < n+1);
                assert(exists|j:int| 0 <= j < n+1 && *all[j].0 == p && all[j].1@.values().contains(*runtime));
            } else if exists|i:int| 0 <= i < n+1 && *all[i].0 == p && all[i].1@.values().contains(*runtime) {
                let i = choose|i:int| 0 <= i < n+1 && *all[i].0 == p && all[i].1@.values().contains(*runtime);
                if i < n { assert(prior.contains(p)); }
            }
        }
        proof { n = n+1; }
    }
}
}
