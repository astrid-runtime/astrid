//! Resolve a wire source in the current registry before exposing a capsule.
use super::{
    generation::RuntimeId,
    instance_swap::{self, Entry},
};
use std::{collections::HashMap, hash::Hash, sync::Arc};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::iter::IteratorSpec;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_eq::obeys_concrete_eq,
    std_specs::hash::{hash_map_inv, obeys_key_model},
};

verus! {
broadcast use vstd::std_specs::hash::group_hash_axioms;

pub(super) open spec fn eligible<K,A,S,C: ?Sized,P>(v: RuntimeId<K,A,S>, artifact: A,
    instances: Map<RuntimeId<K,A,S>,Entry<C,P>>) -> bool {
    v.identity().0.1 == artifact && instances.contains_key(v)
}

pub(super) fn unique_legacy<'a,K: Eq + Hash,A: Eq + Hash,S: Eq + Hash,C: ?Sized,P>(
    view: &'a HashMap<K,RuntimeId<K,A,S>>, instances: &HashMap<RuntimeId<K,A,S>,Entry<C,P>>,
    artifact: &A,
) -> (out: Option<&'a RuntimeId<K,A,S>>)
    requires hash_map_inv(view), hash_map_inv(instances), obeys_key_model::<K>(),
        obeys_concrete_eq::<A>(), obeys_concrete_eq::<RuntimeId<K,A,S>>(), obeys_key_model::<RuntimeId<K,A,S>>(),
    ensures ({
        let keys = view@.dom().filter(|key:K| eligible(view@[key],*artifact,instances@));
        match out {
            Some(v) => exists|key:K| keys == Set::empty().insert(key) && *v == #[trigger] view@[key],
            None => forall|key:K| keys != #[trigger] Set::empty().insert(key),
        }
    }),
{
    proof { reveal(obeys_concrete_eq); }
    let mut entries = view.iter();
    let ghost all = entries.remaining();
    let ghost keys = view@.dom().filter(|k:K| eligible(view@[k],*artifact,instances@));
    let ghost mut n:int = 0;
    let ghost mut matched: Option<K> = None;
    let mut found = None;
    loop
        invariant 0 <= n <= all.len(), all.len() == view@.dom().len(), all.no_duplicates(),
            keys == view@.dom().filter(|k:K| eligible(view@[k],*artifact,instances@)),
            hash_map_inv(instances), obeys_key_model::<RuntimeId<K,A,S>>(), obeys_concrete_eq::<RuntimeId<K,A,S>>(),
            obeys_concrete_eq::<A>(), entries.remaining() == all.skip(n),
            forall|i:int| 0 <= i < all.len() ==> view@.contains_key(*all[i].0) && #[trigger] view@[*all[i].0] == *all[i].1,
            forall|k:K| view@.contains_key(k) ==> all.contains((&k,&view@[k])),
            matched.is_some() == found.is_some(),
            matched matches Some(k) ==> keys.contains(k) && found == Some(&view@[k]) &&
                exists|i:int| 0 <= i < n && *all[i].0 == k,
            forall|i:int| 0 <= i < n && keys.contains(*all[i].0) ==> matched == Some(*all[i].0),
        decreases view@.dom().len() - n,
    {
        let Some((_key,v)) = entries.next() else {
            assert(n == all.len());
            assert forall|k:K| keys.contains(k) implies matched == Some(k) by {
                assert(view@.contains_key(k));
                assert(all.contains((&k,&view@[k])));
                let i = choose|i:int| 0 <= i < n && all[i] == (&k,&view@[k]);
                assert(keys.contains(*all[i].0));
            }
            proof {
                if let Some(k) = matched {
                    assert(keys =~= Set::empty().insert(k));
                    assert(*found.unwrap() == view@[k]);
                    assert(exists|_key:K| keys == Set::empty().insert(_key) && *found.unwrap() == #[trigger] view@[_key]);
                } else {
                    assert(keys =~= Set::empty());
                    assert forall|k:K| keys != #[trigger] Set::empty().insert(k) by { assert(!keys.contains(k)); }
                }
            }
            return found;
        };
        assert((_key,v) == all[n]);
        assert(view@[*_key] == *v);
        assert(view@.contains_key(*_key));
        let observed = v.key().artifact();
        assert(*observed == v.identity().0.1);
        proof { reveal(obeys_concrete_eq); }
        let same = A::eq(observed,artifact);
        assert(same == (*observed == *artifact));
        let hit = same && instances.contains_key(v);
        if same { assert(hit == instances@.contains_key(*v)); }
        assert(eligible(*v,*artifact,instances@) == hit);
        assert(hit == keys.contains(*_key));
        if hit {
            if found.is_some() {
                assert(keys.contains(*_key));
                let ghost k = matched.unwrap();
                assert(k != *_key) by {
                    let i = choose|i:int| 0 <= i < n && *all[i].0 == k;
                    assert(*all[i].1 == view@[k]);
                }
                assert forall|x:K| keys != #[trigger] Set::empty().insert(x) by {
                    assert(keys.contains(k) && keys.contains(*_key));
                }
                return None;
            }
            found = Some(v);
            proof {
                matched = Some(*_key);
                assert(exists|i:int| 0 <= i < n+1 && *all[i].0 == *_key);
            }
        }
        assert(entries.remaining() =~= all.skip(n+1));
        assert forall|i:int| 0 <= i < n+1 && keys.contains(*all[i].0) implies matched == Some(*all[i].0) by {
            if i == n { assert(*all[i].0 == *_key); }
        }
        proof { n = n+1; }
    }
}
/// A scoped source always takes precedence, including when its instance has gone.
pub(super) fn capsule_for<U: Eq + Hash,P: Eq + Hash,K: Eq + Hash,A: Eq + Hash,S: Eq + Hash,C: ?Sized>(
    scoped: &HashMap<(U,P),RuntimeId<K,A,S>>, aliases: &HashMap<U,A>,
    instances: &HashMap<RuntimeId<K,A,S>,Entry<C,P>>, views: &HashMap<P,HashMap<K,RuntimeId<K,A,S>>>,
    key: (U,P),
) -> (out: Option<Arc<C>>)
    requires hash_map_inv(scoped), hash_map_inv(aliases), hash_map_inv(instances), hash_map_inv(views),
        obeys_key_model::<(U,P)>(), obeys_concrete_eq::<(U,P)>(), obeys_key_model::<U>(), obeys_concrete_eq::<U>(),
        obeys_key_model::<P>(), obeys_concrete_eq::<P>(), obeys_key_model::<K>(), obeys_concrete_eq::<A>(),
        obeys_key_model::<RuntimeId<K,A,S>>(), obeys_concrete_eq::<RuntimeId<K,A,S>>(),
        views@.contains_key(key.1) ==> hash_map_inv(&views@[key.1]),
    ensures ({
        if scoped@.contains_key(key) {
            let v = scoped@[key];
            out == if instances@.contains_key(v) { Some(instances@[v].capsule) } else { None }
        } else if aliases@.contains_key(key.0) && views@.contains_key(key.1) {
            let view = views@[key.1]@;
            let keys = view.dom().filter(|k:K| eligible(view[k],aliases@[key.0],instances@));
            match out {
                Some(handle) => exists|k:K| keys == Set::empty().insert(k) && handle == #[trigger] instances@[view[k]].capsule,
                None => forall|k:K| keys != #[trigger] Set::empty().insert(k),
            }
        } else { out.is_none() }
    }),
{
    if let Some(v) = scoped.get(&key) {
        return instance_swap::installed(instances,v);
    }
    let artifact = aliases.get(&key.0)?;
    let view = views.get(&key.1)?;
    let selected = unique_legacy(view,instances,artifact)?;
    proof {
        let keys = view@.dom().filter(|k:K| eligible(view@[k],*artifact,instances@));
        let k = choose|k:K| keys == Set::empty().insert(k) && *selected == #[trigger] view@[k];
        assert(keys.contains(k));
        assert(instances@.contains_key(*selected));
    }
    instance_swap::installed(instances,selected)
}

}
