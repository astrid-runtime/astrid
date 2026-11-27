//! Resolve the principal and capsule slot before consulting the instance map.
use super::instance_swap::{self, Entry};
use std::{collections::HashMap, hash::Hash, sync::Arc};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_eq::obeys_concrete_eq,
    std_specs::hash::{hash_map_inv, obeys_key_model},
};

verus! {
broadcast use vstd::std_specs::hash::group_hash_axioms;

pub(super) open spec fn slot<P,K,V>(views: Map<P,HashMap<K,V>>, principal: P, capsule: K) -> Option<V> {
    if views.contains_key(principal) && views[principal]@.contains_key(capsule) {
        Some(views[principal]@[capsule])
    } else { None }
}

pub(super) fn resolve<'a,P: Eq + Hash,K: Eq + Hash,V>(
    views: &'a HashMap<P,HashMap<K,V>>, principal: &P, capsule: &K,
) -> (out: Option<&'a V>)
    requires hash_map_inv(views), obeys_key_model::<P>(), obeys_concrete_eq::<P>(),
        obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
        views@.contains_key(*principal) ==> hash_map_inv(&views@[*principal]),
    ensures out == match slot(views@,*principal,*capsule) { Some(v) => Some(&v), None => None },
{
    views.get(principal)?.get(capsule)
}

pub(super) fn current<P: Eq + Hash,K: Eq + Hash,V: Eq>(
    views: &HashMap<P,HashMap<K,V>>, principal: &P, capsule: &K, expected: &V,
) -> (yes: bool)
    requires hash_map_inv(views), obeys_key_model::<P>(), obeys_concrete_eq::<P>(),
        obeys_key_model::<K>(), obeys_concrete_eq::<K>(), obeys_concrete_eq::<V>(),
        views@.contains_key(*principal) ==> hash_map_inv(&views@[*principal]),
    ensures yes == (slot(views@,*principal,*capsule) == Some(*expected)),
{
    proof { reveal(obeys_concrete_eq); }
    match resolve(views,principal,capsule) {
        Some(actual) => V::eq(actual,expected),
        None => false,
    }
}

pub(super) fn capsule_for<P: Eq + Hash,K: Eq + Hash,V: Eq + Hash,C: ?Sized,A>(
    views: &HashMap<P,HashMap<K,V>>, instances: &HashMap<V,Entry<C,A>>, principal: &P, capsule: &K,
) -> (out: Option<Arc<C>>)
    requires hash_map_inv(views), hash_map_inv(instances),
        obeys_key_model::<P>(), obeys_concrete_eq::<P>(), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
        obeys_key_model::<V>(), obeys_concrete_eq::<V>(),
        views@.contains_key(*principal) ==> hash_map_inv(&views@[*principal]),
    ensures out == match slot(views@,*principal,*capsule) {
        Some(v) if instances@.contains_key(v) => Some(instances@[v].capsule),
        _ => None,
    },
{
    let generation = resolve(views,principal,capsule)?;
    instance_swap::installed(instances,generation)
}
}
