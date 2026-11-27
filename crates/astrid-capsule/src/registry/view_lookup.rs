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

/// Detach only the named slot and prune its owner row when it becomes empty.
pub(super) fn detach<P: Eq + Hash + Clone, K: Eq + Hash, V: Eq + Hash, C: ?Sized, A>(
    views: &mut HashMap<P,HashMap<K,V>>, instances: &HashMap<V,Entry<C,A>>, principal: &P, capsule: &K,
) -> (out: Option<(V, Option<Arc<C>>)>)
    requires hash_map_inv(instances), obeys_key_model::<V>(), obeys_concrete_eq::<V>(),
        hash_map_inv(old(views)), vstd::pervasive::obeys_clone_eq::<P>(), obeys_key_model::<P>(), obeys_concrete_eq::<P>(),
        obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
        old(views)@.contains_key(*principal) ==> hash_map_inv(&old(views)@[*principal]),
    ensures
        hash_map_inv(final(views)),
        out == match slot(old(views)@,*principal,*capsule) {
            Some(id) => Some((id, if instances@.contains_key(id) { Some(instances@[id].capsule) } else { None })),
            None => None,
        },
        out.is_none() ==> final(views)@ == old(views)@,
        out.is_some() ==> ({
            let before = old(views)@;
            let after = final(views)@;
            let remaining = before[*principal]@.remove(*capsule);
            if remaining.is_empty() { after == before.remove(*principal) }
            else {
                &&& after.contains_key(*principal)
                &&& after[*principal]@ == remaining
                &&& hash_map_inv(&after[*principal])
                &&& after.remove(*principal) == before.remove(*principal)
            }
        }),
{
    proof { reveal(vstd::pervasive::obeys_clone_eq); }
    let key = principal.clone();
    assert(vstd::pervasive::cloned(*principal, key));
    let std::collections::hash_map::Entry::Occupied(mut row) = views.entry(key) else { return None; };
    if !row.get().contains_key(capsule) { return None; }
    let generation = row.get_mut().remove(capsule)?;
    if row.get().is_empty() { row.remove_entry(); }
    let handle = instance_swap::installed(instances, &generation);
    Some((generation, handle))
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

/// Result of capturing the installed incarnation for restart preparation.
pub enum RestartSnapshot<V,C: ?Sized> {
    /// No installed capsule occupies the requested view.
    Missing,
    /// The view no longer contains the caller's expected incarnation.
    Superseded,
    /// The installed handle and the identity under which it was found.
    Current(V,Arc<C>),
}

/// Capture the installed capsule and its full incarnation from one view lookup.
pub(super) fn snapshot<P: Eq + Hash,K: Eq + Hash,V: Eq + Hash + Clone,C: ?Sized,A>(
    views: &HashMap<P,HashMap<K,V>>, instances: &HashMap<V,Entry<C,A>>, principal: &P, capsule: &K, expected: Option<&V>,
) -> (out: RestartSnapshot<V,C>)
    requires hash_map_inv(views), hash_map_inv(instances),
        obeys_key_model::<P>(), obeys_concrete_eq::<P>(), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
        obeys_key_model::<V>(), obeys_concrete_eq::<V>(), vstd::pervasive::obeys_clone_eq::<V>(),
        views@.contains_key(*principal) ==> hash_map_inv(&views@[*principal]),
    ensures out == match slot(views@, *principal, *capsule) {
        Some(v) if instances@.contains_key(v) => match expected {
            Some(e) if *e != v => RestartSnapshot::Superseded,
            _ => RestartSnapshot::Current(v,instances@[v].capsule),
        },
        _ => RestartSnapshot::Missing,
    },
{
    let Some(selected) = resolve(views,principal,capsule) else { return RestartSnapshot::Missing; };
    let Some(handle) = instance_swap::installed(instances,selected) else { return RestartSnapshot::Missing; };
    proof { reveal(obeys_concrete_eq); }
    match expected {
        Some(captured) if !V::eq(selected,captured) => return RestartSnapshot::Superseded,
        _ => {},
    }
    proof { reveal(vstd::pervasive::obeys_clone_eq); }
    let id = V::clone(selected);
    assert(vstd::pervasive::cloned(*selected,id));
    RestartSnapshot::Current(id,handle)
}

}
