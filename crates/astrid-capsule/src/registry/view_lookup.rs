//! Resolve the principal and capsule slot before consulting the instance map.
use super::{
    generation::RuntimeId,
    instance_swap::{self, Entry},
};
use std::{collections::HashMap, hash::Hash, sync::Arc};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_eq::obeys_concrete_eq,
    std_specs::hash::{hash_map_inv, obeys_key_model},
    std_specs::iter::IteratorSpec,
};

verus! {
broadcast use vstd::std_specs::hash::group_hash_axioms;

fn matches_shared<K: Eq,A: Eq>(id: &RuntimeId<K,A,super::RuntimeScope>, package: &K, artifact: &A)
    -> (yes: bool)
    requires obeys_concrete_eq::<K>(), obeys_concrete_eq::<A>(),
    ensures yes == (id.identity().0 == (*package,*artifact,super::RuntimeScope::SystemResident)),
{
    proof { reveal(obeys_concrete_eq); }
    let key = id.key();
    if let super::RuntimeScope::Principal(_) = key.scope() { return false; }
    let candidate = key.capsule_id();
    if !K::eq(candidate,package) { return false; }
    let bytes = key.artifact();
    A::eq(bytes,artifact)
}

/// Select an installed shareable generation with the requested package and artifact.
pub(super) fn shared<K: Eq + Hash + Clone,A: Eq + Hash + Clone,E>(
    instances: &HashMap<RuntimeId<K,A,super::RuntimeScope>,E>, package: &K, artifact: &A)
    -> (out: Option<RuntimeId<K,A,super::RuntimeScope>>)
    requires hash_map_inv(instances), obeys_key_model::<RuntimeId<K,A,super::RuntimeScope>>(),
        obeys_concrete_eq::<K>(), obeys_concrete_eq::<A>(),
        vstd::pervasive::obeys_clone_eq::<RuntimeId<K,A,super::RuntimeScope>>(),
    ensures match out {
        Some(id) => instances@.contains_key(id) &&
            id.identity().0 == (*package,*artifact,super::RuntimeScope::SystemResident),
        None => forall|id:RuntimeId<K,A,super::RuntimeScope>| instances@.contains_key(id) ==>
            id.identity().0 != (*package,*artifact,super::RuntimeScope::SystemResident),
    },
{
    proof { reveal(obeys_concrete_eq); reveal(vstd::pervasive::obeys_clone_eq); }
    let mut rows = instances.iter();
    let ghost all = rows.remaining();
    let ghost mut n:int = 0;
    loop
        invariant
            obeys_concrete_eq::<K>(), obeys_concrete_eq::<A>(),
            vstd::pervasive::obeys_clone_eq::<RuntimeId<K,A,super::RuntimeScope>>(),
            0 <= n <= all.len(), all.len() == instances@.dom().len(), rows.remaining() == all.skip(n),
            forall|id:RuntimeId<K,A,super::RuntimeScope>| instances@.contains_key(id) ==> all.contains((&id,&instances@[id])),
            forall|i:int| 0 <= i < all.len() ==> instances@.contains_key(*all[i].0),
            forall|i:int| 0 <= i < n ==> (#[trigger] all[i].0).identity().0 != (*package,*artifact,super::RuntimeScope::SystemResident),
        decreases instances@.dom().len() - n,
    {
        let Some((id,_)) = rows.next() else {
            assert(n == all.len());
            assert forall|id:RuntimeId<K,A,super::RuntimeScope>| instances@.contains_key(id) implies
                id.identity().0 != (*package,*artifact,super::RuntimeScope::SystemResident) by {
                let i = all.index_of((&id,&instances@[id]));
                assert(all[i].0 == &id);
            }
            return None;
        };
        assert(all[n].0 == id);
        assert(instances@.contains_key(*id));
        if matches_shared(id,package,artifact) {
            let selected = id.clone();
            assert(vstd::pervasive::cloned(*id,selected));
            assert(selected == *id);
            assert(id.identity().0 == (*package,*artifact,super::RuntimeScope::SystemResident));
            return Some(selected);
        }
        assert(id.identity().0 != (*package,*artifact,super::RuntimeScope::SystemResident));
        assert(rows.remaining() =~= all.skip(n+1));
        proof { n = n+1; }
    }
}

/// Publish the generation under the package carried by its own runtime identity.
pub(super) fn bind<P: Eq + Hash,K: Eq + Hash + Clone,A,S>(
    views: &mut HashMap<P,HashMap<K,RuntimeId<K,A,S>>>, principal: P, runtime: RuntimeId<K,A,S>)
    requires hash_map_inv(old(views)), obeys_key_model::<P>(), obeys_concrete_eq::<P>(),
        obeys_key_model::<K>(), obeys_concrete_eq::<K>(), vstd::pervasive::obeys_clone_eq::<K>(),
        old(views)@.contains_key(principal) ==> hash_map_inv(&old(views)@[principal]),
    ensures hash_map_inv(final(views)), final(views)@.contains_key(principal),
        hash_map_inv(&final(views)@[principal]),
        final(views)@.remove(principal) == old(views)@.remove(principal),
        final(views)@[principal]@ == (if old(views)@.contains_key(principal) { old(views)@[principal]@ }
            else { Map::empty() }).insert(runtime.identity().0.0,runtime),
{
    proof { reveal(vstd::pervasive::obeys_clone_eq); }
    let key = runtime.key().capsule_id();
    let package = key.clone();
    assert(vstd::pervasive::cloned(*key,package));
    match views.entry(principal) {
        std::collections::hash_map::Entry::Occupied(mut row) => {
            row.get_mut().insert(package,runtime);
        },
        std::collections::hash_map::Entry::Vacant(row) => {
            let mut packages = HashMap::new();
            packages.insert(package,runtime);
            row.insert(packages);
        },
    }
}

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
