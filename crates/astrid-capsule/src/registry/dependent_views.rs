//! Sweep view slots belonging to a retired system runtime generation.
use super::{RuntimeScope, generation::RuntimeId, instance_swap::Entry};
use std::{collections::HashMap, hash::Hash};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_eq::obeys_concrete_eq,
    pervasive::obeys_clone_eq,
    std_specs::hash::{hash_map_inv, obeys_key_model},
};

type Id<K, A> = RuntimeId<K, A, RuntimeScope>;

verus! {
broadcast use {vstd::std_specs::hash::group_hash_axioms, vstd::seq_lib::group_seq_properties};

/// Remove every package slot pointing to this exact generation within a view.
fn remove_generation<K: Eq + Hash + Clone,V: Eq>(view: &mut HashMap<K,V>, runtime: &V)
    -> (changed: bool)
    requires hash_map_inv(old(view)), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
        obeys_clone_eq::<K>(), obeys_concrete_eq::<V>(),
    ensures hash_map_inv(final(view)),
        changed == old(view)@.values().contains(*runtime),
        final(view)@ == old(view)@.restrict(old(view)@.dom().filter(|k:K| old(view)@[k] != *runtime)),
{
    proof { reveal(obeys_concrete_eq); reveal(obeys_clone_eq); }
    let ghost before = view@;
    let keys = crate::registry_keys::keys_for(view,
        |v:&V| -> (yes:bool) ensures yes == (*v == *runtime), { V::eq(v,runtime) },
        |k:&K| -> (out:K) ensures out == *k, {
            let out = k.clone();
            assert(vstd::pervasive::cloned(*k,out));
            out
        });
    let mut i = 0usize;
    while i < keys.len()
        invariant i <= keys.len(), keys@.no_duplicates(), hash_map_inv(view),
            obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
            view@ == before.remove_keys(keys@.take(i as int).to_set()),
        decreases keys.len() - i,
    {
        view.remove(&keys[i]);
        assert(keys@.take(i+1) =~= keys@.take(i as int).push(keys@[i as int]));
        assert(keys@.take(i+1).to_set() =~= keys@.take(i as int).to_set().insert(keys@[i as int]));
        i += 1;
    }
    assert(keys@.take(i as int) =~= keys@);
    assert(view@ =~= before.restrict(before.dom().filter(|k:K| before[k] != *runtime)));
    proof {
        if keys@.len() > 0 {
            let k = keys@[0];
            assert(keys@.contains(k));
            assert(before[k] == *runtime);
        } else if before.values().contains(*runtime) {
            let k = choose|k:K| before.contains_key(k) && before[k] == *runtime;
            assert(keys@.contains(k));
        }
    }
    !keys.is_empty()
}

/// Update the principal-scoped source routes under the same registry write lock.
pub(super) fn revoke_sources<U: Eq + Hash + Copy,P: Eq + Hash + Clone,V: Eq + Hash,I>(
    routes: &mut HashMap<(U,P),V>, sources: &mut HashMap<V,U>, names: &mut HashMap<U,I>, runtime: &V,
    principal: &P, tear_down: bool)
    requires hash_map_inv(old(routes)), hash_map_inv(old(sources)), hash_map_inv(old(names)),
        obeys_key_model::<U>(), obeys_concrete_eq::<U>(), obeys_key_model::<V>(),
        obeys_key_model::<(U,P)>(), obeys_concrete_eq::<V>(), obeys_concrete_eq::<(U,P)>(),
        obeys_clone_eq::<P>(), obeys_clone_eq::<(U,P)>(),
    ensures hash_map_inv(final(routes)), hash_map_inv(final(sources)), hash_map_inv(final(names)),
        final(sources)@ == if tear_down { old(sources)@.remove(*runtime) } else { old(sources)@ },
        final(names)@ == if tear_down && old(sources)@.contains_key(*runtime) &&
            !old(sources)@.remove(*runtime).values().contains(old(sources)@[*runtime]) {
            old(names)@.remove(old(sources)@[*runtime])
        } else { old(names)@ },
        tear_down ==> final(routes)@ == kept(old(routes)@,*runtime),
        !tear_down ==> final(routes)@ == if old(sources)@.contains_key(*runtime) {
            old(routes)@.remove((old(sources)@[*runtime],*principal))
        } else { old(routes)@ },
{
    if tear_down {
        remove_generation(routes,runtime);
        let Some(source) = sources.remove(runtime) else { return; };
        if !super::viewers::attached(sources,&source) {
            names.remove(&source);
        }
    } else if let Some(source) = sources.get(runtime) {
        proof { reveal(obeys_clone_eq); }
        let departing = principal.clone();
        assert(vstd::pervasive::cloned(*principal,departing));
        routes.remove(&(*source,departing));
    }
}

pub(super) open spec fn kept<K,V>(view: Map<K,V>, runtime: V) -> Map<K,V> {
    view.restrict(view.dom().filter(|k:K| view[k] != runtime))
}

pub(super) open spec fn swept<P,K: Eq + Hash,V>(before:Map<P,HashMap<K,V>>, after:Map<P,HashMap<K,V>>,
    runtime:V, prior:Seq<P>, reported:Seq<P>) -> bool {
    let appended = reported.skip(prior.len() as int);
    &&& reported == prior + appended
    &&& appended.no_duplicates()
    &&& forall|p:P| #[trigger] appended.contains(p) == (before.contains_key(p) && before[p]@.values().contains(runtime))
    &&& forall|p:P| #[trigger] after.contains_key(p) == (before.contains_key(p) && !kept(before[p]@,runtime).is_empty())
    &&& forall|p:P| after.contains_key(p) ==> (#[trigger] after[p])@ == kept(before[p]@,runtime) && hash_map_inv(&after[p])
}

fn sweep<P: Eq + Hash + Clone,K: Eq + Hash + Clone,V: Eq>(
    views: &mut HashMap<P,HashMap<K,V>>, runtime: &V, removed: &mut Vec<P>)
    requires hash_map_inv(old(views)), obeys_key_model::<P>(), obeys_concrete_eq::<P>(),
        obeys_key_model::<K>(), obeys_concrete_eq::<K>(), obeys_concrete_eq::<V>(),
        obeys_clone_eq::<P>(), obeys_clone_eq::<K>(),
        forall|p:P| old(views)@.contains_key(p) ==> hash_map_inv(&old(views)@[p]),
    ensures hash_map_inv(final(views)),
        swept(old(views)@,final(views)@,*runtime,old(removed)@,final(removed)@),
{
    proof { reveal(obeys_clone_eq); }
    let ghost before = views@;
    let ghost start = removed@;
    // Collect affected owners before mutating the table. An already-empty
    // row is pruned without reporting that its owner lost a package.
    let owners = crate::registry_keys::keys_for(views,
        |v:&HashMap<K,V>| -> (yes:bool)
            requires hash_map_inv(v),
            ensures yes == (v@.is_empty() || v@.values().contains(*runtime)),
        { v.is_empty() || super::viewers::attached(v,runtime) },
        |p:&P| -> (out:P) ensures out == *p, {
            let out = p.clone(); assert(vstd::pervasive::cloned(*p,out)); out
        });
    let mut i = 0usize;
    while i < owners.len()
        invariant
            i <= owners.len(), owners@.no_duplicates(), hash_map_inv(views),
            obeys_key_model::<K>(), obeys_concrete_eq::<K>(), obeys_concrete_eq::<V>(), obeys_clone_eq::<K>(),
            obeys_key_model::<P>(), obeys_concrete_eq::<P>(), obeys_clone_eq::<P>(),
            forall|p:P| owners@.contains(p) ==> before.contains_key(p),
            forall|p:P| before.contains_key(p) ==> hash_map_inv(&before[p]),
            forall|p:P| before.contains_key(p) ==> owners@.contains(p) == (before[p]@.is_empty() || before[p]@.values().contains(*runtime)),
            forall|p:P| #[trigger] views@.contains_key(p) == (before.contains_key(p) && (!owners@.take(i as int).contains(p) || !kept(before[p]@,*runtime).is_empty())),
            forall|p:P| views@.contains_key(p) ==> (#[trigger] views@[p])@ ==
                (if owners@.take(i as int).contains(p) { kept(before[p]@,*runtime) } else { before[p]@ }) && hash_map_inv(&views@[p]),
            removed@ == start + removed@.skip(start.len() as int),
            removed@.skip(start.len() as int).no_duplicates(),
            forall|p:P| #[trigger] removed@.skip(start.len() as int).contains(p) ==
                (owners@.take(i as int).contains(p) && before.contains_key(p) && before[p]@.values().contains(*runtime)),
        decreases owners.len() - i,
    {
        let p = &owners[i];
        assert(owners@.contains(*p));
        assert(!owners@.take(i as int).contains(*p));
        let ghost prior = views@;
        let ghost suffix = removed@.skip(start.len() as int);
        let owner = p.clone();
        assert(vstd::pervasive::cloned(*p,owner));
        let std::collections::hash_map::Entry::Occupied(mut row) = views.entry(owner) else { unreachable!(); };
        let changed = remove_generation(row.get_mut(),runtime);
        let empty = row.get().is_empty();
        if empty { row.remove_entry(); }
        if changed {
            let affected = p.clone();
            assert(vstd::pervasive::cloned(*p,affected));
            removed.push(affected);
            assert(!suffix.contains(*p));
            assert(removed@.skip(start.len() as int) =~= suffix.push(*p));
            assert forall|a:int,b:int| 0 <= a < b < suffix.len()+1 implies
                suffix.push(*p)[a] != suffix.push(*p)[b] by {
                if b == suffix.len() { assert(suffix.contains(suffix[a])); }
            }
        }
        assert(owners@.take(i+1) =~= owners@.take(i as int).push(*p));
        i += 1;
    }
    assert(owners@.take(i as int) =~= owners@);
    assert forall|p:P| before.contains_key(p) && !owners@.contains(p) implies
        kept(before[p]@,*runtime) == before[p]@ by {
        assert(kept(before[p]@,*runtime) =~= before[p]@);
    }
}

/// Apply the view cleanup that accompanies the registry's teardown decision.
pub(super) fn depart<P: Eq + Hash + Clone,K: Eq + Hash + Clone,A: Eq + Hash,C: ?Sized>(
    views: &mut HashMap<P,HashMap<K,Id<K,A>>>, instances: &mut HashMap<Id<K,A>,Entry<C,P>>,
    runtime: &Id<K,A>, departing: &P, removed: &mut Vec<P>)
    -> (tear_down: bool)
    requires hash_map_inv(old(views)), hash_map_inv(old(instances)),
        old(instances)@.contains_key(*runtime),
        obeys_key_model::<P>(), obeys_concrete_eq::<P>(), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
        obeys_key_model::<Id<K,A>>(), obeys_concrete_eq::<Id<K,A>>(), obeys_clone_eq::<P>(), obeys_clone_eq::<K>(),
        forall|p:P| old(views)@.contains_key(p) ==> hash_map_inv(&old(views)@[p]),
    ensures hash_map_inv(final(views)), hash_map_inv(final(instances)),
        final(instances)@ == if tear_down { old(instances)@.remove(*runtime) } else { old(instances)@ },
        ({
        let before = old(views)@;
        let system = runtime.identity().0.2 is SystemResident;
        let owns = old(instances)@[*runtime].owner_alias == Some(*departing);
        &&& tear_down == (!system || owns || !(exists|p:P| before.contains_key(p) && (#[trigger] before[p])@.values().contains(*runtime)))
        &&& if system && owns { swept(before,final(views)@,*runtime,old(removed)@,final(removed)@) }
            else { final(views)@ == before && final(removed)@ == old(removed)@ }
    }),
{
    let owner = match instances.get(runtime) {
        Some(entry) => entry.owner_alias.as_ref(),
        None => None,
    };
    assert((owner == Some(departing)) == (instances@[*runtime].owner_alias == Some(*departing)));
    match super::viewers::departure(views,runtime,runtime.key().scope(),owner,departing) {
        super::viewers::Departure::KeepRuntime => return false,
        super::viewers::Departure::RemoveRuntime => {},
        super::viewers::Departure::RemoveRuntimeAndViews => sweep(views,runtime,removed),
    }
    instances.remove(runtime);
    true
}
}
