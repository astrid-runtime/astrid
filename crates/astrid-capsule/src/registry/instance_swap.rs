//! Replacement of the concrete registry entry under its write lock.
use std::{collections::HashMap, hash::Hash, sync::Arc};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_eq::obeys_concrete_eq,
    std_specs::hash::{hash_map_inv, obeys_key_model},
};

verus! {
broadcast use vstd::std_specs::hash::group_hash_axioms;

pub(super) struct Entry<C: ?Sized, A> {
    pub(super) capsule: Arc<C>,
    /// Alias used for view teardown and compatibility registration. The runtime key carries the authority UID.
    pub(super) owner_alias: Option<A>,
}

/// Return the previous capsule and install the candidate at the reserved key.
pub(super) fn replace<K: Eq + Hash, C: ?Sized, A>(
    instances: &mut HashMap<K, Entry<C, A>>, expected: &K, reserved: K,
    capsule: Arc<C>, owner_alias: Option<A>,
) -> (out: Option<Arc<C>>)
    requires hash_map_inv(old(instances)), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
    ensures hash_map_inv(final(instances)), ({
        let before = old(instances)@;
        if before.contains_key(*expected) {
            &&& out == Some(before[*expected].capsule)
            &&& final(instances)@ == before.remove(*expected).insert(reserved, Entry { capsule, owner_alias })
        } else {
            out.is_none() && final(instances)@ == before
        }
    }),
{
    let prior = instances.remove(expected)?;
    instances.insert(reserved, Entry { capsule, owner_alias });
    Some(prior.capsule)
}

/// Resolve the exact installed generation, including its artifact and scope.
pub(super) fn installed<K: Eq + Hash, C: ?Sized, A>(instances: &HashMap<K, Entry<C,A>>, generation: &K)
    -> (out: Option<Arc<C>>)
    requires hash_map_inv(instances), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
    ensures out == if instances@.contains_key(*generation) {
        Some(instances@[*generation].capsule)
    } else { None },
{
    Some(instances.get(generation)?.capsule.clone())
}
}

verus! {
/// Retarget exactly those view slots which still refer to the retired identity.
pub(super) fn retarget<K: Eq + Clone>(slot: &mut K, expected: &K, reserved: &K)
    requires obeys_concrete_eq::<K>(), vstd::pervasive::obeys_clone_eq::<K>(),
    ensures *final(slot) == if *old(slot) == *expected { *reserved } else { *old(slot) },
{
    proof { reveal(obeys_concrete_eq); reveal(vstd::pervasive::obeys_clone_eq); }
    let matches = K::eq(slot, expected);
    assert(matches == (*slot == *expected));
    if matches {
        let next = K::clone(reserved);
        assert(vstd::pervasive::cloned(*reserved, next));
        *slot = next;
    }
}

/// Replace every package slot in one view that still names the retired generation.
fn retarget_view<K: Eq + Hash + Clone,V: Eq + Clone>(
    view: &mut HashMap<K,V>, expected: &V, reserved: &V)
    requires hash_map_inv(old(view)), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
        obeys_concrete_eq::<V>(), vstd::pervasive::obeys_clone_eq::<K>(), vstd::pervasive::obeys_clone_eq::<V>(),
    ensures hash_map_inv(final(view)), final(view)@.dom() == old(view)@.dom(),
        forall|k:K| final(view)@.contains_key(k) ==> #[trigger] final(view)@[k] ==
            if old(view)@[k] == *expected { *reserved } else { old(view)@[k] },
{
    proof { reveal(obeys_concrete_eq); reveal(vstd::pervasive::obeys_clone_eq); }
    let ghost before = view@;
    let mut keys = crate::registry_keys::keys_for(view,
        |v:&V| -> (found:bool) ensures found == (*v == *expected), { V::eq(v,expected) },
        |k:&K| -> (key:K) ensures key == *k, {
            let key = k.clone(); assert(vstd::pervasive::cloned(*k,key)); key
        });
    let ghost selected = keys@;
    loop
        invariant before == old(view)@, hash_map_inv(view), view@.dom() == before.dom(), keys@.no_duplicates(),
            obeys_key_model::<K>(), obeys_concrete_eq::<K>(), obeys_concrete_eq::<V>(), vstd::pervasive::obeys_clone_eq::<V>(),
            forall|k:K| keys@.contains(k) ==> selected.contains(k),
            forall|k:K| selected.contains(k) ==> before.contains_key(k),
            forall|k:K| before.contains_key(k) ==> selected.contains(k) == (before[k] == *expected),
            forall|k:K| before.contains_key(k) ==> #[trigger] view@[k] ==
                if selected.contains(k) && !keys@.contains(k) { *reserved } else { before[k] },
        decreases keys.len(),
    {
        let ghost remaining = keys@;
        let Some(key) = keys.pop() else {
            assert(remaining.len() == 0);
            return;
        };
        assert(remaining =~= keys@.push(key));
        assert(remaining.contains(key));
        assert(selected.contains(key));
        assert(!keys@.contains(key));
        assert(before.contains_key(key));
        assert(view@.contains_key(key));
        assert(view@[key] == *expected);
        let std::collections::hash_map::Entry::Occupied(mut slot) = view.entry(key) else { unreachable!(); };
        retarget(slot.get_mut(),expected,reserved);
    }
}

pub(super) open spec fn retargeted<K,V>(before:Map<K,V>, after:Map<K,V>, expected:V, reserved:V) -> bool {
    &&& after.dom() == before.dom()
    &&& forall|k:K| after.contains_key(k) ==> #[trigger] after[k] ==
        if before[k] == expected { reserved } else { before[k] }
}

/// Retarget every principal's matching package slots under the registry write lock.
pub(super) fn retarget_views<P: Eq + Hash + Clone,K: Eq + Hash + Clone,V: Eq + Clone>(
    views: &mut HashMap<P,HashMap<K,V>>, expected: &V, reserved: &V)
    requires hash_map_inv(old(views)), obeys_key_model::<P>(), obeys_concrete_eq::<P>(),
        obeys_key_model::<K>(), obeys_concrete_eq::<K>(), obeys_concrete_eq::<V>(),
        vstd::pervasive::obeys_clone_eq::<P>(), vstd::pervasive::obeys_clone_eq::<K>(), vstd::pervasive::obeys_clone_eq::<V>(),
        forall|p:P| old(views)@.contains_key(p) ==> hash_map_inv(&old(views)@[p]),
    ensures hash_map_inv(final(views)), final(views)@.dom() == old(views)@.dom(),
        forall|p:P| final(views)@.contains_key(p) ==> hash_map_inv(&final(views)@[p]) &&
            retargeted(old(views)@[p]@,(#[trigger] final(views)@[p])@,*expected,*reserved),
{
    let ghost before = views@;
    let mut owners = super::viewers::viewers(views,expected);
    let ghost selected = owners@;
    loop
        invariant before == old(views)@, hash_map_inv(views), views@.dom() == before.dom(), owners@.no_duplicates(),
            obeys_key_model::<P>(), obeys_concrete_eq::<P>(), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
            obeys_concrete_eq::<V>(), vstd::pervasive::obeys_clone_eq::<K>(), vstd::pervasive::obeys_clone_eq::<V>(),
            forall|p:P| owners@.contains(p) ==> selected.contains(p),
            forall|p:P| #[trigger] selected.contains(p) == (before.contains_key(p) && before[p]@.values().contains(*expected)),
            forall|p:P| views@.contains_key(p) ==> hash_map_inv(&views@[p]) &&
                (if selected.contains(p) && !owners@.contains(p) {
                    retargeted(before[p]@,(#[trigger] views@[p])@,*expected,*reserved)
                } else { views@[p]@ == before[p]@ }),
        decreases owners.len(),
    {
        let ghost remaining = owners@;
        let Some(p) = owners.pop() else {
            assert(remaining.len() == 0);
            assert forall|p:P| views@.contains_key(p) implies
                retargeted(before[p]@,(#[trigger] views@[p])@,*expected,*reserved) by {
                if !selected.contains(p) {
                    assert(!before[p]@.values().contains(*expected));
                    assert forall|k:K| before[p]@.contains_key(k) implies #[trigger] before[p]@[k] != *expected by {
                        if before[p]@[k] == *expected { assert(before[p]@.values().contains(*expected)); }
                    }
                }
            }
            return;
        };
        assert(remaining =~= owners@.push(p));
        assert(remaining.contains(p));
        assert(selected.contains(p));
        assert(!owners@.contains(p));
        assert(before.contains_key(p));
        assert(views@.contains_key(p));
        let std::collections::hash_map::Entry::Occupied(mut row) = views.entry(p) else { unreachable!(); };
        retarget_view(row.get_mut(),expected,reserved);
    }
}
}
