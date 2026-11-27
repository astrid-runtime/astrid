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
    /// Diagnostic alias. Authority belongs to the immutable runtime identity used as the map key.
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
}
