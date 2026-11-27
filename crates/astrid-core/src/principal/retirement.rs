//! Membership of principal retirement fences in the authority stores.
use std::{
    collections::HashSet,
    hash::{BuildHasher, Hash},
};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_eq::obeys_concrete_eq,
    std_specs::hash::{builds_valid_hashers, hash_set_inv, obeys_key_model},
};

verus! {
broadcast use vstd::std_specs::hash::group_hash_axioms;

/// Close admission for the named principal while preserving unrelated fences.
pub fn fence<K: Eq + Hash, S: BuildHasher>(set: &mut HashSet<K,S>, principal: K)
    requires builds_valid_hashers::<S>(), hash_set_inv(old(set)), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
    ensures hash_set_inv(final(set)), final(set)@ == old(set)@.insert(principal),
{
    set.insert(principal);
}

/// Test the same principal identity used by retirement.
pub fn fenced<K: Eq + Hash, S: BuildHasher>(set: &HashSet<K,S>, principal: &K) -> (closed: bool)
    requires builds_valid_hashers::<S>(), hash_set_inv(set), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
    ensures closed == set@.contains(*principal),
{
    set.contains(principal)
}

/// Reopen only the named principal after reclamation.
pub fn release<K: Eq + Hash, S: BuildHasher>(set: &mut HashSet<K,S>, principal: &K)
    requires builds_valid_hashers::<S>(), hash_set_inv(old(set)), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
    ensures hash_set_inv(final(set)), final(set)@ == old(set)@.remove(*principal),
{
    set.remove(principal);
}
}
