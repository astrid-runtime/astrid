//! Membership of principal retirement fences in the authority stores.
use std::{
    collections::{HashMap, HashSet},
    hash::{BuildHasher, Hash},
};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_eq::obeys_concrete_eq,
    pervasive::{cloned, obeys_clone_eq},
    std_specs::hash::{builds_valid_hashers, hash_map_inv, hash_set_inv, obeys_key_model},
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

/// Remove the entire grant bucket of a fenced principal.
pub fn purge_grants<K: Eq + Hash,V,S: BuildHasher>(grants: &mut HashMap<K,V,S>, principal: &K)
    requires builds_valid_hashers::<S>(), hash_map_inv(old(grants)), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
    ensures hash_map_inv(final(grants)), final(grants)@ == old(grants)@.remove(*principal),
{
    grants.remove(principal);
}

/// The identity whose capability fence has been restored during bootstrap.
#[must_use = "finish restoring allowances for the fenced principal"]
pub struct RecoveredCapabilityFence<K> {
    principal: K,
}

impl<K> RecoveredCapabilityFence<K> {
    pub closed spec fn owner(&self) -> K {
        self.principal
    }
}

/// Close capability admission and carry its exact owner to allowance recovery.
pub fn restore_capability<K: Eq + Hash + Clone, S: BuildHasher>(
    closed: &mut HashSet<K,S>, principal: K,
)
    -> (receipt: RecoveredCapabilityFence<K>)
    requires builds_valid_hashers::<S>(), hash_set_inv(old(closed)), obeys_key_model::<K>(), obeys_concrete_eq::<K>(), obeys_clone_eq::<K>(),
    ensures hash_set_inv(final(closed)), final(closed)@ == old(closed)@.insert(principal), receipt.owner() == principal,
{
    proof { reveal(obeys_clone_eq); }
    let key = K::clone(&principal);
    assert(cloned(principal,key));
    fence(closed,key);
    RecoveredCapabilityFence { principal }
}

/// Close allowance admission and remove grants for the owner of the capability fence.
pub fn restore_allowances<K: Eq + Hash, V, S: BuildHasher, G: BuildHasher>(
    receipt: RecoveredCapabilityFence<K>, closed: &mut HashSet<K,S>, grants: &mut HashMap<K,V,G>,
)
    requires builds_valid_hashers::<S>(), builds_valid_hashers::<G>(),
        hash_set_inv(old(closed)), hash_map_inv(old(grants)), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
    ensures hash_set_inv(final(closed)), hash_map_inv(final(grants)),
        final(closed)@ == old(closed)@.insert(receipt.owner()), final(grants)@ == old(grants)@.remove(receipt.owner()),
{
    purge_grants(grants,&receipt.principal);
    fence(closed,receipt.principal);
}

/// Restore both allowance tables only when both exclusive borrows succeeded.
///
/// # Errors
///
/// Propagates the fence-table access error first, then the grant-table error.
pub fn restore_accessible_allowances<K:Eq+Hash,V,S:BuildHasher,G:BuildHasher,E>(
    receipt:RecoveredCapabilityFence<K>,closed:Result<&mut HashSet<K,S>,E>,
    grants:Result<&mut HashMap<K,V,G>,E>,
) -> (out:Result<(),E>)
    requires builds_valid_hashers::<S>(), builds_valid_hashers::<G>(),
        obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
        closed matches Ok(c) ==> hash_set_inv(c),
        grants matches Ok(g) ==> hash_map_inv(g),
    ensures out == match closed {Err(e)=>Err(e),Ok(_)=>match grants {Err(e)=>Err(e),Ok(_)=>Ok(())}},
        closed matches Ok(c) ==> hash_set_inv(final(c)) &&
            final(c)@ == if out.is_ok() {c@.insert(receipt.owner())} else {c@},
        grants matches Ok(g) ==> hash_map_inv(final(g)) &&
            final(g)@ == if out.is_ok() {g@.remove(receipt.owner())} else {g@},
{
    let closed = closed?;
    let grants = grants?;
    restore_allowances(receipt,closed,grants);
    Ok(())
}

/// Reopen only the named principal after reclamation.
pub fn release<K: Eq + Hash, S: BuildHasher>(set: &mut HashSet<K,S>, principal: &K)
    requires builds_valid_hashers::<S>(), hash_set_inv(old(set)), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
    ensures hash_set_inv(final(set)), final(set)@ == old(set)@.remove(*principal),
{
    set.remove(principal);
}
}
