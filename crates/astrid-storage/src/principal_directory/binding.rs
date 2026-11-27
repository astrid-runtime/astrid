//! Immutable owner selection for staged principal operations.

use std::{collections::HashMap, hash::Hash};
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_eq::obeys_concrete_eq,
    pervasive::{cloned, obeys_clone_eq},
    std_specs::hash::{hash_map_inv, obeys_key_model},
};

use vstd::prelude::*;

verus! {

pub(super) fn select(expected: Option<[u8; 32]>, observed: [u8; 32]) -> (owner: Option<[u8; 32]>)
    ensures
        owner.is_some() == (match expected { None => true, Some(uid) => uid@ == observed@ }),
        owner matches Some(uid) ==> uid@ == observed@ && (match expected { None => true, Some(pinned) => pinned@ == uid@ }),
{
    match expected {
        Some(uid) if uid.as_slice() != observed.as_slice() => None,
        Some(uid) => { assert(uid@ =~= observed@); Some(uid) },
        None => Some(observed),
    }
}

pub(super) fn matches_pair(
    alias: &[u8], uid: &[u8; 32], forward: Option<&[u8; 32]>, reverse: Option<&[u8]>,
) -> (accepted: bool)
    ensures accepted == ((forward matches Some(f) && f@ == uid@)
        && (reverse matches Some(r) && r@ == alias@)),
{
    let (Some(f), Some(r)) = (forward, reverse) else { return false; };
    if f.as_slice() != uid.as_slice() || r != alias { return false; }
    assert(f@ =~= uid@);
    assert(r@ =~= alias@);
    true
}

/// Supply the original operand only under a matching forward and reverse binding.
pub(super) fn with_pair<T,R,F:FnOnce(T)->R>(
    alias: &[u8], uid: &[u8; 32], forward: Option<&[u8; 32]>, reverse: Option<&[u8]>,
    input: T, operation: F,
) -> (out: Result<R,T>)
    requires operation.requires((input,)),
    ensures if (forward matches Some(f) && f@ == uid@) && (reverse matches Some(r) && r@ == alias@) {
        out matches Ok(value) && operation.ensures((input,),value)
    } else { out == Err(input) },
{
    if matches_pair(alias,uid,forward,reverse) { Ok(operation(input)) } else { Err(input) }
}

}

verus! {
broadcast use vstd::std_specs::hash::group_hash_axioms;

/// Select the alias from the reverse map, then confirm its forward UID
/// before passing that exact alias to an operation under the directory guard.
pub(super) fn with_live_alias<U:Eq+Hash,A:Eq+Hash,R,F:FnOnce(&A)->R>(
    aliases:&HashMap<A,U>,principals:&HashMap<U,A>,uid:&U,operation:F,
) -> (out:Result<R,F>)
    requires hash_map_inv(aliases), hash_map_inv(principals),
        obeys_key_model::<U>(), obeys_concrete_eq::<U>(),
        obeys_key_model::<A>(), obeys_concrete_eq::<A>(),
        forall|alias:&A| #[trigger] operation.requires((alias,)),
    ensures match principals@.get(*uid) {
        None => out == Err(operation),
        Some(alias) => if aliases@.get(alias) == Some(*uid) {
            out matches Ok(r) && operation.ensures((&alias,),r)
        } else { out == Err(operation) },
    },
{
    reveal(obeys_concrete_eq);
    let Some(alias) = principals.get(uid) else { return Err(operation); };
    let Some(current) = aliases.get(alias) else { return Err(operation); };
    if !U::eq(current,uid) { return Err(operation); }
    Ok(operation(alias))
}

/// Return the retained name and any distinct live name of this generation.
pub(crate) fn recovery_aliases<U: Eq + Hash, A: Eq + Clone>(directory: &HashMap<U,A>, uid: &U, retained: Option<A>)
    -> (targets: [Option<A>;2])
    requires hash_map_inv(directory), obeys_key_model::<U>(), obeys_concrete_eq::<U>(),
        obeys_concrete_eq::<A>(), obeys_clone_eq::<A>(),
    ensures targets[0] == retained,
        targets[1] == if directory@.get(*uid) == retained { None } else { directory@.get(*uid) },
{
    proof { reveal(obeys_concrete_eq); reveal(obeys_clone_eq); }
    let live = match directory.get(uid) {
        Some(current) => {
            match &retained {
                Some(prior) if A::eq(prior,current) => return [retained,None],
                _ => {},
            }
            let alias = A::clone(current);
            assert(cloned(*current,alias));
            Some(alias)
        },
        None => None,
    };
    [retained,live]
}
}
