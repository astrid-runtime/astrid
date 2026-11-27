//! Publish a process under a fresh digest without displacing another child.
use std::{collections::HashMap, hash::Hash};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_eq::obeys_concrete_eq,
    std_specs::hash::{hash_map_inv, obeys_key_model},
};

verus! {
// One initial token and at most eight retries.
pub(super) const TOKEN_ATTEMPTS: u8 = 9;

pub(super) open spec fn collided<T,K,V,M: Fn(u8) -> T,H: Fn(&T) -> K>(
    entries: Map<K,V>, mint: M, digest: H, attempt: u8,
) -> bool {
    exists|token:T,key:K| mint.ensures((attempt,),token) && digest.ensures((&token,),key) && entries.contains_key(key)
}

pub(super) open spec fn installed<T,K,V,P,M: Fn(u8) -> T,H: Fn(&T) -> K,B: FnOnce(&T,P) -> V>(
    before: Map<K,V>, after: Map<K,V>, token:T, pending:P, mint:M, digest:H, build:B,
) -> bool {
    &&& exists|i:u8| i < TOKEN_ATTEMPTS && mint.ensures((i,),token)
        && forall|j:u8| j < i ==> #[trigger] collided(before,mint,digest,j)
    &&& exists|key:K,entry:V| digest.ensures((&token,),key) && !before.contains_key(key)
        && build.ensures((&token,pending),entry) && after == #[trigger] before.insert(key,entry)
}

pub(super) fn publish<T,K: Eq + Hash,V,P,M: Fn(u8) -> T,H: Fn(&T) -> K,B: FnOnce(&T,P) -> V>(
    entries: &mut HashMap<K,V>, pending: P, mint: M, digest: H, build: B,
) -> (out: Result<T,P>)
    requires hash_map_inv(old(entries)), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
        forall|i:u8| i < TOKEN_ATTEMPTS ==> mint.requires((i,)),
        forall|i:u8,token:T| i < TOKEN_ATTEMPTS && #[trigger] mint.ensures((i,),token)
            ==> digest.requires((&token,)) && build.requires((&token,pending)),
    ensures hash_map_inv(final(entries)), match out {
        Ok(token) => installed(old(entries)@,final(entries)@,token,pending,mint,digest,build),
        Err(p) => p == pending && final(entries)@ == old(entries)@ && forall|i:u8| i < TOKEN_ATTEMPTS ==> #[trigger] collided(old(entries)@,mint,digest,i),
    },
{
    let mut attempts = 0u8;
    while attempts < TOKEN_ATTEMPTS
        invariant attempts <= TOKEN_ATTEMPTS, entries@ == old(entries)@, hash_map_inv(entries),
            obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
            forall|i:u8| i < TOKEN_ATTEMPTS ==> mint.requires((i,)),
            forall|i:u8,token:T| i < TOKEN_ATTEMPTS && #[trigger] mint.ensures((i,),token)
                ==> digest.requires((&token,)) && build.requires((&token,pending)),
            forall|i:u8| i < attempts ==> #[trigger] collided(old(entries)@,mint,digest,i),
        decreases TOKEN_ATTEMPTS - attempts,
    {
        let token = mint(attempts);
        let key = digest(&token);
        if let std::collections::hash_map::Entry::Vacant(slot) = entries.entry(key) {
            let entry = build(&token,pending);
            slot.insert(entry);
            assert(exists|k:K,v:V| digest.ensures((&token,),k) && !old(entries)@.contains_key(k)
                && build.ensures((&token,pending),v) && entries@ == #[trigger] old(entries)@.insert(k,v));
            assert(exists|i:u8| i < TOKEN_ATTEMPTS && mint.ensures((i,),token)
                && forall|j:u8| j < i ==> #[trigger] collided(old(entries)@,mint,digest,j));
            assert(installed(old(entries)@,entries@,token,pending,mint,digest,build));
            return Ok(token);
        }
        assert(exists|t:T,k:K| mint.ensures((attempts,),t) && digest.ensures((&t,),k) && old(entries)@.contains_key(k));
        assert(collided(old(entries)@,mint,digest,attempts));
        attempts += 1;
    }
    Err(pending)
}
}
