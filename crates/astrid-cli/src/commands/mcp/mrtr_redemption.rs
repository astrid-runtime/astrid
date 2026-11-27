//! Process-local consent redemption while the broker holds its replay-table lock.
use std::collections::HashMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::hash::{hash_map_inv, obeys_key_model};

verus! {
broadcast use vstd::std_specs::hash::group_hash_axioms;

pub(super) struct Claim {
    digest: [u8;32],
    committed: bool,
}

impl Claim {
    pub(super) closed spec fn id(&self) -> [u8;32] { self.digest }
    pub(super) closed spec fn settled(&self) -> bool { self.committed }

    pub(super) fn commit(&mut self)
        ensures final(self).settled(), final(self).id() == old(self).id(),
    { self.committed = true; }

    pub(super) fn committed(&self) -> (yes:bool)
        ensures yes == self.settled(),
    { self.committed }

    pub(super) fn on_drop<T>(&self, entries:&mut HashMap<[u8;32],T>)
        requires hash_map_inv(old(entries)), obeys_key_model::<[u8;32]>(), vstd::laws_eq::obeys_concrete_eq::<[u8;32]>(),
        ensures hash_map_inv(final(entries)), final(entries)@ == if self.settled() {
            old(entries)@
        } else { old(entries)@.remove(self.id()) },
    {
        if !self.committed { entries.remove(&self.digest); }
    }
}

/// A duplicate refreshes its deadline and receives no claim.
pub(super) fn reserve<T>(entries:&mut HashMap<[u8;32],T>, digest:[u8;32], expiry:T)
    -> (claim:Option<Claim>)
    requires hash_map_inv(old(entries)), obeys_key_model::<[u8;32]>(), vstd::laws_eq::obeys_concrete_eq::<[u8;32]>(),
    ensures hash_map_inv(final(entries)), final(entries)@ == old(entries)@.insert(digest,expiry),
        claim.is_some() == !old(entries)@.contains_key(digest),
        claim matches Some(c) ==> c.id() == digest && !c.settled(),
{
    if entries.insert(digest,expiry).is_some() { None }
    else { Some(Claim { digest, committed:false }) }
}
}
