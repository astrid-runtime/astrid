//! Transitions performed while the principal invocation tracker is locked.

use vstd::prelude::*;

verus! {

pub(super) struct PrincipalInvocation {
    retired: bool,
    active: usize,
}

impl PrincipalInvocation {

    pub(super) closed spec fn is_retired(&self) -> bool {
        self.retired
    }

    pub(super) closed spec fn active_count(&self) -> usize {
        self.active
    }

    pub(super) fn new() -> (state: Self)
        ensures !state.is_retired(), state.active_count() == 0,
    {
        Self { retired: false, active: 0 }
    }

    pub(super) fn active(&self) -> (active: usize)
        ensures active == self.active_count(),
    {
        self.active
    }

    pub(super) fn begin(&mut self) -> (admitted: bool)
        ensures
            final(self).is_retired() == old(self).is_retired(),
            admitted == (!old(self).is_retired() && old(self).active_count() < usize::MAX),
            final(self).active_count() as int == old(self).active_count() as int + if admitted { 1int } else { 0int },
    {
        if self.retired {
            return false;
        }
        let Some(active) = self.active.checked_add(1) else {
            return false;
        };
        self.active = active;
        true
    }

    pub(super) fn finish(&mut self)
        ensures
            final(self).is_retired() == old(self).is_retired(),
            final(self).active_count() as int == if old(self).active_count() == 0 { 0 } else { old(self).active_count() as int - 1 },
    {
        self.active = self.active.saturating_sub(1);
    }

    pub(super) fn retire(&mut self)
        ensures final(self).is_retired(), final(self).active_count() == old(self).active_count(),
    {
        self.retired = true;
    }

    pub(super) fn resume(&mut self)
        ensures !final(self).is_retired(), final(self).active_count() == old(self).active_count(),
    {
        self.retired = false;
    }

    pub(super) fn discardable(&self) -> (empty: bool)
        ensures empty == (!self.is_retired() && self.active_count() == 0),
    {
        !self.retired && self.active == 0
    }
}

}

use std::{collections::HashMap, hash::Hash};
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_eq::obeys_concrete_eq,
    std_specs::hash::{hash_map_inv, obeys_key_model},
};

verus! {
broadcast use vstd::std_specs::hash::group_hash_axioms;

pub(super) open spec fn binding<K>(m: Map<K,PrincipalInvocation>, k: K) -> (bool,int) {
    if m.contains_key(k) { (m[k].is_retired(),m[k].active_count() as int) } else { (false,0) }
}

/// Return the key that the RAII guard will finish on this tracker.
pub(super) fn acquire<K: Eq + Hash + Clone>(entries: &mut HashMap<K,PrincipalInvocation>, principal: &K)
    -> (guard: Option<K>)
    requires hash_map_inv(old(entries)), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
        vstd::pervasive::obeys_clone_eq::<K>(),
    ensures hash_map_inv(final(entries)), ({
        let (retired,n) = binding(old(entries)@,*principal);
        let allowed = !retired && n < usize::MAX;
        &&& guard == if allowed { Some(*principal) } else { None }
        &&& binding(final(entries)@,*principal) == (retired,n + if allowed {1int} else {0int})
        &&& final(entries)@.remove(*principal) == old(entries)@.remove(*principal)
    }),
{
    proof { reveal(vstd::pervasive::obeys_clone_eq); }
    let key = K::clone(principal);
    assert(vstd::pervasive::cloned(*principal,key));
    if entries.entry(key).or_insert(PrincipalInvocation::new()).begin() {
        let owner = K::clone(principal);
        assert(vstd::pervasive::cloned(*principal,owner));
        Some(owner)
    } else { None }
}

pub(super) fn retire_locked<K: Eq + Hash>(entries: &mut HashMap<K,PrincipalInvocation>, key: K)
    requires hash_map_inv(old(entries)), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
    ensures hash_map_inv(final(entries)),
        binding(final(entries)@,key) == (true,binding(old(entries)@,key).1),
        final(entries)@.remove(key) == old(entries)@.remove(key),
{
    entries.entry(key).or_insert(PrincipalInvocation::new()).retire();
}

pub(super) fn active_locked<K: Eq + Hash>(entries: &HashMap<K,PrincipalInvocation>, key: &K) -> (n: usize)
    requires hash_map_inv(entries), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
    ensures n == binding(entries@,*key).1,
{
    match entries.get(key) { Some(entry) => entry.active(), None => 0 }
}

pub(super) enum DrainAction { Finish, Resume }

pub(super) fn drain_locked<K: Eq + Hash>(entries: &mut HashMap<K,PrincipalInvocation>, key: K, action: DrainAction)
    requires hash_map_inv(old(entries)), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
    ensures hash_map_inv(final(entries)), ({
        let (retired,n) = binding(old(entries)@,key);
        let after = match action {
            DrainAction::Finish => (retired, if n > 0 { n - 1 } else { 0int }),
            DrainAction::Resume => (false,n),
        };
        &&& binding(final(entries)@,key) == after
        &&& final(entries)@.contains_key(key) == (after.0 || after.1 > 0)
        &&& final(entries)@.remove(key) == old(entries)@.remove(key)
    }),
{
    if let std::collections::hash_map::Entry::Occupied(mut slot) = entries.entry(key) {
        let entry = slot.get_mut();
        match action {
            DrainAction::Finish => entry.finish(),
            DrainAction::Resume => entry.resume(),
        }
        if entry.discardable() { slot.remove(); }
    }
    assert(entries@.remove(key) =~= old(entries)@.remove(key));
}
}
