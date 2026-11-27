//! Selection of one persistent process while the caller holds its registry lock.
use std::{collections::HashMap, hash::Hash};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_eq::obeys_concrete_eq,
    std_specs::hash::{hash_map_inv, obeys_key_model},
};

verus! {
broadcast use vstd::std_specs::hash::group_hash_axioms;

pub(super) fn matches(principal: &[u8], capsule: &[u8], creator: &[u8], package: &[u8]) -> (yes: bool)
    ensures yes == (principal@ == creator@ && capsule@ == package@),
{
    if principal != creator || capsule != package { return false; }
    assert(principal@ =~= creator@);
    assert(capsule@ =~= package@);
    true
}

pub(super) enum Selection<'a,T> { Absent, Foreign, Owned(&'a T) }

pub(super) fn select<'a,K: Eq + Hash,T,F: FnOnce(&'a T) -> bool>(
    entries: &'a HashMap<K,T>, key: &K, owns: F,
) -> (out: Selection<'a,T>)
    requires hash_map_inv(entries), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
        entries@.contains_key(*key) ==> owns.requires((&entries@[*key],)),
    ensures match out {
        Selection::Absent => !entries@.contains_key(*key),
        Selection::Foreign => entries@.contains_key(*key) && owns.ensures((&entries@[*key],),false),
        Selection::Owned(entry) => entries@.contains_key(*key) && *entry == entries@[*key]
            && owns.ensures((entry,),true),
    },
{
    let Some(entry) = entries.get(key) else { return Selection::Absent; };
    if owns(entry) { Selection::Owned(entry) } else { Selection::Foreign }
}

pub(super) enum Release<T> { Absent, Foreign, Live, Removed(T) }

/// Both observations and the removal run under the same registry guard.
pub(super) fn release<K: Eq + Hash,T,O:FnOnce(&T)->bool,L:FnOnce(&T)->bool>(
    entries:&mut HashMap<K,T>, key:&K, owns:O, live:L,
) -> (out:Release<T>)
    requires hash_map_inv(old(entries)), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
        old(entries)@.contains_key(*key) ==> owns.requires((&old(entries)@[*key],)),
        old(entries)@.contains_key(*key) && owns.ensures((&old(entries)@[*key],),true)
            ==> live.requires((&old(entries)@[*key],)),
    ensures hash_map_inv(final(entries)), ({
        let before = old(entries)@;
        let e = before[*key];
        match out {
            Release::Absent => !before.contains_key(*key) && final(entries)@ == before,
            Release::Foreign => before.contains_key(*key) && owns.ensures((&e,),false)
                && final(entries)@ == before,
            Release::Live => before.contains_key(*key) && owns.ensures((&e,),true)
                && live.ensures((&e,),true) && final(entries)@ == before,
            Release::Removed(removed) => before.contains_key(*key) && removed == e
                && owns.ensures((&e,),true) && live.ensures((&e,),false)
                && final(entries)@ == before.remove(*key),
        }
    }),
{
    let Some(entry) = entries.get(key) else { return Release::Absent; };
    if !owns(entry) { return Release::Foreign; }
    if live(entry) { return Release::Live; }
    match entries.remove(key) {
        Some(removed) => Release::Removed(removed),
        None => Release::Absent,
    }
}
}
