//! Dispatch owned persistent entries to the native reaper outside the registry lock.
use std::{collections::HashMap, hash::Hash};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::{
    hash::{hash_map_inv, obeys_key_model},
    iter::IteratorSpec,
};

verus! {
broadcast use {vstd::std_specs::hash::group_hash_axioms, vstd::seq_lib::group_seq_properties};

// Native reaping supplies this operation. The trace exists only in the proof.
pub(super) trait Reaper<T> {
    spec fn calls(&self) -> Seq<T>;

    fn reap(&mut self, entry: T)
        ensures final(self).calls() == old(self).calls().push(entry);
}

/// Dispatch the owned batch outside the registry lock, preserving order.
pub(super) fn reap_batch<T, R: Reaper<T>>(entries: Vec<T>, reaper: &mut R)
    ensures final(reaper).calls() == old(reaper).calls() + entries@,
{
    let ghost initial = reaper.calls();
    let mut iter = entries.into_iter();
    loop
        invariant
            iter.decrease().is_some(),
            initial == old(reaper).calls(),
            reaper.calls() + iter.remaining() == initial + entries@,
        decreases iter.decrease().unwrap(),
    {
        let ghost remaining = iter.remaining();
        let Some(entry) = iter.next() else {
            assert(reaper.calls() + remaining == initial + entries@);
            assert(reaper.calls() + remaining =~= reaper.calls());
            assert(reaper.calls() == old(reaper).calls() + entries@);
            return;
        };
        reaper.reap(entry);
        assert(reaper.calls() + iter.remaining() =~= initial + entries@);
    }
}

/// Replace the live registry while holding its mutex. Reap the old map after unlock.
pub(super) fn take_all<K: Eq + Hash, T>(entries: &mut HashMap<K,T>) -> (drained: HashMap<K,T>)
    requires hash_map_inv(old(entries)),
    ensures hash_map_inv(final(entries)), hash_map_inv(&drained), drained@ == old(entries)@,
        final(entries)@ == Map::<K,T>::empty(),
{
    let mut drained = HashMap::new();
    std::mem::swap(entries, &mut drained);
    drained
}

pub(super) open spec fn values<K,T>(pairs: Seq<(K,T)>) -> Seq<T> {
    pairs.map(|_,pair:(K,T)| pair.1)
}

pub(super) fn reap_all<K: Eq + Hash, T, R: Reaper<T>>(drained: HashMap<K,T>, reaper: &mut R)
    requires hash_map_inv(&drained), obeys_key_model::<K>(),
    ensures exists|order:Seq<(K,T)>| order.no_duplicates() && order.to_set() == drained@.kv_pairs()
        && final(reaper).calls() == old(reaper).calls() + values(order),
{
    let ghost prior = reaper.calls();
    let mut iter = drained.into_iter();
    let ghost order = iter.remaining();
    loop
        invariant
            iter.decrease().is_some(), prior == old(reaper).calls(),
            order.no_duplicates(), order.to_set() == drained@.kv_pairs(),
            reaper.calls() + values(iter.remaining()) == prior + values(order),
        decreases iter.decrease().unwrap(),
    {
        let ghost remaining = iter.remaining();
        let Some((_,entry)) = iter.next() else {
            assert(values(remaining) =~= Seq::<T>::empty());
            assert(reaper.calls() + values(remaining) =~= reaper.calls());
            assert(reaper.calls() == prior + values(order));
            return;
        };
        assert(values(remaining) =~= seq![entry] + values(iter.remaining()));
        reaper.reap(entry);
        assert(reaper.calls() + values(iter.remaining()) =~= prior + values(order));
    }
}
}
