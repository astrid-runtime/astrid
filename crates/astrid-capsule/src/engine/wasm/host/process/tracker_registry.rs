//! PID registration and principal snapshots used by the ephemeral process tracker.
use super::registry_keys;
use std::collections::HashMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::hash::hash_map_inv;

verus! {
broadcast use vstd::std_specs::hash::group_hash_axioms;

pub(super) fn registrable(pid: u32) -> (allowed: bool)
    ensures allowed == (pid != 0),
{
    pid != 0
}

pub(super) fn register<T>(entries: &mut HashMap<u32,T>, pid: u32, record: T)
    requires hash_map_inv(old(entries)), pid != 0,
    ensures hash_map_inv(final(entries)), final(entries)@ == old(entries)@.insert(pid,record),
{
    entries.insert(pid,record);
}

pub(super) fn unregister<T>(entries: &mut HashMap<u32,T>, pid: u32)
    requires hash_map_inv(old(entries)),
    ensures hash_map_inv(final(entries)), final(entries)@ == old(entries)@.remove(pid),
{
    entries.remove(&pid);
}

pub(super) fn owned_pids<P,C,F: Fn(&P) -> bool>(
    entries: &HashMap<u32,(P,Option<C>)>, owns: F,
) -> (pids: Vec<u32>)
    requires hash_map_inv(entries), forall|principal:&P| owns.requires((principal,)),
    ensures pids@.no_duplicates(),
        forall|pid:u32| entries@.contains_key(pid) ==> owns.ensures((&entries@[pid].0,),pids@.contains(pid)),
        forall|pid:u32| pids@.contains(pid) ==> entries@.contains_key(pid),
{
    registry_keys::keys_for(entries,|record:&(P,Option<C>)| -> (yes:bool)
        ensures owns.ensures((&record.0,),yes),
    { owns(&record.0) }, |pid:&u32| -> (out:u32) ensures out == *pid, { *pid })
}
}
