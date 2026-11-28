//! Bind principal retirement to numeric targets in the ephemeral registry snapshot.
use crate::{process_batch, registry_keys, tracker_registry};
use std::collections::HashMap;
use vstd::prelude::*;
use vstd::std_specs::hash::hash_map_inv;

verus! {
struct Dispatch { calls: Vec<u32> }

impl process_batch::Reaper<u32> for Dispatch {
    closed spec fn calls(&self) -> Seq<u32> { self.calls@ }
    fn reap(&mut self, pid: u32) { self.calls.push(pid); }
}

// Call identifiers are irrelevant to a principal-wide retirement.
fn cancel<C>(entries: &HashMap<u32,(Vec<u8>,Option<C>)>, principal: &[u8], sink: &mut Dispatch)
    requires hash_map_inv(entries), !entries@.contains_key(0),
    ensures ({
        let prior = old(sink).calls@;
        let calls = final(sink).calls@.skip(prior.len() as int);
        &&& final(sink).calls@ == prior + calls
        &&& calls.no_duplicates() && !calls.contains(0)
        &&& forall|pid:u32| calls.contains(pid) == (entries@.contains_key(pid) && entries@[pid].0@ == principal@)
    }),
{
    let pids = tracker_registry::owned_pids(entries, |owner:&Vec<u8>| -> (yes:bool)
        ensures yes == (owner@ == principal@),
    { registry_keys::owned_by(principal,owner.as_slice()) });
    assert forall|pid:u32| pids@.contains(pid) == (entries@.contains_key(pid) && entries@[pid].0@ == principal@) by {
        if entries@.contains_key(pid) {
            assert(pids@.contains(pid) == (entries@[pid].0@ == principal@));
        }
    }
    process_batch::reap_batch(pids,sink);
    assert(sink.calls@.skip(old(sink).calls@.len() as int) =~= pids@);
}

// The same numeric PID may be registered again with new ownership. Selection
// must use the current registration, and unregistering must remove that PID.
fn register_cancel_unregister<C>(entries: &mut HashMap<u32,(Vec<u8>,Option<C>)>, pid:u32,
    owner: Vec<u8>, call:Option<C>, retiring: &[u8]) -> (calls:Vec<u32>)
    requires hash_map_inv(old(entries)), !old(entries)@.contains_key(0),
    ensures final(entries)@ == old(entries)@.remove(pid),
        calls@.contains(pid) == (pid != 0 && owner@ == retiring@),
        forall|other:u32| other != pid ==> (calls@.contains(other) == (old(entries)@.contains_key(other) && old(entries)@[other].0@ == retiring@)),
{
    if tracker_registry::registrable(pid) {
        tracker_registry::register(entries,pid,(owner,call));
    }
    let mut sink = Dispatch { calls: Vec::new() };
    cancel(entries,retiring,&mut sink);
    assert(sink.calls@.skip(0) =~= sink.calls@);
    tracker_registry::unregister(entries,pid);
    assert(entries@ =~= old(entries)@.remove(pid));
    sink.calls
}
}
