//! Live HTTP responses, keyed by the slot reserved for their owned WIT handle.
use std::collections::{HashMap, hash_map::Entry};
use vstd::prelude::*;

verus! {
broadcast use vstd::std_specs::hash::group_hash_axioms;


#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal { Full, Occupied }

pub(super) fn room<V>(streams: &HashMap<u64,V>, limit:usize) -> (ok:bool)
    requires vstd::std_specs::hash::hash_map_inv(streams),
    ensures ok == (streams@.len() < limit),
{ streams.len() < limit }

pub(super) fn publish<V>(streams:&mut HashMap<u64,V>,limit:usize,rep:u32,stream:V)
    -> (result:Result<u32, Refusal>)
    requires vstd::std_specs::hash::hash_map_inv(old(streams)),
    ensures vstd::std_specs::hash::hash_map_inv(final(streams)), ({
        let before = old(streams)@;
        let key = rep as u64;
        if before.len() >= limit {
            result == Err(Refusal::Full) && final(streams)@ == before
        } else if before.contains_key(key) {
            result == Err(Refusal::Occupied) && final(streams)@ == before
        } else {
            result == Ok(rep) && final(streams)@ == before.insert(key,stream)
        }
    }),
{
    if !room(streams,limit) { return Err(Refusal::Full); }
    match streams.entry(u64::from(rep)) {
        Entry::Occupied(_) => Err(Refusal::Occupied),
        Entry::Vacant(entry) => { entry.insert(stream); Ok(rep) }
    }
}

pub(super) fn release<V>(streams:&mut HashMap<u64,V>,rep:u32) -> (removed:Option<V>)
    requires vstd::std_specs::hash::hash_map_inv(old(streams)),
    ensures vstd::std_specs::hash::hash_map_inv(final(streams)), ({
        let before = old(streams)@;
        let key = rep as u64;
        &&& removed == if before.contains_key(key) { Some(before[key]) } else { None }
        &&& final(streams)@ == before.remove(key)
    }),
{
    streams.remove(&u64::from(rep))
}
/// Remove the response only when Wasmtime deleted the matching owned slot.
pub(super) fn drop_owned<V,F:FnOnce(u32)->bool>(streams:&mut HashMap<u64,V>,rep:u32,delete:F)
    -> (removed:Option<V>)
    requires vstd::std_specs::hash::hash_map_inv(old(streams)), delete.requires((rep,)),
    ensures vstd::std_specs::hash::hash_map_inv(final(streams)), exists|deleted:bool| #[trigger] delete.ensures((rep,),deleted)
        && ({
            let before = old(streams)@;
            let key = rep as u64;
            &&& removed == if deleted && before.contains_key(key) {Some(before[key])} else {None}
            &&& final(streams)@ == if deleted {before.remove(key)} else {before}
        }),
{
    let deleted = delete(rep);
    assert(delete.ensures((rep,),deleted));
    if deleted { release(streams,rep) } else { None }
}

}
