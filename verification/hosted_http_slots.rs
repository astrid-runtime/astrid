//! Closing a stream twice cannot remove another stream or release its quota slot.
use crate::http_slots;
use std::collections::HashMap;
use vstd::prelude::*;
use vstd::std_specs::hash::hash_map_inv;

verus! {
fn close_and_reopen(streams:&mut HashMap<u64,u64>,limit:usize,first:u32,second:u32,payload:u64)
    requires hash_map_inv(old(streams)), first != second,
        old(streams)@.contains_key(first as u64), !old(streams)@.contains_key(second as u64),
        old(streams)@.len() <= limit,
    ensures final(streams)@ == old(streams)@.remove(first as u64).insert(second as u64,payload),
{
    let ghost before = streams@;
    let removed = http_slots::release(streams,first);
    assert(removed == Some(before[first as u64]));
    assert(streams@.dom() =~= before.dom().remove(first as u64));
    let opened = http_slots::publish(streams,limit,second,payload);
    assert(opened == Ok(second));
    let repeated = http_slots::release(streams,first);
    assert(repeated.is_none());
    assert(streams@ =~= before.remove(first as u64).insert(second as u64,payload));
}

fn refused(streams:&mut HashMap<u64,u64>, limit:usize, rep:u32, payload:u64)
    requires hash_map_inv(old(streams)),
        old(streams)@.len() >= limit || old(streams)@.contains_key(rep as u64),
    ensures final(streams)@ == old(streams)@,
{
    let r = http_slots::publish(streams,limit,rep,payload);
    assert(r == if old(streams)@.len() >= limit {Err(http_slots::Refusal::Full)}
        else {Err(http_slots::Refusal::Occupied)});
}
fn destructor(streams:&mut HashMap<u64,u64>, rep:u32, selected:u32, deleted:bool)
    -> (value:Option<u64>)
    requires hash_map_inv(old(streams)),
    ensures ({
        let before = old(streams)@;
        let key = rep as u64;
        let done = rep == selected && deleted;
        &&& value == if done && before.contains_key(key) {Some(before[key])} else {None}
        &&& final(streams)@ == if done {before.remove(key)} else {before}
    }),
{
    http_slots::drop_owned(streams,rep,|slot:u32| -> (r:bool)
        ensures r == (slot == selected && deleted),
    {slot == selected && deleted})
}

}
