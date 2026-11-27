//! Process token selection must bind both the creator and the capsule to the selected entry.
use crate::process_selection::{self, Selection};
use std::collections::HashMap;
use vstd::prelude::*;
use vstd::std_specs::hash::{hash_map_inv,obeys_key_model};
use vstd::laws_eq::obeys_concrete_eq;

verus! {
struct Entry<T> { creator: Vec<u8>, package: Vec<u8>, target: T }

fn resolve<'a,T>(entries: &'a HashMap<[u8;32],Entry<T>>, key: &[u8;32],
    principal: &[u8], capsule: &[u8]) -> (out: Selection<'a,Entry<T>>)
    requires hash_map_inv(entries), obeys_key_model::<[u8;32]>(), obeys_concrete_eq::<[u8;32]>(),
    ensures if entries@.contains_key(*key) {
        let e = entries@[*key];
        if e.creator@ == principal@ && e.package@ == capsule@ {
            out == Selection::Owned(&e)
        } else { out == Selection::Foreign }
    } else { out == Selection::Absent },
{
    process_selection::select(entries,key,|e: &'a Entry<T>| -> (yes:bool)
        ensures yes == (e.creator@ == principal@ && e.package@ == capsule@),
    { process_selection::matches(principal,capsule,e.creator.as_slice(),e.package.as_slice()) })
}
// The observed group and fallback outcomes are defined only for the selected
// entry's PID and requested signal. Foreign or absent entries return early.
fn signal(entries: &HashMap<[u8;32],Entry<u32>>, key: &[u8;32], principal: &[u8], capsule: &[u8],
    sig: u8, group_ok: bool, direct: Result<(),u8>) -> (out: Option<Result<(),crate::signal_target::DeliveryError<u8>>>)
    requires hash_map_inv(entries), obeys_key_model::<[u8;32]>(), obeys_concrete_eq::<[u8;32]>(),
    ensures if entries@.contains_key(*key) && entries@[*key].creator@ == principal@
            && entries@[*key].package@ == capsule@ {
        let pid = entries@[*key].target;
        out == Some(if pid == 0 { Err(crate::signal_target::DeliveryError::Closed) }
            else if pid > i32::MAX { Err(crate::signal_target::DeliveryError::InvalidPid) }
            else if group_ok { Ok(()) }
            else { match direct { Ok(()) => Ok(()), Err(e) => Err(crate::signal_target::DeliveryError::Send(e)) } })
    } else { out.is_none() },
{
    let Selection::Owned(entry) = resolve(entries,key,principal,capsule) else { return None; };
    let pid = entry.target;
    Some(crate::signal_target::deliver(pid,sig,|target:i32,s:u8| -> (ok:bool)
        requires target as int == pid as int && s == sig,
        ensures ok == group_ok,
    { group_ok }, |target:i32,s:u8| -> (r:Result<(),u8>)
        requires target as int == pid as int && s == sig,
        ensures r == direct,
    { direct }))
}

}
