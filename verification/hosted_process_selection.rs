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

// Each index denotes one opaque token and its precomputed keyed digest. Even
// distinct tokens may collide. The returned entry carries the admitted target.
fn publish_child<T>(entries: &mut HashMap<[u8;32],Entry<(u8,T)>>, keys: &[[u8;32];9], candidate: Entry<T>)
    -> (out: Result<u8,Entry<T>>)
    requires hash_map_inv(old(entries)), obeys_key_model::<[u8;32]>(), obeys_concrete_eq::<[u8;32]>(),
    ensures hash_map_inv(final(entries)), match out {
        Ok(i) => i < 9 && !old(entries)@.contains_key(keys@[i as int])
            && (forall|j:u8| j < i ==> old(entries)@.contains_key(#[trigger] keys@[j as int]))
            && final(entries)@ == old(entries)@.insert(keys@[i as int],Entry {
                creator: candidate.creator, package: candidate.package, target: (i,candidate.target),
            }),
        Err(e) => e == candidate && final(entries)@ == old(entries)@
            && forall|i:u8| i < 9 ==> old(entries)@.contains_key(#[trigger] keys@[i as int]),
    },
{
    let ghost before = entries@;
    let mint = |i:u8| -> (token:u8) ensures token == i, { i };
    let digest = |token:&u8| -> (key:[u8;32]) requires *token < 9, ensures key == keys@[*token as int],
        { keys[*token as usize] };
    let build = |token:&u8,e:Entry<T>| -> (entry:Entry<(u8,T)>)
        ensures entry == (Entry { creator:e.creator, package:e.package, target:(*token,e.target) }),
        { Entry { creator:e.creator, package:e.package, target:(*token,e.target) } };
    let result = crate::process_publication::publish(entries,candidate,mint,digest,build);
    proof {
        match result {
            Ok(i) => {
                assert(crate::process_publication::installed(before,entries@,i,candidate,mint,digest,build));
                let attempt = choose|a:u8| a < 9 && mint.ensures((a,),i)
                    && forall|j:u8| j < a ==> #[trigger] crate::process_publication::collided(before,mint,digest,j);
                assert(attempt == i);
                assert forall|j:u8| j < i implies before.contains_key(#[trigger] keys@[j as int]) by {
                    assert(crate::process_publication::collided(before,mint,digest,j));
                    let (t,k) = choose|t:u8,k:[u8;32]| mint.ensures((j,),t) && digest.ensures((&t,),k) && before.contains_key(k);
                    assert(t == j && k == keys@[j as int]);
                }
                let (k,e) = choose|k:[u8;32],e:Entry<(u8,T)>| digest.ensures((&i,),k)
                    && !before.contains_key(k) && build.ensures((&i,candidate),e)
                    && entries@ == #[trigger] before.insert(k,e);
                assert(k == keys@[i as int]);
            },
            Err(_) => {
                assert forall|i:u8| i < 9 implies before.contains_key(#[trigger] keys@[i as int]) by {
                    assert(crate::process_publication::collided(before,mint,digest,i));
                    let (t,k) = choose|t:u8,k:[u8;32]| mint.ensures((i,),t) && digest.ensures((&t,),k) && before.contains_key(k);
                    assert(t == i && k == keys@[i as int]);
                }
            },
        }
    }
    result
}

// Resolve the token just published, allowing the next caller to differ from
// the creator. The old digest map may already contain other tenants' tokens.
fn publish_then_lookup<T:Copy>(entries: &mut HashMap<[u8;32],Entry<(u8,T)>>,
    keys:&[[u8;32];9], candidate:Entry<T>, principal:&[u8], capsule:&[u8])
    -> (out:(Option<u8>,Option<T>))
    requires hash_map_inv(old(entries)), obeys_key_model::<[u8;32]>(), obeys_concrete_eq::<[u8;32]>(),
    ensures match out.0 {
        Some(i) => i < 9 && !old(entries)@.contains_key(keys@[i as int])
            && out.1 == if principal@ == candidate.creator@ && capsule@ == candidate.package@ {
                Some(candidate.target)
            } else { None },
        None => out.1.is_none() && final(entries)@ == old(entries)@,
    },
{
    let Ok(i) = publish_child(entries,keys,candidate) else { return (None,None); };
    let selected = match resolve(entries,&keys[i as usize],principal,capsule) {
        Selection::Owned(entry) => Some(entry.target.1),
        Selection::Foreign | Selection::Absent => None,
    };
    (Some(i),selected)
}

}
