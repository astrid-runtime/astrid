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


// The phase bit is the observation supplied under the native entry mutex.
fn release_child<T>(entries:&mut HashMap<[u8;32],Entry<(bool,T)>>, key:&[u8;32],
    principal:&[u8], capsule:&[u8]) -> (out:process_selection::Release<Entry<(bool,T)>>)
    requires hash_map_inv(old(entries)), obeys_key_model::<[u8;32]>(), obeys_concrete_eq::<[u8;32]>(),
    ensures hash_map_inv(final(entries)), ({
        let before = old(entries)@;
        if !before.contains_key(*key) {
            out == process_selection::Release::Absent && final(entries)@ == before
        } else {
            let e = before[*key];
            if e.creator@ != principal@ || e.package@ != capsule@ {
                out == process_selection::Release::Foreign && final(entries)@ == before
            } else if e.target.0 {
                out == process_selection::Release::Live && final(entries)@ == before
            } else {
                out == process_selection::Release::Removed(e) && final(entries)@ == before.remove(*key)
            }
        }
    }),
{
    process_selection::release(entries,key,|e:&Entry<(bool,T)>| -> (yes:bool)
        ensures yes == (e.creator@ == principal@ && e.package@ == capsule@),
    { process_selection::matches(principal,capsule,e.creator.as_slice(),e.package.as_slice()) },
        |e:&Entry<(bool,T)>| -> (yes:bool) ensures yes == e.target.0, { e.target.0 })
}

// Retirement spans every capsule of this principal. A key witness accounts
// for every entry handed to the cleanup loop, including duplicate payloads.
fn retire_principal<T>(entries:&mut HashMap<[u8;32],Entry<T>>, principal:&[u8])
    -> (removed:Vec<Entry<T>>)
    requires hash_map_inv(old(entries)), obeys_key_model::<[u8;32]>(), obeys_concrete_eq::<[u8;32]>(),
    ensures ({
        let before = old(entries)@;
        &&& final(entries)@ == before.restrict(before.dom().filter(|k| before[k].creator@ != principal@))
        &&& exists|keys:Seq<[u8;32]>| keys.no_duplicates() && keys.len() == removed@.len()
            && (forall|k:[u8;32]| #[trigger] before.contains_key(k) ==> (keys.contains(k) == (before[k].creator@ == principal@)))
            && (forall|i:int| 0 <= i < keys.len() ==> before.contains_key(#[trigger] keys[i]) && removed@[i] == before[keys[i]])
    }),
{
    let ghost before = entries@;
    let owns = |entry:&Entry<T>| -> (yes:bool) ensures yes == (entry.creator@ == principal@), {
        crate::process_retirement::owned_by(principal,entry.creator.as_slice())
    };
    let removed = crate::process_retirement::drain_for(entries,owns);
    proof {
        let keys = choose|keys:Seq<[u8;32]>| crate::process_retirement::retired(before,entries@,keys,removed@,owns);
        assert forall|k:[u8;32]| #[trigger] before.contains_key(k) implies
            (keys.contains(k) == (before[k].creator@ == principal@)) by {
            assert(owns.ensures((&before[k],),keys.contains(k)));
        }
        assert(entries@ =~= before.restrict(before.dom().filter(|k| before[k].creator@ != principal@)));
    }
    removed
}

// Publication and retirement share the same map. At this order an admitted
// child is either handed to its owner's cleanup or stays at the minted key.
fn publish_then_retire<T>(entries: &mut HashMap<[u8;32],Entry<(u8,T)>>,
    keys: &[[u8;32];9], candidate: Entry<T>, retiring: &[u8])
    -> (out: (Option<u8>,Vec<Entry<(u8,T)>>))
    requires hash_map_inv(old(entries)), obeys_key_model::<[u8;32]>(), obeys_concrete_eq::<[u8;32]>(),
    ensures match out.0 {
        Some(i) => {
            let k = keys@[i as int];
            let published = Entry { creator: candidate.creator, package: candidate.package, target: (i,candidate.target) };
            &&& i < 9 && !old(entries)@.contains_key(k)
            &&& if candidate.creator@ == retiring@ {
                !final(entries)@.contains_key(k) && out.1@.contains(published)
            } else {
                final(entries)@.contains_key(k) && final(entries)@[k] == published
            }
        },
        None => final(entries)@ == old(entries)@ && out.1@.len() == 0,
    },
{
    let Ok(i) = publish_child(entries,keys,candidate) else { return (None, Vec::new()); };
    let ghost admitted = entries@;
    let removed = retire_principal(entries,retiring);
    proof {
        let k = keys@[i as int];
        if candidate.creator@ == retiring@ {
            let removed_keys = choose|ks:Seq<[u8;32]>| ks.no_duplicates() && ks.len() == removed@.len()
                && (forall|k:[u8;32]| #[trigger] admitted.contains_key(k) ==> (ks.contains(k) == (admitted[k].creator@ == retiring@)))
                && (forall|j:int| 0 <= j < ks.len() ==> admitted.contains_key(#[trigger] ks[j]) && removed@[j] == admitted[ks[j]]);
            assert(admitted.contains_key(k));
            assert(admitted[k].creator == candidate.creator);
            assert(removed_keys.contains(k));
            let j = removed_keys.index_of(k);
            assert(removed_keys[j] == k && removed@[j] == admitted[k]);
            assert(removed@.contains(admitted[k]));
        }
    }
    (Some(i), removed)
}

struct Cleanup<T> { received: Vec<T> }

impl<T> crate::process_cleanup::Reaper<T> for Cleanup<T> {
    closed spec fn calls(&self) -> Seq<T> { self.received@ }
    fn reap(&mut self, entry: T) { self.received.push(entry); }
}

// Follow retirement past mutex release to the sequence of cleanup calls.
// The reaper may have received earlier batches.
fn retire_and_reap<T>(entries: &mut HashMap<[u8;32],Entry<T>>, principal: &[u8],
    cleanup: &mut Cleanup<Entry<T>>)
    requires hash_map_inv(old(entries)), obeys_key_model::<[u8;32]>(), obeys_concrete_eq::<[u8;32]>(),
    ensures ({
        let before = old(entries)@;
        let prior = old(cleanup).received@;
        let after = final(cleanup).received@;
        &&& final(entries)@ == before.restrict(before.dom().filter(|k| before[k].creator@ != principal@))
        &&& exists|keys:Seq<[u8;32]>, batch:Seq<Entry<T>>| after == prior + batch
            && keys.no_duplicates() && keys.len() == batch.len()
            && (forall|k:[u8;32]| #[trigger] before.contains_key(k) ==> (keys.contains(k) == (before[k].creator@ == principal@)))
            && (forall|i:int| 0 <= i < keys.len() ==> before.contains_key(#[trigger] keys[i]) && batch[i] == before[keys[i]])
    }),
{
    let ghost before = entries@;
    let batch = retire_principal(entries,principal);
    crate::process_cleanup::reap_batch(batch,cleanup);
    proof {
        let keys = choose|ks:Seq<[u8;32]>| ks.no_duplicates() && ks.len() == batch@.len()
            && (forall|k:[u8;32]| #[trigger] before.contains_key(k) ==> (ks.contains(k) == (before[k].creator@ == principal@)))
            && (forall|i:int| 0 <= i < ks.len() ==> before.contains_key(#[trigger] ks[i]) && batch@[i] == before[ks[i]]);
        assert(cleanup.received@ == old(cleanup).received@ + batch@);
    }
}

// Graceful daemon shutdown detaches every token, including two different
// tokens that refer to equal abstract values. The witness binds each callback
// to a distinct original (token, entry) pair in arbitrary map iteration order.
fn shutdown_and_reap<T>(entries: &mut HashMap<[u8;32],Entry<T>>, cleanup: &mut Cleanup<Entry<T>>)
    requires hash_map_inv(old(entries)), obeys_key_model::<[u8;32]>(),
    ensures final(entries)@ == Map::<[u8;32],Entry<T>>::empty(), ({
        let before = old(entries)@;
        let prior = old(cleanup).received@;
        let after = final(cleanup).received@;
        exists|order:Seq<([u8;32],Entry<T>)>| order.no_duplicates() && order.to_set() == before.kv_pairs()
            && after.len() == prior.len() + order.len() && after.take(prior.len() as int) == prior
            && (forall|i:int| 0 <= i < order.len() ==> after[prior.len()+i] == (#[trigger] order[i]).1)
    }),
{
    let drained = crate::process_cleanup::take_all(entries);
    crate::process_cleanup::reap_all(drained,cleanup);
    proof {
        let prior = old(cleanup).received@;
        let after = cleanup.received@;
        let order = choose|order:Seq<([u8;32],Entry<T>)>| order.no_duplicates()
            && order.to_set() == drained@.kv_pairs() && after == prior + crate::process_cleanup::values(order);
        assert(after.take(prior.len() as int) =~= prior);
        assert forall|i:int| 0 <= i < order.len() implies after[prior.len()+i] == (#[trigger] order[i]).1 by {
            assert(after[prior.len()+i] == crate::process_cleanup::values(order)[i]);
        }
    }
}
}
