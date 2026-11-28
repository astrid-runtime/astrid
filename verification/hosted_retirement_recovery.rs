//! Consume the production recovery driver with the actual fence and grant transitions.
use std::collections::{BTreeMap, HashMap, HashSet};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::{btree::btree_map_wf, hash::{hash_map_inv,hash_set_inv}};
use crate::recovery::RetirementSink;

type Reservation = crate::pending_deletions::Reservation<u64,u64>;

verus! {
struct Stores {
    history: Ghost<Seq<(u64,Option<()>)>>,
    capabilities: HashSet<u64>,
    allowances: HashSet<u64>,
    grants: HashMap<u64,u64>,
}

impl RetirementSink<u64> for Stores {
    type Error = ();
    #[cfg(verus_keep_ghost)]
    type Bucket = u64;

    closed spec fn valid(&self) -> bool {
        hash_set_inv(&self.capabilities) && hash_set_inv(&self.allowances) && hash_map_inv(&self.grants)
    }
    closed spec fn history(&self) -> Seq<(u64,Option<()>)> { self.history@ }
    closed spec fn failure(&self) -> Option<()> { None }
    closed spec fn authority(&self,key:u64) -> (bool,bool,Option<u64>) {
        (self.capabilities@.contains(key),self.allowances@.contains(key),self.grants@.get(key))
    }

    fn restore(&mut self, key:u64) -> (result: Result<(),()>) {
        let receipt = crate::principal_fences::restore_capability(&mut self.capabilities,key);
        crate::principal_fences::restore_allowances(receipt,&mut self.allowances,&mut self.grants);
        self.history = Ghost(self.history@.push((key,None)));
        Ok(())
    }
}

fn recover(reservations: &BTreeMap<u64,Reservation>, directory: &HashMap<u64,u64>, stores: &mut Stores)
    -> (result: Result<(),()>)
    requires old(stores).valid(), btree_map_wf(reservations), hash_map_inv(directory),
    ensures result.is_ok(), forall|probe:u64| {
        let named = exists|uid:u64| #[trigger] reservations@.contains_key(uid) &&
            (reservations@[uid].alias == Some(probe) || directory@.get(uid) == Some(probe));
        #[trigger] final(stores).authority(probe) ==
            if named { (true,true,None) } else { old(stores).authority(probe) }
    },
{
    crate::recovery::replay(reservations,directory,stores)
}

// Stage the same reservation consumed by startup. Persistence must still
// establish that the acknowledged candidate is the recovered graph.
fn reserve_then_recover(rows:&mut BTreeMap<u64,Reservation>,uid:u64,requested:u64,fleet:Option<u64>,
    permitted:bool,directory:&HashMap<u64,u64>,stores:&mut Stores)
    requires vstd::std_specs::btree::btree_map_inv(old(rows)),hash_map_inv(directory),old(stores).valid(),
{
    use crate::pending_deletions::{reserve,ReserveError};
    let ghost before = rows@;
    let result = reserve(rows,uid,Some(&requested),fleet,
        |_:&BTreeMap<u64,Reservation>| -> (out:Result<(),()>) ensures out.is_ok() == permitted,
            {if permitted {Ok(())} else {Err(())}});
    match result {
        Ok(()) => {
            assert(before.contains_key(uid) || permitted);
            assert(rows@.contains_key(uid));
            assert(rows@[uid].alias == Some(requested));
            assert(rows@[uid].fleet == if before.contains_key(uid) {before[uid].fleet} else {fleet});
            assert(rows@.remove(uid) =~= before.remove(uid));
            let _ = recover(rows,directory,stores);
            assert(stores.authority(requested) == (true,true,None));
            assert forall|live:u64| directory@.get(uid) == Some(live) implies #[trigger] stores.authority(live) == (true,true,None) by {};
        },
        Err(ReserveError::Conflict(retained)) => {
            assert(before.contains_key(uid) && before[uid].alias == Some(retained) && retained != requested);
            assert(rows@ == before);
        },
        Err(ReserveError::Admission(())) => {
            assert(!permitted && !before.contains_key(uid));
            assert(rows@ == before);
        },
    }
}

// Exercise the real KV adapter's read/compare/stage step with an immutable
// header observation. A matching empty value differs from an absent entry.
fn graph_compare(namespace:&[u8],key:&[u8],header:u64,observed_at:u64,prior:Option<Vec<u8>>,
    expected:Option<&[u8]>,candidate:&[u8],object:crate::ObjectId) {
    use crate::kv_replacement::{bytes,Replacement};
    let address = crate::encoding::composite(namespace,key);
    let ghost image = bytes(prior);
    let ghost location = namespace@ + seq![0u8] + key@;
    let read = |h:&u64,k:&[u8]| -> (r:Result<Option<Vec<u8>>,u64>)
        requires k@ == location,
        ensures match r {Ok(v) => *h == observed_at && k@ == location && bytes(v) == image,
            Err(e) => *h != observed_at && e == *h},
    {
        if *h == observed_at { Ok(prior) } else { Err(*h) }
    };
    let result = Replacement::compare_at(&header,&address,expected,candidate,read);
    match result {
        Ok((accepted,mut rows,changed)) => {
            assert(header == observed_at);
            let ghost compare = match expected {Some(v) => Some(v@),None => None};
            assert(accepted == (image == compare));
            assert(changed == (accepted && image != Some(candidate@)));
            assert(rows.len() == if changed {1int} else {0int});
            if changed {
                assert(rows@[0].fields() == (location,Some(candidate@),
                    Some((match image {Some(old) => Some(old.len() as usize),None => None},false))));
                let Some(row) = rows.pop() else {assert(false);return;};
                let (key,_,value) = row.into_parts();
                let mut overlay = None;
                let stored = crate::overlay_update::stage(&mut overlay,key,value,
                    |data:&Vec<u8>| -> (r:Result<crate::checkpoint_value::ValueSlot,()>)
                        requires data@ == candidate@,
                        ensures r.is_ok() && match r {
                            Ok(crate::checkpoint_value::ValueSlot::Inline(v)) => data.len() <= crate::checkpoint_value::INLINE_VALUE_MAX && v@ == data@,
                            Ok(crate::checkpoint_value::ValueSlot::Spilled {object:id,length}) =>
                                data.len() > crate::checkpoint_value::INLINE_VALUE_MAX && id == object && length == data.len(),
                            Err(_) => false,
                        },
                    {
                        crate::delta_mutation::encode(data,|payload:&[u8],length:u64| -> (v:Result<crate::ObjectId,()>)
                            requires payload@ == candidate@ && length == candidate.len(),
                            ensures v == Ok(object), {Ok(object)})
                    });
                let Ok(mutation) = stored else {assert(false);return;};
                assert(mutation.key@ == location);
                if candidate.len() <= crate::checkpoint_value::INLINE_VALUE_MAX {
                    assert(mutation.value matches Some(crate::checkpoint_value::ValueSlot::Inline(v)) && v@ == candidate@);
                } else {
                    assert(mutation.value == Some(crate::checkpoint_value::ValueSlot::Spilled {object,length:candidate.len() as u64}));
                }
                assert(crate::traversal::lookup_spec(overlay,location) matches Some(Some(v)) && v@ == candidate@);
            }
        },
        Err(e) => {assert(e == header && observed_at != header);},
    }
}

/// Encoding failure leaves an arbitrary existing overlay intact. A delete
/// writes a tombstone, leaving all other keys as they were.
fn stage_refusal_and_delete(root:&mut Option<std::sync::Arc<crate::traversal::Node>>,
    key:Vec<u8>,value:Vec<u8>,error:u64,other:&[u8])
    requires crate::traversal::ordered(*old(root)), other@ != key@,
{
    let ghost before = *root;
    let rejected = crate::overlay_update::stage(root,key.clone(),Some(value),
        |_:&Vec<u8>| -> (r:Result<crate::checkpoint_value::ValueSlot,u64>) ensures r == Err(error), {Err(error)});
    assert(rejected == Err(error) && *root == before);
    let deleted = crate::overlay_update::stage(root,key,None,
        |_:&Vec<u8>| -> (r:Result<crate::checkpoint_value::ValueSlot,u64>) requires false, {Err(error)});
    let Ok(row) = deleted else {assert(false);return;};
    assert(row.key@ == key@ && row.value.is_none());
    assert(crate::traversal::lookup_spec(*root,key@) == Some(None));
    assert(crate::traversal::lookup_spec(*root,other@) == crate::traversal::lookup_spec(before,other@));
}

// Both observations describe the same final state of one invocation.
fn recover_renamed(reservations: &BTreeMap<u64,Reservation>, directory: &HashMap<u64,u64>,
    stores: &mut Stores, uid: u64, retained: u64, live: u64)
    requires old(stores).valid(), btree_map_wf(reservations), hash_map_inv(directory),
        reservations@.contains_key(uid), reservations@[uid].alias == Some(retained), directory@.get(uid) == Some(live),
    ensures final(stores).capabilities@.contains(retained), final(stores).capabilities@.contains(live),
        final(stores).allowances@.contains(retained), final(stores).allowances@.contains(live),
        !final(stores).grants@.contains_key(retained), !final(stores).grants@.contains_key(live),
{
    let _ = recover(reservations,directory,stores);
    assert(stores.authority(retained) == (true,true,None));
    assert(stores.authority(live) == (true,true,None));
}
}

verus! {
// Finishing one reclamation can never reopen another principal's fence.
fn release_fence(closed: &mut HashSet<u64>, finished: u64, probe: u64) -> (still_closed: bool)
    requires hash_set_inv(old(closed)),
    ensures still_closed == (old(closed)@.contains(probe) && probe != finished),
{
    crate::principal_fences::release(closed,&finished);
    crate::principal_fences::fenced(closed,&probe)
}
}

verus! {
// An independent, fallible sink with no successful calls in its history.
struct RefusingStore {
    refused: Option<u64>,
    attempts: Ghost<Seq<(u64,Option<u64>)>>,
}

impl RetirementSink<u64> for RefusingStore {
    type Error = u64;
    #[cfg(verus_keep_ghost)]
    type Bucket = u64;

    closed spec fn valid(&self) -> bool {
        forall|i:int| 0 <= i < self.attempts@.len() ==> #[trigger] self.attempts@[i].1 == Some(self.attempts@[i].0)
    }
    closed spec fn failure(&self) -> Option<u64> { self.refused }
    closed spec fn history(&self) -> Seq<(u64,Option<u64>)> { self.attempts@ }
    closed spec fn authority(&self,_alias:u64) -> (bool,bool,Option<u64>) { (false,false,None) }

    fn restore(&mut self, alias:u64) -> (result:Result<(),u64>) {
        self.refused = Some(alias);
        self.attempts = Ghost(self.attempts@.push((alias,Some(alias))));
        Err(alias)
    }
}

fn refuses_first_target(reservations: &BTreeMap<u64,Reservation>, directory: &HashMap<u64,u64>,
    sink: &mut RefusingStore, uid:u64, alias:u64)
    -> (result:Result<(),u64>)
    requires old(sink).valid(), old(sink).refused.is_none(), old(sink).attempts@.len() == 0,
        btree_map_wf(reservations), hash_map_inv(directory), reservations@.contains_key(uid),
        reservations@[uid].alias == Some(alias),
    ensures result matches Err(error) && final(sink).attempts@ == seq![(error,Some(error))]
        && crate::recovery::reserved(reservations@,directory@,error),
{
    let result = crate::recovery::replay(reservations,directory,sink);
    assert(sink.authority(alias) == (false,false,None));
    assert(result.is_err());
    proof {
        if sink.attempts@.len() > 1 {
            assert(sink.attempts@[0].1.is_none());
            assert(sink.attempts@[0].1 == Some(sink.attempts@[0].0));
        }
    }
    let error = result.unwrap_err();
    assert(sink.attempts@[0] == (error,Some(error)));
    assert(sink.attempts@ =~= seq![(error,Some(error))]);
    result
}
}
