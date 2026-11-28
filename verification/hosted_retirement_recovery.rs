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
