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

fn label(a:&u64) -> (r:&str) ensures r == (if *a==1 {"first"} else {"second"})
{if *a==1 {"first"} else {"second"}}

// Validate the same two reserved generations subsequently consumed by startup.
fn validate_then_restore(duplicate:bool,owned:bool,missing_fleet:bool,legacy:bool,stores:&mut Stores)
    requires old(stores).valid(), vstd::laws_cmp::obeys_cmp::<&str>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<&str>(),
{
    use crate::reservation_validation::{validate,Error,named,projected};
    let mut rows = BTreeMap::<u64,Reservation>::new();
    let mut owners = BTreeMap::<u64,()>::new();let mut fleets = BTreeMap::<u64,()>::new();
    let mut directory = HashMap::<u64,u64>::new();
    rows.insert(11,Reservation {alias:if legacy {None} else {Some(1)},fleet:None});
    rows.insert(12,Reservation {alias:Some(if duplicate {1} else {2}),fleet:Some(9)});
    if owned {owners.insert(12,());}
    if !missing_fleet {fleets.insert(9,());}
    directory.insert(11,7); directory.insert(12,8);
    proof {reveal_strlit("first");reveal_strlit("second");}
    let first = label(&1);let second = label(&2);
    assert(label.ensures((&1u64,),first) && label.ensures((&2u64,),second));
    assert(rows@.contains_key(11) && rows@.contains_key(12));
    assert(rows@[11].alias == (if legacy {None} else {Some(1u64)}) && rows@[12].alias == Some(if duplicate {1u64} else {2u64}));
    assert(directory@.get(11) == Some(7) && directory@.get(12) == Some(8));
    let result = validate(&rows,&owners,&fleets,label);
    assert(projected(rows@[12],label) == Some(if duplicate {"first"} else {"second"}));
    assert(projected(rows@[11],label) == (if legacy {None} else {Some("first")}));
    match result {
        Ok(()) => {
            assert(!owners@.contains_key(12) && fleets@.contains_key(9));
            assert(!owned && !missing_fleet);
            if duplicate && !legacy {
                assert(named(rows@,11u64,"first",label) && named(rows@,12u64,"first",label));
                assert(false);
            }
            let _ = recover(&rows,&directory,stores);
            assert(exists|uid:u64| #[trigger] rows@.contains_key(uid) && (rows@[uid].alias==Some(7u64) || directory@.get(uid)==Some(7u64))) by {assert(rows@.contains_key(11));}
            assert(exists|uid:u64| #[trigger] rows@.contains_key(uid) && (rows@[uid].alias==Some(8u64) || directory@.get(uid)==Some(8u64))) by {assert(rows@.contains_key(12));}
            assert(stores.authority(7) == (true,true,None) && stores.authority(8) == (true,true,None));
            assert(stores.authority(if duplicate {1} else {2}) == (true,true,None));
            if !legacy {assert(stores.authority(1) == (true,true,None));}
        },
        Err(Error::Fleet(f)) => {
            let ghost k=choose|k:u64| #[trigger] rows@.contains_key(k) && rows@[k].fleet == Some(f);
            assert(k==12 && f==9 && missing_fleet);
        },
        Err(Error::Owned(k)) => {assert(k==12 && owned);},
        Err(Error::Alias(n,a,b)) => {
            assert(named(rows@,a,n,label) && named(rows@,b,n,label));
            assert((a==11 && b==12)||(a==12 && b==11));assert(duplicate && !legacy);
        },
    }
}
struct Graph {
    rows:BTreeMap<u64,Reservation>,
    owners:BTreeMap<u64,()>,
    fleets:BTreeMap<u64,()>,
}
impl Graph {
    spec fn valid_maps(&self) -> bool {
        vstd::std_specs::btree::btree_map_inv(&self.rows) && vstd::std_specs::btree::btree_map_inv(&self.owners) &&
        vstd::std_specs::btree::btree_map_inv(&self.fleets)
    }
    spec fn empty(&self) -> bool { self.rows@.is_empty() && self.owners@.is_empty() && self.fleets@.is_empty() }
    spec fn consistent(&self) -> bool {
        &&& forall|k:u64| #[trigger] self.rows@.contains_key(k) ==> !self.owners@.contains_key(k) &&
            (self.rows@[k].fleet matches Some(f) ==> self.fleets@.contains_key(f))
        &&& forall|k:u64,j:u64,n:&str| #[trigger] crate::reservation_validation::named(self.rows@,k,n,label) &&
            #[trigger] crate::reservation_validation::named(self.rows@,j,n,label) ==> k==j
    }
}
// The decoder is a boundary. Only its result for these bytes may reach either fence.
fn admitted_graph<D:FnOnce(&[u8])->Result<Graph,u8>>(raw:Result<Option<&[u8]>,u8>,decode:D,
    directory:&HashMap<u64,u64>,stores:&mut Stores) -> (out:Result<Graph,u8>)
    requires old(stores).valid(),hash_map_inv(directory),vstd::laws_cmp::obeys_cmp::<&str>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<&str>(),
        raw matches Ok(Some(bytes)) ==> decode.requires((bytes,)),
        forall|b:&[u8],g:Graph| #[trigger] decode.ensures((b,),Ok(g)) ==> g.valid_maps(),
    ensures match out {
        Ok(g) => g.consistent() && (raw==Ok(None) && g.empty() || (raw matches Ok(Some(b)) && decode.ensures((b,),Ok(g)))) &&
            forall|a:u64| #[trigger] final(stores).authority(a) == if crate::recovery::reserved(g.rows@,directory@,a) {
                (true,true,None) } else {old(stores).authority(a)},
        Err(e) => *final(stores)==*old(stores) &&
            (raw==Err(e) || (raw matches Ok(Some(b)) && (decode.ensures((b,),Err(e)) ||
                exists|g:Graph| #[trigger] decode.ensures((b,),Ok(g)) && !g.consistent() && e==3u8))),
    },
{
    let empty = || -> (g:Graph) ensures g.valid_maps() && g.empty(),
        {Graph {rows:BTreeMap::new(),owners:BTreeMap::new(),fleets:BTreeMap::new()}};
    let validate = |g:&Graph| -> (r:Result<(),u8>) requires g.valid_maps(), ensures r == (if g.consistent() {Ok(())} else {Err(3u8)}),
    {
        match crate::reservation_validation::validate(&g.rows,&g.owners,&g.fleets,label) {
            Ok(()) => Ok(()),
            Err(e) => {
                proof {
                    match e {
                        crate::reservation_validation::Error::Fleet(f) => {
                            let k=choose|k:u64| #[trigger] g.rows@.contains_key(k) && g.rows@[k].fleet==Some(f);
                            assert(g.rows@.contains_key(k));
                        },
                        crate::reservation_validation::Error::Owned(k) => {assert(g.rows@.contains_key(k));},
                        crate::reservation_validation::Error::Alias(n,k,j) => {
                            assert(crate::reservation_validation::named(g.rows@,k,n,label) && crate::reservation_validation::named(g.rows@,j,n,label));
                        },
                    }
                }
                Err(3)
            },
        }
    };
    let g=crate::graph_read::admit(raw,empty,decode,validate)?;
    let _=recover(&g.rows,directory,stores);
    Ok(g)
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

// A conflicting root invalidates this entire changed comparison attempt. Even
// an accepted comparison can return no answer until the next header is read.
fn acknowledge_graph_compare(key:&[u8],prior:Option<Vec<u8>>,expected:Option<&[u8]>,
    candidate:&[u8],commit:Result<bool,u64>) {
    use crate::kv_replacement::{bytes,Replacement};
    let ghost image = bytes(prior);
    let ghost matches = image == match expected {Some(v)=>Some(v@),None=>None};
    let read = |_:&(),_:&[u8]| -> (r:Result<Option<Vec<u8>>,u64>)
        ensures r matches Ok(v) && bytes(v) == image, {Ok(prior)};
    let Ok((accepted,rows,changed)) = Replacement::compare_at(&(),key,expected,candidate,read)
        else {assert(false);return;};
    let publish = |entries:Vec<Replacement>| -> (r:Result<bool,u64>)
        requires entries.len() == 1, entries@[0].fields() == (key@,Some(candidate@),
            Some((match image {Some(old)=>Some(old.len() as usize),None=>None},false))),
        ensures r == commit, {commit};
    let answer = crate::mutation_ack::finish(accepted,rows,changed,publish);
    proof { if !matches {assert(answer == Ok(Some(false)));}
    else if image == Some(candidate@) {assert(answer == Ok(Some(true)));}
    else {
        assert(answer == match commit {
            Ok(true)=>Ok(Some(true)), Ok(false)=>Ok(None), Err(e)=>Err(e),
        });
    } }
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

verus! {
// A failed allowance update may leave the private capability store fenced.
// Ownership of both stores must stay inside recovery until replay succeeds.
struct StartupStores {
    inner:Stores,
    // Model a store error for this alias after the capability fence has closed.
    failed:Option<u64>,
    calls:Ghost<Seq<(u64,Option<u64>)>>,
}

impl RetirementSink<u64> for StartupStores {
    type Error = u64;
    #[cfg(verus_keep_ghost)]
    type Bucket = u64;

    closed spec fn valid(&self) -> bool {
        (forall|i:int| 0 <= i < self.calls@.len() && (#[trigger] self.calls@[i]).1.is_some() ==> self.calls@[i].1 == Some(self.calls@[i].0)) && self.inner.valid() && (self.failed.is_some() ==> self.failed == Some(7u64))
    }
    closed spec fn failure(&self) -> Option<u64> {self.failed}
    closed spec fn history(&self) -> Seq<(u64,Option<u64>)> {self.calls@}
    closed spec fn authority(&self,k:u64) -> (bool,bool,Option<u64>) {self.inner.authority(k)}

    fn restore(&mut self,k:u64) -> (r:Result<(),u64>) {
        let receipt = crate::principal_fences::restore_capability(&mut self.inner.capabilities,k);
        let grants = if k == 7 {Err(k)} else {Ok(&mut self.inner.grants)};
        if let Err(e) = crate::principal_fences::restore_accessible_allowances(
            receipt,Ok(&mut self.inner.allowances),grants,
        ) {
            self.failed = Some(e);
            self.calls = Ghost(self.calls@.push((k,Some(e))));
            return Err(e);
        }
        self.calls = Ghost(self.calls@.push((k,None)));
        Ok(())
    }
}

// Exercise both exclusive-access results, including distinct simultaneous failures.
fn restore_with_poison(closed:&mut HashSet<u64>,grants:&mut HashMap<u64,u64>,cap:&mut HashSet<u64>,
    alias:u64,bad_fence:bool,bad_grants:bool)
    requires hash_set_inv(old(closed)),hash_set_inv(old(cap)),hash_map_inv(old(grants)),
{
    let receipt = crate::principal_fences::restore_capability(cap,alias);
    let ghost before = closed@;
    let ghost buckets = grants@;
    let fence_access = if bad_fence {Err(1u8)} else {Ok(&mut *closed)};
    let grant_access = if bad_grants {Err(2u8)} else {Ok(&mut *grants)};
    let out = crate::principal_fences::restore_accessible_allowances(receipt,fence_access,grant_access);
    assert(cap@.contains(alias));
    assert(out == (if bad_fence {Err(1u8)} else if bad_grants {Err(2u8)} else {Ok(())}));
    assert(closed@ == if out.is_ok() {before.insert(alias)} else {before});
    assert(grants@ == if out.is_ok() {buckets.remove(alias)} else {buckets});
}

type PublishedAllowances = (HashSet<u64>,HashMap<u64,u64>);

spec fn shared_authority(cap:HashSet<u64>,pair:PublishedAllowances,a:u64) -> (bool,bool,Option<u64>) {
    (cap@.contains(a),pair.0@.contains(a),pair.1@.get(a))
}

spec fn restored_handles(cap:HashSet<u64>,pair:PublishedAllowances,rows:Map<u64,Reservation>,
    directory:Map<u64,u64>,prior:StartupStores) -> bool {
    forall|a:u64| #[trigger] shared_authority(cap,pair,a) ==
        if crate::recovery::reserved(rows,directory,a) {(true,true,None)} else {prior.authority(a)}
}

fn publish_startup(read:Result<BTreeMap<u64,Reservation>,u64>,directory:&HashMap<u64,u64>,private:StartupStores)
    requires private.valid(),private.failed.is_none(),hash_map_inv(directory),
        read matches Ok(rows) ==> btree_map_wf(&rows),
{
    let restore = |rows:BTreeMap<u64,Reservation>,stores:StartupStores| ->
        (out:Result<(HashSet<u64>,PublishedAllowances),u64>)
        requires stores.valid(),stores.failed.is_none(),btree_map_wf(&rows),
        ensures match out {
            Ok((cap,pair)) => restored_handles(cap,pair,rows@,directory@,stores),
            Err(e) => e == 7 && crate::recovery::reserved(rows@,directory@,e),
        },
    {
        let mut active = stores;
        let ghost n = active.calls@.len();
        match crate::recovery::replay(&rows,directory,&mut active) {
            Err(e)=>{
                assert(active.failure()==Some(e) && active.valid());
                assert(active.calls@.last().1==Some(e));
                let ghost i = active.calls@.len() - 1;
                assert(n <= i && active.calls@[i].1 == Some(e));
                assert(active.calls@[i].0 == e);
                assert(crate::recovery::reserved(rows@,directory@,active.history()[i].0));
                Err(e)
            },
            Ok(())=>{
                assert forall|a:u64| #[trigger] active.authority(a) ==
                    if crate::recovery::reserved(rows@,directory@,a) {(true,true,None)} else {stores.authority(a)} by {};
                let cap = active.inner.capabilities;
                let pair = (active.inner.allowances,active.inner.grants);
                assert forall|a:u64| #[trigger] shared_authority(cap,pair,a) ==
                    if crate::recovery::reserved(rows@,directory@,a) {(true,true,None)} else {stores.authority(a)}
                    by {assert(shared_authority(cap,pair,a)==active.authority(a));}
                Ok((cap,pair))
            },
        }
    };
    let out = crate::retirement_publication::publish(read,private,restore);
    let ghost original_read = read;
    let ghost published = out;
    proof { match original_read {
        Err(e)=>{assert(out==Err(e));},
        Ok(rows)=>match published {
            Ok((cap,pair))=>{
                assert(restored_handles(*cap,*pair,rows@,directory@,private));
                assert forall|a:u64| #[trigger] shared_authority(*cap,*pair,a) ==
                    if crate::recovery::reserved(rows@,directory@,a) {(true,true,None)} else {private.authority(a)} by {};
            },
            Err(e)=>{assert(e==7 && crate::recovery::reserved(rows@,directory@,e));},
        }
    } }
}
}
