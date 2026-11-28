//! Principal-scoped cache probes, duplicate miss positions and content traversal handoff.
use crate::{ObjectId, ObjectRecord, batch_slots as slots, child_range};
use std::sync::Arc;
use vstd::prelude::*;

verus! {
fn publish_one<P,F,I>(owner:&P,ids:&[ObjectId],id:ObjectId,loaded:ObjectRecord,probe:F,insert:I,
    cache:Ghost<spec_fn(P,ObjectId)->Option<Arc<ObjectRecord>>>)
    -> (out:Vec<Option<Arc<ObjectRecord>>>)
    where F:Fn(&P,ObjectId)->Option<Arc<ObjectRecord>>,
        I:FnOnce(&P,ObjectId,ObjectRecord)->Arc<ObjectRecord>,
    requires vstd::laws_cmp::obeys_cmp::<ObjectId>(), vstd::laws_cmp::obeys_cmp_concrete_eq::<ObjectId>(),
        forall|key:ObjectId| #[trigger] probe.requires((owner,key)),
        forall|key:ObjectId,row:Option<Arc<ObjectRecord>>| #[trigger] probe.ensures((owner,key),row) ==> row == (cache@)(*owner,key),
        insert.requires((owner,id,loaded)),
    ensures out.len() == ids.len(), exists|kept:Arc<ObjectRecord>| #[trigger] insert.ensures((owner,id,loaded),kept)
        && forall|i:int| 0 <= i < ids.len() ==> #[trigger] out@[i] ==
            if ids@[i] == id && (cache@)(*owner,id).is_none() { Some(kept) } else { (cache@)(*owner,ids@[i]) },
{
    let mut batch = slots::prepare(owner,ids,probe);
    let ghost before = batch.records@;
    let ghost missing = batch.missing@;
    assert forall|j:int| #[trigger] slots::waiting(missing,id,j) implies j < batch.records.len() by {}
    slots::publish(&mut batch,owner,id,loaded,insert);
    proof {
        let kept = choose|kept:Arc<ObjectRecord>| #[trigger] insert.ensures((owner,id,loaded),kept)
            && forall|j:int| 0 <= j < before.len() ==> #[trigger] batch.records@[j] ==
                if slots::waiting(missing,id,j) { Some(kept) } else { before[j] };
        assert forall|j:int| 0 <= j < ids.len() implies #[trigger] batch.records@[j] ==
            if ids@[j] == id && (cache@)(*owner,id).is_none() { Some(kept) } else { (cache@)(*owner,ids@[j]) } by {
            assert(probe.ensures((owner,ids@[j]),before[j]));
            if slots::waiting(missing,id,j) { assert(ids@[j] == id); }
        }
    }
    batch.records
}

/// A competing generation or a missing object cannot publish a stale load.
fn readmission<P:Copy>(owner:P,key:ObjectId,observed:u64,current:u64,indexed:Option<ObjectId>,
    pending:Option<ObjectId>,loaded:ObjectRecord) -> (out:Option<(P,ObjectId,ObjectRecord)>)
    ensures out == if observed == current && (indexed == Some(key) || pending == Some(key)) {
        Some((owner,key,loaded))
    } else { None },
{
    let present = |id:ObjectId| -> (found:bool) ensures found == (indexed == Some(id) || pending == Some(id)) {
        (match indexed {Some(k) => k.same(&id),None => false}) ||
        (match pending {Some(k) => k.same(&id),None => false})
    };
    let publish = |p:&P,id:ObjectId,r:ObjectRecord| -> (row:(P,ObjectId,ObjectRecord)) ensures row == (*p,id,r) { (*p,id,r) };
    crate::read_admission::retain(&owner,key,observed,current,loaded,present,publish)
}

/// A snapshot with both sources offers the WAL body even if the arena reader
/// changed generation or would fail. A stale publication of either body retries.
fn snapshot<P:Copy>(principal:P,id:ObjectId,generation:u64,reader_generation:u64,current:u64,
    pending:Option<ObjectRecord>,location:Option<crate::ArenaLocation>,disk:ObjectRecord,
    disk_error:Option<u8>,membership:bool)
    -> (out:Result<crate::read_admission::Attempt<(P,ObjectId,ObjectRecord)>,u8>)
    ensures ({
        let retained = |r:ObjectRecord| if generation == current && membership {
            Ok(crate::read_admission::Attempt::Found((principal,id,r)))
        } else { Ok(crate::read_admission::Attempt::Retry) };
        out == match pending {
            Some(r) => retained(r),
            None => if location.is_none() {Ok(crate::read_admission::Attempt::Missing)}
                else if generation != reader_generation {Ok(crate::read_admission::Attempt::Retry)}
                else if let Some(e) = disk_error {Err(e)}
                else {retained(disk)},
        }
    }),
{
    use crate::read_admission;
    let read = |g:u64,key:ObjectId,loc:crate::ArenaLocation| -> (result:Result<Option<ObjectRecord>,u8>)
        requires g == generation && key == id && Some(loc) == location,
        ensures result == if g != reader_generation { Ok(None) }
            else if let Some(e) = disk_error { Err(e) } else { Ok(Some(disk)) },
    {
        if g != reader_generation {Ok(None)} else if let Some(e) = disk_error {Err(e)} else {Ok(Some(disk))}
    };
    let keep = |p:&P,key:ObjectId,g:u64,r:ObjectRecord| -> (result:Result<Option<(P,ObjectId,ObjectRecord)>,u8>)
        ensures result == if g == current && membership {Ok(Some((*p,key,r)))} else {Ok(None)},
    {
        let present = |_:ObjectId| -> (yes:bool) ensures yes == membership {membership};
        let insert = |q:&P,k:ObjectId,loaded:ObjectRecord| -> (row:(P,ObjectId,ObjectRecord))
            ensures row == (*q,k,loaded) {(*q,k,loaded)};
        Ok(read_admission::retain(p,key,g,current,r,present,insert))
    };
    read_admission::attempt(&principal,id,generation,pending,location,read,keep)
}

/// Follow an actual confirmed frame through both warm-cache gates. A reference-free
/// record requires no fallible reference allocation, so admission is an equivalence.
fn published<P:Ord+Copy>(owner:P,commit:&crate::read_admission::PublishedCommitPayload,current:u64,
    roots:&std::collections::BTreeMap<P,crate::RootState>,index:&std::collections::BTreeMap<ObjectId,crate::ArenaLocation>,
    checksum:[u8;32],scheme:crate::root_wire::Scheme,derived:[u8;32])
    -> (out:Option<(P,ObjectId,ObjectRecord)>)
    requires vstd::std_specs::btree::btree_map_inv(roots),vstd::std_specs::btree::btree_map_inv(index),
        vstd::laws_cmp::obeys_cmp::<P>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<P>(),
        vstd::laws_cmp::obeys_cmp::<ObjectId>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<ObjectId>(),
        crate::verified_record::leaf_body((*commit.payload)@,40),
    ensures ({
        let b = (*commit.payload)@;
        let id = commit.root.commit;
        &&& out.is_some() == (b.len() == commit.location.payload_len && checksum == commit.location.checksum &&
            crate::verified_record::tag(b,0,scheme) && id.digest() == b.subrange(8,40) && derived@ == id.digest() &&
            commit.arena_generation == current && roots@.contains_key(owner) && roots@[owner] == commit.root &&
            index@.contains_key(id) && index@[id] == commit.location)
        &&& out matches Some((p,key,r)) ==> p == owner && key == id && crate::verified_record::record_at(b,40,scheme,r)
    }),
{
    let hash = |_:u64,_:&[u8]| -> (sum:[u8;32]) ensures sum == checksum {checksum};
    let confirm = |b:&[u8],key:ObjectId| -> (out:Option<ObjectRecord>)
        requires crate::verified_record::leaf_body(b@,40),
        ensures out.is_some() == (crate::verified_record::tag(b@,0,scheme) && key.digest() == b@.subrange(8,40) &&
            derived@ == key.digest()), out matches Some(r) ==> crate::verified_record::record_at(b@,40,scheme,r),
    {
        let name = |_:&ObjectRecord| -> (v:[u8;32]) ensures v == derived {derived};
        crate::verified_record::confirmed(b,scheme,key,name).ok()
    };
    let candidate = commit.prepare(hash,confirm)?;
    let offer = |p:&P,key:ObjectId,r:ObjectRecord| -> (row:(P,ObjectId,ObjectRecord))
        ensures row == (*p,key,r) {(*p,key,r)};
    candidate.warm(&owner,current,roots,index,offer)
}

/// Read the newly installed physical record through a real principal partition.
fn resident_lookup(owner:u64,requester:u64,stored:ObjectId,request:ObjectId,record:Arc<ObjectRecord>,
    tick:u64,projection:u64) -> (out:Option<Arc<ObjectRecord>>)
    requires vstd::laws_cmp::obeys_cmp::<Arc<u64>>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<Arc<u64>>(),
        vstd::laws_cmp::obeys_cmp::<ObjectId>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<ObjectId>(),
        vstd::laws_cmp::obeys_cmp::<(u64,ObjectId)>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<(u64,ObjectId)>(),
        vstd::std_specs::cmp::borrowed_key_ordering_matches::<Arc<u64>,u64>(),
    ensures out == if requester == owner && request == stored {Some(record)} else {None},
{
    use std::collections::{BTreeMap,BTreeSet};
    use crate::resident::{self,Partition,PrincipalEntry};
    let mut objects = BTreeMap::new();
    let mut partitions = BTreeMap::new();
    let mut entries = BTreeMap::new();
    let mut global = BTreeSet::new();
    let mut local = BTreeSet::new();
    let mut clock = tick;
    resident::install(&mut objects,stored,record,17,tick,owner);
    entries.insert(stored,PrincipalEntry {last_access:tick,projections:projection});
    global.insert((tick,stored)); local.insert((tick,stored));
    let key = Arc::new(owner);
    partitions.insert(Arc::clone(&key),Partition {entries,lru:local,charged_bytes:17});
    let peer = Arc::new(if owner == 0 {1u64} else {0u64});
    let other = Partition {entries:BTreeMap::new(),lru:BTreeSet::new(),charged_bytes:0};
    let ghost peer_before = other;
    partitions.insert(Arc::clone(&peer),other);
    assert(*peer != owner);
    assert(partitions@.contains_key(peer) && partitions@[peer] == peer_before);
    let ghost original_global = global@;
    let ghost original_local = partitions@[key].lru@;
    let check = |p:&u64| requires *p == requester, { };
    assert(partitions@.contains_key(key) && *key == owner && partitions@[key].entries@.contains_key(stored));
    if requester == owner && stored.same(&request) {assert(resident::member(partitions@,requester,request));}
    let out = resident::visit(&requester,request,&mut partitions,&mut objects,&mut clock,&mut global,check);
    assert(objects@[stored].record == record);
    if requester != *peer {
        assert(partitions@[peer] == peer_before);
    } else {
        assert(partitions@[peer].entries@ == peer_before.entries@);
    }
    let partition = partitions.get(&key).unwrap();
    assert(partition.charged_bytes == 17 && partition.entries@[stored].projections == projection);
    if requester == owner && stored.same(&request) {
        assert(global@ == original_global.remove((tick,stored)).insert((clock,stored)));
        assert(partition.lru@ == original_local.remove((tick,stored)).insert((clock,stored)));
        assert(objects@[stored].last_access == clock);
    } else {
        assert(global@ == original_global && partition.lru@ == original_local);
    }
    assert(clock == if requester == owner && request == stored {resident::next(tick)} else {tick});
    out
}

fn load_visits<R,E,F>(plan:&[child_range::Visit],read:F, table:Ghost<spec_fn(ObjectId)->Option<R>>,
    error:Ghost<E>) -> (out:Result<Vec<(child_range::Visit,R)>,child_range::LoadError<E>>)
    where F:FnOnce(Vec<ObjectId>)->Result<Vec<Option<R>>,E>,
    requires forall|ids:Vec<ObjectId>| #[trigger] read.requires((ids,)),
        forall|ids:Vec<ObjectId>,rows:Vec<Option<R>>| #[trigger] read.ensures((ids,),Ok(rows)) ==>
            (forall|j:int| 0 <= j < rows.len() && j < ids.len() ==> #[trigger] rows@[j] == (table@)(ids@[j])),
        forall|ids:Vec<ObjectId>,e:E| #[trigger] read.ensures((ids,),Err(e)) ==> e == error@,
    ensures out matches Ok(pairs) ==> pairs.len() == plan.len() &&
        forall|j:int| 0 <= j < plan.len() ==> #[trigger] pairs@[j].0 == plan@[j] &&
            (table@)(plan@[j].object) == Some(pairs@[j].1),
        out matches Err(child_range::LoadError::Source(e)) ==> e == error@,
        out matches Err(child_range::LoadError::Length(id)) ==> plan.len() > 0 && id == plan@[0].object,
        out matches Err(child_range::LoadError::Missing(id)) ==> exists|i:int| 0 <= i < plan.len() &&
            #[trigger] plan@[i].object == id && (table@)(id).is_none() &&
            forall|j:int| 0 <= j < i ==> (table@)(#[trigger] plan@[j].object).is_some(),
{
    let out = child_range::load(plan,read);
    proof {
        if let Ok(pairs) = &out {
            if plan.len() > 0 {
                let (ids,rows) = choose|ids:Vec<ObjectId>,rows:Vec<Option<R>>| ids@ == child_range::keys(plan@) &&
                    #[trigger] read.ensures((ids,),Ok(rows)) && rows.len() == pairs.len() &&
                    forall|i:int| 0 <= i < pairs.len() ==> #[trigger] pairs@[i].0 == plan@[i] && rows@[i] == Some(pairs@[i].1);
                assert forall|j:int| 0 <= j < plan.len() implies #[trigger] pairs@[j].0 == plan@[j] &&
                    (table@)(plan@[j].object) == Some(pairs@[j].1) by {
                    assert(ids@[j] == plan@[j].object);
                    assert(pairs@[j].0 == plan@[j]);
                    assert(rows@[j] == Some(pairs@[j].1));
                }
            }
        } else if let Err(child_range::LoadError::Missing(id)) = &out {
            let (ids,rows,i) = choose|ids:Vec<ObjectId>,rows:Vec<Option<R>>,i:int|
                ids@ == child_range::keys(plan@) && #[trigger] read.ensures((ids,),Ok(rows)) && rows.len() == plan.len()
                && 0 <= i < plan.len() && #[trigger] plan@[i].object == *id && rows@[i].is_none()
                && forall|j:int| 0 <= j < i ==> (#[trigger] rows@[j]).is_some();
            assert(ids@[i] == *id);
            assert forall|j:int| 0 <= j < i implies (table@)(#[trigger] plan@[j].object).is_some() by {
                assert(ids@[j] == plan@[j].object);
                assert(rows@[j].is_some());
            }
        }
    }
    out
}

/// A backend supplying every requested row in order cannot cause a batch refusal.
fn complete<R,E,F>(plan:&[child_range::Visit],read:F)
    -> (out:Result<Vec<(child_range::Visit,R)>,child_range::LoadError<E>>)
    where F:FnOnce(Vec<ObjectId>)->Result<Vec<Option<R>>,E>,
    requires forall|ids:Vec<ObjectId>| #[trigger] read.requires((ids,)),
        forall|ids:Vec<ObjectId>,result:Result<Vec<Option<R>>,E>| #[trigger] read.ensures((ids,),result) ==>
            (result matches Ok(rows) && rows.len() == ids.len() &&
             forall|i:int| 0 <= i < rows.len() ==> (#[trigger] rows@[i]).is_some()),
    ensures out.is_ok(),
{
    child_range::load(plan,read)
}
}
