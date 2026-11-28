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

spec fn cached_bytes(result:Option<Option<Vec<u8>>>) -> Option<Option<Seq<u8>>> {
    match result { Some(Some(v)) => Some(Some(v@)), Some(None) => Some(None), None => None }
}

/// A replacement in an arbitrary sampled table preserves every other byte key.
fn update_row(rows:&mut std::collections::BTreeMap<Vec<u8>,crate::hot_lookup::CachedValue>,
    key:Vec<u8>,value:crate::hot_lookup::CachedValue,request:&Vec<u8>) -> (out:Option<Option<Vec<u8>>>)
    requires vstd::std_specs::btree::btree_map_inv(old(rows)),vstd::laws_cmp::obeys_cmp::<Vec<u8>>(),
        vstd::laws_cmp::obeys_cmp_deep_eq::<Vec<u8>>(),
    ensures cached_bytes(out) == if request@ == key@ {Some(value.bytes_view())}
        else {old(rows).deep_view().get(request@)},
{
    crate::hot_lookup::store_row(rows,key,value);
    match crate::hot_lookup::row(rows,request) {
        Some(v) => Some(v.to_vec()),
        None => None,
    }
}

/// The runtime point-cache may return a cached absence. An unavailable sample,
/// missing owner, stale root or different composite key must remain a miss.
fn hot_point(owner:u64,requester:u64,recorded:Option<crate::RootState>,published:Option<crate::RootState>,
    before:bool,after:bool,namespace:&[u8],logical:&[u8],stored:&[u8],value:&crate::hot_lookup::CachedValue)
    -> (out:Option<Option<Vec<u8>>>)
    requires vstd::laws_cmp::obeys_cmp::<Vec<u8>>(),vstd::laws_cmp::obeys_cmp_deep_eq::<Vec<u8>>(),
    ensures cached_bytes(out) == if before && after && owner == requester && recorded == published &&
        stored@ == namespace@ + seq![0u8] + logical@ {Some(value.bytes_view())} else {None},
{
    broadcast use vstd::std_specs::btree::group_btree_axioms;
    let mut owners = std::collections::BTreeMap::new();
    owners.insert(owner,recorded);
    let mut rows = std::collections::BTreeMap::new();
    let mut stored_key = Vec::with_capacity(stored.len());
    stored_key.extend_from_slice(stored);
    assert(stored_key@ =~= stored@);
    proof {
        vstd::std_specs::btree::lemma_btree_map_deepview_dom(rows);
        assert(rows@.dom() =~= Set::<Vec<u8>>::empty());
        assert(rows.deep_view().dom() =~= Set::<Seq<u8>>::empty());
        assert(rows.deep_view() =~= Map::<Seq<u8>,Option<Seq<u8>>>::empty());
    }
    let copy = crate::hot_lookup::CachedValue::clone(value);
    assert(copy == *value);
    crate::hot_lookup::store_row(&mut rows,stored_key,copy);
    assert(rows.deep_view().get(stored@) == Some(value.bytes_view()));
    assert(rows.deep_view().dom() =~= set![stored@]);
    let select = |p:&u64| -> (r:Option<crate::RootState>)
        ensures r == if *p == owner {published} else {None},
        {if *p == owner {published} else {None}};
    let root = crate::ready_root::ReadyKvRoot::sample_ready(&requester,
        || -> (ready:bool) ensures ready == before {before},select,
        || -> (ready:bool) ensures ready == after {after})?.get();
    let address = crate::encoding::composite(namespace,logical);
    crate::hot_lookup::lookup(&owners,&requester,root,&address,
        |sample:&Option<crate::RootState>,wanted:Option<crate::RootState>,key:&Vec<u8>| -> (r:Option<Option<Vec<u8>>>)
            ensures cached_bytes(r) == if *sample == wanted && key@ == stored@ {Some(value.bytes_view())} else {None},
        {
            crate::hot_lookup::at_root(*sample,wanted,key,|k:&Vec<u8>| -> (v:Option<Option<Vec<u8>>>)
                ensures cached_bytes(v) == if k@ == stored@ {Some(value.bytes_view())} else {None},
                {match crate::hot_lookup::row(&rows,k) {Some(v) => Some(v.to_vec()),None => None}})
        })
}

fn fill_point<C>(owner:u64,namespace:&[u8],logical:&[u8],
    observation:Result<(Option<crate::RootState>,Option<Vec<u8>>),u64>,cache:C)
    -> (out:Result<Option<Vec<u8>>,u64>)
    where C:FnOnce(&u64,Vec<u8>,Option<crate::RootState>,&Option<Vec<u8>>),
    requires forall|k:Vec<u8>| #[trigger] k@ == namespace@ + seq![0u8] + logical@ ==>
        (observation matches Ok((root,v)) ==> cache.requires((&owner,k,root,&v))),
    ensures match observation {
        Err(e) => out == Err(e),
        Ok((root,value)) => out == Ok(value) && exists|k:Vec<u8>| k@ == namespace@ + seq![0u8] + logical@ &&
            #[trigger] cache.ensures((&owner,k,root,&value),()),
    },
{
    let address = crate::encoding::composite(namespace,logical);
    let read = crate::hot_lookup::PointRead::load(owner,address,
        |p:u64,k:&Vec<u8>| -> (r:Result<(Option<crate::RootState>,Option<Vec<u8>>),u64>)
            requires p == owner && k@ == namespace@ + seq![0u8] + logical@,
            ensures r == observation,
            {observation})?;
    let value = read.retain(cache);
    assert(cache.ensures((&owner,address,observation.unwrap().0,&value),()));
    Ok(value)
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
