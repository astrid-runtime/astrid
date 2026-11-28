//! Independently consume the production graph traversal and edge scheduler.
use crate::closure_walk::{self as walk, Edge, Failure, Source, Work};
use std::collections::{BTreeMap,BTreeSet};
use vstd::{laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},prelude::*,std_specs::btree::{btree_map_inv,btree_set_inv}};

verus! {
/// With no WAL overlay and an empty index, recovery selects exactly the same records and errors as the layered loader.
fn preload_equivalence<K:Ord+Copy,V,F:Fn(&V)->V>(table:&BTreeMap<K,V>,id:K,copy:F) -> (out:Result<V,K>)
    requires btree_map_inv(table),obeys_cmp::<K>(),obeys_cmp_concrete_eq::<K>(),
        forall|v:&V| #[trigger] copy.requires((v,)),
        forall|v:&V,r:V| #[trigger] copy.ensures((v,),r) ==> r == *v,
    ensures out == if table@.contains_key(id) {Ok(table@[id])} else {Err(id)},
{
    use crate::closure_load::{self,Layers};
    let empty = BTreeMap::<K,u64>::new();
    let layered = closure_load::load(id,&Layers {incoming:table,pending:None::<&BTreeMap<K,V>>,index:&empty},
        |v:&V| -> (r:V) ensures r == *v, {copy(v)},
        |v:&V| -> (r:V) ensures r == *v, {copy(v)},
        |k:K,_:&u64| -> (r:Result<V,K>) ensures r == Err(k), {Err(k)},
        |k:K| -> (r:K) ensures r == k, {k});
    let result = closure_load::preloaded(id,table,|v:&V| -> (r:V) ensures r == *v, {copy(v)},
        |k:K| -> (r:K) ensures r == k, {k});
    assert(result == layered);
    result
}

/// A root's owning child must be returned with its preloaded contents. An
/// unrelated row outside any closed superset cannot appear in the result.
fn recovered_child<F:Fn(&crate::ObjectRecord)->crate::ObjectRecord>(
    table:&BTreeMap<crate::ObjectId,crate::ObjectRecord>,root:crate::ObjectId,
    child:crate::ObjectId,scope:Ghost<Set<crate::ObjectId>>,copy:F)
    requires crate::closure_load::Preload(table).valid(),
        table@.contains_key(root),walk::children(table@[root].contents().3).contains(child),
        walk::closed(root,Set::empty(),crate::closure_load::Preload(table).edges(),scope@),
        forall|v:&crate::ObjectRecord| #[trigger] copy.requires((v,)),
        forall|v:&crate::ObjectRecord,r:crate::ObjectRecord| #[trigger] copy.ensures((v,),r) ==> r.contents() == v.contents(),
{
    use crate::closure_load::{self,Preload,row_ids};
    match closure_load::materialize(table,root,copy) {
        Ok(rows) => {
            let ghost ids = row_ids(rows@).to_set();
            let ghost graph = Preload(table).edges();
            assert(graph[root].contains(child));
            assert(ids.contains(root) && ids.contains(child));
            assert(closure_load::in_id_order(row_ids(rows@)));
            assert(ids.subset_of(scope@));
            assert(exists|rank:Map<crate::ObjectId,nat>| rank.dom() == ids && #[trigger] walk::ranked(graph,Set::empty(),rank));
            assert forall|i:int| 0 <= i < rows.len() implies
                (#[trigger] rows@[i]).1.contents() == table@[rows@[i].0].contents() by {};
        },
        Err(Failure::Source(id,e)) => {
            assert(!table@.contains_key(id) && e == id && scope@.contains(id));
        },
        Err(Failure::Cycle(id)) => {
            assert(walk::reaches(Preload(table).edges(),Set::empty(),id,id) && scope@.contains(id));
        },
        Err(Failure::Root(_)) => {assert(false);},
    }
}

/// Equal duplicate declarations are admitted. A rejected name actually
/// appears twice with different records in the supplied batch.
fn duplicate_declarations(rows:Vec<(u64,u64)>)
    -> (out:Result<BTreeMap<u64,u64>,u64>)
    ensures out.is_ok() == (forall|i:int,j:int| 0 <= i < j < rows.len() &&
        #[trigger] rows@[i].0 == #[trigger] rows@[j].0 ==> rows@[i].1 == rows@[j].1),
        out matches Ok(map) ==> crate::transaction_records::represents(map@,rows@),
        out matches Err(id) ==> exists|i:int,j:int| 0 <= i < j < rows.len() &&
            #[trigger] rows@[i].0 == id && #[trigger] rows@[j].0 == id && rows@[i].1 != rows@[j].1,
{
    let out = crate::transaction_records::unique(rows);
    if let Ok(ref map) = out {
        assert forall|i:int,j:int| 0 <= i < j < rows.len() && #[trigger] rows@[i].0 == #[trigger] rows@[j].0
            implies rows@[i].1 == rows@[j].1 by {
            assert(map@[rows@[i].0] == rows@[i].1);
            assert(map@[rows@[j].0] == rows@[j].1);
        }
    }
    out
}

/// The map used for closure lookup carries the exact authenticated records
/// even when the transaction repeats declarations or names unrelated objects.
fn authenticated_map<R:PartialEq,F:Fn(&R)->crate::ObjectId>(
    rows:Vec<(crate::ObjectId,R)>,identify:F,
) -> (out:Result<BTreeMap<crate::ObjectId,R>,()>)
    requires vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
        vstd::laws_eq::obeys_concrete_eq::<R>(),forall|r:&R| #[trigger] identify.requires((r,)),
    ensures out matches Ok(map) ==> {
        &&& btree_map_inv(&map)
        &&& crate::transaction_records::represents(map@,rows@)
        &&& forall|id:crate::ObjectId| map@.contains_key(id) ==> #[trigger] crate::transaction_records::authentic((id,map@[id]),identify)
    },
{
    crate::transaction_records::check_transaction(&rows,&identify).map_err(|_| ())?;
    let map = crate::transaction_records::unique(rows).map_err(|_| ())?;
    assert forall|id:crate::ObjectId| map@.contains_key(id) implies #[trigger] crate::transaction_records::authentic((id,map@[id]),identify) by {
        let i = choose|i:int| 0 <= i < rows.len() && #[trigger] rows@[i].0 == id;
        assert(crate::transaction_records::authentic(rows@[i],&identify));
        assert(rows@[i] == (id,map@[id]));
    }
    Ok(map)
}

/// Compose unsealed preparation, deduplication and live layered lookup.
/// The pending producer and indexed reader must separately authenticate their results.
fn prepared_lookup<R:PartialEq,P,L,H,C,Q,D>(rows:Vec<(crate::ObjectId,R)>,id:crate::ObjectId,
    pending:&BTreeMap<crate::ObjectId,P>,index:&BTreeMap<crate::ObjectId,L>,
    identify:H,copy:C,unpack:Q,disk:D) -> (out:Result<R,()>)
    where H:Fn(&R)->crate::ObjectId,C:Fn(&R)->R,Q:Fn(&P)->R,D:Fn(crate::ObjectId,&L)->Result<R,()>,
    requires vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
        vstd::laws_eq::obeys_concrete_eq::<R>(),btree_map_inv(pending),btree_map_inv(index),
        forall|r:&R| #[trigger] identify.requires((r,)),
        forall|r:&R| #[trigger] copy.requires((r,)),
        forall|r:&R,v:R| #[trigger] copy.ensures((r,),v) ==> v == *r,
        forall|r:&P| #[trigger] unpack.requires((r,)),
        forall|r:R| pending@.contains_key(id) && #[trigger] unpack.ensures((&pending@[id],),r) ==>
            crate::transaction_records::authentic((id,r),identify),
        forall|l:&L| #[trigger] disk.requires((id,l)),
        forall|r:R| index@.contains_key(id) && #[trigger] disk.ensures((id,&index@[id]),Ok(r)) ==>
            crate::transaction_records::authentic((id,r),identify),
    ensures out matches Ok(r) ==> crate::transaction_records::authentic((id,r),identify) &&
        forall|i:int| 0 <= i < rows.len() && #[trigger] rows@[i].0 == id ==> rows@[i].1 == r,
{
    let map = authenticated_map(rows,&identify)?;
    let result = crate::closure_load::load(id,&crate::closure_load::Layers {incoming:&map,pending:Some(pending),index},
        copy,unpack,disk,|_:crate::ObjectId| ());
    proof { if let Ok(ref r) = result {
        if map@.contains_key(id) {
            assert(crate::transaction_records::authentic((id,map@[id]),&identify));
        }
        assert forall|i:int| 0 <= i < rows.len() && #[trigger] rows@[i].0 == id implies rows@[i].1 == *r by {
            assert(map@.contains_key(rows@[i].0));
        }
    } }
    result
}

/// The checkpoint returned by admission must belong to the same engine.
fn seal_admission<F:Fn(&[u8;32])->crate::ObjectId>(bound:Option<u64>,current:u64,
    rows:&[(crate::ObjectId,[u8;32])],mut checkpoint:Option<u64>,identify:F)
    -> (out:Result<Option<u64>,(crate::ObjectId,crate::ObjectId)>)
    requires forall|r:&[u8;32]| #[trigger] identify.requires((r,)),
        forall|r:&[u8;32],id:crate::ObjectId| #[trigger] identify.ensures((r,),id) ==> id.digest() == r@,
    ensures if bound == Some(current) {out == Ok(checkpoint)}
        else {match out {
            Ok(result) => result.is_none() && forall|i:int| 0 <= i < rows.len() ==> #[trigger] rows@[i].0.digest() == rows@[i].1@,
            Err((name,computed)) => name.digest() != computed.digest() &&
                exists|i:int| 0 <= i < rows.len() && #[trigger] rows@[i].0 == name && rows@[i].1@ == computed.digest(),
        }},
{
    let proof_value = match bound {
        Some(owner) => crate::transaction_records::IdentityProof::Engine(owner),
        None => crate::transaction_records::IdentityProof::Untrusted,
    };
    let matches = |a:&u64,b:&u64| -> (out:bool) ensures out == (*a == *b) {*a == *b};
    let admission = proof_value.admit(&current,matches,rows,identify)?;
    if let crate::transaction_records::Admission::Rechecked = admission {
        assert forall|i:int| 0 <= i < rows.len() implies #[trigger] rows@[i].0.digest() == rows@[i].1@ by {
            assert(crate::transaction_records::authentic(rows@[i],identify));
        }
    }
    Ok(admission.take_checkpoint(&mut checkpoint))
}

/// Staging returns the identity of its input and retains the original map on collision.
fn staged_record(map:&mut BTreeMap<u64,u64>,value:u64) -> (out:Result<u64,u64>)
    requires btree_map_inv(old(map)),
    ensures if old(map)@.contains_key(value) && old(map)@[value] != value {
        out == Err(value) && final(map)@ == old(map)@
    } else {out == Ok(value) && final(map)@ == old(map)@.insert(value,value)},
{
    let (id,r) = crate::transaction_records::identify(value,|r:&u64| -> (id:u64) ensures id == *r {*r});
    crate::transaction_records::insert(map,id,r)
}

/// Isolate row ordering with the identity function on 32-byte payloads.
/// A rejection names the first row whose declared digest differs from its payload.
fn supplied_names(rows:&[(crate::ObjectId,[u8;32])])
    -> (out:Result<(),(crate::ObjectId,crate::ObjectId)>)
    ensures match out {
        Ok(()) => forall|i:int| 0 <= i < rows.len() ==> #[trigger] rows@[i].0.digest() == rows@[i].1@,
        Err((name,computed)) => exists|i:int| 0 <= i < rows.len() && #[trigger] rows@[i].0 == name &&
            rows@[i].1@ == computed.digest() && name.digest() != computed.digest() &&
            forall|j:int| 0 <= j < i ==> #[trigger] rows@[j].0.digest() == rows@[j].1@,
    },
{
    let identify = |data:&[u8;32]| -> (id:crate::ObjectId) ensures id.digest() == data@ {crate::ObjectId::new(*data)};
    let out = crate::transaction_records::check_transaction(rows,identify);
    proof {
        if let Err((name,computed)) = out {
            let i = choose|i:int| 0 <= i < rows.len() && name == rows@[i].0 &&
                #[trigger] identify.ensures((&rows@[i].1,),computed) && computed.digest() != name.digest() &&
                forall|j:int| 0 <= j < i ==> #[trigger] crate::transaction_records::authentic(rows@[j],identify);
            assert forall|j:int| 0 <= j < i implies #[trigger] rows@[j].0.digest() == rows@[j].1@ by {
                assert(crate::transaction_records::authentic(rows@[j],identify));
            }
        } else {
            assert forall|i:int| 0 <= i < rows.len() implies #[trigger] rows@[i].0.digest() == rows@[i].1@ by {
                assert(crate::transaction_records::authentic(rows@[i],identify));
            }
        }
    }
    out
}

/// Overlapping keys must obey transaction precedence. The physical reader
/// receives both the requested id and its own index entry, including on failure.
fn layered_read(id:u64,incoming:&BTreeMap<u64,u32>,pending:Option<&BTreeMap<u64,u16>>,
    index:&BTreeMap<u64,u64>,disk_ok:bool) -> (out:Result<(u64,u64),(u64,Option<u64>)>)
    requires btree_map_inv(incoming), btree_map_inv(index),
        pending matches Some(table) ==> btree_map_inv(table),
    ensures if incoming@.contains_key(id) {out == Ok((1,incoming@[id] as u64))}
        else if pending matches Some(table) && table@.contains_key(id) {out == Ok((2,pending.unwrap()@[id] as u64))}
        else if index@.contains_key(id) {
            out == if disk_ok {Ok((id,index@[id]))} else {Err((id,Some(index@[id])))}
        } else {out == Err((id,None))},
{
    crate::closure_load::load(id,&crate::closure_load::Layers {incoming,pending,index},
        |v:&u32| -> (r:(u64,u64)) ensures r == (1,*v as u64) {(1,u64::from(*v))},
        |v:&u16| -> (r:(u64,u64)) ensures r == (2,*v as u64) {(2,u64::from(*v))},
        |key:u64,loc:&u64| -> (r:Result<(u64,u64),(u64,Option<u64>)>)
            ensures r == if disk_ok {Ok((key,*loc))} else {Err((key,Some(*loc)))} {
            if disk_ok {Ok((key,*loc))} else {Err((key,Some(*loc)))}
        },
        |key:u64| -> (e:(u64,Option<u64>)) ensures e == (key,None) {(key,None)})
}

use crate::reference_kind::ReferenceKind;
struct Reference {kind:ReferenceKind,id:u64}

impl Edge<u64> for Reference {
    closed spec fn target(&self) -> Option<u64> {
        if self.kind is Owns {Some(self.id)} else {None}
    }
    fn owned_target(&self) -> Option<u64> {
        self.kind.owned_target(self.id)
    }
}

struct Records { records:BTreeMap<u64,Vec<Reference>>,commits:BTreeSet<u64> }

impl Source<u64> for Records {
    type Error = ();

    closed spec fn valid(&self) -> bool {btree_map_inv(&self.records) && btree_set_inv(&self.commits)}
    closed spec fn edges(&self) -> Map<u64,Set<u64>> {
        self.records@.map_values(|refs:Vec<Reference>| walk::children(refs@))
    }
    closed spec fn failed(graph:Map<u64,Set<u64>>,id:u64,_:()) -> bool { !graph.contains_key(id) }

    closed spec fn commit(&self,root:u64) -> bool { self.records@.contains_key(root) && self.commits@.contains(root) }
    closed spec fn root_failed(&self,root:u64,_:()) -> bool { !self.commit(root) }

    fn check_root(&mut self,root:u64) -> Result<(),()> {
        if self.records.contains_key(&root) && self.commits.contains(&root) {Ok(())} else {Err(())}
    }

    fn expand(&mut self,id:u64,stack:&mut Vec<Work<u64>>) -> Result<(),()> {
        let Some(refs) = self.records.get(&id) else {return Err(());};
        walk::schedule(refs.as_slice(),stack);
        Ok(())
    }
}

/// Any finite map with all records present along the uncached owning paths
/// and a descending order on those paths must succeed. Cached children may
/// be absent from the map, and unrelated records may be missing or cyclic.
fn complete(records:&mut Records,cached:&BTreeSet<u64>,root:u64,
    Ghost(domain):Ghost<Set<u64>>,Ghost(rank):Ghost<Map<u64,nat>>)
    -> (out:Result<BTreeSet<u64>,Failure<u64,()>>)
    requires old(records).valid(),old(records).commit(root), btree_set_inv(cached),walk::closed(root,cached@,old(records).edges(),domain),
        walk::descending(old(records).edges(),cached@,domain,rank),
        forall|k:u64| domain.contains(k) && !cached@.contains(k) ==> old(records).edges().contains_key(k),
    ensures out matches Ok(seen) && walk::closed(root,cached@,old(records).edges(),seen@) && seen@.subset_of(domain) &&
        (walk::certified(old(records).edges(),cached@) ==> walk::certified(old(records).edges(),cached@.union(seen@))),
{
    proof {
        if cached@.is_empty() {
            assert(walk::certificate(records.edges(),cached@,Map::<u64,nat>::empty()));
            assert(walk::certified(records.edges(),cached@));
        }
    };
    let result = walk::walk(records,cached,root);
    match result {
        Err(Failure::Root(_)) => {assert(false);},
        Err(Failure::Source(id,_)) => {assert(domain.contains(id));assert(false);},
        Err(Failure::Cycle(_)) => {assert(false);},
        Ok(_) => {},
    }
    result
}

/// A commit with an uncached owning reference back to itself cannot pass.
/// The cached case still requires a present commit and returns precisely it.
fn self_reference(cached_root:bool) {
    let root = 7u64;
    let mut records = Records {records:BTreeMap::new(),commits:BTreeSet::new()};
    records.records.insert(root,vec![Reference {kind:ReferenceKind::Evidence,id:99},Reference {kind:ReferenceKind::Owns,id:root}]);
    records.commits.insert(root);
    let mut cached = BTreeSet::new();
    if cached_root {cached.insert(root);}
    let ghost graph = records.edges();
    assert(graph[root] =~= set![root]) by {
        let refs = records.records@[root]@;
        assert(refs.skip(1).skip(1).len() == 0);
        reveal_with_fuel(walk::children,3);
    }
    let ghost single = set![root];
    proof {assert(walk::closed(root,cached@,graph,single));}
    let result = walk::walk(&mut records,&cached,root);
    match result {
        Ok(seen) => {
            assert(seen@ =~= single);
            if !cached_root {
                let ghost d = choose|d:Map<u64,nat>| d.dom() == seen@.difference(cached@) && #[trigger] walk::ranked(graph,cached@,d);
                assert(d.contains_key(root));
                assert(d[root] < d[root]);
                assert(false);
            }
        },
        Err(Failure::Cycle(_)) => {
            if cached_root {
                let ghost rank = Map::<u64,nat>::empty();
                assert(walk::descending(graph,cached@,single,rank));
                assert(false);
            }
        },
        Err(Failure::Source(id,_)) => {assert(single.contains(id));assert(false);},
        Err(Failure::Root(_)) => {assert(false);},
    }
}

/// The reachable cycle is below the Commit. Its diagnostic must identify
/// the child on that cycle; the Commit itself has no incoming edge.
fn descendant_cycle() {
    let root = 1u64;
    let child = 2u64;
    let mut records = Records {records:BTreeMap::new(),commits:BTreeSet::new()};
    records.records.insert(root,vec![Reference {kind:ReferenceKind::Owns,id:child}]);
    records.records.insert(child,vec![Reference {kind:ReferenceKind::Owns,id:child}]);
    records.commits.insert(root);
    let cached = BTreeSet::new();
    let ghost graph = records.edges();
    proof {
        reveal_with_fuel(walk::children,2);
        assert(graph[root] =~= set![child]); assert(graph[child] =~= set![child]);
        assert(graph.dom() =~= set![root,child]);
        assert(walk::closed(root,cached@,graph,graph.dom()));
    }
    match walk::walk(&mut records,&cached,root) {
        Ok(seen) => {
            assert(seen@.contains(root) && graph[root].contains(child));
            assert(seen@.contains(child));
            let ghost d = choose|d:Map<u64,nat>| d.dom() == seen@.difference(cached@) && #[trigger] walk::ranked(graph,cached@,d);
            assert(d.contains_key(child));
            assert(d[child] < d[child]);
            assert(false);
        },
        Err(Failure::Cycle(k)) => {
            proof {
                let chain = choose|v:Seq<u64>| #[trigger] walk::path(graph,cached@,k,k,v);
                assert(walk::path(graph,cached@,k,k,chain));
                let before = chain.len()-2;
                assert(walk::owning_step(graph,cached@,chain[before],chain[before+1]));
                assert(chain[before+1] == k);
                assert(k == child);
            }
        },
        Err(Failure::Root(_)) => {assert(false);},
        Err(Failure::Source(id,_)) => {assert(graph.dom().contains(id));assert(false);},
    }
}

}
