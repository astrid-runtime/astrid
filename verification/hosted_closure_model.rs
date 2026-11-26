//! Independently consume the production graph traversal and edge scheduler.
use crate::closure_walk::{self as walk, Edge, Failure, Source, Work};
use std::collections::{BTreeMap,BTreeSet};
use vstd::{prelude::*,std_specs::btree::{btree_map_inv,btree_set_inv}};

verus! {

/// An unsealed batch can enter preparation only when every supplied name
/// matches the identity of its own record. A rejection names the first bad row.
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
    let out = crate::closure_load::check_transaction(rows,identify);
    proof {
        if let Err((name,computed)) = out {
            let i = choose|i:int| 0 <= i < rows.len() && name == rows@[i].0 &&
                #[trigger] identify.ensures((&rows@[i].1,),computed) && computed.digest() != name.digest() &&
                forall|j:int| 0 <= j < i ==> #[trigger] crate::closure_load::authentic(rows@[j],identify);
            assert forall|j:int| 0 <= j < i implies #[trigger] rows@[j].0.digest() == rows@[j].1@ by {
                assert(crate::closure_load::authentic(rows@[j],identify));
            }
        } else {
            assert forall|i:int| 0 <= i < rows.len() implies #[trigger] rows@[i].0.digest() == rows@[i].1@ by {
                assert(crate::closure_load::authentic(rows@[i],identify));
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
