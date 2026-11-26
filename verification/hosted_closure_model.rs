//! Independently consume the production graph traversal and edge scheduler.
use crate::closure_walk::{self as walk, Edge, Failure, Source, Work};
use std::collections::{BTreeMap,BTreeSet};
use vstd::{prelude::*,std_specs::btree::{btree_map_inv,btree_set_inv}};

verus! {

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

}
