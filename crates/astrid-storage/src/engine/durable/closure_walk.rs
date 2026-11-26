//! Depth-first validation of the owning edges missing from the validated cache.
use std::collections::{BTreeMap, BTreeSet};
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::{btree_map_inv, btree_set_inv},
};

verus! {

#[derive(Clone,Copy)]
pub(super) enum Work<K> { Visit(K), Finish(K) }

pub(super) enum Failure<K,E> { Root(E), Cycle(K), Source(K,E) }

pub(super) trait Edge<K> {
    spec fn target(&self) -> Option<K>;
    fn owned_target(&self) -> (out:Option<K>) ensures out == self.target();
}

pub(super) open spec fn children<K,R:Edge<K>>(refs:Seq<R>) -> Set<K>
    decreases refs.len(),
{
    if refs.len() == 0 {Set::empty()} else {
        let rest = children(refs.skip(1));
        match refs.first().target() {Some(k) => rest.insert(k),None => rest}
    }
}

/// Select only owning references. Iterating backwards preserves canonical
/// visitation order on the LIFO worklist, including repeated references.
pub(super) fn schedule<K:Copy,R:Edge<K>>(refs:&[R],stack:&mut Vec<Work<K>>)
    ensures scheduled(old(stack)@,final(stack)@,children(refs@)),
        final(stack)@ == old(stack)@ + reversed_visits(refs@),
{
    let mut pos = refs.len();
    while pos > 0
        invariant pos <= refs.len(), stack@ == old(stack)@ + reversed_visits(refs@.skip(pos as int)),
            scheduled(old(stack)@,stack@,children(refs@.skip(pos as int))),
        decreases pos,
    {
        pos = pos.saturating_sub(1);
        let ghost suffix = refs@.skip(pos as int);
        assert(suffix.first() == refs@[pos as int]);
        assert(suffix.skip(1) =~= refs@.skip(pos as int + 1));
        let ghost previous = stack@;
        if let Some(k) = refs[pos].owned_target() { stack.push(Work::Visit(k)); }
        proof {
            assert forall|k:K| #[trigger] children(suffix).contains(k) implies exists|j:int|
                old(stack).len() <= j < stack.len() && #[trigger] stack@[j] == Work::Visit(k) by {
                if suffix.first().target() == Some(k) {assert(stack@[previous.len() as int] == Work::Visit(k));}
                else {
                    let i = choose|i:int| old(stack).len() <= i < previous.len() && #[trigger] previous[i] == Work::Visit(k);
                    assert(stack@[i] == previous[i]);
                }
            }
        };
    }
    assert(refs@.skip(0) =~= refs@);
}

pub(super) open spec fn reversed_visits<K,R:Edge<K>>(refs:Seq<R>) -> Seq<Work<K>>
    decreases refs.len(),
{
    if refs.len() == 0 {Seq::empty()} else {
        let rest = reversed_visits(refs.skip(1));
        match refs.first().target() {Some(k) => rest.push(Work::Visit(k)), None => rest}
    }
}

pub(super) trait Source<K> {
    type Error;
    spec fn valid(&self) -> bool;
    spec fn edges(&self) -> Map<K,Set<K>>;
    spec fn failed(graph:Map<K,Set<K>>,id:K,error:Self::Error) -> bool;

    spec fn commit(&self,root:K) -> bool;
    spec fn root_failed(&self,root:K,error:Self::Error) -> bool;

    fn check_root(&mut self,root:K) -> (r:Result<(),Self::Error>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).edges() == old(self).edges(),
            r.is_ok() ==> old(self).commit(root),
            r matches Err(e) ==> old(self).root_failed(root,e);

    /// Append visits for the selected record's owning references, in reverse
    /// record order so that the next pop visits the first owning reference.
    fn expand(&mut self,id:K,stack:&mut Vec<Work<K>>) -> (r:Result<(),Self::Error>)
        requires old(self).valid(),
        ensures final(self).valid(), r matches Err(e) ==> Self::failed(old(self).edges(),id,e),
            final(self).edges() == old(self).edges(),
            r.is_ok() ==> old(self).edges().contains_key(id) &&
                scheduled(old(stack)@,final(stack)@,old(self).edges()[id]);
}

pub(super) open spec fn scheduled<K>(before:Seq<Work<K>>,after:Seq<Work<K>>,edges:Set<K>) -> bool {
    &&& before.len() <= after.len()
    &&& forall|i:int| 0 <= i < before.len() ==> #[trigger] after[i] == before[i]
    &&& forall|i:int| before.len() <= i < after.len() ==> (#[trigger] after[i] matches Work::Visit(k) && edges.contains(k))
    &&& forall|k:K| #[trigger] edges.contains(k) ==> exists|i:int| before.len() <= i < after.len() && #[trigger] after[i] == Work::Visit(k)
}

pub(super) open spec fn closed<K>(root:K,cached:Set<K>,graph:Map<K,Set<K>>,nodes:Set<K>) -> bool {
    &&& nodes.contains(root)
    &&& forall|p:K,k:K| nodes.contains(p) && !cached.contains(p) && graph.contains_key(p) &&
        #[trigger] graph[p].contains(k) ==> nodes.contains(k)
}

pub(super) open spec fn needed<K>(root:K,cached:Set<K>,graph:Map<K,Set<K>>,seen:Set<K>,k:K) -> bool {
    k == root || exists|p:K| seen.contains(p) && !cached.contains(p) && graph.contains_key(p) && #[trigger] graph[p].contains(k)
}

spec fn depends<K>(work:Work<K>,graph:Map<K,Set<K>>,k:K) -> bool {
    work matches Work::Finish(p) && graph[p].contains(k)
}

spec fn queued<K>(work:Seq<Work<K>>,from:int,id:K) -> bool {
    exists|j:int| from <= j < work.len() && (#[trigger] work[j] == Work::Visit(id) || work[j] == Work::Finish(id))
}

/// Removing cached subgraphs, each owning edge leads to a strictly lower
/// completion rank. A reachable uncached cycle cannot satisfy this condition.
pub(super) open spec fn ranked<K>(graph:Map<K,Set<K>>,cached:Set<K>,done:Map<K,nat>) -> bool {
    forall|p:K,k:K| done.contains_key(p) && #[trigger] graph[p].contains(k) && !cached.contains(k)
        ==> done.contains_key(k) && done[k] < done[p]
}

/// An established cache contains only present records, owns its entire
/// subgraph, and has a finite descending order for every owning edge.
pub(super) open spec fn certificate<K>(graph:Map<K,Set<K>>,cache:Set<K>,rank:Map<K,nat>) -> bool {
    &&& rank.dom() == cache
    &&& cache.subset_of(graph.dom())
    &&& ranked(graph,Set::empty(),rank)
    &&& forall|k:K| #[trigger] cache.contains(k) ==> rank[k] < cache.len()
}

pub(super) open spec fn certified<K>(graph:Map<K,Set<K>>,cache:Set<K>) -> bool {
    exists|r:Map<K,nat>| #[trigger] certificate(graph,cache,r)
}

proof fn combine<K>(root:K,graph:Map<K,Set<K>>,cache:Set<K>,seen:Set<K>,old_rank:Map<K,nat>,done:Map<K,nat>)
    requires certificate(graph,cache,old_rank), closed(root,cache,graph,seen),
        done.dom() == seen.difference(cache), ranked(graph,cache,done),
        done.dom().subset_of(graph.dom()),
        forall|k:K| #[trigger] done.contains_key(k) ==> done[k] < done.dom().len(),
    ensures exists|r:Map<K,nat>| #[trigger] certificate(graph,cache.union(seen),r),
{
    let all = cache.union(seen);
    let r = Map::new(all,|k:K| if cache.contains(k) {old_rank[k]} else {cache.len()+done[k]});
    assert(all =~= cache.union(done.dom()));
    assert(cache.disjoint(done.dom()));
    assert(cache.intersect(done.dom()) =~= Set::empty());
    vstd::set_lib::lemma_set_intersect_union_lens(cache,done.dom());
    assert(all.len() == cache.len()+done.dom().len());
    assert forall|p:K,k:K| r.contains_key(p) && #[trigger] graph[p].contains(k) && !Set::<K>::empty().contains(k)
        implies r.contains_key(k) && r[k] < r[p] by {
        if cache.contains(p) {assert(old_rank.contains_key(p));assert(old_rank.contains_key(k));}
        else if !cache.contains(k) {assert(done.contains_key(p));assert(done.contains_key(k));}
    }
    assert(certificate(graph,all,r));
}

pub(super) open spec fn descending<K>(graph:Map<K,Set<K>>,cache:Set<K>,domain:Set<K>,rank:Map<K,nat>) -> bool {
    forall|p:K,k:K| domain.contains(p) && !cache.contains(p) && !cache.contains(k) &&
        graph.contains_key(p) && #[trigger] graph[p].contains(k) ==> rank[k] < rank[p]
}

spec fn below<K>(older:Work<K>,younger:Work<K>,cache:Set<K>,rank:Map<K,nat>) -> bool {
    match (older,younger) {
        (Work::Finish(p),Work::Visit(k)) | (Work::Finish(p),Work::Finish(k)) =>
            cache.contains(k) || rank[k] < rank[p],
        _ => true,
    }
}

#[derive(Clone, Copy)]
enum Mark { Active, Finished }

#[allow(clippy::too_many_lines, reason = "loop invariants and erased proofs accompany the traversal they establish")]
pub(super) fn walk<K:Ord+Copy,S:Source<K>>(source:&mut S,cached:&BTreeSet<K>,root:K)
    -> (out:Result<BTreeSet<K>,Failure<K,S::Error>>)
    requires old(source).valid(), obeys_cmp::<K>(), obeys_cmp_concrete_eq::<K>(), btree_set_inv(cached),
    ensures final(source).edges() == old(source).edges(),
        out matches Err(Failure::Root(e)) ==> old(source).root_failed(root,e),
        out matches Err(Failure::Cycle(k)) ==> !cached@.contains(k) &&
            (forall|nodes:Set<K>,rank:Map<K,nat>| closed(root,cached@,old(source).edges(),nodes) ==>
                ! #[trigger] descending(old(source).edges(),cached@,nodes,rank)),
        out matches Err(Failure::Source(k,e)) ==> S::failed(old(source).edges(),k,e) && !cached@.contains(k) &&
            (forall|nodes:Set<K>| #[trigger] closed(root,cached@,old(source).edges(),nodes) ==> nodes.contains(k)),
        out matches Ok(seen) ==> {
            &&& old(source).commit(root)
            &&& (certified(old(source).edges(),cached@) ==> certified(old(source).edges(),cached@.union(seen@)))
            &&& btree_set_inv(&seen)
            &&& exists|done:Map<K,nat>| done.dom() == seen@.difference(cached@) && #[trigger] ranked(old(source).edges(),cached@,done)
            &&& closed(root,cached@,old(source).edges(),seen@)
            &&& forall|nodes:Set<K>| #[trigger] closed(root,cached@,old(source).edges(),nodes) ==> seen@.subset_of(nodes)
            &&& forall|k:K| seen@.contains(k) && !cached@.contains(k) ==> old(source).edges().contains_key(k)
        },
{
    let ghost graph = source.edges();
    if let Err(e) = source.check_root(root) {return Err(Failure::Root(e));}
    let mut seen = BTreeSet::new();
    let mut marks = BTreeMap::<K,Mark>::new();
    let ghost mut done = Map::<K,nat>::empty();
    let mut stack = vec![Work::Visit(root)];
    while !stack.is_empty()
        invariant
            obeys_cmp::<K>(), obeys_cmp_concrete_eq::<K>(), graph == old(source).edges(),
            old(source).commit(root), source.valid(), source.edges() == graph, btree_set_inv(cached),
            btree_map_inv(&marks), btree_set_inv(&seen),
            marks@.dom().subset_of(graph.dom()), marks@.dom().subset_of(seen@),
            forall|nodes:Set<K>,rank:Map<K,nat>| closed(root,cached@,graph,nodes) && #[trigger] descending(graph,cached@,nodes,rank) ==>
                (forall|i:int,j:int| 0 <= i < j < stack.len() ==> #[trigger] below(stack@[i],stack@[j],cached@,rank)),
            done.dom().subset_of(marks@.dom()), ranked(graph,cached@,done),
            forall|k:K| marks@.contains_key(k) ==> !(#[trigger] cached@.contains(k)) &&
                (done.contains_key(k) == (marks@[k] is Finished)),
            forall|k:K| #[trigger] done.contains_key(k) ==> done[k] < done.dom().len(),
            forall|i:int,j:int| 0 <= i <= j < stack.len() && (#[trigger] stack@[i] is Finish) &&
                #[trigger] stack@[j] == stack@[i] ==> i == j,
            forall|i:int,k:K| 0 <= i < stack.len() && #[trigger] depends(stack@[i],graph,k) ==> cached@.contains(k) || done.contains_key(k) || queued(stack@,i+1,k),
            forall|k:K| marks@.contains_key(k) && (marks@[k] is Active) ==> stack@.contains(Work::Finish(k)),
            forall|k:K| seen@.contains(k) && !cached@.contains(k) ==> marks@.contains_key(k),
            forall|k:K| #[trigger] needed(root,cached@,graph,seen@,k) ==> seen@.contains(k) || stack@.contains(Work::Visit(k)),
            forall|nodes:Set<K>| #[trigger] closed(root,cached@,graph,nodes) ==> seen@.subset_of(nodes) &&
                (forall|i:int| 0 <= i < stack.len() ==> (#[trigger] stack@[i] matches Work::Visit(k) ==> nodes.contains(k))),
            forall|i:int| 0 <= i < stack.len() ==> (#[trigger] stack@[i] matches Work::Finish(k) ==> marks@.contains_key(k) && (marks@[k] is Active)),
        decreases graph.dom().len() - marks@.dom().len(), stack.len(),
    {
        let ghost pending = stack@;
        let ghost prev = seen@;
        let ghost previously_done = done;
        let ghost known = marks@.dom();
        proof {vstd::set_lib::lemma_len_subset(known,graph.dom());}
        #[expect(clippy::unwrap_used, reason = "the loop guard and verifier establish a nonempty stack")]
        let work = stack.pop().unwrap();
        let id = match work {
            Work::Visit(k) | Work::Finish(k) => k,
        };
        proof {
            assert forall|k:K| #[trigger] needed(root,cached@,graph,prev,k) && !prev.contains(k) && k != id
                implies stack@.contains(Work::Visit(k)) by {
                let j = choose|j:int| 0 <= j < pending.len() && pending[j] == Work::Visit(k);
                assert(stack@[j] == pending[j]);
            }
        };
        if cached.contains(&id) {
            seen.insert(id);
            proof {
                assert forall|k:K| #[trigger] needed(root,cached@,graph,seen@,k) implies needed(root,cached@,graph,prev,k) by {
                    if k != root {
                        let p = choose|p:K| seen@.contains(p) && !cached@.contains(p) && graph.contains_key(p) && #[trigger] graph[p].contains(k);
                        assert(prev.contains(p));
                    }
                }
            };
        } else {
            match work {
                Work::Finish(_) => {
                    proof {
                        assert(pending.last() == Work::Finish(id));
                        assert(!done.contains_key(id)) by {
                            // A finish item was pushed only on the first visit.
                            assert(marks@[id] is Active);
                        }
                        done = done.insert(id,done.dom().len());
                        assert(done.dom() =~= previously_done.dom().insert(id));
                        assert forall|p:K,k:K| done.contains_key(p) && #[trigger] graph[p].contains(k) && !cached@.contains(k)
                            implies done.contains_key(k) && done[k] < done[p] by {
                            if p == id {
                                assert(depends(pending[pending.len()-1],graph,k));
                                assert(!queued(pending,pending.len() as int,k));
                                assert(previously_done.contains_key(k));
                            }
                        }
                    };
                    marks.insert(id,Mark::Finished);
                    assert(marks@.dom() =~= known);
                },
                Work::Visit(_) => match marks.get(&id) {
                    Some(Mark::Finished) => {},
                    Some(Mark::Active) => {
                        proof {
                            let j = choose|j:int| 0 <= j < pending.len() && pending[j] == Work::Finish(id);
                            assert forall|nodes:Set<K>,rank:Map<K,nat>| closed(root,cached@,graph,nodes) implies
                                ! #[trigger] descending(graph,cached@,nodes,rank) by {
                                if descending(graph,cached@,nodes,rank) {
                                    assert(below(pending[j],pending[pending.len()-1],cached@,rank));
                                }
                            }
                        };
                        return Err(Failure::Cycle(id));
                    },
                    None => {
                        let ghost old_marks = marks@.dom();
                        marks.insert(id,Mark::Active);
                        seen.insert(id);
                        stack.push(Work::Finish(id));
                        let ghost prefix = stack@;
                        if let Err(e) = source.expand(id,&mut stack) {
                            assert forall|nodes:Set<K>| #[trigger] closed(root,cached@,graph,nodes) implies nodes.contains(id) by {
                                assert(pending[pending.len()-1] == Work::Visit(id));
                            }
                            assert(S::failed(graph,id,e));
                            return Err(Failure::Source(id,e));
                        }
                        proof {

                            assert forall|nodes:Set<K>,rank:Map<K,nat>| closed(root,cached@,graph,nodes) && #[trigger] descending(graph,cached@,nodes,rank) implies
                                (forall|i:int,j:int| 0 <= i < j < stack.len() ==> #[trigger] below(stack@[i],stack@[j],cached@,rank)) by {
                                assert(nodes.contains(id));
                                let top = pending.len()-1;
                                assert forall|i:int,j:int| 0 <= i < j < stack.len() implies #[trigger] below(stack@[i],stack@[j],cached@,rank) by {
                                    if j < top {
                                        assert(stack@[i] == pending[i] && stack@[j] == pending[j]);
                                    } else if i <= top {
                                        if i < top {
                                            assert(stack@[i] == pending[i]);
                                            assert(below(pending[i],pending[top],cached@,rank));
                                        }
                                        if j > top { if let Work::Visit(k) = stack@[j] {
                                            assert(graph[id].contains(k)); }
                                        }
                                    }
                                }
                            }
                            assert(marks@.dom() =~= old_marks.insert(id));
                            vstd::set_lib::lemma_len_subset(old_marks,graph.dom());
                            assert(marks@.dom().len() == old_marks.len()+1);
                            assert(marks@.dom().subset_of(graph.dom()));
                            vstd::set_lib::lemma_len_subset(marks@.dom(),graph.dom());
                            assert(graph.dom().len()-marks@.dom().len() < graph.dom().len()-known.len());
                            assert forall|j:int| 0 <= j < stack.len() implies (#[trigger] stack@[j] matches Work::Finish(k) ==> marks@.contains_key(k) && (marks@[k] is Active)) by {
                                if j < pending.len()-1 {assert(stack@[j] == pending[j]);}
                                else if j == pending.len()-1 {assert(stack@[j] == Work::Finish(id));}
                            }
                            assert forall|k:K| #[trigger] needed(root,cached@,graph,seen@,k) implies
                                seen@.contains(k) || stack@.contains(Work::Visit(k)) by {
                                if needed(root,cached@,graph,prev,k) && !prev.contains(k) && k != id {
                                    let j = choose|j:int| 0 <= j < pending.len() && pending[j] == Work::Visit(k);
                                    assert(prefix[j] == pending[j]); assert(stack@[j] == prefix[j]);
                                } else if !prev.contains(k) && k != id {
                                    assert(graph[id].contains(k));
                                    let j = choose|j:int| prefix.len() <= j < stack.len() && stack@[j] == Work::Visit(k);
                                }
                            }
                            assert forall|nodes:Set<K>| #[trigger] closed(root,cached@,graph,nodes) implies
                                seen@.subset_of(nodes) && (forall|i:int| 0 <= i < stack.len() ==>
                                (#[trigger] stack@[i] matches Work::Visit(k) ==> nodes.contains(k))) by {
                                assert(nodes.contains(id));
                                assert forall|j:int| 0 <= j < stack.len() implies (#[trigger] stack@[j] matches Work::Visit(k) ==> nodes.contains(k)) by {
                                    if j < pending.len()-1 {assert(stack@[j] == pending[j]);}
                                    else if j == pending.len()-1 {assert(stack@[j] == Work::Finish(id));}
                                    else if let Work::Visit(k) = stack@[j] {assert(graph[id].contains(k));}
                                }
                            }
                        };
                    },
                },
            }
        }
        proof {
            let last = pending.len()-1;
            assert forall|k:K| marks@.contains_key(k) && (marks@[k] is Active) implies stack@.contains(Work::Finish(k)) by {
                if k == id && stack.len() > last {assert(stack@[last] == Work::Finish(k));}
                else {
                    let j = choose|j:int| 0 <= j < pending.len() && pending[j] == Work::Finish(k);
                    assert(j < last);
                    assert(stack@[j] == pending[j]);
                }
            }
            assert forall|i:int,k:K| 0 <= i < stack.len() && #[trigger] depends(stack@[i],graph,k)
                implies cached@.contains(k) || done.contains_key(k) || queued(stack@,i+1,k) by {
                if i >= last {
                    assert(i == last && stack@[i] == Work::Finish(id));
                    let j = choose|j:int| last < j < stack.len() && stack@[j] == Work::Visit(k);
                    assert(queued(stack@,i+1,k));
                } else if !cached@.contains(k) && !done.contains_key(k) {
                    assert(pending[i] == stack@[i]);
                    assert(depends(pending[i],graph,k));
                    assert(queued(pending,i+1,k));
                    let j = choose|j:int| i < j < pending.len() &&
                        (#[trigger] pending[j] == Work::Visit(k) || pending[j] == Work::Finish(k));
                    if j < last {assert(stack@[j] == pending[j]);}
                    else {
                        assert(k == id);
                        assert(stack@[last] == Work::Finish(id));
                    }
                }
            }
        };
    }
    proof {
        assert(needed(root,cached@,graph,seen@,root));
        assert forall|p:K,k:K| seen@.contains(p) && !cached@.contains(p) && graph.contains_key(p) &&
            #[trigger] graph[p].contains(k) implies seen@.contains(k) by {
            assert(needed(root,cached@,graph,seen@,k));
        }
    };
    assert(done.dom() =~= seen@.difference(cached@));
    proof {
        if certified(graph,cached@) {
            let prior = choose|r:Map<K,nat>| #[trigger] certificate(graph,cached@,r);
            combine(root,graph,cached@,seen@,prior,done);
            assert(certified(graph,cached@.union(seen@)));
        }
    };
    assert(ranked(graph,cached@,done));
    assert(exists|order:Map<K,nat>| order.dom() == seen@.difference(cached@) && #[trigger] ranked(graph,cached@,order));
    assert(closed(root,cached@,graph,seen@));
    assert forall|k:K| seen@.contains(k) && !cached@.contains(k) implies graph.contains_key(k) by {
        assert(marks@.contains_key(k));
    }
    Ok(seen)
}

}
