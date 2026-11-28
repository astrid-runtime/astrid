//! Follow KV predecessor edges under the same principal, from newest delta to checkpoint.
use super::{ObjectId, checkpoint_totals::NodeTotals, delta_mutation::Mutation};
use std::collections::BTreeSet;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_set_inv,
};

verus! {
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Head {
    Checkpoint {
        tree: Option<ObjectId>,
        totals: NodeTotals,
    },
    Delta {
        previous: Option<ObjectId>,
        depth: u64,
        delta_bytes: u64,
        mutations: Vec<Mutation>,
        totals: NodeTotals,
    },
}

pub(super) struct Step {
    pub(super) object:ObjectId,
    pub(super) depth:u64,
    pub(super) delta_bytes:u64,
    pub(super) mutations:Vec<Mutation>,
    pub(super) totals:NodeTotals,
}

pub(super) struct Chain {
    pub(super) newest_first:Vec<Step>,
    pub(super) tree:Option<ObjectId>,
    pub(super) totals:NodeTotals,
}

pub(super) enum Error<E> { Cycle(ObjectId), Source(E) }

pub(super) open spec fn ids(steps:Seq<Step>) -> Seq<ObjectId> {steps.map(|i:int,r:Step| r.object)}

pub(super) open spec fn follows<P,E,L:Fn(&P,ObjectId)->Result<Head,E>>(owner:&P,head:ObjectId,
    steps:Seq<Step>,next:Option<ObjectId>,read:L) -> bool
    decreases steps.len(),
{
    if steps.len() == 0 {next == Some(head)}
    else {
        let r = steps.last();
        &&& !ids(steps.drop_last()).contains(r.object)
        &&& follows(owner,head,steps.drop_last(),Some(r.object),read)
        &&& read.ensures((owner,r.object),Ok(Head::Delta {previous:next,depth:r.depth,delta_bytes:r.delta_bytes,mutations:r.mutations,totals:r.totals}))
    }
}

/// Every returned row is the result of reading its address under the original owner.
pub(super) proof fn at<P,E,L:Fn(&P,ObjectId)->Result<Head,E>>(owner:&P,head:ObjectId,
    steps:Seq<Step>,end:Option<ObjectId>,read:L,i:int)
    requires follows(owner,head,steps,end,read),0 <= i < steps.len(),
    ensures steps[0].object == head, ids(steps).no_duplicates(), {
        let r = steps[i];
        let next = if i+1 < steps.len() {Some(steps[i+1].object)} else {end};
        read.ensures((owner,r.object),Ok(Head::Delta {previous:next,depth:r.depth,delta_bytes:r.delta_bytes,
            mutations:r.mutations,totals:r.totals}))
    },
    decreases steps.len(),
{
    let prior = steps.drop_last();
    if prior.len() != 0 {
        at(owner,head,prior,Some(steps.last().object),read,if i < prior.len() {i} else {0});
        assert(prior[0] == steps[0]);
        if i < prior.len() {assert(prior[i] == steps[i]);}
    } else {
        reveal_with_fuel(follows,2);
        assert(steps[0] == steps.last() && Some(steps.last().object) == Some(head));
    }
    assert(ids(steps) =~= ids(prior).push(steps.last().object));
    assert forall|j:int,k:int| 0 <= j < k < steps.len() implies ids(steps)[j] != ids(steps)[k] by {
        if k == prior.len() {assert(ids(prior).contains(ids(prior)[j]));}
    }
}

pub(super) open spec fn zero(t:NodeTotals) -> bool {
    t.entries == 0 && t.logical_bytes == 0 && t.quota_bytes == 0
}

pub(super) open spec fn complete<P,E,L:Fn(&P,ObjectId)->Result<Head,E>>(owner:&P,head:ObjectId,c:Chain,end:Option<ObjectId>,read:L) -> bool {
    follows(owner,head,c.newest_first@,end,read) && match end {
        Some(id) => !ids(c.newest_first@).contains(id) &&
            read.ensures((owner,id),Ok(Head::Checkpoint {tree:c.tree,totals:c.totals})),
        None => c.tree.is_none() && zero(c.totals),
    }
}

pub(super) open spec fn stopped<P,E,L:Fn(&P,ObjectId)->Result<Head,E>>(owner:&P,head:ObjectId,steps:Seq<Step>,
    id:ObjectId,read:L,e:Error<E>) -> bool {
    follows(owner,head,steps,Some(id),read) && match e {
        Error::Cycle(k)=>k == id && ids(steps).contains(id),
        Error::Source(cause)=>!ids(steps).contains(id) && read.ensures((owner,id),Err(cause)),
    }
}

proof fn extend<P,E,L:Fn(&P,ObjectId)->Result<Head,E>>(owner:&P,head:ObjectId,steps:Seq<Step>,r:Step,prev:Option<ObjectId>,read:L)
    requires follows(owner,head,steps,Some(r.object),read),!ids(steps).contains(r.object),
        read.ensures((owner,r.object),Ok(Head::Delta {previous:prev,depth:r.depth,delta_bytes:r.delta_bytes,mutations:r.mutations,totals:r.totals})),
    ensures follows(owner,head,steps.push(r),prev,read),ids(steps.push(r)).to_set() == ids(steps).to_set().insert(r.object),
{
    assert(steps.push(r).drop_last() =~= steps);
    assert(ids(steps.push(r)) =~= ids(steps).push(r.object));
    ids(steps).lemma_push_to_set_commute(r.object);
}

#[verifier::rlimit(35)]
pub(super) fn walk<P,E,L:Fn(&P,ObjectId)->Result<Head,E>>(owner:&P,head:ObjectId,read:L)
    -> (out:Result<Chain,Error<E>>)
    requires obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|p:&P,id:ObjectId| #[trigger] read.requires((p,id)),
    ensures match out {
        Ok(c) => exists|end:Option<ObjectId>| #[trigger] complete(owner,head,c,end,read),
        Err(e) => exists|steps:Seq<Step>,id:ObjectId| #[trigger] stopped(owner,head,steps,id,read,e),
    },
{
    let mut steps = Vec::<Step>::new();
    let mut seen = BTreeSet::new();
    let mut id = head;
    assert(follows(owner,head,steps@,Some(id),read));
    loop
        invariant steps.len() <= usize::MAX, obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),btree_set_inv(&seen),
            seen@ == ids(steps@).to_set(), follows(owner,head,steps@,Some(id),read),
            forall|p:&P,k:ObjectId| #[trigger] read.requires((p,k)),
        decreases usize::MAX - steps.len(),
    {
        let ghost old_steps = steps@;
        if !seen.insert(id) {
            assert(ids(steps@).contains(id));
            assert(stopped(owner,head,steps@,id,read,Error::<E>::Cycle(id)));
            return Err(Error::Cycle(id));
        }
        assert(!ids(steps@).contains(id));
        let decoded = match read(owner,id) {Ok(h)=>h,Err(e)=>{assert(stopped(owner,head,steps@,id,read,Error::Source(e))); return Err(Error::Source(e));}};
        match decoded {
            Head::Checkpoint {tree,totals} => {let c = Chain {newest_first:steps,tree,totals}; assert(complete(owner,head,c,Some(id),read)); return Ok(c);},
            Head::Delta {previous,depth,delta_bytes,mutations,totals} => {
                let step = Step {object:id,depth,delta_bytes,mutations,totals};
                proof {extend(owner,head,old_steps,step,previous,read);}
                steps.push(step);
                if let Some(next) = previous {
                    id = next;
                } else {
                    let c = Chain {newest_first:steps,tree:None,totals:NodeTotals {entries:0,logical_bytes:0,quota_bytes:0}};
                    assert(complete(owner,head,c,None,read));
                    return Ok(c);
                }
            },
        }
    }
}
}
