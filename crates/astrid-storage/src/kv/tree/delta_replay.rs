//! Apply the verified predecessor walk in chronological order to its selected checkpoint.
#[cfg(verus_keep_ghost)]
use super::delta_batch;
use super::{
    ObjectId,
    checkpoint_totals::NodeTotals,
    delta_chain::Step,
    delta_mutation::Mutation,
    delta_recovery::{self, CounterError},
};
use vstd::prelude::*;

verus! {
pub(super) struct Cursor<S> {
    pub(super) state:S,
    pub(super) totals:NodeTotals,
    pub(super) depth:u64,
    pub(super) bytes:u64,
}

pub(super) enum Error<E> {
    Counter(ObjectId,CounterError),
    Apply(E),
    Totals(ObjectId),
}

pub(super) open spec fn counter<S>(prior:Cursor<S>, row:Step) -> Option<CounterError> {
    let charge = delta_batch::usage(row.mutations@,row.mutations.len() as nat).0;
    let next_depth = if prior.depth < u64::MAX {prior.depth as nat + 1} else {u64::MAX as nat};
    if row.depth != next_depth {Some(CounterError::Disagree)}
    else if charge > u64::MAX {Some(CounterError::RowOverflow)}
    else if prior.bytes as nat + charge > u64::MAX {Some(CounterError::ChainOverflow)}
    else if row.delta_bytes != prior.bytes as nat + charge {Some(CounterError::Disagree)}
    else {None}
}

pub(super) open spec fn applied<S,E,F:Fn(S,Option<ObjectId>,ObjectId,&Vec<Mutation>,NodeTotals)->Result<(S,NodeTotals),E>>(
    tree:Option<ObjectId>,prior:Cursor<S>,row:Step,apply:F,end:Cursor<S>) -> bool {
    &&& end.depth == row.depth && end.bytes == row.delta_bytes && end.totals == row.totals
    &&& counter(prior,row).is_none()
    &&& apply.ensures((prior.state,tree,row.object,&row.mutations,prior.totals),Ok((end.state,end.totals)))
}

pub(super) open spec fn history<S,E,F:Fn(S,Option<ObjectId>,ObjectId,&Vec<Mutation>,NodeTotals)->Result<(S,NodeTotals),E>>(
    initial:S,base:NodeTotals,tree:Option<ObjectId>,rows:Seq<Step>,n:int,apply:F,h:Seq<Cursor<S>>) -> bool {
    &&& 0 <= n <= rows.len() && h.len() == rows.len()-n+1
    &&& h[0] == (Cursor {state:initial,totals:base,depth:0,bytes:0})
    &&& forall|j:int| 0 <= j < h.len()-1 ==> applied(tree,#[trigger] h[j],rows[rows.len()-1-j],apply,h[j+1])
}

pub(super) open spec fn replayed<S,E,F:Fn(S,Option<ObjectId>,ObjectId,&Vec<Mutation>,NodeTotals)->Result<(S,NodeTotals),E>>(
    initial:S,base:NodeTotals,tree:Option<ObjectId>,rows:Seq<Step>,n:int,apply:F,end:Cursor<S>) -> bool {
    exists|h:Seq<Cursor<S>>| #[trigger] history(initial,base,tree,rows,n,apply,h) && h.last() == end
}

pub(super) open spec fn rejected<S,E,F:Fn(S,Option<ObjectId>,ObjectId,&Vec<Mutation>,NodeTotals)->Result<(S,NodeTotals),E>>(
    tree:Option<ObjectId>,prior:Cursor<S>,row:Step,apply:F,error:Error<E>) -> bool {
    let args = (prior.state,tree,row.object,&row.mutations,prior.totals);
    match error {
        Error::Counter(id,c) => id == row.object && counter(prior,row) == Some(c),
        Error::Apply(e) => counter(prior,row).is_none() && apply.ensures(args,Err(e)),
        Error::Totals(id) => id == row.object && counter(prior,row).is_none() &&
            exists|s:S,t:NodeTotals| #[trigger] apply.ensures(args,Ok((s,t))) && t != row.totals,
    }
}

pub(super) open spec fn failed<S,E,F:Fn(S,Option<ObjectId>,ObjectId,&Vec<Mutation>,NodeTotals)->Result<(S,NodeTotals),E>>(
    initial:S,base:NodeTotals,tree:Option<ObjectId>,rows:Seq<Step>,apply:F,error:Error<E>) -> bool {
    exists|i:int,p:Cursor<S>| 0 <= i < rows.len() && #[trigger] rejected(tree,p,rows[i],apply,error) &&
        replayed(initial,base,tree,rows,i+1,apply,p)
}

proof fn fail_at<S,E,F:Fn(S,Option<ObjectId>,ObjectId,&Vec<Mutation>,NodeTotals)->Result<(S,NodeTotals),E>>(
    initial:S,base:NodeTotals,tree:Option<ObjectId>,rows:Seq<Step>,i:int,prior:Cursor<S>,apply:F,error:Error<E>)
    requires 0 <= i < rows.len(), replayed(initial,base,tree,rows,i+1,apply,prior), rejected(tree,prior,rows[i],apply,error),
    ensures failed(initial,base,tree,rows,apply,error),
{}
pub(super) open spec fn preserves<S,E,F:Fn(S,Option<ObjectId>,ObjectId,&Vec<Mutation>,NodeTotals)->Result<(S,NodeTotals),E>>(
    apply:F,valid:spec_fn(S)->bool,
) -> bool {
    &&& forall|s:S,t:Option<ObjectId>,id:ObjectId,r:&Vec<Mutation>,n:NodeTotals|
        valid(s) ==> #[trigger] apply.requires((s,t,id,r,n))
    &&& forall|s:S,t:Option<ObjectId>,id:ObjectId,r:&Vec<Mutation>,n:NodeTotals,next:S,m:NodeTotals|
        valid(s) && #[trigger] apply.ensures((s,t,id,r,n),Ok((next,m))) ==> valid(next)
}

pub(super) fn run<S,E,F:Fn(S,Option<ObjectId>,ObjectId,&Vec<Mutation>,NodeTotals)->Result<(S,NodeTotals),E>>(
    initial:S,base:NodeTotals,tree:Option<ObjectId>,input:Vec<Step>,apply:F,Ghost(valid):Ghost<spec_fn(S)->bool>) -> (out:Result<Cursor<S>,Error<E>>)
    requires valid(initial),preserves(apply,valid),
    ensures
        out matches Ok(c) ==> replayed(initial,base,tree,input@,0,apply,c),
        out matches Err(e) ==> failed(initial,base,tree,input@,apply,e),
{
    let ghost all = input@;
    let mut rows = input;
    let mut cursor = Cursor {state:initial,totals:base,depth:0,bytes:0};
    let ghost mut h = seq![cursor];
    loop
        invariant all == input@,valid(cursor.state),preserves(apply,valid),
            rows@ == all.take(rows.len() as int), rows.len() <= all.len(),
            history(initial,base,tree,all,rows.len() as int,apply,h), h.last() == cursor,
        decreases rows.len(),
    {
        let Some(row) = rows.pop() else {
            assert(history(initial,base,tree,all,0,apply,h));
            assert(replayed(initial,base,tree,all,0,apply,cursor));
            return Ok(cursor);
        };
        let ghost prior = cursor;

        let ghost i = rows.len() as int;
        assert(row == all[i] && rows@ =~= all.take(i));
        assert(replayed(initial,base,tree,all,i+1,apply,prior));
        if let Err(e) = delta_recovery::counters(cursor.depth,cursor.bytes,row.depth,row.delta_bytes,&row.mutations) {
            let error = Error::Counter(row.object,e);
            proof {fail_at(initial,base,tree,all,i,prior,apply,error);}
            return Err(error);
        }
        let (state,totals) = match apply(cursor.state,tree,row.object,&row.mutations,cursor.totals) {
            Ok(v) => v,
            Err(e) => {
                let error = Error::Apply(e);
                proof {fail_at(initial,base,tree,all,i,prior,apply,error);}
                return Err(error);
            },
        };
        if totals.entries != row.totals.entries || totals.logical_bytes != row.totals.logical_bytes ||
            totals.quota_bytes != row.totals.quota_bytes {
            let error = Error::Totals(row.object);
            proof {fail_at(initial,base,tree,all,i,prior,apply,error);}
            return Err(error);
        }
        cursor = Cursor {state,totals,depth:row.depth,bytes:row.delta_bytes};
        proof {
            let next = h.push(cursor);
            assert forall|j:int| 0 <= j < next.len()-1 implies
                #[trigger] applied(tree,next[j],all[all.len()-1-j],apply,next[j+1]) by {
                if j < h.len()-1 {assert(applied(tree,h[j],all[all.len()-1-j],apply,h[j+1]));}
            }
            h = next;
        };
    }
}
}
