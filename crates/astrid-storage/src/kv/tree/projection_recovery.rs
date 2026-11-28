//! Bind the cold projection to the owner-addressed chain and the completed replay.
use super::{
    ObjectId, checkpoint_replay,
    checkpoint_totals::NodeTotals,
    checkpoint_value::ValueSlot,
    delta_chain::{self, Head},
    delta_mutation::Mutation,
    delta_totals::ApplyError,
    memo_projection::Projection,
    overlay::OverlayMap,
};
#[cfg(verus_keep_ghost)]
use super::{
    delta_chain::Chain,
    delta_replay::{self, Cursor},
};
#[cfg(verus_keep_ghost)]
use vstd::laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq};
use vstd::prelude::*;

verus! {
pub(super) struct Measured<B,V> {
    pub(super) root:Option<ObjectId>,
    pub(super) totals:NodeTotals,
    pub(super) boundary:B,
    pub(super) validation:V,
}

pub(super) enum Error<E> {
    Chain(delta_chain::Error<E>),
    Validation(E),
    Checkpoint(checkpoint_replay::Error<E>),
}

pub(super) open spec fn assembled<S,B,V>(head:ObjectId,chain:Chain,m:Measured<B,V>,cursor:Cursor<(S,OverlayMap)>,
    out:(Projection<B>,V)) -> bool {
    &&& chain.tree == m.root && chain.totals == m.totals
    &&& out.1 == m.validation && out.0.head == Some(head) && out.0.tree == chain.tree
    &&& out.0.overlay == cursor.state.1 && out.0.depth == cursor.depth && out.0.delta_bytes == cursor.bytes
    &&& out.0.totals == cursor.totals && out.0.boundary == Some(m.boundary)
}

pub(super) open spec fn after_chain(steps:Seq<delta_chain::Step>,count:nat,key:Seq<u8>) -> Option<bool>
    decreases count,
{
    if count==0 {None} else {
        let rows=steps[steps.len()-count].mutations@;
        super::overlay_batch::after_rows(rows,rows.len(),key,after_chain(steps,(count-1) as nat,key))
    }
}

pub(super) open spec fn writes<S,E,F:Fn((S,OverlayMap),Option<ObjectId>,ObjectId,&Vec<Mutation>,NodeTotals)->Result<((S,OverlayMap),NodeTotals),E>>(apply:F) -> bool {
    forall|s:(S,OverlayMap),t:Option<ObjectId>,id:ObjectId,r:&Vec<Mutation>,n:NodeTotals,next:(S,OverlayMap),m:NodeTotals,k:Seq<u8>|
        s.1.ordered_snapshot() && #[trigger] apply.ensures((s,t,id,r,n),Ok((next,m))) ==>
        #[trigger] next.1.presence(k) == super::overlay_batch::after_rows(r@,r.len() as nat,k,s.1.presence(k))
}

proof fn ordered_history<S,E,F:Fn((S,OverlayMap),Option<ObjectId>,ObjectId,&Vec<Mutation>,NodeTotals)->Result<((S,OverlayMap),NodeTotals),E>>(
    start:(S,OverlayMap),totals:NodeTotals,tree:Option<ObjectId>,steps:Seq<delta_chain::Step>,apply:F,
    h:Seq<Cursor<(S,OverlayMap)>>,n:nat,k:Seq<u8>)
    requires start.1.is_empty_snapshot(),start.1.ordered_snapshot(),writes(apply),
        delta_replay::preserves(apply,|s:(S,OverlayMap)| s.1.ordered_snapshot()),
        delta_replay::history(start,totals,tree,steps,0,apply,h),n<h.len(),
    ensures h[n as int].state.1.ordered_snapshot() && h[n as int].state.1.presence(k)==after_chain(steps,n,k),
    decreases n,
{
    if n>0 {
        ordered_history(start,totals,tree,steps,apply,h,(n-1) as nat,k);
        let row=steps[steps.len()-n];
        let prior=h[n-1];let next=h[n as int];
        assert(delta_replay::applied(tree,prior,row,apply,next));
        assert(apply.ensures((prior.state,tree,row.object,&row.mutations,prior.totals),Ok((next.state,next.totals))));
    }
}

pub(super) open spec fn from_chain<'a,P,S,B,V,E,M,I,F>(
    owner:&'a P,head:ObjectId,chain:Chain,measure:M,start:I,apply:F,other:Result<(Projection<B>,V),Error<E>>,
) -> bool
    where M:FnOnce(&P,Option<ObjectId>)->Result<Measured<B,V>,E>,I:FnOnce(&'a P)->S,
        F:Fn((S,OverlayMap),Option<ObjectId>,ObjectId,&Vec<Mutation>,NodeTotals)->Result<((S,OverlayMap),NodeTotals),E>,
{
    match other {
            Err(Error::Validation(e)) => measure.ensures((owner,chain.tree),Err(e)),
            result => exists|m:Measured<B,V>| #[trigger] measure.ensures((owner,chain.tree),Ok(m)) && match result {
                Ok(pair) => exists|s:S,c:Cursor<(S,OverlayMap)>,empty:OverlayMap|
                    #[trigger] start.ensures((owner,),s) && empty.is_empty_snapshot() &&
                    #[trigger] delta_replay::replayed((s,empty),m.totals,m.root,chain.newest_first@,0,apply,c) &&
                    assembled(head,chain,m,c,pair) && pair.0.overlay.ordered_snapshot() &&
                    forall|k:Seq<u8>| #[trigger] pair.0.overlay.presence(k) == after_chain(chain.newest_first@,chain.newest_first.len() as nat,k),
                Err(Error::Checkpoint(checkpoint_replay::Error::Root)) => m.root != chain.tree,
                Err(Error::Checkpoint(checkpoint_replay::Error::Totals)) => m.root == chain.tree && m.totals != chain.totals,
                Err(Error::Checkpoint(checkpoint_replay::Error::Replay(e))) => m.root == chain.tree && m.totals == chain.totals &&
                    exists|s:S,empty:OverlayMap| #[trigger] start.ensures((owner,),s) && empty.is_empty_snapshot() &&
                        #[trigger] delta_replay::failed((s,empty),m.totals,m.root,chain.newest_first@,apply,e),
                _ => false,
            },
        }
}

pub(super) fn decode<'a,P,S,B,V,E,L,M,I,F>(owner:&'a P,head:ObjectId,load:L,measure:M,start:I,apply:F)
    -> (out:Result<(Projection<B>,V),Error<E>>)
    where L:Fn(&P,ObjectId)->Result<Head,E>,M:FnOnce(&P,Option<ObjectId>)->Result<Measured<B,V>,E>,
        I:FnOnce(&'a P)->S,F:Fn((S,OverlayMap),Option<ObjectId>,ObjectId,&Vec<Mutation>,NodeTotals)->Result<((S,OverlayMap),NodeTotals),E>,
    requires obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|p:&P,id:ObjectId| #[trigger] load.requires((p,id)),
        forall|tree:Option<ObjectId>| #[trigger] measure.requires((owner,tree)),
        start.requires((owner,)),
        writes(apply),delta_replay::preserves(apply,|s:(S,OverlayMap)| s.1.ordered_snapshot()),
    ensures match out {
        Err(Error::Chain(e)) => exists|steps:Seq<delta_chain::Step>,id:ObjectId| #[trigger] delta_chain::stopped(owner,head,steps,id,load,e),
        other => exists|chain:Chain,end:Option<ObjectId>| #[trigger] delta_chain::complete(owner,head,chain,end,load) &&
            from_chain(owner,head,chain,measure,start,apply,other),
    },
{
    let chain = match delta_chain::walk(owner,head,load) {Ok(c) => c,Err(e) => return Err(Error::Chain(e))};
    let tree = chain.tree;
    let m = match measure(owner,tree) {Ok(m) => m,Err(e) => return Err(Error::Validation(e))};
    let begin = || -> (s:(S,OverlayMap)) ensures start.ensures((owner,),s.0) && s.1.is_empty_snapshot() && s.1.ordered_snapshot(), {
        (start(owner),OverlayMap::empty())
    };
    let c = match checkpoint_replay::recover(chain,m.root,m.totals,begin,apply,Ghost(|s:(S,OverlayMap)| s.1.ordered_snapshot())) {
        Ok(c) => c, Err(e) => return Err(Error::Checkpoint(e)),
    };
    proof {
        let init=choose|s:(S,OverlayMap)| #[trigger] begin.ensures((),s) &&
            delta_replay::replayed(s,m.totals,m.root,chain.newest_first@,0,apply,c);
        let h=choose|h:Seq<Cursor<(S,OverlayMap)>>| #[trigger] delta_replay::history(init,m.totals,m.root,chain.newest_first@,0,apply,h) && h.last()==c;
        ordered_history(init,m.totals,m.root,chain.newest_first@,apply,h,chain.newest_first.len() as nat,Seq::empty());
        assert forall|k:Seq<u8>| #[trigger] c.state.1.presence(k)==after_chain(chain.newest_first@,chain.newest_first.len() as nat,k) by {
            ordered_history(init,m.totals,m.root,chain.newest_first@,apply,h,chain.newest_first.len() as nat,k);
        }
    }
    Ok((Projection {head:Some(head),tree,overlay:c.state.1,depth:c.depth,delta_bytes:c.bytes,
        totals:c.totals,boundary:Some(m.boundary)},m.validation))
}
pub(super) open spec fn recovered<P,B,V,E,L,M>(owner:&P,head:ObjectId,load:L,measure:M,pair:(Projection<B>,V)) -> bool
    where L:Fn(&P,ObjectId)->Result<Head,E>,M:FnOnce(&P,Option<ObjectId>)->Result<Measured<B,V>,E>,
{
    exists|c:Chain,end:Option<ObjectId>,m:Measured<B,V>|
        #[trigger] delta_chain::complete(owner,head,c,end,load) && #[trigger] measure.ensures((owner,c.tree),Ok(m)) &&
        c.tree==m.root && c.totals==m.totals && pair.1==m.validation &&
        pair.0.head==Some(head) && pair.0.tree==c.tree && pair.0.boundary==Some(m.boundary) &&
        pair.0.overlay.ordered_snapshot() && (forall|key:Seq<u8>| #[trigger] pair.0.overlay.presence(key) == after_chain(c.newest_first@,c.newest_first.len() as nat,key)) &&
        (if c.newest_first.len()==0 {pair.0.depth==0 && pair.0.delta_bytes==0 && pair.0.totals==m.totals}
         else {pair.0.depth==c.newest_first@[0].depth && pair.0.delta_bytes==c.newest_first@[0].delta_bytes &&
            pair.0.totals==c.newest_first@[0].totals})
}

/// If the newest delta writes the addressed key, its final write wins even
/// when preceding deltas and the checkpoint contain a different value.
pub(super) open spec fn head_writes<P,E,L:Fn(&P,ObjectId)->Result<Head,E>>(
    owner:&P,head:ObjectId,load:L,key:Seq<u8>,present:bool) -> bool {
    forall|h:Head| #[trigger] load.ensures((owner,head),Ok(h)) ==> (h matches Head::Delta{mutations,..} &&
        super::overlay_batch::after_rows(mutations@,mutations.len() as nat,key,None)==Some(present))
}

proof fn overwrites(rows:Seq<Mutation>,n:nat,key:Seq<u8>,initial:Option<bool>)
    requires n<=rows.len(),
    ensures super::overlay_batch::after_rows(rows,n,key,initial) ==
        match super::overlay_batch::after_rows(rows,n,key,None) {Some(b)=>Some(b),None=>initial},
    decreases n,
{
    if n>0 {overwrites(rows,(n-1) as nat,key,initial);}
}

/// A source-addressed predecessor path to the recorded write. Every newer
/// record links to the next ID and leaves the key untouched.
pub(super) open spec fn retained<P,E,L:Fn(&P,ObjectId)->Result<Head,E>>(owner:&P,head:ObjectId,path:Seq<ObjectId>,
    load:L,key:Seq<u8>,present:bool) -> bool {
    &&& path.len()>0 && path[0]==head && head_writes(owner,path.last(),load,key,present)
    &&& forall|i:int,h:Head| 0<=i<path.len()-1 && #[trigger] load.ensures((owner,path[i]),Ok(h)) ==>
        (h matches Head::Delta{previous,mutations,..} && previous==Some(path[i+1]) &&
        super::overlay_batch::after_rows(mutations@,mutations.len() as nat,key,None).is_none())
}

proof fn along_path<P,E,L:Fn(&P,ObjectId)->Result<Head,E>>(owner:&P,head:ObjectId,c:Chain,end:Option<ObjectId>,
    path:Seq<ObjectId>,i:nat,load:L,key:Seq<u8>,present:bool)
    requires delta_chain::complete(owner,head,c,end,load),retained(owner,head,path,load,key,present),
        i<path.len(),i<=c.newest_first.len(), Some(path[i as int]) ==
        (if i<c.newest_first.len() {Some(c.newest_first@[i as int].object)} else {end}),
    ensures after_chain(c.newest_first@,(c.newest_first.len()-i) as nat,key)==Some(present),
    decreases path.len()-i,
{
    let id=path[i as int];
    if i==c.newest_first.len() {
        assert(load.ensures((owner,id),Ok(Head::Checkpoint{tree:c.tree,totals:c.totals})));
        if i+1==path.len() {assert(id==path.last());}
        assert(false);
    }
    delta_chain::at(owner,head,c.newest_first@,end,load,i as int);
    let row=c.newest_first@[i as int];
    let prev=if i+1<c.newest_first.len() {Some(c.newest_first@[(i+1) as int].object)} else {end};
    assert(load.ensures((owner,id),Ok(Head::Delta {previous:prev,depth:row.depth,delta_bytes:row.delta_bytes,
        mutations:row.mutations,totals:row.totals})));
    let older=after_chain(c.newest_first@,(c.newest_first.len()-i-1) as nat,key);
    overwrites(row.mutations@,row.mutations.len() as nat,key,older);
    if i+1==path.len() {
        assert(id==path.last());
        assert(super::overlay_batch::after_rows(row.mutations@,row.mutations.len() as nat,key,None)==Some(present));
    } else {
        assert(prev==Some(path[(i+1) as int]));
        along_path(owner,head,c,end,path,i+1,load,key,present);
    }
}

pub(super) proof fn retained_write<P,B,V,E,L,M>(owner:&P,head:ObjectId,load:L,measure:M,pair:(Projection<B>,V),
    path:Seq<ObjectId>,key:Seq<u8>,present:bool)
    where L:Fn(&P,ObjectId)->Result<Head,E>,M:FnOnce(&P,Option<ObjectId>)->Result<Measured<B,V>,E>,
    requires recovered(owner,head,load,measure,pair),retained(owner,head,path,load,key,present),
    ensures pair.0.overlay.presence(key)==Some(present),
{
    let (c,end)=choose|c:Chain,end:Option<ObjectId>| #[trigger] delta_chain::complete(owner,head,c,end,load) &&
        forall|k:Seq<u8>| #[trigger] pair.0.overlay.presence(k)==after_chain(c.newest_first@,c.newest_first.len() as nat,k);
    if c.newest_first.len()>0 {delta_chain::at(owner,head,c.newest_first@,end,load,0);}
    along_path(owner,head,c,end,path,0,load,key,present);
}

/// Decode using the production mutation applicator. The remaining callbacks read
/// checkpoint values and resolve value slots; they cannot choose overlay keys.
pub(super) fn read<'a,P,S,B,V,E,L,M,I,K,W,A>(owner:&'a P,head:ObjectId,load:L,measure:M,start:I,
    read_values:(K,W),translate:A) -> (out:Result<(Projection<B>,V),Error<E>>)
    where L:Fn(&P,ObjectId)->Result<Head,E>,M:FnOnce(&P,Option<ObjectId>)->Result<Measured<B,V>,E>,
        I:FnOnce(&'a P)->S,K:Fn(S,Option<ObjectId>,&Vec<u8>)->Result<(S,Option<Vec<u8>>),E>+Copy,
        W:Fn(S,&ValueSlot)->Result<(S,Vec<u8>),E>+Copy,A:Fn(ObjectId,ApplyError<E>)->E,
    requires obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|p:&P,id:ObjectId| #[trigger] load.requires((p,id)),
        forall|tree:Option<ObjectId>| #[trigger] measure.requires((owner,tree)),start.requires((owner,)),
        forall|s:S,t:Option<ObjectId>,key:&Vec<u8>| #[trigger] read_values.0.requires((s,t,key)),
        forall|s:S,v:&ValueSlot| #[trigger] read_values.1.requires((s,v)),
        forall|id:ObjectId,e:ApplyError<E>| #[trigger] translate.requires((id,e)),
    ensures out matches Ok(pair) ==> recovered(owner,head,load,measure,pair),
{
    let (lookup,value)=read_values;
    let apply=|s:(S,OverlayMap),t:Option<ObjectId>,id:ObjectId,rows:&Vec<Mutation>,n:NodeTotals|
        -> (out:Result<((S,OverlayMap),NodeTotals),E>)
        requires s.1.ordered_snapshot(),
        ensures out matches Ok(((c,o),m)) ==> o.ordered_snapshot() && forall|k:Seq<u8>| #[trigger] o.presence(k) ==
            super::overlay_batch::after_rows(rows@,rows.len() as nat,k,s.1.presence(k)),
    {
        match s.1.recover((s.0,n),t,id,rows.as_slice(),lookup,value) {
            Ok((c,o,m)) => Ok(((c,o),m)),
            Err((_,(address,e))) => Err(translate(address,e)),
        }
    };
    let out=decode(owner,head,load,measure,start,apply);
    let ghost result=out;
    proof {
        if let Ok(pair)=result {
            let (c,end)=choose|c:Chain,end:Option<ObjectId>| #[trigger] delta_chain::complete(owner,head,c,end,load) &&
                from_chain(owner,head,c,measure,start,apply,result);
            let m=choose|m:Measured<B,V>| #[trigger] measure.ensures((owner,c.tree),Ok(m)) &&
                exists|s:S,r:Cursor<(S,OverlayMap)>,empty:OverlayMap|
                    #[trigger] start.ensures((owner,),s) && empty.is_empty_snapshot() &&
                    #[trigger] delta_replay::replayed((s,empty),m.totals,m.root,c.newest_first@,0,apply,r) &&
                    assembled(head,c,m,r,pair) && forall|k:Seq<u8>| #[trigger] pair.0.overlay.presence(k) ==
                        after_chain(c.newest_first@,c.newest_first.len() as nat,k);
            let (s,r,empty)=choose|s:S,r:Cursor<(S,OverlayMap)>,empty:OverlayMap| #[trigger] start.ensures((owner,),s) &&
                empty.is_empty_snapshot() && #[trigger] delta_replay::replayed((s,empty),m.totals,m.root,c.newest_first@,0,apply,r) &&
                assembled(head,c,m,r,pair);
            let h=choose|h:Seq<Cursor<(S,OverlayMap)>>| #[trigger] delta_replay::history((s,empty),m.totals,m.root,c.newest_first@,0,apply,h) && h.last()==r;
            if c.newest_first.len()==0 {assert(h.last()==h[0]);}
            else {assert(delta_replay::applied(m.root,h[h.len()-2],c.newest_first@[0],apply,h.last()));}
        }
    }
    out
}

}
