//! A captured component that names a checkpoint must reopen that checkpoint with an empty overlay.
use crate::{ObjectId,checkpoint_totals::NodeTotals,checkpoint_replay,delta_chain::{self,Chain,Head,Step},
    delta_mutation::Mutation,delta_replay::{self,Cursor},overlay::OverlayMap,projection_recovery::{self,Error,Measured}};
use vstd::{laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},prelude::*};

verus! {
proof fn no_deltas<L:Fn(&u64,ObjectId)->Result<Head,u8>>(owner:&u64,head:ObjectId,steps:Seq<Step>,end:Option<ObjectId>,load:L)
    requires delta_chain::follows(owner,head,steps,end,load),
        forall|k:ObjectId,h:Head| #[trigger] load.ensures((owner,k),Ok(h)) ==> h is Checkpoint,
    ensures steps.len()==0 && end==Some(head),
{
    if steps.len()>0 {
        delta_chain::at(owner,head,steps,end,load,0);
        assert(delta_chain::step_read(owner,steps,end,load,0));
    }
}

fn direct(owner:u64,head:ObjectId,tree:ObjectId,bad_measure:bool)
    -> (out:Result<(crate::memo_projection::Projection<u64>,u64),Error<u8>>)
    requires obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
    ensures if bad_measure {out matches Err(Error::Checkpoint(checkpoint_replay::Error::Totals))}
        else {out matches Ok((p,proof_id)) && p.head==Some(head) && p.tree==Some(tree) &&
            p.overlay.is_empty_snapshot() && p.depth==0 && p.delta_bytes==0 && p.totals.entries==1 &&
            p.totals.logical_bytes==2 && p.totals.quota_bytes==3 && p.boundary==Some(41u64) && proof_id==42},
{
    let totals = NodeTotals {entries:1,logical_bytes:2,quota_bytes:3};
    let observed = NodeTotals {entries:if bad_measure {0} else {1},logical_bytes:2,quota_bytes:3};
    let load = |p:&u64,k:ObjectId| -> (r:Result<Head,u8>)
        ensures r == if *p==owner && k==head {Ok(Head::Checkpoint {tree:Some(tree),totals})} else {Err(1u8)},
    {if *p==owner && k.same(&head) {Ok(Head::Checkpoint {tree:Some(tree),totals})} else {Err(1)}};
    let measure = |p:&u64,t:Option<ObjectId>| -> (r:Result<Measured<u64,u64>,u8>)
        ensures r == if *p==owner && t==Some(tree) {Ok(Measured {root:t,totals:observed,boundary:41u64,validation:42u64})}
            else {Err(2u8)},
    {
        if *p==owner {if let Some(k)=t {if k.same(&tree) {return Ok(Measured {root:t,totals:observed,boundary:41,validation:42});}}}
        Err(2)
    };
    let start = |p:&u64| -> (s:u64) ensures s==*p, {*p};
    let apply = |_s:(u64,OverlayMap),_t:Option<ObjectId>,_id:ObjectId,_m:&Vec<Mutation>,_n:NodeTotals|
        -> (r:Result<((u64,OverlayMap),NodeTotals),u8>) ensures r==Err(3u8), {Err(3)};
    let result = projection_recovery::decode(&owner,head,load,measure,start,apply);
    let ghost saved = result;
    proof {
        if let Err(Error::Chain(e)) = saved {
            let (steps,k)=choose|steps:Seq<Step>,k:ObjectId| #[trigger] delta_chain::stopped(&owner,head,steps,k,load,e);
            no_deltas(&owner,head,steps,Some(k),load);
            assert(delta_chain::ids(steps).len()==0);
            assert(false);
        } else {
            let (c,end)=choose|c:Chain,end:Option<ObjectId>| #[trigger] delta_chain::complete(&owner,head,c,end,load) &&
                projection_recovery::from_chain(&owner,head,c,measure,start,apply,saved);
            no_deltas(&owner,head,c.newest_first@,end,load);
            assert(c.tree==Some(tree) && c.totals==totals);
            if let Ok(pair)=saved {
                let (r,empty)=choose|r:Cursor<(u64,OverlayMap)>,empty:OverlayMap| empty.is_empty_snapshot() &&
                    #[trigger] delta_replay::replayed((owner,empty),observed,Some(tree),c.newest_first@,0,apply,r) &&
                    projection_recovery::assembled(head,c,Measured {root:Some(tree),totals:observed,boundary:41u64,validation:42u64},r,pair);
                let h=choose|h:Seq<Cursor<(u64,OverlayMap)>>| #[trigger] delta_replay::history((owner,empty),observed,Some(tree),c.newest_first@,0,apply,h) && h.last()==r;
                assert(h.len()==1 && h.last()==h[0]);
            }
        }
    }
    result
}
}
