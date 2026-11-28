//! One owner-scoped chain with a real checkpoint, genesis, missing checkpoint or cycle.
use crate::{ObjectId,checkpoint_totals::NodeTotals,delta_chain::{self as chain,Head,Error}};
use vstd::{prelude::*,laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq}};

verus! {

spec fn scenario(owner:u64,id:ObjectId,expected:u64,head:ObjectId,base:ObjectId,tree:ObjectId,
    link:Option<ObjectId>,missing:bool,t:NodeTotals,out:Result<Head,u8>) -> bool {
    if owner != expected {out == Err(9u8)}
    else if id == head {out matches Ok(Head::Delta {previous,depth,delta_bytes,mutations,totals}) &&
        previous == link && depth == 1 && delta_bytes == 3 && mutations.len() == 1 && mutations@[0].key@ == seq![110u8,0,97] && mutations@[0].value.is_none() && totals == t}
    else if id == base && !missing { out == Ok(Head::Checkpoint {tree:Some(tree),totals:t}) }
    else {out == Err(7u8)}
}

proof fn shape<L:Fn(&u64,ObjectId)->Result<Head,u8>>(owner:u64,head:ObjectId,base:ObjectId,tree:ObjectId,
    link:Option<ObjectId>,missing:bool,t:NodeTotals,steps:Seq<chain::Step>,end:Option<ObjectId>,read:L)
    requires head != base,chain::follows(&owner,head,steps,end,read),
        forall|p:&u64,id:ObjectId,r:Result<Head,u8>| #[trigger] read.ensures((p,id),r) ==>
            scenario(*p,id,owner,head,base,tree,link,missing,t,r),
    ensures steps.len() <= 1,
        steps.len() == 1 ==> end == link && steps[0].object == head && steps[0].depth == 1 &&
            steps[0].delta_bytes == 3 && steps[0].mutations.len()==1 && steps[0].mutations@[0].key@ == seq![110u8,0,97] && steps[0].mutations@[0].value.is_none() && steps[0].totals == t,
        steps.len() == 0 ==> end == Some(head),
{
    if steps.len() > 0 {
        chain::at(&owner,head,steps,end,read,0);
        if steps.len() > 1 {
            chain::at(&owner,head,steps,end,read,1);
            assert(chain::ids(steps)[0] != chain::ids(steps)[1]);
            assert(steps[1].object != head);
        }
    }
}

fn selection(owner:u64,head:ObjectId,base:ObjectId,tree:ObjectId,cycle:bool,genesis:bool,missing:bool,t:NodeTotals)
    requires head != base,obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
{
    let link = if genesis {None} else if cycle {Some(head)} else {Some(base)};
    let load = |p:&u64,id:ObjectId| -> (out:Result<Head,u8>)
        ensures scenario(*p,id,owner,head,base,tree,link,missing,t,out) {
        if *p != owner {Err(9u8)}
        else if id.same(&head) {Ok(Head::Delta {previous:link,depth:1,delta_bytes:3,mutations:vec![crate::delta_mutation::Mutation {key:vec![110u8,0,97],value:None}],totals:t})}
        else if id.same(&base) && !missing {Ok(Head::Checkpoint {tree:Some(tree),totals:t})}
        else {Err(7u8)}
    };
    let out = chain::walk(&owner,head,load);
    let ghost verdict = out;
    proof {
        match verdict {
            Ok(c) => {
                let end = choose|end:Option<ObjectId>| #[trigger] chain::complete(&owner,head,c,end,load);
                shape(owner,head,base,tree,link,missing,t,c.newest_first@,end,load);
                assert(c.newest_first.len() == 1);
                assert(chain::ids(c.newest_first@)[0] == head);
                assert(chain::ids(c.newest_first@).contains(head));
                assert(if genesis {c.tree.is_none() && chain::zero(c.totals)}
                    else {!missing && !cycle && c.tree == Some(tree) && c.totals == t});
            },
            Err(e) => {
                let (s,id) = choose|s:Seq<chain::Step>,id:ObjectId| #[trigger] chain::stopped(&owner,head,s,id,load,e);
                shape(owner,head,base,tree,link,missing,t,s,Some(id),load);
                if s.len() == 0 {assert(chain::ids(s) =~= Seq::<ObjectId>::empty());}
                else {assert(chain::ids(s) =~= seq![head]);}
                assert(!genesis && if cycle {e == Error::Cycle(head)} else {missing && e == Error::Source(7u8)});
            },
        }
    }
}
}
