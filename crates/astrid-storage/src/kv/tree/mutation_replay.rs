//! Replay the encoded mutations in one delta against the same checkpoint.
use super::{ObjectId, delta_mutation::Mutation};
use vstd::prelude::*;

verus! {
pub(super) open spec fn prefix<S,E,F:Fn(S,Option<ObjectId>,ObjectId,&Mutation)->Result<S,E>>(
    initial:S,tree:Option<ObjectId>,id:ObjectId,rows:Seq<Mutation>,states:Seq<S>,f:F,
) -> bool {
    &&& 1 <= states.len() <= rows.len()+1
    &&& states[0] == initial
    &&& forall|i:int| 0 <= i < states.len()-1 ==>
        f.ensures(((#[trigger] states[i]),tree,id,&rows[i]),Ok(states[i+1]))
}

pub(super) fn run<S,E,F:Fn(S,Option<ObjectId>,ObjectId,&Mutation)->Result<S,E>>(
    initial:S,tree:Option<ObjectId>,id:ObjectId,rows:&[Mutation],apply:F,
) -> (out:Result<S,E>)
    requires forall|states:Seq<S>| #[trigger] prefix(initial,tree,id,rows@,states,apply) && states.len() <= rows.len() ==>
            apply.requires((states.last(),tree,id,&rows@[states.len()-1])),
    ensures exists|states:Seq<S>| #[trigger] prefix(initial,tree,id,rows@,states,apply) && match out {
        Ok(s) => states.len() == rows.len()+1 && states.last() == s,
        Err(e) => states.len() <= rows.len() && apply.ensures((states.last(),tree,id,&rows@[states.len()-1]),Err(e)),
    },
{
    let mut state = initial;
    let mut i = 0usize;
    let ghost mut states = seq![initial];
    while i < rows.len()
        invariant i <= rows.len(), states.len() == i+1, states.last() == state,
            prefix(initial,tree,id,rows@,states,apply),
            forall|states:Seq<S>| #[trigger] prefix(initial,tree,id,rows@,states,apply) && states.len() <= rows.len() ==>
            apply.requires((states.last(),tree,id,&rows@[states.len()-1])),
        decreases rows.len()-i,
    {
        assert(apply.requires((state,tree,id,&rows@[i as int])));
        state = apply(state,tree,id,&rows[i])?;
        let ghost before = states;
        proof {
            states = before.push(state);
            assert forall|j:int| 0 <= j < states.len()-1 implies
                #[trigger] apply.ensures((states[j],tree,id,&rows@[j]),Ok(states[j+1])) by {
                if j < i {assert(apply.ensures((before[j],tree,id,&rows@[j]),Ok(before[j+1])));}
            }
            assert(prefix(initial,tree,id,rows@,states,apply));
        }
        i = i.saturating_add(1);
    }
    Ok(state)
}
}
