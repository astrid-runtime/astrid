//! Exercise both steps of chronological replay and faults on the second step.
use super::{ObjectId, checkpoint_totals::NodeTotals, delta_batch, delta_chain::Step,
    delta_mutation::Mutation, delta_recovery::CounterError, delta_replay as replay};
use vstd::prelude::*;

verus! {
fn two_steps(tree:ObjectId,older:ObjectId,newer:ObjectId,wrong_depth:bool,wrong_totals:bool,refuse:bool)
    requires older != newer,
{
    let base = NodeTotals {entries:0,logical_bytes:0,quota_bytes:0};
    let first = Step {object:older,depth:1,delta_bytes:3,totals:base,
        mutations:vec![Mutation {key:vec![97u8,0,97],value:None}]};
    let last = Step {object:newer,depth:if wrong_depth {1} else {2},delta_bytes:6,
        totals:NodeTotals {entries:if wrong_totals {1} else {0},logical_bytes:0,quota_bytes:0},
        mutations:vec![Mutation {key:vec![97u8,0,98],value:None}]};
    let rows = vec![last,first];
    let ghost input = rows@;
    let apply = |n:u8,t:Option<ObjectId>,id:ObjectId,m:&Vec<Mutation>,totals:NodeTotals| -> (out:Result<(u8,NodeTotals),u8>)
        ensures out == if t != Some(tree) || totals != base || m.len() != 1 {Err(7u8)}
            else if n == 0 && id == older && m@[0].key@ == seq![97u8,0,97u8] {Ok((1u8,totals))}
            else if n == 1 && id == newer && m@[0].key@ == seq![97u8,0,98u8] && !refuse {Ok((2u8,totals))}
            else {Err(8u8)},
    {
        let Some(t) = t else {return Err(7u8);};
        if !t.same(&tree) || totals.entries != 0 || totals.logical_bytes != 0 || totals.quota_bytes != 0 || m.len()!=1 {return Err(7u8);}
        let key = m[0].key.as_slice();
        let first = key.len()==3 && key[0]==97 && key[1]==0 && key[2]==97;
        let last = key.len()==3 && key[0]==97 && key[1]==0 && key[2]==98;
        assert(first == (key@ =~= seq![97u8,0,97u8]) && last == (key@ =~= seq![97u8,0,98u8]));
        if n == 0 && id.same(&older) && first {Ok((1,totals))}
        else if n == 1 && id.same(&newer) && last && !refuse {Ok((2,totals))}
        else {Err(8u8)}
    };
    let result = replay::run(0u8,base,Some(tree),rows,apply);
    let ghost out = result;
    proof {
        reveal_with_fuel(delta_batch::usage,2);
        let (remaining,end) = match out {
            Ok(c) => (0int,c),
            Err(e) => {
                let (i,c) = choose|i:int,c:replay::Cursor<u8>| 0 <= i < input.len() &&
                    #[trigger] replay::rejected(Some(tree),c,input[i],apply,e) &&
                    replay::replayed(0u8,base,Some(tree),input,i+1,apply,c);
                (i+1,c)
            },
        };
        assert(replay::replayed(0u8,base,Some(tree),input,remaining,apply,end));
        let h = choose|h:Seq<replay::Cursor<u8>>| #[trigger] replay::history(0u8,base,Some(tree),input,remaining,apply,h) && h.last() == end;
        assert(replay::history(0u8,base,Some(tree),input,remaining,apply,h) && h.last() == end);
        if h.len() >= 2 {
            assert(replay::applied(Some(tree),h[0],input[1],apply,h[1]));
            assert(h[1].state == 1 && h[1].totals == base);
        }
        if h.len() == 3 {assert(replay::applied(Some(tree),h[1],input[0],apply,h[2]));}
        match out {
            Err(e) => {
                let (i,c) = choose|i:int,c:replay::Cursor<u8>| 0 <= i < input.len() &&
                    #[trigger] replay::rejected(Some(tree),c,input[i],apply,e) &&
                    replay::replayed(0u8,base,Some(tree),input,i+1,apply,c);
                assert(i+1 == remaining && c == end);
                assert(i == 0);
                assert(if wrong_depth {e == replay::Error::Counter(newer,CounterError::Disagree)}
                    else if refuse {e == replay::Error::Apply(8u8)}
                    else {wrong_totals && e == replay::Error::Totals(newer)});
            },
            Ok(c) => {
                assert(!wrong_depth && !wrong_totals && !refuse);
                assert(c.state == 2 && c.totals == base && c.depth == 2 && c.bytes == 6);
            },
        }
    }
}
}
