//! Check ordered delivery and the successful prefix at a rejected checkpoint slot.
use crate::{checkpoint_leaf::{self,Entry,visited},encoding};
use vstd::prelude::*;

verus! {

type Row = Entry<u64>;
type Trace = Vec<Row>;
type Failure = (Trace,Row);

spec fn selected(rows:Seq<Row>, n:nat, start:Seq<u8>, end:Seq<u8>) -> Seq<Row>
    decreases n,
{
    if n == 0 { Seq::empty() } else {
        let prior = selected(rows,(n-1) as nat,start,end);
        if encoding::range_contains(start,end,rows[n-1].key@) { prior.push(rows[n-1]) } else { prior }
    }
}

spec fn accepts(rows:Seq<Row>, n:nat, start:Seq<u8>, end:Seq<u8>, refused:u64) -> bool {
    forall|i:int| 0 <= i < n && encoding::range_contains(start,end,rows[i].key@) ==> (#[trigger] rows[i]).value != refused
}

spec fn transition(prior:Trace, entry:Row, result:Result<Trace,Failure>, refused:u64) -> bool {
    match result {
        Ok(after) => entry.value != refused && after@ == prior@.push(entry),
        Err((prefix,failed)) => entry.value == refused && prefix@ == prior@ && failed == entry,
    }
}

proof fn trace_prefix<F:Fn(Trace,Row)->Result<Trace,Failure>>(
    rows:Seq<Row>, n:nat, start:Seq<u8>, end:Seq<u8>, initial:Trace, state:Trace, callback:F, refused:u64,
)
    requires n <= rows.len(), initial@.len() == 0, visited(rows,n,start,end,initial,state,callback),
        forall|s:Trace,r:Row,out:Result<Trace,Failure>| #[trigger] callback.ensures((s,r),out) ==> transition(s,r,out,refused),
    ensures state@ == selected(rows,n,start,end), accepts(rows,n,start,end,refused),
    decreases n,
{
    if n == 0 { assert(initial@ =~= Seq::empty()); return; }
    let r = rows[n-1];
    if encoding::range_contains(start,end,r.key@) {
        let prior = choose|p:Trace| visited(rows,(n-1) as nat,start,end,initial,p,callback) &&
            #[trigger] callback.ensures((p,r),Ok(state));
        trace_prefix(rows,(n-1) as nat,start,end,initial,prior,callback,refused);
    } else {
        trace_prefix(rows,(n-1) as nat,start,end,initial,state,callback,refused);
    }
}

fn collect_until_refusal(rows:Vec<Row>, start:&[u8], end:&[u8], refused:u64)
    -> (result:Result<Trace,Failure>)
    ensures match result {
        Ok(trace) => trace@ == selected(rows@,rows@.len(),start@,end@) &&
            accepts(rows@,rows@.len(),start@,end@,refused),
        Err((prefix,failed)) => exists|i:int| 0 <= i < rows.len() &&
            failed == #[trigger] rows@[i] && failed.value == refused &&
            encoding::range_contains(start@,end@,failed.key@) &&
            prefix@ == selected(rows@,i as nat,start@,end@) && accepts(rows@,i as nat,start@,end@,refused),
    },
{
    let initial:Trace = Vec::new();
    let callback = |mut s:Trace,r:Row| -> (out:Result<Trace,Failure>)
        ensures transition(s,r,out,refused),
    {
        if r.value == refused { Err((s,r)) } else { s.push(r); Ok(s) }
    };
    let result = checkpoint_leaf::visit(rows,start,end,initial,callback);
    let ghost observed = result;
    proof {
        match observed {
            Ok(trace) => trace_prefix(rows@,rows@.len(),start@,end@,initial,trace,callback,refused),
            Err(e) => {
                let (i,s) = choose|i:int,s:Trace| 0 <= i < rows.len() &&
                    visited(rows@,i as nat,start@,end@,initial,s,callback) &&
                    encoding::range_contains(start@,end@,rows@[i].key@) &&
                    #[trigger] callback.ensures((s,rows@[i]),Err(e));
                trace_prefix(rows@,i as nat,start@,end@,initial,s,callback,refused);
                assert(e.1 == rows@[i]);
            },
        }
    }
    result
}
}
