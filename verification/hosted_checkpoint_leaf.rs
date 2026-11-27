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

use std::collections::BTreeMap;
use vstd::{laws_cmp::{obeys_cmp,obeys_cmp_deep_eq},std_specs::btree::btree_map_inv};
type Presence = BTreeMap<Vec<u8>,bool>;

verus! {
pub(super) open spec fn checkpoint_keys<V>(before:Map<Seq<u8>,bool>,rows:Seq<Entry<V>>,n:nat,start:Seq<u8>,end:Seq<u8>)
    -> Map<Seq<u8>,bool>
    decreases n,
{
    if n == 0 { before } else {
        let prior = checkpoint_keys(before,rows,(n-1) as nat,start,end);
        let key = rows[n-1].key@;
        if encoding::range_contains(start,end,key) { prior.insert(key,true) } else { prior }
    }
}

pub(super) proof fn marks<V,E,F:Fn(Presence,Entry<V>)->Result<Presence,E>>(
    rows:Seq<Entry<V>>, n:nat,start:Seq<u8>,end:Seq<u8>,initial:Presence,after:Presence,callback:F,
)
    requires n <= rows.len(), btree_map_inv(&initial), visited(rows,n,start,end,initial,after,callback),
        forall|s:Presence,r:Entry<V>,o:Result<Presence,E>| btree_map_inv(&s) && #[trigger] callback.ensures((s,r),o) ==>
            match o { Ok(a) => btree_map_inv(&a) && a.deep_view() == s.deep_view().insert(r.key@,true), Err(_) => false },
    ensures btree_map_inv(&after), after.deep_view() == checkpoint_keys(initial.deep_view(),rows,n,start,end),
    decreases n,
{
    if n == 0 { return; }
    let r = rows[n-1];
    if encoding::range_contains(start,end,r.key@) {
        let prior = choose|p:Presence| visited(rows,(n-1) as nat,start,end,initial,p,callback) &&
            #[trigger] callback.ensures((p,r),Ok(after));
        marks(rows,(n-1) as nat,start,end,initial,prior,callback);
    } else { marks(rows,(n-1) as nat,start,end,initial,after,callback); }
}

// Use the function item passed by projected_keys_in_range, including the
// same callback type and owned map passed between checkpoint leaves.
fn enumerate_slots<V,E>(rows:Vec<Entry<V>>,start:&[u8],end:&[u8],keys:Presence) -> (out:Result<Presence,E>)
    requires btree_map_inv(&keys), obeys_cmp::<Vec<u8>>(), obeys_cmp_deep_eq::<Vec<u8>>(),
    ensures match out { Ok(after) => btree_map_inv(&after) && after.deep_view() ==
        checkpoint_keys(keys.deep_view(),rows@,rows@.len(),start@,end@), Err(_) => false },
{
    let callback = checkpoint_leaf::mark::<V,E>;
    assert forall|i:int,s:Presence| 0 <= i < rows.len() && visited(rows@,i as nat,start@,end@,keys,s,callback)
        && encoding::range_contains(start@,end@,rows@[i].key@) implies #[trigger] callback.requires((s,rows@[i])) by {
        marks(rows@,i as nat,start@,end@,keys,s,callback);
    }
    let out = checkpoint_leaf::visit(rows,start,end,keys,callback);
    let ghost observed = out;
    proof {
        match observed {
            Ok(after) => marks(rows@,rows@.len(),start@,end@,keys,after,callback),
            Err(e) => {
                let (i,s) = choose|i:int,s:Presence| 0 <= i < rows.len() &&
                    visited(rows@,i as nat,start@,end@,keys,s,callback) &&
                    encoding::range_contains(start@,end@,rows@[i].key@) &&
                    #[trigger] callback.ensures((s,rows@[i]),Err(e));
                marks(rows@,i as nat,start@,end@,keys,s,callback);
            },
        }
    }
    out
}
}
