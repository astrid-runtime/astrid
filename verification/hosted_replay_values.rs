//! Exercise checkpoint fallback and value resolution at the actual overlay entry.
use crate::{ObjectId,checkpoint_value::ValueSlot,delta_mutation::Mutation,delta_totals as totals,
    overlay_update,replay_values as values,traversal};
use std::sync::Arc;
use vstd::prelude::*;

verus! {
fn addressed(root:&mut Option<Arc<traversal::Node>>, accounting:&mut crate::checkpoint_totals::NodeTotals,
    owner:u64,tree:ObjectId,present:bool,delete:bool,fail_lookup:bool,fail_value:bool)
    requires traversal::ordered(*old(root)),
        traversal::lookup_spec(*old(root),seq![97u8,0,98u8]) ==
            (if present {Some(None)} else {None}),
{
    let key = vec![97u8,0,98];
    let slot = if delete {None} else {Some(ValueSlot::Inline(vec![22u8]))};
    let row = Mutation {key,value:slot};
    let load = |key:&Vec<u8>,slot:&Option<ValueSlot>,need:bool| -> (out:Result<(values::Bytes,values::Bytes),u8>)
        ensures key@ == row.key@ && *slot == row.value && need == !present ==> {
            if need && fail_lookup {out == Err(1u8)}
            else if !delete && fail_value {out == Err(2u8)}
            else {out.is_ok() &&
                totals::data_bytes(out->Ok_0.0) == (if need {Some(seq![11u8])} else {None}) &&
                totals::data_bytes(out->Ok_0.1) == (if delete {None} else {Some(seq![22u8])})}
        }
    {
        let read = |p:(u64,bool),base:Option<ObjectId>,address:&[u8]| -> (r:Result<((u64,bool),values::Bytes),u8>)
            ensures if p != (owner,false) || base != Some(tree) || address@ != row.key@ {r == Err(9u8)}
                else if fail_lookup {r == Err(1u8)}
                else {r.is_ok() && r->Ok_0.0 == (owner,true) && totals::data_bytes(r->Ok_0.1) == Some(seq![11u8])} {
            let Some(id) = base else {return Err(9);};
            let a = address;
            let same = a.len()==3 && a[0]==97 && a[1]==0 && a[2]==98;
            assert(same == (a@ =~= row.key@));
            if p.0 != owner || p.1 || !id.same(&tree) || !same {Err(9)}
            else if fail_lookup {Err(1)} else {let d=vec![11u8];assert(d@ =~= seq![11u8]);Ok(((owner,true),Some(d)))}
        };
        let resolve = |c:(u64,bool),v:&ValueSlot| -> (r:Result<Vec<u8>,u8>)
            ensures if c != (owner,need) {r == Err(9u8)} else if fail_value {r == Err(2u8)}
                else {match v {ValueSlot::Inline(d) => r matches Ok(bytes) && bytes@ == d@, _ => r == Err(8u8)}} {
            if c.0 != owner || c.1 != need {return Err(9);}
            if fail_value {return Err(2);}
            match v {ValueSlot::Inline(d) => {let mut bytes=Vec::new();bytes.extend_from_slice(d);assert(bytes@ =~= d@);Ok(bytes)}, _ => Err(8)}
        };
        let address = key.as_slice();
        let submitted = slot.as_ref();
        let out = values::resolve((owner,false),Some(tree),address,submitted,need,read,resolve);
        proof {
            if key@ == row.key@ && *slot == row.value && need == !present {
                if need && !(out matches Err(e) && read.ensures(((owner,false),Some(tree),address),Err(e))) {
                    let (c,p) = choose|c:(u64,bool),p:values::Bytes|
                        #[trigger] read.ensures(((owner,false),Some(tree),address),Ok((c,p))) &&
                        values::after_prior(c,p,submitted,resolve,out);
                    assert(c == (owner,true) && totals::data_bytes(p) == Some(seq![11u8]));
                }
                if !delete {assert(submitted matches Some(ValueSlot::Inline(d)) && d@ == seq![22u8]);}
            }
        }
        out
    };
    let ghost before = *root;
    let ghost starting = *accounting;
    let charge = totals::admit(*accounting,3,if present {None} else {Some(1)},if delete {None} else {Some(1)},present && delete);
    let out = overlay_update::apply(root,accounting,&row,load);
    if (!present && fail_lookup) || (!delete && fail_value) {
        assert(out == Err(totals::ApplyError::Load(if !present && fail_lookup {1u8} else {2u8})));
        assert(*root == before && *accounting == starting);
    } else {
        assert(seq![11u8] != seq![22u8]) by {assert(seq![11u8][0] != seq![22u8][0]);}
        assert(charge.is_ok() == out.is_ok());
        assert(out.is_ok() ==> charge == Ok(*accounting));
    }
    if present && delete {
        assert(out == Err(totals::ApplyError::Change(totals::ReplayError::Unchanged)));
    } else if out.is_ok() {
        let ghost chosen = traversal::lookup_spec(*root,row.key@);
        assert(chosen matches Some(bytes) && totals::data_bytes(bytes) ==
            (if delete {None} else {Some(seq![22u8])}));
    }
}
}
