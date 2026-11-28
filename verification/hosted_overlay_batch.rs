//! Run the production inner replay with an addressed checkpoint and a stateful value reader.
use crate::{ObjectId,checkpoint_totals::NodeTotals,checkpoint_value::ValueSlot,delta_mutation::Mutation,
    delta_totals::{self,ApplyError},overlay_batch as batch,replay_values::Bytes,traversal};
use vstd::prelude::*;

verus! {
fn two(tree:ObjectId,object:ObjectId,first_error:bool,second_error:bool,no_change:bool) {
    let a=vec![110u8,0,97];let b=vec![110u8,0,98];
    let bytes=vec![31u8];assert(bytes@ =~= seq![31u8]);let slot=ValueSlot::Inline(bytes);
    let rows=[Mutation {key:a,value:Some(slot)},Mutation {key:b,value:None}];
    let ghost ka=seq![110u8,0u8,97u8];let ghost kb=seq![110u8,0u8,98u8];
    assert(rows@[0].key@ =~= ka && rows@[1].key@ =~= kb && ka!=kb);
    let read=|ctx:u8,base:Option<ObjectId>,key:&Vec<u8>| -> (out:Result<(u8,Bytes),u8>)
        ensures if base!=Some(tree) {out==Err(9u8)}
        else if ctx==0 && key@==seq![110u8,0u8,97u8] {out==(if first_error {Err(1u8)} else {Ok((1u8,None))})}
        else if ctx==2 && key@==seq![110u8,0u8,98u8] {if second_error {out==Err(2u8)} else {
            out matches Ok((3u8,p)) && delta_totals::data_bytes(p)==(if no_change {None} else {Some(seq![17u8])})}}
        else {out==Err(9u8)},
    {
        let Some(base)=base else {return Err(9);};
        if !base.same(&tree) || key.len()!=3 || key[0]!=110 || key[1]!=0 {return Err(9);}
        assert((key[2]==97)==(key@ =~=seq![110u8,0u8,97u8]) && (key[2]==98)==(key@ =~=seq![110u8,0u8,98u8]));
        match (ctx,key[2]) {
            (0,97) => if first_error {Err(1)} else {Ok((1,None))},
            (2,98) => if second_error {Err(2)} else if no_change {Ok((3,None))} else {
                let old=vec![17u8];assert(old@ =~= seq![17u8]);Ok((3,Some(old)))},
            _=>Err(9),
        }
    };
    let value=|ctx:u8,v:&ValueSlot| -> (out:Result<(u8,Vec<u8>),u8>)
        ensures if ctx==1 && (v matches ValueSlot::Inline(bytes) && bytes@==seq![31u8]) {out matches Ok((2u8,data)) && data@==seq![31u8]}
            else {true},
    {
        if ctx==1 {if let ValueSlot::Inline(d)=v {let copy=d.clone();
            assert((v matches ValueSlot::Inline(bytes) && bytes@==seq![31u8]) ==> copy@ =~= seq![31u8]);return Ok((2,copy));}}
        Err(8)
    };
    let start=(0u8,None,NodeTotals {entries:1,logical_bytes:1,quota_bytes:4});
    let result=batch::run(start,Some(tree),object,&rows,read,value);
    let ghost out=result;
    proof {
        let h=choose|h:Seq<batch::State<u8>>| #[trigger] batch::history(start,Some(tree),object,rows@,read,value,h) &&
            match out {Ok(s)=>h.len()==rows.len()+1 && h.last()==s,
            Err((i,e))=>i<rows.len() && h.len()==i+1 && batch::transition(h.last(),Some(tree),object,&rows@[i as int],read,value,Err(e))};
        assert(h[0]==start && traversal::lookup_spec(start.1,ka).is_none());
        assert(rows@[0].value matches Some(ValueSlot::Inline(bytes)) && bytes@==seq![31u8]);
        if h.len()>=2 {
            assert(batch::transition(h[0],Some(tree),object,&rows@[0],read,value,Ok(h[1])));
            let p=choose|p:(Bytes,Bytes)| #[trigger] batch::installed(h[0],Some(tree),&rows@[0],read,value,h[1],p);
            assert(batch::installed(start,Some(tree),&rows@[0],read,value,h[1],p));
            let (ctx,prior)=choose|c:u8,v:Bytes| #[trigger] read.ensures((0u8,Some(tree),&rows@[0].key),Ok((c,v))) &&
                crate::replay_values::finish(c,v,crate::replay_values::borrowed(&rows@[0].value),value,Ok((h[1].0,p)));
            assert(ctx==1 && prior.is_none());
            assert(!first_error && h[1].0==2 && delta_totals::data_bytes(p.1)==Some(seq![31u8]) && p.0.is_none());
            assert(h[1].2 == (NodeTotals {entries:2,logical_bytes:2,quota_bytes:8}));
            assert(traversal::lookup_spec(h[1].1,ka)==Some(p.1) && traversal::lookup_spec(h[1].1,kb).is_none());
        }
        if h.len()==3 {
            assert(batch::transition(h[1],Some(tree),object,&rows@[1],read,value,Ok(h[2])));
            let p=choose|p:(Bytes,Bytes)| #[trigger] batch::installed(h[1],Some(tree),&rows@[1],read,value,h[2],p);
            assert(!second_error && !no_change && h[2].0==3 && p.1.is_none());
            assert(h[2].2==start.2 && traversal::lookup_spec(h[2].1,kb)==Some(None));
            assert(traversal::lookup_spec(h[2].1,ka)==traversal::lookup_spec(h[1].1,ka));
        }
        if out matches Err((i,e)) {
            let (i,(k,e))=out->Err_0;
            assert(k==object);
            if i==0 {assert(first_error && e==ApplyError::Load(1u8));}
            else if second_error {assert(i==1 && e==ApplyError::Load(2u8));}
            else {assert(i==1 && no_change && e==ApplyError::Change(delta_totals::ReplayError::Unchanged));}
        }
        assert(out.is_ok() == (!first_error && !second_error && !no_change));
    }
}
}
