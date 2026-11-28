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
type RowsState = (Option<Arc<traversal::Node>>,crate::checkpoint_totals::NodeTotals);

fn ordered_rows<E,F>(initial:RowsState,tree:Option<ObjectId>,id:ObjectId,rows:&[Mutation],load:F)
    -> (out:Result<RowsState,totals::ApplyError<E>>)
    where F:Fn(&Vec<u8>,&Option<ValueSlot>,bool)->Result<(values::Bytes,values::Bytes),E>+Copy,
    requires traversal::ordered(initial.0),forall|k:&Vec<u8>,v:&Option<ValueSlot>,need:bool| #[trigger] load.requires((k,v,need)),
    ensures exists|h:Seq<RowsState>| h.len() >= 1 && h[0] == initial && h.len() <= rows.len()+1 &&
        (forall|i:int| 0 <= i < h.len()-1 ==> #[trigger] overlay_update::applied(h[i].0,h[i+1].0,
            &rows@[i],h[i].1,h[i+1].1,load,Ok(()))) &&
        match out { Ok(s) => h.len()==rows.len()+1 && s == h.last(),
            Err(e) => h.len() <= rows.len() && overlay_update::applied(h.last().0,h.last().0,
                &rows@[h.len()-1],h.last().1,h.last().1,load,Err(e)) },
{
    use crate::mutation_replay::{self,prefix};
    let step = |s:RowsState,_:Option<ObjectId>,_:ObjectId,row:&Mutation| -> (out:Result<RowsState,totals::ApplyError<E>>)
        requires traversal::ordered(s.0),
        ensures match out {
            Ok(next) => overlay_update::applied(s.0,next.0,row,s.1,next.1,load,Ok(())),
            Err(e) => overlay_update::applied(s.0,s.0,row,s.1,s.1,load,Err(e)),
        }
    {
        let (mut root,mut accounting) = s;
        match overlay_update::apply(&mut root,&mut accounting,row,load) {
            Ok(()) => Ok((root,accounting)),
            Err(e) => {assert(root == s.0 && accounting == s.1);Err(e)},
        }
    };
    assert forall|h:Seq<RowsState>| #[trigger] prefix(initial,tree,id,rows@,h,step) && h.len() <= rows.len() implies
        step.requires((h.last(),tree,id,&rows@[h.len()-1])) by {
        if h.len()>1 {
            let i = h.len() as int-2;
            assert(step.ensures((h[i],tree,id,&rows@[i]),Ok(h[i+1])));
        }
    }
    let out = mutation_replay::run(initial,tree,id,rows,step);
    proof {
        let h = choose|h:Seq<RowsState>| #[trigger] prefix(initial,tree,id,rows@,h,step) && match out {
            Ok(s) => h.len()==rows.len()+1 && h.last()==s,
            Err(e) => h.len()<=rows.len() && step.ensures((h.last(),tree,id,&rows@[h.len()-1]),Err(e)),
        };
        assert forall|i:int| 0 <= i < h.len()-1 implies #[trigger] overlay_update::applied(h[i].0,h[i+1].0,
            &rows@[i],h[i].1,h[i+1].1,load,Ok(())) by {
            assert(step.ensures((h[i],tree,id,&rows@[i]),Ok(h[i+1])));
        }
    }
    out
}

fn two_ordered(tree:ObjectId,object:ObjectId,fail_first:bool,fail_second:bool) {
    use crate::mutation_replay::{self,prefix};
    let a = Mutation {key:vec![1u8],value:None}; let b = Mutation {key:vec![2u8],value:None};
    let rows = [a,b];
    assert(rows@[0].key@ =~= seq![1u8] && rows@[1].key@ =~= seq![2u8]);
    let step = |state:u8,base:Option<ObjectId>,row:ObjectId,m:&Mutation| -> (r:Result<u8,u8>)
        ensures r == if base != Some(tree) || row != object {Err(9u8)}
            else if state == 0 && m.key@ == seq![1u8] {if fail_first {Err(3u8)} else {Ok(1u8)}}
            else if state == 1 && m.key@ == seq![2u8] {if fail_second {Err(4u8)} else {Ok(2u8)}}
            else {Err(8u8)},
    {
        let Some(t) = base else {return Err(9);};
        if !tree.same(&t) || !row.same(&object) {return Err(9);}
        if m.key.len()!=1 {return Err(8);}
        let k = m.key[0];
        assert((k==1) == (m.key@ =~= seq![1u8]) && (k==2) == (m.key@ =~= seq![2u8]));
        if state==0 && k==1 {if fail_first {Err(3)} else {Ok(1)}}
        else if state==1 && k==2 {if fail_second {Err(4)} else {Ok(2)}} else {Err(8)}
    };
    let out = mutation_replay::run(0,Some(tree),object,&rows,step);
    proof {
        let h = choose|h:Seq<u8>| #[trigger] prefix(0u8,Some(tree),object,rows@,h,step) && match out {
            Ok(s) => h.len()==rows.len()+1 && h.last()==s,
            Err(e) => h.len()<=rows.len() && step.ensures((h.last(),Some(tree),object,&rows@[h.len()-1]),Err(e)),
        };
        assert(prefix(0u8,Some(tree),object,rows@,h,step));
        if h.len()>=2 {assert(step.ensures((h[0],Some(tree),object,&rows@[0]),Ok(h[1])));}
        if h.len()==3 {assert(step.ensures((h[1],Some(tree),object,&rows@[1]),Ok(h[2])));}
        assert(out == (if fail_first {Err(3u8)} else if fail_second {Err(4u8)} else {Ok(2u8)}));
    }
}

}
