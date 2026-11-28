//! A selected child must be loaded with the full pointer from the previous page.
use crate::{ObjectId,checkpoint_descent as walk,checkpoint_entries::Row,checkpoint_range::{Child,Page},
    checkpoint_totals::NodeTotals,checkpoint_value::ValueSlot,checkpoint_walk::Contents};
use vstd::prelude::*;

verus! {
fn trace(root:ObjectId,child:ObjectId,owner:u64,bad_level:bool,refuse:bool,query:u8)
    requires root != child,
{
    let totals = NodeTotals {entries:1,logical_bytes:1,quota_bytes:2};
    let read = |state:(u64,bool),page:&walk::Address| -> (out:Result<((u64,bool),walk::Body),u8>)
        ensures match page {
            Page::Root(k) if *k == root && state == (owner,false) => {
                out.is_ok() && out->Ok_0.0 == (owner,true) &&
                (out->Ok_0.1 matches Contents::Branch(h,c) && h == 1 && c.len()==1 &&
                    c@[0].object == child && c@[0].lower_bound@ == seq![19u8] && c@[0].totals == totals &&
                    c@[0].level == (if bad_level {1u16} else {0u16}))
            },
            Page::Child(p) if p.object == child && p.level == 0 && p.totals == totals && p.lower_bound@ == seq![19u8] && state == (owner,true) => {
                if refuse {out == Err(7u8)} else {
                    out.is_ok() && out->Ok_0.0 == (owner,true) && (out->Ok_0.1 matches Contents::Leaf(rows) &&
                        rows.len()==1 && rows@[0].key@ == seq![19u8] && (rows@[0].value matches ValueSlot::Inline(d) && d@ == seq![23u8]))
                }
            },
            _ => out == Err(9u8),
        },
    {
        match page {
            Page::Root(k) if k.same(&root) && state.0 == owner && !state.1 => {
                let p = Child {object:child,lower_bound:vec![19u8],level:if bad_level {1} else {0},totals};
                assert(p.lower_bound@ =~= seq![19u8]);
                Ok(((owner,true),Contents::Branch(1,vec![p])))
            },
            Page::Child(p) => {
                let same = p.lower_bound.len()==1 && p.lower_bound[0]==19;
                assert(same == (p.lower_bound@ =~= seq![19u8]));
                if !p.object.same(&child) || p.level != 0 || !same || p.totals.entries!=1 ||
                    p.totals.logical_bytes!=1 || p.totals.quota_bytes!=2 || state.0!=owner || !state.1 {Err(9)}
                else if refuse {Err(7)} else {
                    let k = vec![19u8]; let v = vec![23u8];
                    assert(k@ =~= seq![19u8] && v@ =~= seq![23u8]);
                    Ok((state,Contents::Leaf(vec![Row {key:k,value:ValueSlot::Inline(v)}])))
                }
            },
            _ => Err(9),
        }
    };
    let key = [query];
    let result = walk::lookup((owner,false),Some(root),&key,read);
    let ghost out = result;
    proof {
        reveal(walk::reached);reveal(walk::finished);
        let (path,at) = choose|path:Seq<walk::Hop<(u64,bool)>>,at:((u64,bool),walk::Address)|
            #[trigger] walk::reached(path,(owner,false),root,at,key@,read) && walk::terminal(at,key@,read,out);
        let all = path.map(|i:int,h:walk::Hop<(u64,bool)>| h.0).push(at);
        if path.len() > 0 {
            assert(walk::step(path[0],all[1],key@,read));
            assert(!bad_level && all[1].0 == (owner,true) && (all[1].1 matches Page::Child(p) &&
                p.object == child && p.level == 0 && p.lower_bound@ == seq![19u8] && p.totals == totals));
            if path.len() > 1 {assert(walk::step(path[1],all[2],key@,read));assert(false);}
        }
        if bad_level {assert(out == Err(walk::Error::Branch(root)));}
        else if refuse {assert(out == Err(walk::Error::Source(7u8)));}
        else {
            assert(path.len() == 1 && out.is_ok());
            let (s,rows) = choose|s:(u64,bool),rows:Vec<Row>|
                #[trigger] read.ensures((at.0,&at.1),Ok((s,Contents::Leaf(rows)))) && walk::slot(rows@,key@,out->Ok_0);
            assert(rows.len()==1 && walk::slot(rows@,key@,out->Ok_0));
            assert(crate::checkpoint_leaf_summary::ordered(rows@,1));
            assert((query==19) == (key@ =~= rows@[0].key@));
            assert(if query == 19 {out->Ok_0 matches Some(ValueSlot::Inline(d)) && d@ == seq![23u8]} else {out == Ok(None)});
        }
    }
}
}
