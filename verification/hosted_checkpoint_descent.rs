//! A fetched handle is admitted by the production page reader at each hop.
use crate::{ObjectId,checkpoint_descent as walk,checkpoint_entries::Row,checkpoint_range::{Child,Page},
    checkpoint_page::{Handle,Node,Leaf,Branch},checkpoint_totals::NodeTotals,checkpoint_value::ValueSlot,checkpoint_walk::Contents};
use vstd::prelude::*;

verus! {
fn trace(root:ObjectId,child:ObjectId,owner:u64,bad_root:bool,bad_level:bool,refuse:bool,bad_summary:bool,query:u8)
    requires root != child,
{
    let totals = NodeTotals {entries:1,logical_bytes:1,quota_bytes:2};
    let read = |state:(u64,bool),k:ObjectId| -> (out:Result<((u64,bool),walk::Loaded),u8>)
        ensures if k == root && state == (owner,false) {
            out.is_ok() && out->Ok_0.0 == (owner,true) &&
            out->Ok_0.1.object == (if bad_root {child} else {root}) &&
            (out->Ok_0.1.node matches Node::Branch(b) && b.level == 1 && b.totals == totals && b.children.len()==1 &&
                b.children@[0].object == child && b.children@[0].lower_bound@ == seq![19u8] && b.children@[0].totals == totals &&
                b.children@[0].level == (if bad_level {1u16} else {0u16}))
        } else if k == child && state == (owner,true) {
            if refuse {out == Err(7u8)} else {
                out.is_ok() && out->Ok_0.0 == (owner,true) && out->Ok_0.1.object == child &&
                (out->Ok_0.1.node matches Node::Leaf(l) && l.entries.len()==1 && l.totals.logical_bytes==1 &&
                    l.totals.quota_bytes==2 && l.totals.entries==(if bad_summary {2u64} else {1u64}) &&
                    l.entries@[0].key@ == seq![19u8] && (l.entries@[0].value matches ValueSlot::Inline(d) && d@ == seq![23u8]))
            }
        } else {out == Err(9u8)},
    {
        if k.same(&root) && state.0 == owner && !state.1 {
            let p = Child {object:child,lower_bound:vec![19u8],level:if bad_level {1} else {0},totals};
            assert(p.lower_bound@ =~= seq![19u8]);
            Ok(((owner,true),Handle {object:if bad_root {child} else {root},node:Node::Branch(Branch {level:1,children:vec![p],totals})}))
        } else if k.same(&child) && state.0 == owner && state.1 {
            if refuse {Err(7)} else {
                let key = vec![19u8];let bytes = vec![23u8];
                assert(key@ =~= seq![19u8] && bytes@ =~= seq![23u8]);
                let row = Row {key,value:ValueSlot::Inline(bytes)};
                let measured = NodeTotals {entries:if bad_summary {2} else {1},logical_bytes:1,quota_bytes:2};
                Ok((state,Handle {object:child,node:Node::Leaf(Leaf {entries:vec![row],totals:measured})}))
            }
        } else {Err(9)}
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
            assert(!bad_root && !bad_level && all[1].0 == (owner,true) && (all[1].1 matches Page::Child(p) &&
                p.object == child && p.level == 0 && p.lower_bound@ == seq![19u8] && p.totals == totals));
            if path.len() > 1 {assert(walk::step(path[1],all[2],key@,read));assert(false);}
        }
        if bad_root {assert(out == Err(walk::Error::Mismatch(root)));}
        else if bad_level {assert(out == Err(walk::Error::Branch(root)));}
        else if refuse {assert(out == Err(walk::Error::Source(7u8)));}
        else if bad_summary {assert(out == Err(walk::Error::Mismatch(child)));}
        else {
            assert(path.len() == 1 && out.is_ok());
            let (s,rows) = choose|s:(u64,bool),rows:Vec<Row>| #[trigger] walk::accepted(at,s,Contents::Leaf(rows),read) && walk::slot(rows@,key@,out->Ok_0);
            assert(rows.len()==1 && walk::slot(rows@,key@,out->Ok_0));
            assert(crate::checkpoint_leaf_summary::ordered(rows@,1));
            assert((query==19) == (key@ =~= rows@[0].key@));
            assert(if query == 19 {out->Ok_0 matches Some(ValueSlot::Inline(d)) && d@ == seq![23u8]} else {out == Ok(None)});
        }
    }
}
fn decoded_leaf(owner:u64,root:ObjectId,record:&crate::ObjectRecord,version:crate::ObjectFormatVersion,key:&[u8])
    requires record.contents().0 == crate::ObjectKind::KvLeaf,
{
    use crate::checkpoint_record as physical;
    let validate = |_k:&[u8]| -> (out:Result<(),u8>) ensures out == Ok(()) {Ok(())};
    let read = |p:u64,id:ObjectId| -> (out:Result<(u64,walk::Loaded),u8>)
        ensures if p != owner || id != root {out == Err(9u8)} else {
            out matches Ok((after,h)) ==> after == owner && h.object == root && h.node is Leaf &&
                physical::ordered(h.node) && physical::parsed(record,h.node,validate)
        }
    {
        if p != owner || !id.same(&root) {return Err(9);}
        match physical::read(id,record,version,validate) {
            Ok(h) => {assert(h.node is Leaf); Ok((p,h))},
            Err(_) => Err(7),
        }
    };
    let result = walk::lookup(owner,Some(root),key,read);
    let ghost out = result;
    proof {
        reveal(walk::reached);reveal(walk::finished);
        let (path,at) = choose|path:Seq<walk::Hop<u64>>,at:(u64,walk::Address)|
            #[trigger] walk::reached(path,owner,root,at,key@,read) && walk::terminal(at,key@,read,out);
        if path.len() > 0 {
            assert(walk::step(path[0],if path.len()>1 {path[1].0} else {at},key@,read));
            assert(false);
        }
        assert(at == (owner,Page::Root(root)));
        match out {
            Ok(v) => {
                let (after,rows) = choose|p:u64,rows:Vec<Row>| #[trigger] walk::accepted(at,p,Contents::Leaf(rows),read) &&
                    walk::slot(rows@,key@,v);
                let h = choose|h:walk::Loaded| #[trigger] read.ensures((owner,root),Ok((after,h))) &&
                    crate::checkpoint_page::agrees(at.1,h) && h.node.contents() == Contents::Leaf(rows);
                assert(physical::parsed(record,h.node,validate) && h.node is Leaf && h.node->Leaf_0.entries == rows);
                assert(crate::checkpoint_leaf_summary::ordered(rows@,rows.len() as nat));
                assert forall|i:int| 0 <= i < rows.len() && (#[trigger] rows@[i]).key@ == key@ implies v == Some(rows@[i].value) by {}
                if v.is_none() {
                    assert forall|i:int| 0 <= i < rows.len() implies (#[trigger] rows@[i]).key@ != key@ by {}
                }
            },
            Err(e) => {assert(e is Source);}
        }
    }
}

}
