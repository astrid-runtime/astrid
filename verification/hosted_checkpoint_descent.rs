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
// The loader returns the same stale handle for any requested address.
fn stale_root(root:ObjectId,stale:ObjectId)
    requires root != stale,
{
    let fetch = |():(),_address:ObjectId| -> (out:Result<((),walk::Loaded),u8>)
        ensures out.is_ok() && out->Ok_0.1.object == stale {
        let totals = NodeTotals {entries:0,logical_bytes:0,quota_bytes:0};
        Ok(((),Handle {object:stale,node:Node::Leaf(Leaf {entries:Vec::new(),totals})}))
    };
    let key = [0u8];
    let result = walk::lookup((),Some(root),&key,fetch);
    let ghost out = result;
    proof {
        reveal(walk::reached); reveal(walk::finished);
        let (path,at) = choose|path:Seq<walk::Hop<()>>,at:((),walk::Address)|
            #[trigger] walk::reached(path,(),root,at,key@,fetch) && walk::terminal(at,key@,fetch,out);
        if path.len() != 0 {
            assert(walk::step(path[0],if path.len()>1 {path[1].0} else {at},key@,fetch));
            assert(false);
        }
        assert(out == Err(walk::Error::Mismatch(root)));
    }
}

#[verifier::rlimit(25)]
proof fn decoded_membership<V:Fn(&[u8])->Result<(),u8>>(record:&crate::ObjectRecord,h:walk::Loaded,rows:Vec<Row>,
    key:Seq<u8>,validate:V,v:Option<ValueSlot>)
    requires h.node is Leaf, h.node.contents() == Contents::Leaf(rows), crate::checkpoint_record::ordered(h.node),
        walk::slot(rows@,key,v), exists|src:walk::Loaded| #[trigger] crate::checkpoint_cache::image(src) == crate::checkpoint_cache::image(h) &&
            crate::checkpoint_record::parsed(record,src.node,validate),
    ensures exists|src:walk::Loaded| #[trigger] crate::checkpoint_record::parsed(record,src.node,validate) &&
        src.node is Leaf && (v.is_none() ==> forall|i:int| 0 <= i < src.node->Leaf_0.entries.len() ==>
            (#[trigger] src.node->Leaf_0.entries@[i]).key@ != key),
{
    use crate::checkpoint_cache::{image,entry};
    let src = choose|src:walk::Loaded| #[trigger] image(src) == image(h) && crate::checkpoint_record::parsed(record,src.node,validate);
    let encoded = src.node->Leaf_0.entries;
    assert(src.node is Leaf && h.node->Leaf_0.entries == rows);
    assert(crate::checkpoint_leaf_summary::ordered(rows@,rows.len() as nat));
    let ea = encoded@.map(|j:int,e| entry(e));
    let eb = rows@.map(|j:int,e| entry(e));
    assert(image(src).1 == crate::checkpoint_cache::Image::Leaf(ea,src.node->Leaf_0.totals));
    assert(image(h).1 == crate::checkpoint_cache::Image::Leaf(eb,h.node->Leaf_0.totals));
    assert(ea == eb);
    assert(ea.len() == encoded@.len());
    assert(eb.len() == rows@.len());
    assert(encoded.len() == rows.len());
    assert forall|i:int| 0 <= i < rows.len() && (#[trigger] rows@[i]).key@ == key implies v == Some(rows@[i].value) by {}
    assert forall|i:int| 0 <= i < encoded.len() && v.is_none() implies (#[trigger] encoded@[i]).key@ != key by {
        let a = encoded@.map(|j:int,e| entry(e));
        let b = rows@.map(|j:int,e| entry(e));
        assert(a[i] == b[i]);
        assert(rows@[i].key@ != key);
    }
}

#[verifier::rlimit(35)]
fn decoded_leaf(owner:u64,root:ObjectId,record:&crate::ObjectRecord,version:crate::ObjectFormatVersion,key:&[u8],warm:bool)
    requires vstd::laws_cmp::obeys_cmp::<ObjectId>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<ObjectId>(),
        record.contents().0 == crate::ObjectKind::KvLeaf,
{
    use crate::checkpoint_record as physical;
    use crate::checkpoint_cache::{Cache,image};
    let validate = |_k:&[u8]| -> (out:Result<(),u8>) ensures out == Ok(()) {Ok(())};
    let read = |p:u64,id:ObjectId| -> (out:Result<(u64,walk::Loaded),u8>)
        ensures if p != owner || id != root {out == Err(9u8)} else {
            out matches Ok((after,h)) ==> after == owner && h.object == root && h.node is Leaf &&
                physical::ordered(h.node) && exists|src:walk::Loaded| #[trigger] image(src) == image(h) &&
                    physical::parsed(record,src.node,validate)
        }
    {
        if p != owner || !id.same(&root) {return Err(9);}
        if warm {
            let mut cache = Cache::new(&p);
            let fresh = match cache.admit(id,record,version,validate) {Ok(h) => h,Err(_) => return Err(7)};
            let cached = cache.lookup(id,version,|_:&u64,_:ObjectId| -> (r:Result<crate::ObjectRecord,u8>)
                ensures r == Err(9u8) {Err(9)},validate);
            let hit = match cached {Ok(h) => h,Err(_) => {assert(false);return Err(9)}};
            assert(image(hit) == image(fresh));
            assert(exists|src:walk::Loaded| #[trigger] image(src) == image(hit) && physical::parsed(record,src.node,validate)) by {assert(image(fresh) == image(hit) && physical::parsed(record,fresh.node,validate));}
            return Ok((p,hit));
        }
        match physical::read(id,record,version,validate) {
            Ok(h) => {assert(h.node is Leaf); assert(exists|src:walk::Loaded| #[trigger] image(src) == image(h) && physical::parsed(record,src.node,validate)) by {assert(image(h) == image(h) && physical::parsed(record,h.node,validate));} Ok((p,h))},
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
                decoded_membership(record,h,rows,key@,validate,v);
            },
            Err(e) => {assert(e is Source);}
        }
    }
}

}
