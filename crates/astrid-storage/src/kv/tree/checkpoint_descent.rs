//! Follow one key from its requested root through checked child pointers.
use super::{
    ObjectId,
    checkpoint_page::{self, Handle},
    checkpoint_point as point,
    checkpoint_range::Page,
    checkpoint_totals::NodeTotals,
    checkpoint_value::ValueSlot,
    checkpoint_walk::Contents,
};
#[cfg(verus_keep_ghost)]
use super::{
    checkpoint_entries::Row, checkpoint_leaf_summary, checkpoint_range::Child, checkpoint_summary,
    encoding,
};
use vstd::prelude::*;

verus! {
#[cfg(verus_keep_ghost)]
type Pointer = Child<ObjectId,NodeTotals>;
#[cfg(verus_keep_ghost)]
pub(super) type Address = Page<ObjectId,NodeTotals>;
pub(super) type Loaded = Handle<ObjectId,NodeTotals,ValueSlot>;
#[cfg(verus_keep_ghost)]
pub(super) type Body = Contents<ObjectId,NodeTotals,ValueSlot>;
pub(super) enum Error<E> { Source(E), Mismatch(ObjectId), Branch(ObjectId) }

pub(super) open spec fn accepted<S,E,R:Fn(S,ObjectId)->Result<(S,Loaded),E>>(at:(S,Address),next:S,body:Body,read:R) -> bool {
    exists|handle:Loaded| #[trigger] read.ensures((at.0,id(at.1)),Ok((next,handle))) &&
        checkpoint_page::agrees(at.1,handle) && handle.node.contents() == body
}

pub(super) open spec fn rank(p:Address) -> nat {
    match p {Page::Root(_) => u16::MAX as nat+1,Page::Child(c) => c.level as nat}
}
pub(super) open spec fn id(p:Address) -> ObjectId {
    match p {Page::Root(id) => id,Page::Child(c) => c.object}
}
pub(super) open spec fn routes(rows:Seq<Pointer>,key:Seq<u8>,i:int) -> bool {
    &&& 0 <= i < rows.len() && i == point::index(rows,key)
    &&& checkpoint_summary::ordered(rows,rows.len()) ==> {
        &&& forall|j:int| 0 <= j <= i && i > 0 ==> !encoding::below(key,(#[trigger] rows[j]).lower_bound@)
        &&& forall|j:int| i < j < rows.len() ==> encoding::below(key,(#[trigger] rows[j]).lower_bound@)
    }
}
pub(super) open spec fn level_ok(p:Address,level:u16,child:Pointer) -> bool {
    child.level as nat+1 == level && (p matches Page::Child(c) ==> level == c.level)
}
pub(super) open spec fn slot(rows:Seq<Row>,key:Seq<u8>,out:Option<ValueSlot>) -> bool {
    &&& out matches Some(v) ==> exists|i:int| 0 <= i < rows.len() && (#[trigger] rows[i]).key@ == key && rows[i].value == v
    &&& checkpoint_leaf_summary::ordered(rows,rows.len()) ==> forall|i:int| 0 <= i < rows.len() &&
        (#[trigger] rows[i]).key@ == key ==> out == Some(rows[i].value)
}
pub(super) open spec fn edge(from:Address,to:Address,key:Seq<u8>,h:u16,rows:Vec<Pointer>,i:int) -> bool {
    routes(rows@,key,i) && level_ok(from,h,rows@[i]) && to == Page::Child(rows@[i])
}
#[cfg(verus_keep_ghost)]
pub(super) type Hop<S> = ((S,Address),u16,Vec<Pointer>,int);
pub(super) open spec fn step<S,E,R:Fn(S,ObjectId)->Result<(S,Loaded),E>>(
    hop:Hop<S>,to:(S,Address),key:Seq<u8>,read:R) -> bool {
    &&& accepted(hop.0,to.0,Contents::Branch(hop.1,hop.2),read)
    &&& edge(hop.0.1,to.1,key,hop.1,hop.2,hop.3)
}
#[verifier::opaque]
pub(super) open spec fn reached<S,E,R:Fn(S,ObjectId)->Result<(S,Loaded),E>>(
    path:Seq<Hop<S>>,initial:S,root:ObjectId,at:(S,Address),key:Seq<u8>,read:R) -> bool {
    &&& (if path.len()==0 {at} else {path[0].0}) == (initial,Page::Root(root))
    &&& forall|i:int| 0 <= i < path.len() ==> step(#[trigger] path[i],if i+1 < path.len() {path[i+1].0} else {at},key,read)
}
pub(super) open spec fn terminal<S,E,R:Fn(S,ObjectId)->Result<(S,Loaded),E>>(at:(S,Address),key:Seq<u8>,read:R,
    out:Result<Option<ValueSlot>,Error<E>>) -> bool {
    match out {
        Ok(v) => exists|s:S,rows:Vec<Row>| #[trigger] accepted(at,s,Contents::Leaf(rows),read) && slot(rows@,key,v),
        Err(Error::Source(e)) => read.ensures((at.0,id(at.1)),Err(e)),
        Err(Error::Mismatch(k)) => k == id(at.1) && exists|s:S,h:Loaded| #[trigger] read.ensures((at.0,k),Ok((s,h))) && !checkpoint_page::agrees(at.1,h),
        Err(Error::Branch(k)) => k == id(at.1) && exists|s:S,h:u16,rows:Vec<Pointer>|
            #[trigger] accepted(at,s,Contents::Branch(h,rows),read) &&
            (rows.len()==0 || exists|i:int| #[trigger] routes(rows@,key,i) && !level_ok(at.1,h,rows@[i])),
    }
}
#[verifier::opaque]
pub(super) open spec fn finished<S,E,R:Fn(S,ObjectId)->Result<(S,Loaded),E>>(
    initial:S,root:ObjectId,key:Seq<u8>,read:R,out:Result<Option<ValueSlot>,Error<E>>) -> bool {
    exists|path:Seq<Hop<S>>,at:(S,Address)| #[trigger] reached(path,initial,root,at,key,read) && terminal(at,key,read,out)
}

proof fn append<S,E,R:Fn(S,ObjectId)->Result<(S,Loaded),E>>(path:Seq<Hop<S>>,initial:S,root:ObjectId,hop:Hop<S>,
    to:(S,Address),key:Seq<u8>,read:R)
    requires reached(path,initial,root,hop.0,key,read),step(hop,to,key,read),
    ensures reached(path.push(hop),initial,root,to,key,read),
{
    reveal(reached);
    let grown = path.push(hop);
    assert forall|j:int| 0 <= j < grown.len() implies step(#[trigger] grown[j],
        if j+1 < grown.len() {grown[j+1].0} else {to},key,read) by {
        if j < path.len() {assert(step(path[j],if j+1 < path.len() {path[j+1].0} else {hop.0},key,read));}
    }
}
proof fn finish<S,E,R:Fn(S,ObjectId)->Result<(S,Loaded),E>>(path:Seq<Hop<S>>,initial:S,root:ObjectId,at:(S,Address),
    key:Seq<u8>,read:R,out:Result<Option<ValueSlot>,Error<E>>)
    requires reached(path,initial,root,at,key,read),terminal(at,key,read,out),
    ensures finished(initial,root,key,read,out),
{reveal(finished);}

pub(super) fn lookup<S,E,R:Fn(S,ObjectId)->Result<(S,Loaded),E>>(initial:S,root:Option<ObjectId>,key:&[u8],read:R)
    -> (out:Result<Option<ValueSlot>,Error<E>>)
    requires forall|s:S,k:ObjectId| #[trigger] read.requires((s,k)),
    ensures match root {None => out == Ok(None),Some(r) => finished(initial,r,key@,read,out)},
{
    let Some(first) = root else {return Ok(None);};
    let mut page = Page::Root(first);
    let mut state = initial;
    let ghost mut path = Seq::<Hop<S>>::empty();
    assert(reached(path,initial,first,(state,page),key@,read)) by {reveal(reached);}
    loop
        invariant root == Some(first), reached(path,initial,first,(state,page),key@,read),
        forall|s:S,k:ObjectId| #[trigger] read.requires((s,k)),
        decreases rank(page),
    {
        let ghost at = (state,page);
        let address = page.object();
        assert(address == id(page));
        let (next,loaded) = match read(state,address) {
            Ok(pair) => pair,
            Err(e) => {
                let result = Err(Error::Source(e));
                proof {finish(path,initial,first,at,key@,read,result);}
                return result;
            }
        };
        let ghost handle = loaded;
        let Some(body) = checkpoint_page::admit(&page,loaded,ObjectId::same,
            |a:&NodeTotals,b:&NodeTotals| -> (same:bool) ensures same == (*a == *b) {
                a.entries == b.entries && a.logical_bytes == b.logical_bytes && a.quota_bytes == b.quota_bytes
            }) else {
            let result = Err(Error::Mismatch(address));
            proof {finish(path,initial,first,at,key@,read,result);}
            return result;
        };
        assert(read.ensures((at.0,id(at.1)),Ok((next,handle))));
        assert(accepted(at,next,body,read));
        match body {
            Contents::Leaf(rows) => {
                let ghost leaf = rows;
                assert(accepted(at,next,Contents::Leaf(leaf),read));
                let v = point::leaf(rows,key);
                let result = Ok(v);
                assert(slot(leaf@,key@,v));
                proof {finish(path,initial,first,at,key@,read,result);}
                return result;
            },
            Contents::Branch(h,mut children) => {
                let ghost original = children;
                assert(accepted(at,next,Contents::Branch(h,original),read));
                let i = point::child(&children,key);
                if children.is_empty() {
                    let result = Err(Error::Branch(page.object()));
                    proof {finish(path,initial,first,at,key@,read,result);}
                    return result;
                }
                let child = children.swap_remove(i);
                assert(routes(original@,key@,i as int));
                if u32::from(child.level).saturating_add(1) != u32::from(h) || matches!(&page, Page::Child(c) if c.level != h) {
                    let result = Err(Error::Branch(page.object()));
                    proof {finish(path,initial,first,at,key@,read,result);}
                    return result;
                }
                assert(level_ok(at.1,h,original@[i as int]) && child == original@[i as int]);
                state = next;
                page = Page::Child(child);
                proof {
                    assert(edge(at.1,page,key@,h,original,i as int));
                    assert(accepted(at,state,Contents::Branch(h,original),read));
                    let hop = (at,h,original,i as int);
                    assert(step(hop,(state,page),key@,read));
                    append(path,initial,first,hop,(state,page),key@,read);
                    path = path.push(hop);
                };
            },
        }
    }
}
}
