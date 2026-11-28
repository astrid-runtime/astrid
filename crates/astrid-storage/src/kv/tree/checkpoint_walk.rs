//! Depth-first range traversal over authenticated, decoded checkpoint pages.
#[cfg(verus_keep_ghost)]
use super::{
    checkpoint_leaf::visited,
    checkpoint_progress::{branch_progress, leaf_progress, rank},
    checkpoint_range::scheduled,
    encoding,
};
use super::{
    checkpoint_leaf::{self, Entry},
    checkpoint_range::{self, Child, Page},
};
use vstd::prelude::*;

verus! {

pub(super) enum Contents<I,T,V> {
    Leaf(Vec<Entry<V>>),
    Branch(u16,Vec<Child<I,T>>),
}

pub(super) open spec fn initial<I,T>(root:Option<I>) -> Seq<Page<I,T>> {
    match root { Some(id) => seq![Page::Root(id)], None => Seq::empty() }
}

// A successful step either consumes one full decoded leaf or replaces the
// top branch by its selected children. No other pending page may change.
pub(super) open spec fn step<I,T,V,S,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>,F:Fn(S,Entry<V>)->Result<S,E>>(
    stack:Seq<Page<I,T>>,state:S,next:Seq<Page<I,T>>,after:S,start:Seq<u8>,end:Seq<u8>,read:R,visit:F,
) -> bool {
    stack.len()>0 && exists|contents:Contents<I,T,V>| #[trigger] read.ensures((stack.last(),),Ok(contents)) &&
        match contents {
            Contents::Leaf(rows) => next == stack.drop_last() &&
                visited(rows@,rows@.len(),start,end,state,after,visit),
            Contents::Branch(_,children) => after == state &&
                next == stack.drop_last()+scheduled(children@,0,start,end),
        }
}

#[cfg(verus_keep_ghost)]
pub(super) type History<I,T,S> = Seq<(Seq<Page<I,T>>,S)>;

pub(super) open spec fn reached<I,T,V,S,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>,F:Fn(S,Entry<V>)->Result<S,E>>(
    path:History<I,T,S>,root:Option<I>,first:S,stack:Seq<Page<I,T>>,state:S,start:Seq<u8>,end:Seq<u8>,read:R,visit:F,
) -> bool {
    let all = path.push((stack,state));
    &&& all[0] == (initial(root),first)
    &&& forall|i:int| 0 <= i < path.len() ==> step((#[trigger] all[i]).0,all[i].1,all[i+1].0,all[i+1].1,start,end,read,visit)
}

pub(super) open spec fn failed<I,T,V,S,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>,F:Fn(S,Entry<V>)->Result<S,E>>(
    stack:Seq<Page<I,T>>,state:S,start:Seq<u8>,end:Seq<u8>,read:R,visit:F,e:E,
) -> bool {
    stack.len()>0 && (read.ensures((stack.last(),),Err(e)) ||
        exists|rows:Vec<Entry<V>>,i:int,s:S| #[trigger] read.ensures((stack.last(),),Ok(Contents::Leaf(rows))) &&
            0 <= i < rows.len() && visited(rows@,i as nat,start,end,state,s,visit) &&
            encoding::range_contains(start,end,rows@[i].key@) && #[trigger] visit.ensures((s,rows@[i]),Err(e)))
}

proof fn advance<I,T,V,S,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>,F:Fn(S,Entry<V>)->Result<S,E>>(
    path:History<I,T,S>,root:Option<I>,first:S,before:Seq<Page<I,T>>,prior:S,after:Seq<Page<I,T>>,state:S,start:Seq<u8>,end:Seq<u8>,read:R,visit:F)
    requires reached(path,root,first,before,prior,start,end,read,visit),step(before,prior,after,state,start,end,read,visit),
    ensures reached(path.push((before,prior)),root,first,after,state,start,end,read,visit),
{
    let old = path.push((before,prior));
    let all = old.push((after,state));
    assert forall|i:int| 0 <= i < old.len() implies step((#[trigger] all[i]).0,all[i].1,all[i+1].0,all[i+1].1,start,end,read,visit) by {
        assert(all[i] == old[i]);
        if i < path.len() {
            assert(all[i+1] == old[i+1]);
        } else {
            assert(all[i] == (before,prior));
            assert(all[i+1] == (after,state));
            assert(step(before,prior,after,state,start,end,read,visit));
        }
    }
}

pub(super) open spec fn completed<I,T,V,S,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>,F:Fn(S,Entry<V>)->Result<S,E>>(
    result:Result<S,E>,root:Option<I>,first:S,start:Seq<u8>,end:Seq<u8>,read:R,visit:F) -> bool {
    match result {
        Ok(s) => exists|n:History<I,T,S>| #[trigger] reached(n,root,first,Seq::empty(),s,start,end,read,visit),
        Err(e) => exists|n:History<I,T,S>,stack:Seq<Page<I,T>>,s:S|
            #[trigger] reached(n,root,first,stack,s,start,end,read,visit) && failed(stack,s,start,end,read,visit,e),
    }
}

proof fn finish<I,T,V,S,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>,F:Fn(S,Entry<V>)->Result<S,E>>(
    path:History<I,T,S>,root:Option<I>,first:S,state:S,start:Seq<u8>,end:Seq<u8>,read:R,visit:F)
    requires reached(path,root,first,Seq::empty(),state,start,end,read,visit),
    ensures completed(Ok(state),root,first,start,end,read,visit),
{
    let r:Result<S,E> = Ok(state);
    assert(r is Ok);
    assert(r->Ok_0 == state);
    reveal(completed);
    assert(completed(Ok(state),root,first,start,end,read,visit) == (exists|k:History<I,T,S>| #[trigger] reached(k,root,first,Seq::empty(),state,start,end,read,visit)));
    assert(exists|k:History<I,T,S>| #[trigger] reached(k,root,first,Seq::empty(),state,start,end,read,visit));
}

proof fn stop<I,T,V,S,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>,F:Fn(S,Entry<V>)->Result<S,E>>(
    path:History<I,T,S>,root:Option<I>,first:S,stack:Seq<Page<I,T>>,state:S,e:E,start:Seq<u8>,end:Seq<u8>,read:R,visit:F)
    requires reached(path,root,first,stack,state,start,end,read,visit), failed(stack,state,start,end,read,visit,e),
    ensures completed(Err(e),root,first,start,end,read,visit),
{
    assert(exists|k:History<I,T,S>,s:Seq<Page<I,T>>,v:S| #[trigger] reached(k,root,first,s,v,start,end,read,visit) &&
        failed(s,v,start,end,read,visit,e));
}
#[verifier::loop_isolation(false)]
pub(super) fn fold<I,T,V,S,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>,F:Copy+Fn(S,Entry<V>)->Result<S,E>>(
    root:Option<I>,start:&[u8],end:&[u8],first:S,read:R,visit:F,
) -> (result:Result<S,E>)
    requires forall|p:Page<I,T>| #[trigger] read.requires((p,)),
        forall|p:Page<I,T>,h:u16,c:Vec<Child<I,T>>| #[trigger] read.ensures((p,),Ok(Contents::Branch(h,c))) ==>
            h > 0 && (p matches Page::Child(child) ==> child.level == h) &&
            forall|i:int| 0 <= i < c.len() ==> (#[trigger] c@[i]).level as nat+1 == h,
        forall|n:History<I,T,S>,stack:Seq<Page<I,T>>,s:S,rows:Vec<Entry<V>>,i:int,prior:S|
            #[trigger] reached(n,root,first,stack,s,start@,end@,read,visit) && stack.len()>0 &&
            #[trigger] read.ensures((stack.last(),),Ok(Contents::Leaf(rows))) &&
            0 <= i < rows.len() && #[trigger] visited(rows@,i as nat,start@,end@,s,prior,visit) &&
            encoding::range_contains(start@,end@,rows@[i].key@) ==> visit.requires((prior,rows@[i])),
    ensures completed(result,root,first,start@,end@,read,visit),
{
    let mut stack = Vec::new();
    if let Some(id) = root { stack.push(Page::Root(id)); }
    assert(stack@ =~= initial(root));
    let mut state = first;
    let ghost mut n:History<I,T,S> = Seq::empty();
    loop
        invariant reached(n,root,first,stack@,state,start@,end@,read,visit),
        decreases rank(stack@),
    {
        let ghost before = stack@;
        let ghost prior = state;
        let Some(page) = stack.pop() else {
            assert(before =~= Seq::empty());
            assert(reached(n,root,first,Seq::empty(),state,start@,end@,read,visit));
            proof { finish(n,root,first,state,start@,end@,read,visit); }
            return Ok(state);
        };
        assert(before =~= stack@.push(page));
        let contents = match read(page) {
            Ok(contents) => contents,
            Err(e) => { assert(failed(before,prior,start@,end@,read,visit,e)); proof { stop(n,root,first,before,prior,e,start@,end@,read,visit); } return Err(e); },
        };
        match contents {
            Contents::Leaf(rows) => {
                proof { leaf_progress(stack@,page); }
                match checkpoint_leaf::visit(rows,start,end,state,visit) {
                    Ok(after) => { state = after; },
                    Err(e) => { assert(failed(before,prior,start@,end@,read,visit,e)); proof { stop(n,root,first,before,prior,e,start@,end@,read,visit); } return Err(e); },
                }
            }
            Contents::Branch(_level,children) => {
                assert(read.ensures((page,),Ok(Contents::Branch(_level,children))));
                assert(page matches Page::Child(c) ==> c.level == _level);
                proof { branch_progress(stack@,page,children,_level,start@,end@); }
                checkpoint_range::schedule(children,&mut stack,start,end);
            }
        }
        assert(step(before,prior,stack@,state,start@,end@,read,visit));
        proof { advance(n,root,first,before,prior,stack@,state,start@,end@,read,visit); }
        proof { n = n.push((before,prior)); };
    }
}
}
