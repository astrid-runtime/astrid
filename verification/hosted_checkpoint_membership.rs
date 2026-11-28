//! Derive checkpoint membership from finite paths through successful page reads.
use crate::{
    checkpoint_leaf::Entry,
    checkpoint_range::{Child,Page,scheduled},
    checkpoint_walk::Contents,
    hosted_checkpoint_walk::{contains,image,pending},
};
use vstd::prelude::*;

verus! {

pub(super) open spec fn stable<I,T,V,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>>(read:R) -> bool {
    forall|p:Page<I,T>,a:Contents<I,T,V>,b:Contents<I,T,V>|
        #[trigger] read.ensures((p,),Ok(a)) && #[trigger] read.ensures((p,),Ok(b)) ==> a == b
}

// The last element is the current page. Dropping it consumes one branch edge.
pub(super) open spec fn path<I,T,V,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>>(read:R,pages:Seq<Page<I,T>>,
    key:Seq<u8>,start:Seq<u8>,end:Seq<u8>) -> bool
    decreases pages.len(),
{
    if pages.len() == 0 { false }
    else if pages.len() == 1 {
        exists|rows:Vec<Entry<V>>| #[trigger] read.ensures((pages.last(),),Ok(Contents::Leaf(rows))) &&
            contains(rows@,rows@.len(),key,start,end)
    } else {
        &&& exists|h:u16,c:Vec<Child<I,T>>| #[trigger] read.ensures((pages.last(),),Ok(Contents::Branch(h,c))) &&
            scheduled(c@,0,start,end).contains(pages.drop_last().last())
        &&& path(read,pages.drop_last(),key,start,end)
    }
}

pub(super) open spec fn reachable<I,T,V,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>>(read:R,p:Page<I,T>,
    key:Seq<u8>,start:Seq<u8>,end:Seq<u8>) -> bool {
    exists|pages:Seq<Page<I,T>>| pages.len()>0 && pages.last()==p && #[trigger] path(read,pages,key,start,end)
}

pub(super) proof fn derive<I,T,V,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>>(read:R,key:Seq<u8>,start:Seq<u8>,end:Seq<u8>)
    requires stable(read),
    ensures image(read,|p:Page<I,T>| reachable(read,p,key,start,end),key,start,end),
{
    let has = |p:Page<I,T>| reachable(read,p,key,start,end);
    assert forall|p:Page<I,T>,rows:Vec<Entry<V>>| #[trigger] read.ensures((p,),Ok(Contents::Leaf(rows))) implies
        has(p) == contains(rows@,rows@.len(),key,start,end) by {
        if has(p) {
            let pages = choose|pages:Seq<Page<I,T>>| pages.len()>0 && pages.last()==p && #[trigger] path(read,pages,key,start,end);
            reveal_with_fuel(path,2);
        } else if contains(rows@,rows@.len(),key,start,end) {
            let pages = seq![p];
            assert(pages.last()==p);
            assert(path(read,pages,key,start,end));
        }
    }
    assert forall|p:Page<I,T>,h:u16,c:Vec<Child<I,T>>| #[trigger] read.ensures((p,),Ok(Contents::Branch(h,c))) implies
        has(p) == pending(scheduled(c@,0,start,end),has) by {
        let children = scheduled(c@,0,start,end);
        if has(p) {
            let pages = choose|pages:Seq<Page<I,T>>| pages.len()>0 && pages.last()==p && #[trigger] path(read,pages,key,start,end);
            let rest = pages.drop_last();
            reveal_with_fuel(path,2);
            assert(pages.len()>1);
            assert(rest.len() == pages.len()-1);
            assert(path(read,rest,key,start,end));
            assert(children.contains(rest.last()));
            let i = choose|i:int| 0<=i<children.len() && children[i]==rest.last();
            assert(rest.last() == children[i]);
            assert(reachable(read,children[i],key,start,end));
            assert(has(children[i]));
        } else if pending(children,has) {
            let i = choose|i:int| 0<=i<children.len() && has(#[trigger] children[i]);
            let rest = choose|r:Seq<Page<I,T>>| r.len()>0 && r.last()==children[i] && #[trigger] path(read,r,key,start,end);
            let pages = rest.push(p);
            assert(pages.drop_last() =~= rest);
            assert(pages.last()==p);
            assert(children.contains(rest.last()));
            assert(path(read,pages,key,start,end));
        }
    }
}
}
