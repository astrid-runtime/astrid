//! Project the decoded page into the traversal after checking its scheduled summary.
use super::{
    checkpoint_leaf::Entry,
    checkpoint_range::{Child, Page},
    checkpoint_walk::Contents,
};
use vstd::prelude::*;

verus! {

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Leaf<V,T> {
    pub(super) entries: Vec<Entry<V>>,
    pub(super) totals: T,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Branch<I,T> {
    pub(super) level: u16,
    pub(super) children: Vec<Child<I,T>>,
    pub(super) totals: T,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Node<I,T,V> {
    Leaf(Leaf<V,T>),
    Branch(Branch<I,T>),
}
#[derive(Clone, Debug)]
pub(super) struct Handle<I,T,V> {
    pub(super) object:I,
    pub(super) node:Node<I,T,V>,
}

impl<I,T:Copy,V> Node<I,T,V> {
    pub(super) open spec fn height(&self) -> u16 {
        match self { Self::Leaf(_) => 0, Self::Branch(b) => b.level }
    }
    pub(super) open spec fn summary(&self) -> T {
        match self { Self::Leaf(l) => l.totals, Self::Branch(b) => b.totals }
    }
    pub(super) open spec fn lower(&self) -> Seq<u8> {
        match self {
            Self::Leaf(l) => if l.entries.len()==0 { Seq::empty() } else { l.entries@[0].key@ },
            Self::Branch(b) => if b.children.len()==0 { Seq::empty() } else { b.children@[0].lower_bound@ },
        }
    }
    pub(super) open spec fn contents(&self) -> Contents<I,T,V> {
        match self { Self::Leaf(l) => Contents::Leaf(l.entries), Self::Branch(b) => Contents::Branch(b.level,b.children) }
    }
    pub(super) const fn level(&self) -> (out:u16)
        ensures out == self.height(),
    { match self { Self::Leaf(_) => 0, Self::Branch(b) => b.level } }
    pub(super) const fn totals(&self) -> (out:T)
        ensures out == self.summary(),
    { match self { Self::Leaf(l) => l.totals, Self::Branch(b) => b.totals } }
    pub(super) fn minimum_key(&self) -> (out:&[u8])
        ensures out@ == self.lower(),
    {
        match self {
            Self::Leaf(l) => match l.entries.first() { None => &[], Some(e) => e.key.as_slice() },
            Self::Branch(b) => match b.children.first() { None => &[], Some(c) => c.lower_bound.as_slice() },
        }
    }
}

pub(super) open spec fn decoded<I,T,S,E,F:Fn(S,usize)->Result<(S,Vec<u8>,I,T),E>>(
    rows:Seq<Child<I,T>>, states:Seq<S>, first:S,last:S, level:u16,fetch:F,
) -> bool {
    &&& states.len() == rows.len()+1 && states[0] == first && states.last() == last
    &&& forall|i:int| 0 <= i < rows.len() ==> {
        let c = #[trigger] rows[i];
        &&& c.level as nat+1 == level
        &&& fetch.ensures((states[i],i as usize),Ok((states[i+1],c.lower_bound,c.object,c.totals)))
    }
}

/// Decode each indexed child once, and derive its level solely from this branch.
pub(super) fn children<I,T,S,E,F:Fn(S,usize)->Result<(S,Vec<u8>,I,T),E>,M:FnOnce()->E>(
    level:u16,count:usize,first:S,fetch:F,bad_level:M,
) -> (out:Result<(S,Vec<Child<I,T>>),E>)
    requires bad_level.requires(()),forall|s:S,i:usize| i < count ==> #[trigger] fetch.requires((s,i)),
    ensures match out {
        Ok(pair) => level > 0 && pair.1.len() == count &&
            exists|states:Seq<S>| #[trigger] decoded(pair.1@,states,first,pair.0,level,fetch),
        Err(e) => if level==0 { bad_level.ensures((),e) } else {
            exists|rows:Seq<Child<I,T>>,states:Seq<S>,s:S| rows.len() < count &&
                #[trigger] decoded(rows,states,first,s,level,fetch) && fetch.ensures((s,rows.len() as usize),Err(e))
        },
    },
{
    let Some(child_level) = level.checked_sub(1) else { return Err(bad_level()); };
    let mut rows = Vec::with_capacity(count);
    let mut cursor = first;
    let ghost mut states = seq![first];
    while rows.len() < count
        invariant rows.len() <= count, child_level as nat+1 == level, decoded(rows@,states,first,cursor,level,fetch),
            forall|s:S,i:usize| i < count ==> #[trigger] fetch.requires((s,i)),
        decreases count-rows.len(),
    {
        let ghost before = rows@;
        let ghost prior = states;
        let index = rows.len();
        let (next,lower_bound,object,totals) = match fetch(cursor,index) {
            Ok(row) => row,
            Err(e) => {
                assert(fetch.ensures((cursor,index),Err(e)));
                return Err(e);
            },
        };
        rows.push(Child { lower_bound, object, level:child_level, totals });
        proof {
            states = states.push(next);
            assert forall|i:int| 0 <= i < rows.len() implies ({
                let c = #[trigger] rows@[i];
                &&& c.level as nat+1 == level
                &&& fetch.ensures((states[i],i as usize),Ok((states[i+1],c.lower_bound,c.object,c.totals)))
            }) by {
                if i < index { assert(rows@[i] == before[i] && states[i+1] == prior[i+1]); }
            }
        }
        cursor = next;
    }
    assert(decoded(rows@,states,first,cursor,level,fetch));
    let result:Result<(S,Vec<Child<I,T>>),E> = Ok((cursor,rows));
    assert(result is Ok);
    assert(result->Ok_0 == (cursor,rows));
    assert(exists|path:Seq<S>| #[trigger] decoded(rows@,path,first,cursor,level,fetch));
    assert(level > 0 && rows.len() == count);
    assert((result->Ok_0).0 == cursor && (result->Ok_0).1 == rows);
    result
}

pub(super) open spec fn object<I,T>(page:Page<I,T>) -> I {
    match page { Page::Root(id) => id, Page::Child(c) => c.object }
}
pub(super) open spec fn agrees<I,T:Copy,V>(page:Page<I,T>,handle:Handle<I,T,V>) -> bool {
    match page {
        Page::Root(id) => id == handle.object,
        Page::Child(c) => c.object == handle.object && c.lower_bound@ == handle.node.lower() &&
            c.level == handle.node.height() && c.totals == handle.node.summary(),
    }
}

pub(super) fn read<I:Copy+Eq,T:Copy+Eq,V,E,F:FnOnce(I)->Result<Handle<I,T,V>,E>,M:FnOnce(I)->E>(
    page:&Page<I,T>,fetch:F,mismatch:M,
) -> (out:Result<Contents<I,T,V>,E>)
    requires fetch.requires((object(*page),)),mismatch.requires((object(*page),)),
        vstd::laws_eq::obeys_concrete_eq::<I>(),vstd::laws_eq::obeys_concrete_eq::<T>(),
    ensures match out {
        Ok(contents) => exists|h:Handle<I,T,V>| #[trigger] fetch.ensures((object(*page),),Ok(h)) &&
            agrees(*page,h) && contents == h.node.contents(),
        Err(e) => fetch.ensures((object(*page),),Err(e)) || (mismatch.ensures((object(*page),),e) &&
            exists|h:Handle<I,T,V>| #[trigger] fetch.ensures((object(*page),),Ok(h)) && !agrees(*page,h)),
    },
{
    let id = page.object();
    let h = fetch(id)?;
    let ghost source = h;
    assert(fetch.ensures((object(*page),),Ok(source)));
    let same_id = |a:&I,b:&I| -> (yes:bool) ensures yes == (*a == *b) {
        proof {reveal(vstd::laws_eq::obeys_concrete_eq);}
        I::eq(a,b)
    };
    let same_totals = |a:&T,b:&T| -> (yes:bool) ensures yes == (*a == *b) {
        proof {reveal(vstd::laws_eq::obeys_concrete_eq);}
        T::eq(a,b)
    };
    match admit(page,h,same_id,same_totals) {Some(body) => Ok(body), None => Err(mismatch(id))}
}

pub(super) fn admit<I:Copy,T:Copy,V,DI:FnOnce(&I,&I)->bool,DT:FnOnce(&T,&T)->bool>(page:&Page<I,T>,h:Handle<I,T,V>,
    equal_id:DI,equal_totals:DT) -> (out:Option<Contents<I,T,V>>)
    requires forall|a:&I,b:&I| #[trigger] equal_id.requires((a,b)),
        forall|a:&T,b:&T| #[trigger] equal_totals.requires((a,b)),
        forall|a:&I,b:&I,r:bool| #[trigger] equal_id.ensures((a,b),r) ==> r == (*a == *b),
        forall|a:&T,b:&T,r:bool| #[trigger] equal_totals.ensures((a,b),r) ==> r == (*a == *b),
    ensures out == if agrees(*page,h) {Some(h.node.contents())} else {None},
{
    let accepted = match page {
        Page::Root(expected) => equal_id(expected,&h.object),
        Page::Child(expected) => expected.matches(&h.object,h.node.minimum_key(),h.node.level(),&h.node.totals(),equal_id,equal_totals),
    };
    if !accepted { return None; }
    Some(match h.node {
        Node::Leaf(l) => Contents::Leaf(l.entries),
        Node::Branch(b) => Contents::Branch(b.level,b.children),
    })
}
}
