//! Schedule authenticated B+-tree children in the order consumed by the range walk.
use super::encoding;
use vstd::prelude::*;

verus! {

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Child<I,T> {
    pub(super) lower_bound: Vec<u8>,
    pub(super) object: I,
    pub(super) level: u16,
    pub(super) totals: T,
}

impl<I,T> Child<I,T> {
    pub(super) fn matches(&self,object:&I,lower:&[u8],level:u16,totals:&T,
        equal_id:impl FnOnce(&I,&I)->bool,equal_totals:impl FnOnce(&T,&T)->bool) -> (ok:bool)
        requires equal_id.requires((&self.object,object)),equal_totals.requires((&self.totals,totals)),
            forall|r:bool| #[trigger] equal_id.ensures((&self.object,object),r) ==> r == (self.object == *object),
            forall|r:bool| #[trigger] equal_totals.ensures((&self.totals,totals),r) ==> r == (self.totals == *totals),
        ensures ok == (self.object == *object && self.lower_bound@ == lower@ &&
            self.level == level && self.totals == *totals),
    {
        if !equal_id(&self.object,object) || self.level != level || !equal_totals(&self.totals,totals) {return false;}
        matches!(encoding::bytewise_cmp(&self.lower_bound,lower),std::cmp::Ordering::Equal)
    }
}

pub(super) enum Page<I,T> {
    Root(I),
    Child(Child<I,T>),
}

impl<I:Copy,T> Page<I,T> {
    pub(super) fn object(&self) -> (id:I)
        ensures id == match self { Self::Root(root) => *root, Self::Child(child) => child.object },
    {
        match self { Self::Root(root) => *root, Self::Child(child) => child.object }
    }
}

pub(super) open spec fn selected<I,T>(children:Seq<Child<I,T>>, i:int, start:Seq<u8>, end:Seq<u8>) -> bool {
    &&& encoding::below(children[i].lower_bound@,end)
    &&& i+1 == children.len() || encoding::below(start,children[i+1].lower_bound@)
}

pub(super) open spec fn scheduled<I,T>(children:Seq<Child<I,T>>, i:nat, start:Seq<u8>, end:Seq<u8>) -> Seq<Page<I,T>>
    decreases children.len() - i,
{
    if i >= children.len() { Seq::empty() } else {
        let tail = scheduled(children,i+1,start,end);
        if selected(children,i as int,start,end) { tail.push(Page::Child(children[i as int])) } else { tail }
    }
}

/// The next sibling's lower bound is the exclusive upper fence. Move each selected
/// pointer into the stack with its authenticated summary intact.
pub(super) fn schedule<I,T>(input:Vec<Child<I,T>>, stack:&mut Vec<Page<I,T>>, start:&[u8], end:&[u8])
    ensures final(stack)@ == old(stack)@ + scheduled(input@,0,start@,end@),
{
    let ghost original = input@;
    let mut children = input;
    let Some(mut child) = children.pop() else { return; };
    let mut visit = encoding::visit_child(&child.lower_bound,None,start,end);
    loop
        invariant
            original == input@,
            children@ == original.take(children.len() as int),
            children.len() < original.len(),
            child == original[children.len() as int],
            visit == selected(original,children.len() as int,start@,end@),
            stack@ == old(stack)@ + scheduled(original,children.len() as nat + 1,start@,end@),
        decreases children.len(),
    {
        let ghost index = children.len() as nat;
        let prior = children.pop();
        let prior_selected = match &prior {
            Some(prev) => encoding::visit_child(&prev.lower_bound,Some(&child.lower_bound),start,end),
            None => false,
        };
        if visit { stack.push(Page::Child(child)); }
        assert(stack@ =~= old(stack)@ + scheduled(original,index,start@,end@));
        let Some(prev) = prior else { assert(index == 0); return; };
        assert(children@ =~= original.take(children.len() as int));
        child = prev;
        visit = prior_selected;
    }
}
}
