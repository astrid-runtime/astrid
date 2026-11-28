//! An immutable overlay snapshot shares its exact root with every reader.
use super::{
    ObjectId, batch, checkpoint_totals::NodeTotals, checkpoint_value::ValueSlot,
    delta_mutation::Mutation, traversal::Node,
};
use std::sync::Arc;
use vstd::prelude::*;

verus! {
#[derive(Debug,Default)]
pub(crate) struct OverlayMap {
    pub(super) root:Option<Arc<Node>>,
}

impl OverlayMap {
    pub(crate) open spec fn ordered_snapshot(&self) -> bool { super::traversal::ordered(self.root) }

    pub(crate) open spec fn is_empty_snapshot(&self) -> bool { self.root.is_none() }

    pub(crate) fn empty() -> (out:Self)
        ensures out.is_empty_snapshot(),
    { Self {root:None} }

    pub(crate) open spec fn presence(&self,key:Seq<u8>) -> Option<bool> {batch::presence(self.root,key)}

    pub(crate) fn recover<C,E,L:Fn(C,Option<ObjectId>,&Vec<u8>)->Result<(C,Option<Vec<u8>>),E>+Copy,
        V:Fn(C,&ValueSlot)->Result<(C,Vec<u8>),E>+Copy>(self,initial:(C,NodeTotals),tree:Option<ObjectId>,id:ObjectId,
        rows:&[Mutation],lookup:L,value:V) -> (out:Result<(C,Self,NodeTotals),batch::Failure<E>>)
        requires self.ordered_snapshot(),forall|c:C,t:Option<ObjectId>,k:&Vec<u8>| #[trigger] lookup.requires((c,t,k)),
            forall|c:C,v:&ValueSlot| #[trigger] value.requires((c,v)),
        ensures out matches Ok((c,o,n)) ==> o.ordered_snapshot() && forall|k:Seq<u8>| #[trigger] o.presence(k) ==
            batch::after_rows(rows@,rows.len() as nat,k,self.presence(k)),
            exists|h:Seq<batch::State<C>>| #[trigger] batch::history((initial.0,self.root,initial.1),tree,id,rows@,lookup,value,h) &&
                match out {
                    Ok((c,o,n)) => h.len()==rows.len()+1 && h.last()==(c,o.root,n),
                    Err((i,e)) => i<rows.len() && h.len()==i+1 && batch::transition(h.last(),tree,id,&rows@[i as int],lookup,value,Err(e)),
                },
    {
        let (c,root,n)=batch::run((initial.0,self.root,initial.1),tree,id,rows,lookup,value)?;
        Ok((c,Self {root},n))
    }

    pub(crate) fn snapshot(&self) -> (out:Self)
        ensures out == *self,
    {
        let root = match &self.root {Some(n) => {let shared = Arc::clone(n); assert(shared == *n); Some(shared)},None => None};
        Self {root}
    }
}

impl Clone for OverlayMap {
    fn clone(&self) -> Self {self.snapshot()}
}
}
