//! Bind a content commit's lineage and state references to the root used for CAS.
use super::{ObjectId, ObjectReference, ReferenceKind, ReferenceLabel, RootState};
use vstd::prelude::*;

verus! {

pub(super) const PARENT: &[u8;6] = b"parent";
pub(super) const STATE: &[u8;5] = b"state";

pub(super) open spec fn references(before:Seq<ObjectReference>, after:Seq<ObjectReference>,
    expected:Option<RootState>, state:ObjectId) -> bool {
    &&& after.len() == before.len() + (if expected.is_some() { 2int } else { 1int })
    &&& after.take(before.len() as int) == before
    &&& after.last().fields() == (STATE@,state,ReferenceKind::Owns)
    &&& expected matches Some(root) ==> after[before.len() as int].fields() == (PARENT@,root.commit,ReferenceKind::Lineage)
}

pub(super) struct Candidate<P> {
    owner: P,
    expected: Option<RootState>,
    refs: Vec<ObjectReference>,
}

fn label(bytes:&[u8]) -> (out:ReferenceLabel)
    ensures out.value()@ == bytes@,
{
    let mut owned = Vec::with_capacity(bytes.len());
    owned.extend_from_slice(bytes);
    ReferenceLabel::new(owned)
}

impl<P> Candidate<P> {
    pub(super) closed spec fn parts(&self) -> (P,Option<RootState>,Vec<ObjectReference>) {
        (self.owner,self.expected,self.refs)
    }

    pub(super) fn new(owner:P, expected:Option<RootState>, mut refs:Vec<ObjectReference>, state:ObjectId)
        -> (out:Self)
        ensures out.parts().0 == owner, out.parts().1 == expected,
            references(refs@,out.parts().2@,expected,state),
    {
        let ghost prior = refs@;
        if let Some(previous) = expected {
            refs.push(ObjectReference::new(label(PARENT),previous.commit,ReferenceKind::Lineage));
        }
        refs.push(ObjectReference::owns(label(STATE),state));
        assert(refs@.take(prior.len() as int) =~= prior);
        Self {owner,expected,refs}
    }

    pub(super) fn seal<B,E,S>(self,seal:S) -> (out:Result<(P,Option<RootState>,ObjectId,B),E>)
        where S:FnOnce(Vec<ObjectReference>) -> Result<(ObjectId,B),E>,
        requires seal.requires((self.parts().2,)),
        ensures out matches Err(e) ==> seal.ensures((self.parts().2,),Err(e)),
            out matches Ok((p,r,id,b)) ==> p == self.parts().0 && r == self.parts().1
                && seal.ensures((self.parts().2,),Ok((id,b))),
    {
        let (commit,records) = seal(self.refs)?;
        Ok((self.owner,self.expected,commit,records))
    }
}
}
