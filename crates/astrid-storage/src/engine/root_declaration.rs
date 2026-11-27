//! Owner, CAS expectation, target and immutable rows carried through identity admission.
#[cfg(verus_keep_ghost)]
use super::transaction_records::authentic;
use super::transaction_records::{Admission, IdentityProof};
use super::{ObjectId, ObjectRecord, RootState};
use vstd::prelude::*;

verus! {
#[derive(Debug,PartialEq,Eq)]
pub(super) struct Update<P> {
    pub(super) principal:P,
    pub(super) expected:Option<RootState>,
    pub(super) commit:ObjectId,
    pub(super) records:Vec<(ObjectId,ObjectRecord)>,
}

#[derive(Debug)]
pub(super) struct Declaration<P,A> {
    update:Update<P>,
    identity:IdentityProof<A>,
}

impl<P,A> Declaration<P,A> {
    pub(super) closed spec fn payload(&self) -> Update<P> { self.update }
    pub(super) closed spec fn proof_source(&self) -> IdentityProof<A> { self.identity }

    pub(super) const fn update(&self) -> (u:&Update<P>)
        ensures *u == self.payload(),
    { &self.update }

    pub(super) fn is_sealed(&self) -> (sealed:bool)
        ensures sealed == (self.proof_source() is Engine),
    { matches!(self.identity,IdentityProof::Engine(_)) }

    /// The native identity session provides the authority paired with its hasher.
    pub(super) fn sealed(update:Update<P>,authority:A) -> (out:Self)
        ensures out.payload() == update, out.proof_source() == IdentityProof::Engine(authority),
    { Self {update,identity:IdentityProof::Engine(authority)} }

    pub(super) const fn untrusted(principal:P,expected:Option<RootState>,commit:ObjectId,records:Vec<(ObjectId,ObjectRecord)>)
        -> (out:Self)
        ensures out.payload() == (Update { principal,expected,commit,records }), out.proof_source() is Untrusted,
    {
        Self {update:Update {principal,expected,commit,records},identity:IdentityProof::Untrusted}
    }

    pub(super) fn admit<F:Fn(&A,&A)->bool,H:Fn(&ObjectRecord)->ObjectId>(self,current:&A,same:F,identify:H)
        -> (out:Result<(Update<P>,Admission),(ObjectId,ObjectId)>)
        requires forall|bound:&A| #[trigger] same.requires((bound,current)),
            forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),
        ensures match out {
            Ok((update,kind)) => update == self.payload() && match kind {
                Admission::SameEngine => self.proof_source().compared(current,same,true),
                Admission::Rechecked => self.proof_source().compared(current,same,false) &&
                    forall|i:int| 0 <= i < update.records.len() ==> #[trigger] authentic(update.records@[i],identify),
            },
            Err((name,computed)) => self.proof_source().compared(current,same,false) &&
                exists|i:int| 0 <= i < self.payload().records.len() && name == self.payload().records@[i].0 &&
                    #[trigger] identify.ensures((&self.payload().records@[i].1,),computed) && computed.digest() != name.digest() &&
                    forall|j:int| 0 <= j < i ==> #[trigger] authentic(self.payload().records@[j],identify),
        },
    {
        let admission = self.identity.admit(current,same,&self.update.records,identify)?;
        Ok((self.update,admission))
    }
}
}
