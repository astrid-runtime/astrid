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

/// The cache fallback must address the transaction that supplied the hint.
pub(crate) struct CheckpointTarget<P> {
    owner:P,
    commit:ObjectId,
}

impl<P> CheckpointTarget<P> {
    pub(crate) closed spec fn binding(&self) -> (P,ObjectId) {(self.owner,self.commit)}

    pub(crate) fn publish<T,F:FnOnce(P,RootState)->T>(self,root:RootState,publish:F) -> (out:Option<T>)
        requires root.commit == self.binding().1 ==> publish.requires((self.binding().0,root)),
        ensures out.is_some() == (root.commit == self.binding().1),
            out matches Some(result) ==> publish.ensures((self.binding().0,root),result),
    {
        if self.commit.same(&root.commit) {Some(publish(self.owner,root))} else {None}
    }
}

impl<P,A> Declaration<P,A> {
    pub(super) closed spec fn payload(&self) -> Update<P> { self.update }
    pub(super) closed spec fn proof_source(&self) -> IdentityProof<A> { self.identity }

    pub(super) const fn update(&self) -> (u:&Update<P>)
        ensures *u == self.payload(),
    { &self.update }

    pub(super) fn checkpoint_target(&self) -> (target:CheckpointTarget<P>) where P:Clone,
        requires vstd::pervasive::obeys_clone_eq::<P>(),
        ensures target.binding() == (self.payload().principal,self.payload().commit),
    {
        proof {reveal(vstd::pervasive::obeys_clone_eq);}
        let owner = P::clone(&self.update.principal);
        assert(vstd::pervasive::cloned(self.update.principal,owner));
        CheckpointTarget {owner,commit:self.update.commit}
    }

    /// Only an engine-sealed declaration can attach a cache publication. Its
    /// factory receives the owner and commit from this declaration.
    pub(super) fn attach_checkpoint<C,F:FnOnce(&P,ObjectId)->C>(&self,slot:&mut Option<C>,make:F)
        requires self.proof_source() is Engine ==> make.requires((&self.payload().principal,self.payload().commit)),
        ensures match self.proof_source() {
            IdentityProof::Engine(_) => *final(slot) matches Some(hint) &&
                make.ensures((&self.payload().principal,self.payload().commit),hint),
            IdentityProof::Untrusted => *final(slot) == *old(slot),
        },
    {
        if matches!(self.identity,IdentityProof::Engine(_)) {
            *slot = Some(make(&self.update.principal,self.update.commit));
        }
    }

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

    /// Bind checkpoint release to the same declaration that supplied the rows.
    pub(super) fn admit_with_checkpoint<C,F:Fn(&A,&A)->bool,H:Fn(&ObjectRecord)->ObjectId>(
        self,current:&A,same:F,identify:H,checkpoint:&mut Option<C>,
    ) -> (out:Result<(Update<P>,Option<C>),(ObjectId,ObjectId)>)
        requires forall|bound:&A| #[trigger] same.requires((bound,current)),
            forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),
        ensures match out {
            Ok((update,hint)) => update == self.payload() && (
                (self.proof_source().compared(current,same,true) &&
                    hint == *old(checkpoint) && final(checkpoint).is_none()) ||
                (self.proof_source().compared(current,same,false) &&
                    hint.is_none() && *final(checkpoint) == *old(checkpoint) &&
                    forall|i:int| 0 <= i < update.records.len() ==> #[trigger] authentic(update.records@[i],identify))
            ),
            Err((name,computed)) => *final(checkpoint) == *old(checkpoint) &&
                self.proof_source().compared(current,same,false) &&
                exists|i:int| 0 <= i < self.payload().records.len() && name == self.payload().records@[i].0 &&
                    #[trigger] identify.ensures((&self.payload().records@[i].1,),computed) && computed.digest() != name.digest() &&
                    forall|prior:int| 0 <= prior < i ==> #[trigger] authentic(self.payload().records@[prior],identify),
        },
    {
        let (update,kind) = self.admit(current,same,identify)?;
        Ok((update,kind.take_checkpoint(checkpoint)))
    }
}
}
