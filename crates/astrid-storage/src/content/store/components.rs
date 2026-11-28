//! Interpret each owner-state relation before handing its target to storage.
use super::component_labels::{CONTENT, KV, WORKSPACE};
use super::{ObjectId, ObjectReference, RootState};
use vstd::prelude::*;

verus! {
#[derive(Clone,Copy)]
pub(super) enum Charge { Kv, Workspace }

#[cfg(verus_keep_ghost)]
pub(super) ghost enum Observation<C> { Catalog(C), Bytes(u64), Preserved }

pub(super) struct Components<C> {
    pub(super) catalog:Option<C>,
    pub(super) other_bytes:u64,
    pub(super) preserved:Vec<ObjectReference>,
}

pub(super) enum Error<E> { NotOwning, Overflow, Storage(E) }

pub(super) open spec fn workspace(label:Seq<u8>) -> bool {
    label.len() >= WORKSPACE@.len() && label.take(WORKSPACE@.len() as int) == WORKSPACE@
}

pub(super) open spec fn last_catalog<C>(obs:Seq<Observation<C>>) -> Option<C>
    decreases obs.len(),
{
    if obs.len() == 0 {None} else {
        match obs.last() { Observation::Catalog(c) => Some(c), _ => last_catalog(obs.drop_last()) }
    }
}

pub(super) open spec fn total<C>(obs:Seq<Observation<C>>) -> nat
    decreases obs.len(),
{
    if obs.len() == 0 {0} else { total(obs.drop_last()) + match obs.last() { Observation::Bytes(n) => n as nat, _ => 0 } }
}

pub(super) open spec fn accepted<P,C,E,F,Q>(owner:&P,root:RootState,r:&ObjectReference,o:Observation<C>,catalog:F,charge:Q) -> bool
    where F:Fn(&P,ObjectId,RootState)->Result<C,E>, Q:Fn(&P,Charge,&ObjectReference,RootState)->Result<u64,E>,
{
    let (label,id,kind) = r.fields();
    &&& kind == super::ReferenceKind::Owns
    &&& if label == CONTENT@ {o matches Observation::Catalog(c) && catalog.ensures((owner,id,root),Ok(c))}
        else if label == KV@ {o matches Observation::Bytes(n) && charge.ensures((owner,Charge::Kv,r,root),Ok(n))}
        else if workspace(label) {o matches Observation::Bytes(n) && charge.ensures((owner,Charge::Workspace,r,root),Ok(n))}
        else {o is Preserved}
}

pub(super) open spec fn failure<P,C,E,F,Q>(owner:&P,root:RootState,r:&ObjectReference,bytes:nat,n:u64,e:Error<E>,catalog:F,charge:Q) -> bool
    where F:Fn(&P,ObjectId,RootState)->Result<C,E>, Q:Fn(&P,Charge,&ObjectReference,RootState)->Result<u64,E>,
{
    let (label,id,kind) = r.fields();
    if kind != super::ReferenceKind::Owns { e is NotOwning }
    else if label == CONTENT@ { e matches Error::Storage(err) && catalog.ensures((owner,id,root),Err(err)) }
    else if label == KV@ || workspace(label) {
        let k = if label == KV@ {Charge::Kv} else {Charge::Workspace};
        match e {
            Error::Overflow => charge.ensures((owner,k,r,root),Ok(n)) && bytes+n > u64::MAX,
            Error::Storage(err) => charge.ensures((owner,k,r,root),Err(err)),
            Error::NotOwning => false,
        }
    } else {false}
}

pub(super) fn fold<P,C,E,F,Q>(owner:&P,root:RootState,refs:&[ObjectReference],catalog:F,charge:Q)
    -> (out:Result<Components<C>,Error<E>>)
    where F:Fn(&P,ObjectId,RootState)->Result<C,E>, Q:Fn(&P,Charge,&ObjectReference,RootState)->Result<u64,E>,
    requires forall|id:ObjectId| #[trigger] catalog.requires((owner,id,root)),
        forall|k:Charge,r:&ObjectReference| #[trigger] charge.requires((owner,k,r,root)),
    ensures out matches Ok(parts) ==> {
        &&& parts.preserved@.map_values(|r:ObjectReference| r.fields()) == refs@.filter(|r:ObjectReference| r.fields().0 != CONTENT@).map_values(|r:ObjectReference| r.fields())
        &&& exists|obs:Seq<Observation<C>>| obs.len() == refs.len() && parts.other_bytes == #[trigger] total(obs)
            && parts.catalog == last_catalog(obs) && forall|j:int| 0 <= j < obs.len() ==>
                accepted(owner,root,&refs@[j],#[trigger] obs[j],catalog,charge)
    },
        out matches Err(e) ==> exists|obs:Seq<Observation<C>>,n:u64| obs.len() < refs.len()
            && (forall|j:int| 0 <= j < obs.len() ==> accepted(owner,root,&refs@[j],#[trigger] obs[j],catalog,charge))
            && #[trigger] failure(owner,root,&refs@[obs.len() as int],total(obs),n,e,catalog,charge),
{
    let mut parts = Components {catalog:None,other_bytes:0u64,preserved:Vec::new()};
    let ghost mut obs:Seq<Observation<C>> = Seq::empty();
    let mut i = 0usize;
    let ghost keep = |r:ObjectReference| r.fields().0 != CONTENT@;
    while i < refs.len()
        invariant keep == (|r:ObjectReference| r.fields().0 != CONTENT@),
            forall|id:ObjectId| #[trigger] catalog.requires((owner,id,root)),
            forall|k:Charge,r:&ObjectReference| #[trigger] charge.requires((owner,k,r,root)),
            i <= refs.len(), obs.len() == i, parts.other_bytes == total(obs), parts.catalog == last_catalog(obs),
            parts.preserved@.len() == refs@.take(i as int).filter(keep).len(),
            parts.preserved@.map_values(|r:ObjectReference| r.fields()) == refs@.take(i as int).filter(keep).map_values(|r:ObjectReference| r.fields()),
            forall|j:int| 0 <= j < i ==> accepted(owner,root,&refs@[j],#[trigger] obs[j],catalog,charge),
        decreases refs.len()-i,
    {
        let r = &refs[i];
        let Some(id) = r.owning_target() else { assert(failure(owner,root,r,total(obs),0,Error::NotOwning,catalog,charge)); return Err(Error::NotOwning); };
        let label = r.label_bytes();
        let ghost observation;
        let ghost prior_refs = parts.preserved@;
        let ghost kept = refs@.take(i as int).filter(keep);
        if label == CONTENT {
            assert(label@ =~= CONTENT@);
            let c = match catalog(owner,id,root) {Ok(c)=>c,Err(e)=>{assert(failure(owner,root,r,total(obs),0,Error::Storage(e),catalog,charge));return Err(Error::Storage(e));}};
            proof { observation = Observation::Catalog(c); }
            parts.catalog = Some(c);
        } else {
            let kind = if label == KV {
                assert(label@ =~= KV@); Some(Charge::Kv)
            } else if label.len() >= WORKSPACE.len() {
                let (prefix,_) = label.split_at(WORKSPACE.len());
                if prefix == WORKSPACE { assert(prefix@ =~= WORKSPACE@); Some(Charge::Workspace) } else { None }
            } else { None };
            if let Some(k) = kind {
                let ghost expected = if label@ == KV@ { Charge::Kv } else { Charge::Workspace };
                assert(k == expected);
                assert(label@ == KV@ || workspace(label@));
                let n = match charge(owner,k,r,root) {Ok(n)=>n,Err(e)=>{assert(failure(owner,root,r,total(obs),0,Error::Storage(e),catalog,charge));return Err(Error::Storage(e));}};
                let Some(next) = parts.other_bytes.checked_add(n) else {
                    assert(failure(owner,root,r,total(obs),n,Error::Overflow,catalog,charge));
                    return Err(Error::Overflow);
                };
                parts.other_bytes = next;
                proof { observation = Observation::Bytes(n); };
            } else {
                proof { observation = Observation::Preserved; };
            }
            parts.preserved.push(r.duplicate());
        }
        assert(accepted(owner,root,r,observation,catalog,charge));
        proof {
            let prior = obs;
            obs = prior.push(observation);
            assert(obs.drop_last() =~= prior);
            assert(refs@.take(i as int+1) =~= refs@.take(i as int).push(*r));
            assert(refs@.take(i as int+1).drop_last() =~= refs@.take(i as int));
            let next = refs@.take(i as int+1).filter(keep);
            if keep(*r) {
                assert(next == kept.push(*r)) by { reveal(Seq::filter); }
            } else {
                assert(next == kept) by { reveal(Seq::filter); }
            }
            assert(prior_refs.len() == kept.len());
            assert(parts.preserved@.len() == next.len());
            assert forall|j:int| 0 <= j < next.len() implies #[trigger] parts.preserved@[j].fields() == next[j].fields() by {
                if j < kept.len() {
                    assert(prior_refs.map_values(|r:ObjectReference| r.fields())[j] == kept.map_values(|r:ObjectReference| r.fields())[j]);
                }
            }
            assert(parts.preserved@.map_values(|r:ObjectReference| r.fields()) =~= next.map_values(|r:ObjectReference| r.fields()));
        }
        i = i.saturating_add(1);
    }
    assert(refs@.take(i as int) =~= refs@);
    Ok(parts)
}
}
