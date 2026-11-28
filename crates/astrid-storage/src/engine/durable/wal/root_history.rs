//! Check a recovered owner's current root and retain the exact entry for publication.
use std::collections::BTreeMap;
use vstd::prelude::*;

use super::{
    RootState, journal_history, journal_transition,
    root_transition::{self, Replay, Version},
    root_wire,
};
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

verus! {

pub(super) enum Decision<R,J> {
    AlreadyPublished,
    Conflict(Option<R>),
    Applied(J),
}

pub(super) fn lookup<P:Ord,R:Copy>(history:&BTreeMap<P,(R,u64)>,owner:&P) -> (actual:Option<R>)
    requires obeys_cmp::<P>(), obeys_cmp_concrete_eq::<P>(), btree_map_inv(history),
    ensures actual == if history@.contains_key(*owner) {Some(history@[*owner].0)} else {None},
{
    history.get(owner).map(|entry:&(R,u64)| -> (r:R) ensures r == entry.0 { entry.0 })
}

/// Journal encoding can fail. Change the history only after it succeeds for
/// the owner and versions selected by this replay decision.
pub(super) fn fold<P:Ord,R:Copy,F,J,E,W>(history:&mut BTreeMap<P,(R,u64)>,owner:P,
    expected:Option<R>,replacement:R,offset:u64,convert:F,encode:W) -> (out:Result<Decision<R,J>,E>)
    where F:Fn(R)->Version,W:FnOnce(&P,Option<R>,R)->Result<J,E>,
    requires obeys_cmp::<P>(), obeys_cmp_concrete_eq::<P>(), btree_map_inv(old(history)),
        forall|r:R| #[trigger] convert.requires((r,)),
        forall|r:R,v:Version| #[trigger] convert.ensures((r,),v) ==> v == version(convert,r),
        encode.requires((&owner,expected,replacement)),
    ensures ({
        let original = old(history)@;
        let observed = if original.contains_key(owner) {Some(original[owner].0)} else {None};
        let actual = optional_version(convert,observed);
        let prior = optional_version(convert,expected);
        let next = version(convert,replacement);
        let already = root_transition::matches_root(actual,Some(next));
        let applicable = !already && root_transition::matches_root(actual,prior);
        &&& btree_map_inv(final(history))
        &&& final(history)@ == if out matches Ok(Decision::Applied(_)) {
            original.insert(owner,(replacement,offset))
        } else { original }
        &&& convert.ensures((replacement,),next)
        &&& (observed matches Some(r) ==> convert.ensures((r,),version(convert,r)))
        &&& (expected matches Some(r) ==> convert.ensures((r,),version(convert,r)))
        &&& match out {
            Ok(Decision::AlreadyPublished) => already,
            Ok(Decision::Conflict(r)) => r == observed && !already && !applicable,
            Ok(Decision::Applied(j)) => applicable && encode.ensures((&owner,expected,replacement),Ok(j)),
            Err(e) => applicable && encode.ensures((&owner,expected,replacement),Err(e)),
        }
    }),
{
    let observed = lookup(history,&owner);
    let actual = observed.map(|r:R| -> (v:Version) ensures convert.ensures((r,),v) { convert(r) });
    let prior = expected.map(|r:R| -> (v:Version) ensures convert.ensures((r,),v) { convert(r) });
    let next = convert(replacement);
    match root_transition::replay(actual,prior,next) {
        Replay::AlreadyPublished => Ok(Decision::AlreadyPublished),
        Replay::Conflict => Ok(Decision::Conflict(observed)),
        Replay::Apply => {
            let journal = encode(&owner,expected,replacement)?;
            history.insert(owner,(replacement,offset));
            Ok(Decision::Applied(journal))
        },
    }
}

/// Keep the decoded owner and canonical name together across closure validation.
pub(super) struct BoundJournal<'a,P> {
    owner:P,
    name:&'a [u8],
    expected:Option<RootState>,
    replacement:RootState,
    offset:u64,
}

impl<'a,P:Ord> BoundJournal<'a,P> {
    pub(super) closed spec fn binding(&self) -> (P,Seq<u8>,Option<RootState>,RootState,u64) {
        (self.owner,self.name@,self.expected,self.replacement,self.offset)
    }

    pub(super) fn bind<D:FnOnce(&[u8])->Option<P>,E:FnOnce(&P)->Vec<u8>>(name:&'a [u8],
        expected:Option<RootState>,replacement:RootState,offset:u64,decode:D,recode:E) -> (out:Option<Self>)
        requires decode.requires((name,)),forall|p:P| #[trigger] decode.ensures((name,),Some(p)) ==> recode.requires((&p,)),
        ensures match out {
            Some(bound)=>{
                let (p,n,e,r,at)=bound.binding();
                &&& (n,e,r,at)==(name@,expected,replacement,offset)
                &&& decode.ensures((name,),Some(p))
                &&& exists|v:Vec<u8>| #[trigger] recode.ensures((&p,),v) && v@==name@
            },
            None=>decode.ensures((name,),None) || exists|p:P,v:Vec<u8>| #[trigger] decode.ensures((name,),Some(p))
                && #[trigger] recode.ensures((&p,),v) && v@!=name@,
        },
    {
        let owner=journal_history::principal(name,decode,recode)?;
        let ghost canonical=choose|v:Vec<u8>| #[trigger] recode.ensures((&owner,),v) && v@==name@;
        let bound=Self{owner,name,expected,replacement,offset};
        assert(recode.ensures((&bound.binding().0,),canonical));
        Some(bound)
    }

    pub(super) fn owner(&self) -> (p:&P) ensures *p==self.binding().0 {&self.owner}

    pub(super) fn expected(&self) -> (r:Option<RootState>) ensures r==self.binding().2 {self.expected}

    pub(super) fn fold(self,history:&mut BTreeMap<P,(RootState,u64)>,scheme:root_wire::Scheme)
        -> (out:Option<Decision<RootState,Vec<u8>>>)
        requires obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),btree_map_inv(old(history)),
        ensures btree_map_inv(final(history)), ({
            let (key,name,expected,replacement,offset)=self.binding();
            let prior=old(history)@;
            let actual=if prior.contains_key(key) {Some(prior[key].0)} else {None};
            let already=actual==Some(replacement);
            let applicable=!already && actual==expected;
            &&& out.is_none()==(applicable && name.len()>=u64::MAX)
            &&& final(history)@==if out matches Some(Decision::Applied(_)) {prior.insert(key,(replacement,offset))} else {prior}
            &&& match out {
                Some(Decision::AlreadyPublished)=>already,
                Some(Decision::Conflict(r))=>!already && !applicable && r==actual,
                Some(Decision::Applied(bytes))=>applicable && bytes@==journal_transition::wire(name,scheme,expected,replacement),
                None=>true,
            }
        }),
    {
        let owner=self.owner;
        let name=self.name;
        let expected=self.expected;
        let replacement=self.replacement;
        let offset=self.offset;
        let ghost actual=if history@.contains_key(owner) {Some(history@[owner].0)} else {None};
        let convert=|r:RootState| -> (v:Version) ensures root_transition::represents(v,r), {root_transition::version(r)};
        let encoder=|_:&P,e:Option<RootState>,r:RootState| -> (out:Result<Vec<u8>,()>)
            ensures out.is_ok()==(name.len()<u64::MAX),out matches Ok(b) ==> b@==journal_transition::wire(name@,scheme,e,r),
        {journal_transition::encode(name,scheme,e,r).ok_or(())};
        proof {
            assert forall|r:RootState,v:Version| #[trigger] convert.ensures((r,),v) implies v==version(convert,r) by {
                let w=version(convert,r);
                assert(convert.ensures((r,),w));
                assert(v.commit =~= w.commit);
            }
        }
        let result=fold(history,owner,expected,replacement,offset,convert,encoder).ok();
        proof {
            if let Some(a)=actual {
                let av=version(convert,a);
                let rv=version(convert,replacement);
                if root_transition::matches_root(Some(av),Some(rv)) {
                    a.generation.same_value(replacement.generation);
                    super::ObjectId::same_digest(a.commit,replacement.commit);
                }
                if let Some(e)=expected {
                    if root_transition::matches_root(Some(av),Some(version(convert,e))) {
                        a.generation.same_value(e.generation);
                        super::ObjectId::same_digest(a.commit,e.commit);
                    }
                }
            }
        }
        result
    }
}

pub(super) open spec fn version<R,F:Fn(R)->Version>(f:F,r:R) -> Version {
    choose|v:Version| f.ensures((r,),v)
}

pub(super) open spec fn optional_version<R,F:Fn(R)->Version>(f:F,r:Option<R>) -> Option<Version> {
    match r {Some(r) => Some(version(f,r)),None => None}
}

}
