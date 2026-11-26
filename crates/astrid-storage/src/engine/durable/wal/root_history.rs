//! Check a recovered owner's current root and retain the exact entry for publication.
use std::collections::BTreeMap;
use vstd::prelude::*;

use super::root_transition::{self, Replay, Version};
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

pub(super) open spec fn version<R,F:Fn(R)->Version>(f:F,r:R) -> Version {
    choose|v:Version| f.ensures((r,),v)
}

pub(super) open spec fn optional_version<R,F:Fn(R)->Version>(f:F,r:Option<R>) -> Option<Version> {
    match r {Some(r) => Some(version(f,r)),None => None}
}

}
