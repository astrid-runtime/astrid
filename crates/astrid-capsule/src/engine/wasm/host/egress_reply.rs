//! Route a local-egress decision to the grant store for the selected endpoint.
use super::consent_reply::{self, Decision};
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct GrantTarget<P,C,H> {
    pub(super) principal:P,
    pub(super) capsule:C,
    pub(super) host:H,
    pub(super) port:u16,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Store { Session, Profile }

pub(super) trait Writer<T: Copy> {
    type Error;
    spec fn attempts(&self) -> Seq<(Store, T)>;
    spec fn result(&self, store: Store, target: T, r: Result<(),Self::Error>) -> bool;

    fn install(&mut self, store: Store, target: T) -> (r: Result<(),Self::Error>)
        ensures
            final(self).attempts() == old(self).attempts().push((store,target)),
            old(self).result(store,target,r);
}

pub(super) open spec fn destination(decision: Decision, has_profile: bool) -> Option<Store> {
    match decision {
        Decision::Session => Some(Store::Session),
        Decision::Always => Some(if has_profile { Store::Profile } else { Store::Session }),
        _ => None,
    }
}

pub(super) fn apply<T:Copy, W:Writer<T>>(bytes:&[u8], has_profile:bool, target:T, writer:&mut W)
    -> (out:Result<Decision,W::Error>)
    ensures ({
        let decision = consent_reply::scope(bytes@);
        match destination(decision,has_profile) {
            None => final(writer).attempts() == old(writer).attempts() && out == Ok(decision),
            Some(store) => final(writer).attempts() == old(writer).attempts().push((store,target))
                && match out {
                    Ok(d) => d == decision && old(writer).result(store,target,Ok(())),
                    Err(e) => old(writer).result(store,target,Err(e)),
                },
        }
    }),
{
    let decision = consent_reply::classify(bytes);
    match decision {
        Decision::Session => writer.install(Store::Session, target)?,
        Decision::Always if has_profile => writer.install(Store::Profile, target)?,
        Decision::Always => writer.install(Store::Session, target)?,
        _ => {},
    }
    Ok(decision)
}

}
