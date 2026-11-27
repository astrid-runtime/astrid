//! Classify an operator reply and persist a command-family approval.
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Decision { Once, Session, Always, Deny }

pub(super) open spec fn scope(bytes:Seq<u8>) -> Decision {
    if bytes == b"approve"@ {Decision::Once}
    else if bytes == b"approve_session"@ {Decision::Session}
    else if bytes == b"approve_always"@ {Decision::Always}
    else {Decision::Deny}
}

pub(super) fn classify(bytes:&[u8]) -> (result:Decision)
    ensures result == scope(bytes@),
{
    if bytes == b"approve".as_slice() {assert(bytes@ =~= b"approve"@); Decision::Once}
    else if bytes == b"approve_session".as_slice() {assert(bytes@ =~= b"approve_session"@); Decision::Session}
    else if bytes == b"approve_always".as_slice() {assert(bytes@ =~= b"approve_always"@); Decision::Always}
    else {Decision::Deny}
}

/// Hosted grants carry the pristine workspace path. Astrid workspace grants
/// are scoped by the principal and do not carry a host path.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Destination<W> { Hosted(W), AstridWorkspace }

/// Each primitive records exactly one attempted profile write, including
/// attempts that report a storage error.
pub(super) trait Writer<P:Copy,A:Copy,W:Copy> {
    type Error;
    spec fn attempts(&self) -> Seq<(P,A,Destination<W>)>;
    spec fn permits(&self,p:P,a:A,d:Destination<W>,r:Result<(),Self::Error>) -> bool;

    fn hosted(&mut self,p:P,a:A,path:W) -> (r:Result<(),Self::Error>)
        ensures final(self).attempts() == old(self).attempts().push((p,a,Destination::Hosted(path))),
            old(self).permits(p,a,Destination::Hosted(path),r);
    fn workspace(&mut self,p:P,a:A) -> (r:Result<(),Self::Error>)
        ensures final(self).attempts() == old(self).attempts().push((p,a,Destination::AstridWorkspace)),
            old(self).permits(p,a,Destination::AstridWorkspace,r);
}

pub(super) fn save_at<P:Copy,A:Copy,W:Copy,R:Writer<P,A,W>>(p:P,a:A,d:Destination<W>,writer:&mut R)
    -> (r:Result<(),R::Error>)
    ensures final(writer).attempts() == old(writer).attempts().push((p,a,d)), old(writer).permits(p,a,d,r),
{
    match d {
        Destination::Hosted(path) => writer.hosted(p,a,path),
        Destination::AstridWorkspace => writer.workspace(p,a),
    }
}

/// Only the admission function constructs this pair. The caller owns both guards.
pub(super) struct ReplyAuthority<C,S> { _caller:C, _responder:S }

/// Keep both live registrations in the calling frame through the reply effect.
pub(super) fn admit<C,S>(caller:Result<C,()>, responder:Result<S,()>) -> (held:Option<ReplyAuthority<C,S>>)
    ensures match (caller,responder) {
        (Ok(c),Ok(s)) => held matches Some(h) && h.guards() == (c,s), _ => held.is_none(),
    },
{
    match (caller,responder) {
        (Ok(c),Ok(s)) => Some(ReplyAuthority { _caller:c, _responder:s }),
        _ => None,
    }
}

impl<C,S> ReplyAuthority<C,S> {
pub(super) closed spec fn guards(&self) -> (C,S) { (self._caller,self._responder) }

/// An unusable prompt destination affects only a request for persistence.
pub(super) fn apply<P:Copy,A:Copy,W:Copy,R:Writer<P,A,W>>(&self,bytes:&[u8],p:P,a:A,
    target:Result<Destination<W>,R::Error>,writer:&mut R) -> (out:Result<Decision,R::Error>)
    ensures
        final(writer).attempts() == match target {
            Ok(d) if scope(bytes@) == Decision::Always => old(writer).attempts().push((p,a,d)),
            _ => old(writer).attempts(),
        },
        scope(bytes@) != Decision::Always ==> out == Ok(scope(bytes@)),
        scope(bytes@) == Decision::Always ==> match target {
            Err(e) => out == Err(e),
            Ok(d) => match out {
                Ok(value) => value == Decision::Always && old(writer).permits(p,a,d,Ok(())),
                Err(error) => old(writer).permits(p,a,d,Err(error)),
            },
        },
{
    let decision = classify(bytes);
    if matches!(decision,Decision::Always) {
        let destination = target?;
        save_at(p,a,destination,writer)?;
    }
    Ok(decision)
}
}

}
