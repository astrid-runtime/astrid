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

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionRoute { Skip, Unstamped, CheckProfile }

/// A generation without a key still requires validation, which rejects the incomplete stamp.
pub(super) fn session_route<K: Copy, G: Copy>(decision: Decision,
    caller: (Option<K>, Option<G>), responder: (Option<K>, Option<G>)) -> (r: SessionRoute)
    ensures r == if decision != Decision::Session { SessionRoute::Skip }
        else if caller.0.is_none() && caller.1.is_none()
            && responder.0.is_none() && responder.1.is_none() { SessionRoute::Unstamped }
        else { SessionRoute::CheckProfile },
{
    if !matches!(decision, Decision::Session) { SessionRoute::Skip }
    else if caller.0.is_some() || caller.1.is_some() || responder.0.is_some() || responder.1.is_some() {
        SessionRoute::CheckProfile
    } else { SessionRoute::Unstamped }
}

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

/// Only the admission function constructs this authority and owns the three guards.
pub(super) struct ReplyAuthority<P,C,S> { _principal:P, _caller:C, _responder:S }

/// Keep both live registrations in the calling frame through the reply effect.
pub(super) fn admit<P,C,S,F:FnOnce()->Result<C,()>,H:FnOnce()->Result<S,()>>(
    principal:Result<P,()>, caller:F, responder:H,
) -> (held:Option<ReplyAuthority<P,C,S>>)
    requires caller.requires(()), responder.requires(()),
    ensures match principal {
        Err(()) => held.is_none(),
        Ok(p) => exists|c:Result<C,()>| #[trigger] caller.ensures((),c) && match c {
            Err(()) => held.is_none(),
            Ok(c) => exists|s:Result<S,()>| #[trigger] responder.ensures((),s) && match s {
                Ok(s) => held matches Some(h) && h.guards() == (p,c,s),
                Err(()) => held.is_none(),
            },
        },
    },
{
    let p = principal.ok()?;
    let caller_result = caller();
    assert(caller.ensures((),caller_result));
    let c = caller_result.ok()?;
    let responder_result = responder();
    assert(responder.ensures((),responder_result));
    let s = responder_result.ok()?;
    Some(ReplyAuthority { _principal:p, _caller:c, _responder:s })
}

impl<Owner,C,S> ReplyAuthority<Owner,C,S> {
pub(super) closed spec fn guards(&self) -> (Owner,C,S) { (self._principal,self._caller,self._responder) }

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
