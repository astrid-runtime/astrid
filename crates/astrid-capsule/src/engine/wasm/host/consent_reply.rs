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
pub(super) enum Destination<W> { Hosted(W), AstridWorkspace }

pub(super) fn save_at<P:Copy,A:Copy,W:Copy,E,H:FnOnce(P,A,W)->Result<(),E>,S:FnOnce(P,A)->Result<(),E>>(
    principal:P, action:A, destination:Destination<W>, hosted:H, workspace:S,
) -> (out:Result<(),E>)
    requires match destination {
        Destination::Hosted(path) => hosted.requires((principal,action,path)),
        Destination::AstridWorkspace => workspace.requires((principal,action)),
    },
    ensures match destination {
        Destination::Hosted(path) => hosted.ensures((principal,action,path),out),
        Destination::AstridWorkspace => workspace.ensures((principal,action),out),
    },
{
    match destination {
        Destination::Hosted(path) => hosted(principal,action,path),
        Destination::AstridWorkspace => workspace(principal,action),
    }
}

/// The persistent callback uses the principal and action of the pending prompt.
pub(super) fn apply<P:Copy,A:Copy,E,F:FnOnce(P,A)->Result<(),E>>(bytes:&[u8],principal:P,action:A,save:F)
    -> (out:Result<Decision,E>)
    requires save.requires((principal,action)),
    ensures
        scope(bytes@) != Decision::Always ==> out == Ok(scope(bytes@)),
        scope(bytes@) == Decision::Always ==> match out {
            Ok(value) => value == Decision::Always && save.ensures((principal,action),Ok(())),
            Err(error) => save.ensures((principal,action),Err(error)),
        },
{
    let decision = classify(bytes);
    if matches!(decision,Decision::Always) { save(principal,action)?; }
    Ok(decision)
}

}
