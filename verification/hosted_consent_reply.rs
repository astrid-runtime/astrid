//! Compose responder correlation and the persisted command-approval decision.
use crate::{consent_identity, consent_reply::{self,Decision,Destination}};
use vstd::prelude::*;

verus! {

fn answer(principal:&[u8],owner:u128,stamped:Option<&[u8]>,stamped_owner:Option<u128>,
    wire:&[u8],action:&[u8],stored_principal:&[u8],stored_action:&[u8],workspace:Option<&[u8]>,stored_workspace:Option<&[u8]>,failure:Option<u8>)
    -> (out:Option<Result<Decision,u8>>)
    ensures out == if stamped matches Some(p) && p@ == principal@ && stamped_owner == Some(owner) {
        let scope = consent_reply::scope(wire@);
        Some(if scope == Decision::Always {
            if principal@ != stored_principal@ || action@ != stored_action@ || workspace != stored_workspace {Err(0u8)}
            else {match failure {Some(e) => Err(e),None => Ok(Decision::Always)}}
        } else {Ok(scope)})
    } else {None},
{
    if !consent_identity::matches(principal,owner,stamped,stamped_owner) {return None;}
    Some(consent_reply::apply(wire,principal,action,|p:&[u8],a:&[u8]| -> (r:Result<(),u8>)
        ensures r == if p@ != stored_principal@ || a@ != stored_action@ || workspace != stored_workspace {Err(0u8)}
            else {match failure {Some(e) => Err(e),None => Ok(())}}
        {
            let target = match workspace {Some(path) => Destination::Hosted(path),None => Destination::AstridWorkspace};
            consent_reply::save_at(p,a,target,
                |owner:&[u8],action:&[u8],path:&[u8]| -> (r:Result<(),u8>)
                    ensures r == if owner@ != stored_principal@ || action@ != stored_action@ || Some(path) != stored_workspace {Err(0u8)}
                        else {match failure {Some(e) => Err(e),None => Ok(())}}
                    { write(owner,action,Some(path),stored_principal,stored_action,stored_workspace,failure) },
                |owner:&[u8],action:&[u8]| -> (r:Result<(),u8>)
                    ensures r == if owner@ != stored_principal@ || action@ != stored_action@ || stored_workspace.is_some() {Err(0u8)}
                        else {match failure {Some(e) => Err(e),None => Ok(())}}
                    { write(owner,action,None,stored_principal,stored_action,stored_workspace,failure) })

        }))
}

fn write(p:&[u8],a:&[u8],scope:Option<&[u8]>,owner:&[u8],family:&[u8],path:Option<&[u8]>,failure:Option<u8>)
    -> (r:Result<(),u8>)
    ensures r == if p@ != owner@ || a@ != family@ || scope != path {Err(0u8)}
        else {match failure {Some(e) => Err(e),None => Ok(())}},
{
    if p != owner || a != family {return Err(0);}
    assert(p@ =~= owner@ && a@ =~= family@);
    match (scope,path) {
        (Some(left),Some(right)) => {
            if left != right {return Err(0);}
            assert(left@ =~= right@);
            assert(left == right);
        },
        (None,None) => {},
        _ => return Err(0),
    }
    match failure {Some(e) => Err(e),None => Ok(())}
}

}
