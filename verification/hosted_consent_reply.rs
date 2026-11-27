//! Correlate operator replies with the exact attempted profile writes.
use crate::{consent_identity, consent_reply::{self, Decision, Destination, Writer}};
use vstd::prelude::*;

verus! {

/// Separate storage failures from an unexpected principal, action or scope.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Error { Binding, Destination, Storage(u8) }

struct Profile<'a> {
    principal:&'a [u8],action:&'a [u8],scope:Destination<&'a [u8]>,failure:Option<u8>,
    calls:Vec<(&'a [u8],&'a [u8],Destination<&'a [u8]>)>,
}

impl<'a> Profile<'a> {
    closed spec fn result(&self,p:&[u8],a:&[u8],d:Destination<&[u8]>) -> Result<(),Error> {
        if p@ != self.principal@ || a@ != self.action@ || d != self.scope {Err(Error::Binding)}
        else {match self.failure {Some(e) => Err(Error::Storage(e)),None => Ok(())}}
    }

    fn write(&mut self,p:&'a [u8],a:&'a [u8],d:Destination<&'a [u8]>) -> (r:Result<(),Error>)
        ensures final(self).calls@ == old(self).calls@.push((p,a,d)), r == old(self).result(p,a,d),
    {
        self.calls.push((p,a,d));
        if p != self.principal || a != self.action {return Err(Error::Binding);}
        assert(p@ =~= self.principal@ && a@ =~= self.action@);
        match (d,self.scope) {
            (Destination::Hosted(x),Destination::Hosted(y)) => {
                if x != y {return Err(Error::Binding);} assert(x@ =~= y@); assert(x == y);
            },
            (Destination::AstridWorkspace,Destination::AstridWorkspace) => {},
            _ => return Err(Error::Binding),
        }
        match self.failure {Some(e) => Err(Error::Storage(e)),None => Ok(())}
    }
}

impl<'a> Writer<&'a [u8],&'a [u8],&'a [u8]> for Profile<'a> {
    type Error = Error;
    closed spec fn attempts(&self) -> Seq<(&'a [u8],&'a [u8],Destination<&'a [u8]>)> {self.calls@}
    closed spec fn permits(&self,p:&'a [u8],a:&'a [u8],d:Destination<&'a [u8]>,r:Result<(),Error>) -> bool {
        r == self.result(p,a,d)
    }
    fn hosted(&mut self,p:&'a [u8],a:&'a [u8],path:&'a [u8]) -> Result<(),Error> {
        self.write(p,a,Destination::Hosted(path))
    }
    fn workspace(&mut self,p:&'a [u8],a:&'a [u8]) -> Result<(),Error> {
        self.write(p,a,Destination::AstridWorkspace)
    }
}

fn answer<'a>(principal:&'a [u8],owner:u128,stamped:Option<&[u8]>,stamped_owner:Option<u128>,wire:&[u8],
    action:&'a [u8],target:Result<Destination<&'a [u8]>,Error>,profile:&mut Profile<'a>)
    -> (out:Option<Result<Decision,Error>>)
    ensures ({
        let matched = stamped matches Some(p) && p@ == principal@ && stamped_owner == Some(owner);
        let decision = consent_reply::scope(wire@);
        &&& final(profile).calls@ == match target {
            Ok(d) if matched && decision == Decision::Always => old(profile).calls@.push((principal,action,d)),
            _ => old(profile).calls@,
        }
        &&& out == if !matched {None} else if decision != Decision::Always {Some(Ok(decision))}
            else {Some(match target {Err(e) => Err(e),Ok(d) => match old(profile).result(principal,action,d) {
                Ok(()) => Ok(Decision::Always),Err(e) => Err(e)
            }})}
    }),
{
    if !consent_identity::matches(principal,owner,stamped,stamped_owner) {return None;}
    Some(consent_reply::apply(wire,principal,action,target,profile))
}

}
