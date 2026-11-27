//! Admission before persistent process preparation. The native gate supplies
//! the live policy decisions, caller identity, cancellation and audit sink.
use vstd::prelude::*;

verus! {

#[cfg(verus_keep_ghost)]
pub(super) enum Check<P,E,M> {
    Principal(Seq<char>, bool),
    Host(Seq<char>, Seq<char>, Option<String>),
    Owner(Option<P>),
    Cancelled(bool),
    Audit(Seq<char>, Option<E>),
    Prepare(P, Seq<char>, Result<M,E>),
}

pub(super) trait Gate<P,E,M> {
    spec fn checks(&self) -> Seq<Check<P,E,M>>;

    fn principal(&mut self, command: &str) -> (allowed: bool)
        ensures final(self).checks() == old(self).checks().push(Check::Principal(command@, allowed));
    fn host(&mut self, capsule: &str, command: &str) -> (result: Option<String>)
        ensures final(self).checks() == old(self).checks().push(Check::Host(capsule@, command@, result));
    fn owner(&mut self) -> (principal: Option<P>)
        ensures final(self).checks() == old(self).checks().push(Check::Owner(principal));
    fn cancelled(&mut self) -> (stopped: bool)
        ensures final(self).checks() == old(self).checks().push(Check::Cancelled(stopped));
    fn audit(&mut self, command: &str) -> (result: Option<E>)
        ensures final(self).checks() == old(self).checks().push(Check::Audit(command@, result));
    fn prepare(&mut self, owner: &P, command: &str) -> (result: Result<M,E>)
        ensures final(self).checks() == old(self).checks().push(Check::Prepare(*owner,command@,result));

}

pub(super) enum Refusal<E> {
    Principal, Host(String), Persistence, Unauthenticated, IdleTimeout, Cancelled, Audit(E), Prepare(E),
}

pub(super) open spec fn declared(names: Seq<String>) -> bool {
    exists|i:int| 0 <= i < names.len() && (#[trigger] names[i])@ == "allow_persistent"@
}

fn allows_persistence(names: &[String]) -> (yes: bool)
    ensures yes == declared(names@),
{
    let mut i = 0;
    while i < names.len()
        invariant i <= names.len(),
            forall|j:int| 0 <= j < i ==> (#[trigger] names@[j])@ != "allow_persistent"@,
        decreases names.len() - i,
    {
        if names[i].as_str() == "allow_persistent" { return true; }
        i = i.saturating_add(1);
    }
    false
}

pub(super) fn authorize<P,E,M,G:Gate<P,E,M>>(gate:&mut G, names:&[String],
    capsule:&str, command:&str, idle:Option<u64>) -> (out:Result<(P,M),Refusal<E>>)
    ensures ({
        let before = old(gate).checks();
        let after = final(gate).checks();
        let principal = before.push(Check::Principal(command@,true));
        let host = principal.push(Check::Host(capsule@,command@,None));
        let granted = declared(names@);
        match out {
            Err(Refusal::Principal) => after == before.push(Check::Principal(command@,false)),
            Err(Refusal::Host(reason)) => after == principal.push(Check::Host(capsule@,command@,Some(reason))),
            Err(Refusal::Persistence) => !granted && after == host,
            Err(Refusal::Unauthenticated) => granted && after == host.push(Check::Owner(None)),
            Err(Refusal::IdleTimeout) => granted && idle == Some(0) && exists|p:P| after == host.push(Check::Owner(Some(p))),
            Err(Refusal::Cancelled) => granted && idle != Some(0) && exists|p:P|
                after == host.push(Check::Owner(Some(p))).push(Check::Cancelled(true)),
            Err(Refusal::Audit(e)) => granted && idle != Some(0) && exists|p:P|
                after == host.push(Check::Owner(Some(p))).push(Check::Cancelled(false)).push(Check::Audit(command@,Some(e))),
            Err(Refusal::Prepare(e)) => granted && idle != Some(0) && exists|p:P|
                after == host.push(Check::Owner(Some(p))).push(Check::Cancelled(false)).push(Check::Audit(command@,None))
                    .push(Check::Prepare(p,command@,Err(e))),
            Ok((p,m)) => granted && idle != Some(0) &&
                after == host.push(Check::Owner(Some(p))).push(Check::Cancelled(false)).push(Check::Audit(command@,None))
                    .push(Check::Prepare(p,command@,Ok(m))),
        }
    }),
{
    if !gate.principal(command) { return Err(Refusal::Principal); }
    if let Some(reason) = gate.host(capsule, command) { return Err(Refusal::Host(reason)); }
    if !allows_persistence(names) { return Err(Refusal::Persistence); }
    let Some(principal) = gate.owner() else { return Err(Refusal::Unauthenticated); };
    if idle == Some(0) { return Err(Refusal::IdleTimeout); }
    if gate.cancelled() { return Err(Refusal::Cancelled); }
    if let Some(e) = gate.audit(command) { return Err(Refusal::Audit(e)); }
    match gate.prepare(&principal, command) {
        Ok(mount) => Ok((principal,mount)),
        Err(e) => Err(Refusal::Prepare(e)),
    }
}

}
