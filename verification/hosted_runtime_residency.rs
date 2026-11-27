//! An ownerless runtime requires operator admission. A principal runtime carries
//! the UID obtained for the selected caller and expected binding, or refuses.
use crate::runtime_residency::classify;
use vstd::prelude::*;

verus! {
fn runtime_owner(allowed: bool, provides: bool, uplink: bool, has_servers: bool,
    principal: u64, expected: Option<u64>, observed: Result<u64,u8>) -> (out: Result<Option<u64>,u8>)
    ensures out == if provides && !allowed { Err(1u8) }
        else if allowed && (provides || uplink) {
            if has_servers { Err(2u8) } else { Ok(None) }
        } else { match observed { Ok(uid) => Ok(Some(uid)), Err(e) => Err(e) } },
{
    use crate::runtime_residency::Refusal;
    let uplinks = crate::runtime_residency::Uplinks { provides, capability: uplink };
    let residency = match classify(allowed, uplinks, has_servers) {
        Ok(scope) => scope,
        Err(Refusal::UnapprovedProvider) => return Err(1),
        Err(Refusal::SystemMcp) => return Err(2),
    };
    residency.owner(principal, expected, |p:u64,e:Option<u64>| -> (r:Result<u64,u8>)
        ensures r == if p == principal && e == expected { observed } else { Err(255u8) },
    { if p == principal && e == expected { observed } else { Err(255u8) } })
}
fn issue_runtime(next: &mut u64, id: u64, artifact: [u8;32], allowed: bool, provides: bool,
    uplink: bool, has_servers: bool, principal: u64, expected: Option<u64>, observed: Result<u64,u8>)
    -> (out: Option<(u64,[u8;32],Option<u64>,u64)>)
    ensures ({
        let system = allowed && (provides || uplink);
        let refused = (provides && !allowed) || (system && has_servers) || (!system && observed.is_err());
        if refused || *old(next) == u64::MAX {
            out.is_none() && *final(next) == *old(next)
        } else {
            out == Some((id,artifact,if system { None } else { observed.ok() },*old(next)))
                && *final(next) as int == *old(next) as int + 1
        }
    }),
{
    let owner = runtime_owner(allowed,provides,uplink,has_servers,principal,expected,observed).ok()?;
    let issued = crate::runtime_generation::issue(next,id,artifact,owner)?;
    let key = issued.key();
    Some((*key.capsule_id(), *key.artifact(), key.scope(), issued.generation()))
}

}

verus! {
// The two keys may be identical. Exhaustion can refuse the second request
// after the first has consumed the final usable generation.
fn allocate_pair<I,A,S>(next: &mut u64, first: (I,A,S), second: (I,A,S))
    -> (out: (Option<crate::runtime_generation::RuntimeId<I,A,S>>,
              Option<crate::runtime_generation::RuntimeId<I,A,S>>))
    ensures
        out.0.is_some() == (*old(next) < u64::MAX),
        out.1.is_some() == (*old(next) as int + 1 < u64::MAX),
        out.0 matches Some(a) ==> a.identity() == (first,*old(next)),
        out.1 matches Some(b) ==> b.identity().0 == second && b.identity().1 as int == *old(next) as int + 1,
        match (out.0,out.1) { (Some(a),Some(b)) => a.identity().1 < b.identity().1, _ => true },
        *final(next) as int == *old(next) as int + (if out.0.is_some() { 1int } else { 0int })
            + (if out.1.is_some() { 1int } else { 0int }),
{
    let a = crate::runtime_generation::issue(next, first.0, first.1, first.2);
    let b = crate::runtime_generation::issue(next, second.0, second.1, second.2);
    (a,b)
}
}
