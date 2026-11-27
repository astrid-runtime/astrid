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
    crate::runtime_generation::issue(next,(id,artifact,owner),
        |key:(u64,[u8;32],Option<u64>), generation:u64| -> (r:(u64,[u8;32],Option<u64>,u64))
            ensures r == (key.0,key.1,key.2,generation), { (key.0,key.1,key.2,generation) })
}

}
