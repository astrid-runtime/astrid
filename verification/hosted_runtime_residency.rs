//! An ownerless runtime requires operator admission. A principal runtime carries
//! the UID obtained for the selected caller and expected binding, or refuses.
use crate::runtime_residency::classify;
use crate::runtime_scope::RuntimeScope;
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
    let scope = RuntimeScope::from_owner(owner);
    let issued = crate::runtime_generation::issue(next,id,artifact,scope)?;
    let key = issued.key();
    let issued_owner = match key.scope() {
        RuntimeScope::Principal(uid) => Some(uid),
        RuntimeScope::SystemResident => None,
    };
    Some((*key.capsule_id(), *key.artifact(), issued_owner, issued.generation()))
}


fn reserve_replacement(next: &mut u64, package: u64, artifact: [u8;32],
    running: RuntimeScope, observed_owner: Option<u64>)
    -> (out: Option<crate::runtime_generation::RuntimeId<u64,[u8;32],RuntimeScope>>)
    requires vstd::laws_eq::obeys_concrete_eq::<RuntimeScope>(),
    ensures ({
        let requested = match observed_owner {
            Some(uid) => RuntimeScope::Principal(uid), None => RuntimeScope::SystemResident,
        };
        if requested != running || *old(next) == u64::MAX {
            out.is_none() && *final(next) == *old(next)
        } else {
            out matches Some(id) && id.identity() == ((package,artifact,running),*old(next))
                && *final(next) as int == *old(next) as int + 1
        }
    }),
{
    let requested = RuntimeScope::from_owner(observed_owner);
    let admitted = crate::runtime_residency::replacement_scope(&running,requested).ok()?;
    crate::runtime_generation::issue(next,package,artifact,admitted)
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

verus! {
// After switching between distinct generations, retrying the removed one
// cannot replace the installed instance or any unrelated registry entry.
fn swap_and_retry(instances: &mut std::collections::HashMap<u64, crate::instance_swap::Entry<u64,u64>>,
    old_id: u64, new_id: u64, candidate: std::sync::Arc<u64>, owner: Option<u64>)
    requires vstd::std_specs::hash::hash_map_inv(old(instances)),
        old(instances)@.contains_key(old_id), !old(instances)@.contains_key(new_id),
    ensures final(instances)@ == old(instances)@.remove(old_id).insert(new_id,
        crate::instance_swap::Entry { capsule: candidate, owner_alias: owner }),
{
    let ghost before = instances@;
    let replaced = crate::instance_swap::replace(instances, &old_id, new_id, candidate.clone(), owner);
    assert(replaced == Some(before[old_id].capsule));
    let installed = crate::instance_swap::installed(instances, &new_id);
    assert(installed == Some(candidate));
    let removed = crate::instance_swap::installed(instances, &old_id);
    assert(removed.is_none());
    assert(!instances@.contains_key(old_id));
    let retry = crate::instance_swap::replace(instances, &old_id, new_id, candidate, owner);
    assert(retry.is_none());
}
}

verus! {
fn replace_view_pair(old_key: u64, new_key: u64, unrelated: u64)
    -> (out: (u64, u64))
    requires old_key != unrelated,
    ensures out == (new_key, unrelated),
{
    let mut attached = old_key;
    let mut other = unrelated;
    crate::instance_swap::retarget(&mut attached, &old_key, &new_key);
    crate::instance_swap::retarget(&mut other, &old_key, &new_key);
    (attached, other)
}
}

verus! {
// A shared runtime may appear in multiple views. Reusing a capsule name with
// a different runtime identity does not add that principal to the resume list.
fn restart_viewers(views: &std::collections::HashMap<u64,std::collections::HashMap<u64,u64>>,
    runtime: u64, member: u64, outsider: u64) -> (out: Vec<u64>)
    requires vstd::std_specs::hash::hash_map_inv(views),
        forall|p:u64| views@.contains_key(p) ==> vstd::std_specs::hash::hash_map_inv(&views@[p]),
        views@.contains_key(member), views@[member]@.values().contains(runtime),
        !views@.contains_key(outsider) || !views@[outsider]@.values().contains(runtime),
    ensures out@.contains(member), !out@.contains(outsider), out@.no_duplicates(),
{
    crate::viewers::viewers(views, &runtime)
}
}
