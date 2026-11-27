//! The two registry indexes used at dispatch and restart.
use crate::{instance_swap::Entry, runtime_generation::RuntimeId, runtime_scope::RuntimeScope, view_lookup};
use std::{collections::HashMap, sync::Arc};
use vstd::prelude::*;
use vstd::{laws_eq::obeys_concrete_eq, std_specs::hash::{hash_map_inv, obeys_key_model}};

type Id = RuntimeId<u64,[u8;32],RuntimeScope>;

verus! {
// The key model for the derived native identity remains an explicit premise.
// The handle type is allowed to be unsized, as in the production capsule trait object.
fn lookup<C: ?Sized, A>(views: &HashMap<u64,HashMap<u64,Id>>, instances: &HashMap<Id,Entry<C,A>>,
    principal: u64, package: u64, expected: &Id) -> (out: (bool,Option<Arc<C>>))
    requires hash_map_inv(views), hash_map_inv(instances), obeys_key_model::<Id>(), obeys_concrete_eq::<Id>(),
        views@.contains_key(principal) ==> hash_map_inv(&views@[principal]),
    ensures ({
        if views@.contains_key(principal) && views@[principal]@.contains_key(package) {
            let live = views@[principal]@[package];
            &&& out.0 == (live == *expected)
            &&& out.1 == if instances@.contains_key(live) { Some(instances@[live].capsule) } else { None }
        } else {
            !out.0 && out.1.is_none()
        }
    }),
{
    let current = view_lookup::current(views, &principal, &package, expected);
    let capsule = view_lookup::capsule_for(views, instances, &principal, &package);
    (current, capsule)
}
fn restart_snapshot<C: ?Sized,A>(views: &HashMap<u64,HashMap<u64,Id>>, instances: &HashMap<Id,Entry<C,A>>,
    principal: u64, package: u64, expected: Option<&Id>) -> (out: view_lookup::RestartSnapshot<Id,C>)
    requires hash_map_inv(views), hash_map_inv(instances), obeys_key_model::<Id>(), obeys_concrete_eq::<Id>(),
        vstd::pervasive::obeys_clone_eq::<Id>(),
        views@.contains_key(principal) ==> hash_map_inv(&views@[principal]),
    ensures ({
        if views@.contains_key(principal) && views@[principal]@.contains_key(package)
            && instances@.contains_key(views@[principal]@[package]) {
            let id = views@[principal]@[package];
            match expected {
                Some(e) if *e != id => out == view_lookup::RestartSnapshot::Superseded,
                _ => out == view_lookup::RestartSnapshot::Current(id,instances@[id].capsule),
            }
        } else { out == view_lookup::RestartSnapshot::Missing }
    }),
{
    view_lookup::snapshot(views,instances,&principal,&package,expected)
}

// Compose the installed snapshot with the reservation made during preparation.
// A new artifact is allowed, while the running owner scope is preserved.
fn prepare_restart<C: ?Sized,A>(next: &mut u64, views: &HashMap<u64,HashMap<u64,Id>>,
    instances: &HashMap<Id,Entry<C,A>>, principal: u64, package: u64,
    expected: Option<&Id>, observed_owner: Option<u64>, artifact: [u8;32])
    -> (out: Option<(Arc<C>,Id)>)
    requires hash_map_inv(views), hash_map_inv(instances), obeys_key_model::<Id>(), obeys_concrete_eq::<Id>(),
        vstd::pervasive::obeys_clone_eq::<Id>(), obeys_concrete_eq::<RuntimeScope>(),
        views@.contains_key(principal) ==> hash_map_inv(&views@[principal]),
    ensures ({
        let live = views@[principal]@[package];
        let scope = match observed_owner { Some(uid) => RuntimeScope::Principal(uid), None => RuntimeScope::SystemResident };
        if views@.contains_key(principal) && views@[principal]@.contains_key(package)
            && instances@.contains_key(live) && (expected.is_none() || *expected.unwrap() == live)
            && live.identity().0.2 == scope && *old(next) < u64::MAX {
            &&& out matches Some((handle,id)) && handle == instances@[live].capsule
                && id.identity() == ((package,artifact,live.identity().0.2),*old(next))
            &&& *final(next) as int == *old(next) as int + 1
        } else { out.is_none() && *final(next) == *old(next) }
    }),
{
    let view_lookup::RestartSnapshot::Current(running,handle) =
        restart_snapshot(views,instances,principal,package,expected) else { return None; };
    let candidate = crate::hosted_runtime_residency::reserve_replacement(
        next,package,artifact,running.key().scope(),observed_owner)?;
    Some((handle,candidate))
}


// A detached authenticated view supplies both the concrete generation and the
// installed handle used by the kernel when it asks that runtime to quiesce.
fn detach_for_quiescence<C: ?Sized,A>(views: &mut HashMap<u64,HashMap<u64,Id>>,
    instances: &HashMap<Id,Entry<C,A>>, owner: u64, package: u64, peer: u64)
    -> (out: Option<(Id,Option<Arc<C>>)>)
    requires hash_map_inv(old(views)), hash_map_inv(instances), obeys_key_model::<Id>(),
        obeys_concrete_eq::<Id>(), peer != owner,
        old(views)@.contains_key(owner) ==> hash_map_inv(&old(views)@[owner]),
    ensures ({
        let before = old(views)@;
        let after = final(views)@;
        &&& after.contains_key(peer) == before.contains_key(peer)
        &&& before.contains_key(peer) ==> after[peer] == before[peer]
        &&& if before.contains_key(owner) && before[owner]@.contains_key(package) {
            let id = before[owner]@[package];
            let remaining = before[owner]@.remove(package);
            &&& out == Some((id, if instances@.contains_key(id) { Some(instances@[id].capsule) } else { None }))
            &&& if remaining.is_empty() { !after.contains_key(owner) }
                else { after.contains_key(owner) && after[owner]@ == remaining }
        } else { out.is_none() && after == before }
    }),
{
    let ghost before = views@;
    let out = view_lookup::detach(views, instances, &owner, &package);
    proof {
        let after = views@;
        assert(before.remove(owner).contains_key(peer) == before.contains_key(peer));
        assert(after.remove(owner).contains_key(peer) == after.contains_key(peer));
        if before.contains_key(peer) {
            assert(before.remove(owner)[peer] == before[peer]);
            assert(after.remove(owner)[peer] == after[peer]);
        }
    }
    out
}
}
