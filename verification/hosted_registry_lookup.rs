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

// Two principals can have the same package and artifact at different runtime
// generations. Only a survivor attached to the removed generation keeps it alive.
fn detach_with_peer<C: ?Sized>(views: &mut HashMap<u64,HashMap<u64,Id>>,
    instances: &HashMap<Id,Entry<C,u64>>, owner: u64, package: u64, peer: u64)
    -> (out: (Arc<C>,crate::viewers::Departure))
    requires
        owner != peer,
        hash_map_inv(old(views)), hash_map_inv(instances),
        obeys_key_model::<Id>(), obeys_concrete_eq::<Id>(),
        old(views)@.dom() == set![owner,peer],
        old(views)@[owner]@.dom() == set![package], old(views)@[peer]@.dom() == set![package],
        hash_map_inv(&old(views)@[owner]), hash_map_inv(&old(views)@[peer]),
        instances@.contains_key(old(views)@[owner]@[package]),
    ensures ({
        let id = old(views)@[owner]@[package];
        let entry = instances@[id];
        &&& out.0 == entry.capsule
        &&& out.1 == if !(id.identity().0.2 is SystemResident) { crate::viewers::Departure::RemoveRuntime }
            else if entry.owner_alias == Some(owner) { crate::viewers::Departure::RemoveRuntimeAndViews }
            else if old(views)@[peer]@[package] == id { crate::viewers::Departure::KeepRuntime }
            else { crate::viewers::Departure::RemoveRuntime }
    }),
{
    let ghost before = views@;
    let (id,handle) = view_lookup::detach(views,instances,&owner,&package).unwrap();
    assert(before[owner]@.remove(package).is_empty());
    assert(views@ == before.remove(owner));
    let installed = instances.get(&id).unwrap();
    let decision = crate::viewers::departure(views,&id,id.key().scope(),installed.owner_alias.as_ref(),&owner);
    proof {
        assert(views@[peer]@.values().contains(id) == (before[peer]@[package] == id)) by {
            if views@[peer]@.values().contains(id) {
                let k = choose|k:u64| views@[peer]@.contains_key(k) && views@[peer]@[k] == id;
                assert(k == package);
            }
        }
    }
    (handle.unwrap(),decision)
}

// Fresh publication and attachment to a shared runtime both derive their
// package slot from the generation. Preserve that property across all views.
fn publish_view(views: &mut HashMap<u64,HashMap<u64,Id>>, principal: u64, runtime: Id)
    requires hash_map_inv(old(views)),
        forall|p:u64| old(views)@.contains_key(p) ==> hash_map_inv(&old(views)@[p]),
        forall|p:u64,k:u64| old(views)@.contains_key(p) && old(views)@[p]@.contains_key(k) ==>
            (#[trigger] old(views)@[p]@[k]).identity().0.0 == k,
    ensures final(views)@.contains_key(principal),
        final(views)@[principal]@.contains_key(runtime.identity().0.0),
        final(views)@[principal]@[runtime.identity().0.0] == runtime,
        final(views)@[principal]@.remove(runtime.identity().0.0) ==
            (if old(views)@.contains_key(principal) { old(views)@[principal]@ } else { Map::empty() }).remove(runtime.identity().0.0),
        forall|p:u64| final(views)@.contains_key(p) ==> hash_map_inv(&final(views)@[p]),
        final(views)@.remove(principal) == old(views)@.remove(principal),
        forall|p:u64,k:u64| final(views)@.contains_key(p) && final(views)@[p]@.contains_key(k) ==>
            (#[trigger] final(views)@[p]@[k]).identity().0.0 == k,
        forall|k:u64| k != runtime.identity().0.0 && final(views)@[principal]@.contains_key(k) ==>
            (#[trigger] final(views)@[principal]@[k]) != runtime,
{
    let ghost before = views@;
    view_lookup::bind(views,principal,runtime);
    assert(views@[principal]@.remove(runtime.identity().0.0) =~=
        (if before.contains_key(principal) { before[principal]@ } else { Map::empty() }).remove(runtime.identity().0.0));
    assert forall|p:u64| views@.contains_key(p) implies hash_map_inv(&views@[p]) by {
        if p != principal {
            assert(views@.remove(principal).contains_key(p));
            assert(views@.remove(principal)[p] == before.remove(principal)[p]);
        }
    }
    assert forall|p:u64,k:u64| views@.contains_key(p) && views@[p]@.contains_key(k) implies
        (#[trigger] views@[p]@[k]).identity().0.0 == k by {
        if p != principal {
            assert(views@.remove(principal).contains_key(p));
            assert(before.contains_key(p));
            assert(views@.remove(principal)[p] == before.remove(principal)[p]);
            assert(views@[p] == before[p]);
        }
        if p != principal || k != runtime.identity().0.0 {
            assert(before.contains_key(p));
            assert(before[p]@.contains_key(k));
            assert(views@[p]@[k] == before[p]@[k]);
            assert(before[p]@[k].identity().0.0 == k);
        }
    }
}

// Bind a selected shared generation to one principal, including its exact
// installed handle. A miss cannot publish a route to a principal-owned runtime.
fn select_and_publish_shared<C: ?Sized>(views: &mut HashMap<u64,HashMap<u64,Id>>,
    routes: &mut HashMap<(u64,u64),Id>, sources: &HashMap<Id,u64>, aliases: &HashMap<u64,[u8;32]>,
    instances: &HashMap<Id,Entry<C,u64>>, principal: u64, package: u64, artifact: [u8;32])
    -> (out: Option<Arc<C>>)
    requires hash_map_inv(old(routes)), hash_map_inv(sources), hash_map_inv(aliases), obeys_key_model::<(u64,u64)>(), obeys_concrete_eq::<(u64,u64)>(),
        hash_map_inv(old(views)), hash_map_inv(instances), obeys_key_model::<Id>(),
        vstd::pervasive::obeys_clone_eq::<Id>(), obeys_concrete_eq::<Id>(), obeys_concrete_eq::<[u8;32]>(),
        old(views)@.contains_key(principal) ==> hash_map_inv(&old(views)@[principal]),
    ensures match out {
        Some(handle) => ({
            let selected = final(views)@[principal]@[package];
            &&& final(views)@.contains_key(principal) && final(views)@[principal]@.contains_key(package)
            &&& selected.identity().0 == (package,artifact,RuntimeScope::SystemResident)
            &&& instances@.contains_key(selected) && instances@[selected].capsule == handle
            &&& final(routes)@ == if sources@.contains_key(selected) {
                old(routes)@.insert((sources@[selected],principal),selected)
            } else { old(routes)@ }
            &&& final(views)@.remove(principal) == old(views)@.remove(principal)
        }),
        None => final(views)@ == old(views)@ && final(routes)@ == old(routes)@ &&
            forall|id:Id| instances@.contains_key(id) ==> id.identity().0 != (package,artifact,RuntimeScope::SystemResident),
    },
{
    let selected = view_lookup::shared(instances,&package,&artifact)?;
    let installed = crate::instance_swap::installed(instances,&selected);
    view_lookup::attach(views,routes,sources,&principal,&selected);
    if let Some(source) = sources.get(&selected) {
        let routed = crate::source_lookup::capsule_for(routes,aliases,instances,views,(*source,principal));
        assert(routed == installed);
        routed
    } else {
        installed
    }
}

// A system owner's departure may affect many packages in a peer's view. The
// report names each affected peer once and retains every different generation.
fn remove_system_owner<C: ?Sized>(views: &mut HashMap<u64,HashMap<u64,Id>>,
    instances: &mut HashMap<Id,Entry<C,u64>>, routes: &mut HashMap<(u64,u64),Id>, sources: &mut HashMap<Id,u64>, names: &mut HashMap<u64,u64>, legacy: &mut HashMap<u64,[u8;32]>, owner: u64, package: u64)
    -> (out: (Arc<C>, bool, Vec<u64>))
    requires hash_map_inv(old(views)), hash_map_inv(old(instances)), obeys_key_model::<Id>(), obeys_concrete_eq::<Id>(),
        hash_map_inv(old(legacy)), obeys_concrete_eq::<[u8;32]>(),
        hash_map_inv(old(routes)), hash_map_inv(old(sources)), hash_map_inv(old(names)),
        obeys_key_model::<(u64,u64)>(), obeys_concrete_eq::<(u64,u64)>(), vstd::pervasive::obeys_clone_eq::<(u64,u64)>(),
        old(views)@.contains_key(owner), old(views)@[owner]@.contains_key(package),
        forall|k:u64| k != package && old(views)@[owner]@.contains_key(k) ==>
            (#[trigger] old(views)@[owner]@[k]) != old(views)@[owner]@[package],
        forall|p:u64| old(views)@.contains_key(p) ==> hash_map_inv(&old(views)@[p]),
        old(views)@[owner]@[package].identity().0.2 is SystemResident,
        old(instances)@.contains_key(old(views)@[owner]@[package]),
        old(instances)@[old(views)@[owner]@[package]].owner_alias == Some(owner),
    ensures ({
        let before = old(views)@;
        let after = final(views)@;
        let id = before[owner]@[package];
        let report = out.2@;
        &&& out.0 == old(instances)@[id].capsule && out.1
        &&& final(legacy)@ == if exists|peer:Id| old(instances)@.remove(id).contains_key(peer)
            && peer.identity().0.1 == id.identity().0.1 { old(legacy)@ }
            else { crate::dependent_views::kept(old(legacy)@,id.identity().0.1) }
        &&& final(sources)@ == old(sources)@.remove(id)
        &&& final(names)@ == if old(sources)@.contains_key(id) && !old(sources)@.remove(id).values().contains(old(sources)@[id]) {
            old(names)@.remove(old(sources)@[id])
        } else { old(names)@ }
        &&& final(routes)@ == crate::dependent_views::kept(old(routes)@,id)
        &&& final(instances)@ == old(instances)@.remove(id)
        &&& report.len() > 0 && report[0] == owner && report.no_duplicates()
        &&& forall|p:u64| #[trigger] report.contains(p) == (before.contains_key(p) && before[p]@.values().contains(id))
        &&& forall|p:u64| #[trigger] after.contains_key(p) == (before.contains_key(p) && exists|k:u64| before[p]@.contains_key(k) && before[p]@[k] != id)
        &&& forall|p:u64,k:u64| after.contains_key(p) ==> ((#[trigger] after[p]@.contains_key(k)) == (before[p]@.contains_key(k) && before[p]@[k] != id))
        &&& forall|p:u64,k:u64| after.contains_key(p) && after[p]@.contains_key(k) ==> (#[trigger] after[p]@[k]) == before[p]@[k]
    }),
{
    let ghost before = views@;
    let (id,handle) = view_lookup::detach(views,instances,&owner,&package).unwrap();
    let ghost middle = views@;
    proof {
        let remaining = before[owner]@.remove(package);
        assert(middle.remove(owner) == before.remove(owner));
        assert forall|p:u64| p != owner implies
            (middle.contains_key(p) == before.contains_key(p) &&
             (middle.contains_key(p) ==> middle[p] == before[p])) by {
            assert(middle.remove(owner).contains_key(p) == before.remove(owner).contains_key(p));
            if middle.contains_key(p) { assert(middle.remove(owner)[p] == before.remove(owner)[p]); }
        }
        assert forall|p:u64| middle.contains_key(p) implies hash_map_inv(&middle[p]) by {
            if p != owner { assert(middle[p] == before[p]); }
        }
        if !remaining.is_empty() {
            assert(middle[owner]@ == remaining);
            assert forall|k:u64| remaining.contains_key(k) implies #[trigger] remaining[k] != id by {
                assert(k != package);
            }
            assert(!remaining.values().contains(id));
        }
    }
    let mut report = Vec::new();
    report.push(owner);
    let tear_down = crate::dependent_views::depart(views,instances,&id,&owner,&mut report);
    crate::dependent_views::revoke_sources(routes,sources,names,&id,&owner,tear_down);
    if tear_down { crate::dependent_views::prune_legacy(legacy,instances,id.key().artifact()); }
    proof {
        let peers = report@.skip(1);
        assert(report@ == seq![owner] + peers);
        assert(!peers.contains(owner));
        assert forall|i:int,j:int| 0 <= i < j < report@.len() implies report@[i] != report@[j] by {
            assert(peers[j-1] == report@[j]);
            if i == 0 { assert(peers.contains(report@[j])); } else { assert(peers[i-1] == report@[i]); }
        }
        assert(before[owner]@.values().contains(id));
        assert forall|p:u64| #[trigger] report@.contains(p) == (before.contains_key(p) && before[p]@.values().contains(id)) by {
            let first = seq![owner];
            if first.contains(p) {
                let i = choose|i:int| 0 <= i < first.len() && first[i] == p;
                assert(i == 0);
            } else if p == owner { assert(first[0] == p); }
            vstd::seq_lib::lemma_seq_concat_contains_all_elements(first, peers, p);
            assert(report@.contains(p) == (p == owner || peers.contains(p)));
        }
        assert forall|p:u64| #[trigger] views@.contains_key(p) ==
            (before.contains_key(p) && exists|k:u64| before[p]@.contains_key(k) && before[p]@[k] != id) by {
            assert(views@.contains_key(p) == (middle.contains_key(p) && !crate::dependent_views::kept(middle[p]@,id).is_empty()));
            if before.contains_key(p) {
                let surviving = crate::dependent_views::kept(before[p]@,id);
                if p == owner {
                    assert(surviving =~= before[p]@.remove(package));
                    if middle.contains_key(p) {
                        assert(crate::dependent_views::kept(middle[p]@,id) =~= surviving);
                    }
                }
                if !surviving.is_empty() {
                    let k = choose|k:u64| surviving.contains_key(k);
                    assert(before[p]@.contains_key(k) && before[p]@[k] != id);
                }
                if exists|k:u64| before[p]@.contains_key(k) && before[p]@[k] != id {
                    let k = choose|k:u64| before[p]@.contains_key(k) && before[p]@[k] != id;
                    assert(surviving.contains_key(k));
                }
            }
        }
    }
    (handle.unwrap(),tear_down,report)
}

// Non-owner removal keeps a shared generation referenced by any remaining
// package, preserving the entire view map and the caller's pending reports.
fn retain_shared_generation<C: ?Sized>(instances: &mut HashMap<Id,Entry<C,u64>>, views: &mut HashMap<u64,HashMap<u64,Id>>, id: &Id,
    routes: &mut HashMap<(u64,u64),Id>, sources: &mut HashMap<Id,u64>, names: &mut HashMap<u64,u64>, operator: u64, departing: u64, peer: u64, package: u64, report: &mut Vec<u64>) -> (teardown: bool)
    requires hash_map_inv(old(routes)), hash_map_inv(old(sources)), hash_map_inv(old(names)),
        obeys_key_model::<(u64,u64)>(), obeys_concrete_eq::<(u64,u64)>(), vstd::pervasive::obeys_clone_eq::<(u64,u64)>(), operator != departing, id.identity().0.2 is SystemResident,
        hash_map_inv(old(instances)), obeys_key_model::<Id>(), old(instances)@.contains_key(*id),
        old(instances)@[*id].owner_alias == Some(operator),
        hash_map_inv(old(views)), obeys_concrete_eq::<Id>(),
        forall|p:u64| old(views)@.contains_key(p) ==> hash_map_inv(&old(views)@[p]),
        old(views)@.contains_key(peer), old(views)@[peer]@.contains_key(package),
        old(views)@[peer]@[package] == *id,
    ensures final(sources)@ == old(sources)@, final(names)@ == old(names)@,
        final(routes)@ == if old(sources)@.contains_key(*id) { old(routes)@.remove((old(sources)@[*id],departing)) } else { old(routes)@ },
        !teardown, final(instances)@ == old(instances)@, final(views)@ == old(views)@, final(report)@ == old(report)@,
{
    assert(views@[peer]@.values().contains(*id));
    let teardown = crate::dependent_views::depart(views,instances,id,&departing,report);
    crate::dependent_views::revoke_sources(routes,sources,names,id,&departing,teardown);
    teardown
}
}
