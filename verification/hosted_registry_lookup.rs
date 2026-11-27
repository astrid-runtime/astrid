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

// Registration publishes the concrete handle and owner alias, then both
// production lookup paths must resolve that same handle, even with a legacy alias.
fn register_and_resolve<C: ?Sized>(instances: &mut HashMap<Id,Entry<C,u64>>,
    views: &mut HashMap<u64,HashMap<u64,Id>>, routes: &mut HashMap<(u64,u64),Id>,
    sources: &mut HashMap<Id,u64>, names: &mut HashMap<u64,u64>, aliases: &HashMap<u64,[u8;32]>,
    registration: crate::registration::Registration<u64,[u8;32],u64,u64,C>) -> (out:(Id,Arc<C>,Arc<C>))
    requires hash_map_inv(old(instances)), hash_map_inv(old(views)), hash_map_inv(old(routes)),
        hash_map_inv(old(sources)), hash_map_inv(old(names)), hash_map_inv(aliases),
        obeys_key_model::<Id>(), obeys_concrete_eq::<Id>(), vstd::pervasive::obeys_clone_eq::<Id>(),
        obeys_key_model::<(u64,u64)>(), obeys_concrete_eq::<(u64,u64)>(), obeys_concrete_eq::<[u8;32]>(),
        old(views)@.contains_key(registration.principal) ==> hash_map_inv(&old(views)@[registration.principal]),
    ensures ({
        let id = registration.runtime;
        let p = registration.principal;
        let u = registration.source;
        let k = id.identity().0.0;
        &&& out == (id,registration.entry.capsule,registration.entry.capsule)
        &&& final(instances)@ == old(instances)@.insert(id,registration.entry)
        &&& final(routes)@ == old(routes)@.insert((u,p),id)
        &&& final(sources)@ == old(sources)@.insert(id,u)
        &&& final(names)@ == old(names)@.insert(u,k)
        &&& final(views)@.remove(p) == old(views)@.remove(p)
        &&& final(views)@.contains_key(p) && final(views)@[p]@ ==
            (if old(views)@.contains_key(p) { old(views)@[p]@ } else { Map::empty() }).insert(k,id)
    }),
{
    let principal = registration.principal;
    let source = registration.source;
    let runtime = registration.publish(instances,views,routes,sources,names);
    let package = runtime.key().capsule_id();
    let by_package = view_lookup::capsule_for(views,instances,&principal,package).unwrap();
    let by_source = crate::source_lookup::capsule_for(routes,aliases,instances,views,(source,principal)).unwrap();
    (runtime,by_package,by_source)
}

// Outstanding reservations can complete out of order. Equal package bytes and
// source UUID still dispatch to the handle installed for each principal.
fn publish_reserved_pair<C: ?Sized>(next: &mut u64, instances: &mut HashMap<Id,Entry<C,u64>>,
    views: &mut HashMap<u64,HashMap<u64,Id>>, routes: &mut HashMap<(u64,u64),Id>,
    sources: &mut HashMap<Id,u64>, names: &mut HashMap<u64,u64>, aliases: &HashMap<u64,[u8;32]>,
    left: u64, right: u64, left_uid: u64, right_uid: u64, package: u64, artifact: [u8;32],
    source: u64, left_handle: Arc<C>, right_handle: Arc<C>) -> (out:Option<(Id,Id,Arc<C>,Arc<C>)>)
    requires left != right, left_uid != right_uid,
        hash_map_inv(old(instances)), hash_map_inv(old(views)), hash_map_inv(old(routes)),
        hash_map_inv(old(sources)), hash_map_inv(old(names)), hash_map_inv(aliases),
        !old(views)@.contains_key(left), !old(views)@.contains_key(right),
        forall|id:Id| old(instances)@.contains_key(id) ==> id.identity().1 < *old(next),
        obeys_key_model::<Id>(), obeys_concrete_eq::<Id>(), vstd::pervasive::obeys_clone_eq::<Id>(),
        obeys_key_model::<(u64,u64)>(), obeys_concrete_eq::<(u64,u64)>(), obeys_concrete_eq::<[u8;32]>(),
    ensures ({
        if *old(next) as int + 1 >= u64::MAX {
            &&& out.is_none() && *final(next) == u64::MAX
            &&& final(instances)@ == old(instances)@ && final(views)@ == old(views)@
            &&& final(routes)@ == old(routes)@ && final(sources)@ == old(sources)@ && final(names)@ == old(names)@
        } else {
            &&& out.is_some() && *final(next) as int == *old(next) as int + 2
            &&& ({
                let (a,b,ha,hb) = out.unwrap();
                &&& a.identity() == ((package,artifact,RuntimeScope::Principal(left_uid)),*old(next))
                &&& b.identity().0 == (package,artifact,RuntimeScope::Principal(right_uid))
                &&& b.identity().1 as int == a.identity().1 as int + 1 && a != b
                &&& ha == left_handle && hb == right_handle
                &&& final(instances)@ == old(instances)@.insert(b,Entry { capsule:right_handle,owner_alias:Some(right) })
                    .insert(a,Entry { capsule:left_handle,owner_alias:Some(left) })
                &&& final(instances)@.remove(a).remove(b) == old(instances)@
                &&& final(views)@.contains_key(left) && final(views)@.contains_key(right)
                &&& final(views)@[left]@ == Map::empty().insert(package,a)
                &&& final(views)@[right]@ == Map::empty().insert(package,b)
                &&& final(views)@.remove(left).remove(right) == old(views)@
                &&& final(routes)@ == old(routes)@.insert((source,right),b).insert((source,left),a)
                &&& final(sources)@ == old(sources)@.insert(b,source).insert(a,source)
                &&& final(names)@ == old(names)@.insert(source,package)
            })
        }
    }),
{
    let ghost initial_names = names@;
    let ghost initial_views = views@;
    let a = crate::runtime_generation::issue(next,package,artifact,RuntimeScope::Principal(left_uid))?;
    let b = crate::runtime_generation::issue(next,package,artifact,RuntimeScope::Principal(right_uid))?;
    assert(!instances@.contains_key(a) && !instances@.contains_key(b));
    let rb = crate::registration::Registration { runtime:b, principal:right, source,
        entry:Entry { capsule:right_handle,owner_alias:Some(right) } }.publish(instances,views,routes,sources,names);
    assert(views@.remove(right).contains_key(left) == views@.contains_key(left));
    assert(views@.remove(right) =~= initial_views);
    assert(views@[right]@ == Map::empty().insert(package,rb));
    let ra = crate::registration::Registration { runtime:a, principal:left, source,
        entry:Entry { capsule:left_handle,owner_alias:Some(left) } }.publish(instances,views,routes,sources,names);
    assert(views@.remove(left).contains_key(right));
    assert(views@.remove(left)[right] == views@[right]);
    assert(views@.remove(left).remove(right) =~= initial_views);
    assert(views@[left]@ == Map::empty().insert(package,ra));
    assert(views@[right]@ == Map::empty().insert(package,rb));
    assert(names@ =~= initial_names.insert(source,package));
    let ha = crate::source_lookup::capsule_for(routes,aliases,instances,views,(source,left)).unwrap();
    let hb = crate::source_lookup::capsule_for(routes,aliases,instances,views,(source,right)).unwrap();
    Some((ra,rb,ha,hb))
}

// A first registration for this principal and source can be removed without
// changing any pre-existing index. Capture the dispatched handle before detaching.
fn round_trip_private_registration<C: ?Sized>(instances: &mut HashMap<Id,Entry<C,u64>>,
    views: &mut HashMap<u64,HashMap<u64,Id>>, routes: &mut HashMap<(u64,u64),Id>,
    sources: &mut HashMap<Id,u64>, names: &mut HashMap<u64,u64>, aliases: &HashMap<u64,[u8;32]>,
    registration: crate::registration::Registration<u64,[u8;32],u64,u64,C>) -> (out:(Arc<C>,Arc<C>,Vec<u64>))
    requires hash_map_inv(old(instances)), hash_map_inv(old(views)), hash_map_inv(old(routes)),
        hash_map_inv(old(sources)), hash_map_inv(old(names)), hash_map_inv(aliases),
        obeys_key_model::<Id>(), obeys_concrete_eq::<Id>(), vstd::pervasive::obeys_clone_eq::<Id>(),
        obeys_key_model::<(u64,u64)>(), obeys_concrete_eq::<(u64,u64)>(),
        vstd::pervasive::obeys_clone_eq::<(u64,u64)>(), obeys_concrete_eq::<[u8;32]>(),
        forall|p:u64| old(views)@.contains_key(p) ==> hash_map_inv(&old(views)@[p]),
        registration.runtime.identity().0.2 is Principal,
        !old(instances)@.contains_key(registration.runtime), !old(views)@.contains_key(registration.principal),
        !old(routes)@.contains_key((registration.source,registration.principal)), !old(routes)@.values().contains(registration.runtime),
        !old(sources)@.contains_key(registration.runtime), !old(sources)@.values().contains(registration.source),
        !old(names)@.contains_key(registration.source),
    ensures out.0 == registration.entry.capsule, out.1 == out.0, out.2@ == seq![registration.principal],
        final(instances)@ == old(instances)@, final(views)@ == old(views)@, final(routes)@ == old(routes)@,
        final(sources)@ == old(sources)@, final(names)@ == old(names)@,
{
    let ghost initial_views = views@;
    let ghost initial_routes = routes@;
    let principal = registration.principal;
    let source = registration.source;
    let id = registration.publish(instances,views,routes,sources,names);
    let handle = crate::source_lookup::capsule_for(routes,aliases,instances,views,(source,principal)).unwrap();
    let (captured,previous) = view_lookup::detach(views,instances,&principal,id.key().capsule_id()).unwrap();
    assert(views@ =~= initial_views);
    let mut removed = Vec::new();
    removed.push(principal);
    let torn_down = crate::dependent_views::depart(views,instances,&captured,&principal,&mut removed);
    assert(torn_down);
    crate::dependent_views::revoke_sources(routes,sources,names,&captured,&principal,torn_down);
    assert(routes@ =~= initial_routes);
    (handle,previous.unwrap(),removed)
}

// Source-index changes on successful replacement, including same-UUID restarts.
fn replace_source_indexes(sources: &mut HashMap<Id,u64>, names: &mut HashMap<u64,u64>,
    retired: &Id, replacement: &Id, new_source:u64)
    requires hash_map_inv(old(sources)), hash_map_inv(old(names)), obeys_key_model::<Id>(),
        obeys_concrete_eq::<Id>(), vstd::pervasive::obeys_clone_eq::<Id>(),
    ensures final(sources)@ == old(sources)@.remove(*retired).insert(*replacement,new_source),
        final(names)@ == ({
            let prior = old(sources)@;
            let old_source = prior[*retired];
            let remaining = if prior.contains_key(*retired) && !prior.remove(*retired).values().contains(old_source) {
                old(names)@.remove(old_source)
            } else { old(names)@ };
            remaining.insert(new_source,replacement.identity().0.0)
        }),
{
    crate::dependent_views::withdraw_source(sources,names,retired);
    crate::registration::record_source(sources,names,replacement,new_source);
}

// Replace a live runtime and resolve the viewer from its pre-restart package slot.
fn route_replacement<C: ?Sized>(instances: &mut HashMap<Id,Entry<C,u64>>,
    routes: &mut HashMap<(u64,u64),Id>, views: &mut HashMap<u64,HashMap<u64,Id>>, aliases: &mut HashMap<u64,[u8;32]>,
    sources: &mut HashMap<Id,u64>, names: &mut HashMap<u64,u64>, owner_alias: Option<u64>,
    expected: Id, reserved: Id, replacement: Arc<C>, source:u64, viewer:u64, package:u64, outsider:u64)
    -> (out:Option<(Arc<C>,Arc<C>)>)
    requires hash_map_inv(old(instances)), hash_map_inv(old(routes)), hash_map_inv(old(views)), hash_map_inv(old(aliases)),
        hash_map_inv(old(sources)), hash_map_inv(old(names)),
        obeys_key_model::<Id>(), obeys_concrete_eq::<Id>(), vstd::pervasive::obeys_clone_eq::<Id>(),
        obeys_key_model::<(u64,u64)>(), obeys_concrete_eq::<(u64,u64)>(), obeys_concrete_eq::<[u8;32]>(),
        vstd::pervasive::obeys_clone_eq::<(u64,u64)>(),
        forall|p:u64| old(views)@.contains_key(p) ==> hash_map_inv(&old(views)@[p]),
        old(views)@.contains_key(viewer) && old(views)@[viewer]@.contains_key(package) && old(views)@[viewer]@[package] == expected,
        old(views)@.contains_key(outsider) ==> !old(views)@[outsider]@.values().contains(reserved) &&
            !old(views)@[outsider]@.values().contains(expected),
    ensures if old(instances)@.contains_key(expected) {
        &&& final(instances)@ == old(instances)@.remove(expected).insert(reserved,Entry { capsule:replacement, owner_alias })
        &&& final(sources)@ == old(sources)@.remove(expected).insert(reserved,source)
        &&& final(names)@.contains_key(source) && final(names)@[source] == reserved.identity().0.0
        &&& final(aliases)@ == if exists|id:Id| final(instances)@.contains_key(id) && id.identity().0.1 == expected.identity().0.1 {
            old(aliases)@
        } else { crate::dependent_views::kept(old(aliases)@,expected.identity().0.1) }
        &&& out == Some((old(instances)@[expected].capsule,replacement))
        &&& final(routes)@.contains_key((source,viewer)) && final(routes)@[(source,viewer)] == reserved
        &&& final(routes)@.contains_key((source,outsider)) == (old(routes)@.contains_key((source,outsider)) && old(routes)@[(source,outsider)] != expected)
        &&& final(routes)@.contains_key((source,outsider)) ==> final(routes)@[(source,outsider)] == old(routes)@[(source,outsider)]
    } else { out.is_none() && final(aliases)@ == old(aliases)@ && final(names)@ == old(names)@ &&
        final(sources)@ == old(sources)@ && final(views)@ == old(views)@ && final(routes)@ == old(routes)@ && final(instances)@ == old(instances)@ },
{
    let ghost before = views@;
    let publication = crate::generation_replacement::Replacement {
        expected:&expected, reserved:&reserved, source, entry:Entry {capsule:replacement,owner_alias}
    };
    let old_handle = publication.apply(instances,views,routes,sources,names,aliases)?;
    assert(views@[viewer]@[package] == reserved);
    assert(views@[viewer]@.values().contains(reserved));
    proof { if views@.contains_key(outsider) && views@[outsider]@.values().contains(reserved) {
        let k = choose|k:u64| views@[outsider]@.contains_key(k) && views@[outsider]@[k] == reserved;
        assert(before[outsider]@.contains_key(k));
        assert(before[outsider]@.values().contains(before[outsider]@[k]));
        assert(before[outsider]@[k] != expected && before[outsider]@[k] != reserved);
    } }
    assert(routes@.contains_key((source,viewer)));
    assert(routes@[(source,viewer)] == reserved);
    assert(instances@.contains_key(reserved));
    let new_handle = crate::source_lookup::capsule_for(routes,aliases,instances,views,(source,viewer)).unwrap();
    Some((old_handle,new_handle))
}

// Bind the principal preflight to the six-map publication and an actual scoped lookup.
fn publish_principal_if_current<C: ?Sized>(instances:&mut HashMap<Id,Entry<C,u64>>,
    views:&mut HashMap<u64,HashMap<u64,Id>>, routes:&mut HashMap<(u64,u64),Id>,
    sources:&mut HashMap<Id,u64>, names:&mut HashMap<u64,u64>, aliases:&mut HashMap<u64,[u8;32]>,
    principal:u64, uid:u64, package:u64, expected:&Id, reserved:&Id, source:u64, replacement:Arc<C>, provides:bool)
    -> (result:Result<Option<Arc<C>>,crate::generation_replacement::PrincipalRefusal>)
    requires hash_map_inv(old(instances)), hash_map_inv(old(views)), hash_map_inv(old(routes)),
        hash_map_inv(old(sources)), hash_map_inv(old(names)), hash_map_inv(old(aliases)),
        forall|p:u64| old(views)@.contains_key(p) ==> hash_map_inv(&old(views)@[p]),
        obeys_key_model::<Id>(), obeys_concrete_eq::<Id>(), vstd::pervasive::obeys_clone_eq::<Id>(),
        obeys_key_model::<(u64,u64)>(), obeys_concrete_eq::<(u64,u64)>(), vstd::pervasive::obeys_clone_eq::<(u64,u64)>(),
        obeys_concrete_eq::<RuntimeScope>(), obeys_concrete_eq::<[u8;32]>(),
    ensures ({
        let authorized = reserved.identity().0.2 == RuntimeScope::Principal(uid) && reserved.identity().0.0 == package &&
            !provides && expected.identity().0.2 == RuntimeScope::Principal(uid) &&
            view_lookup::slot(old(views)@,principal,package) == Some(*expected);
        &&& result.is_ok() == authorized
        &&& if authorized && old(instances)@.contains_key(*expected) {
            &&& result == Ok(Some(replacement))
            &&& final(instances)@[*reserved].owner_alias == Some(principal)
            &&& final(views)@[principal]@[package] == *reserved
            &&& final(routes)@[(source,principal)] == *reserved
        } else {
            &&& authorized ==> result == Ok(None)
            &&& final(instances)@ == old(instances)@ && final(views)@ == old(views)@ && final(routes)@ == old(routes)@
            &&& final(sources)@ == old(sources)@ && final(names)@ == old(names)@ && final(aliases)@ == old(aliases)@
        }
    }),
{
    crate::generation_replacement::admit_principal(views,&principal,&package,uid,expected,reserved,
        || -> (out:bool) ensures out == provides, { provides })?;
    let publication = crate::generation_replacement::Replacement {
        expected, reserved, source, entry:Entry { capsule:replacement, owner_alias:Some(principal) }
    };
    if publication.apply(instances,views,routes,sources,names,aliases).is_none() { return Ok(None); }
    assert(views@[principal]@[package] == *reserved);
    assert(views@[principal]@.values().contains(*reserved));
    assert(routes@.contains_key((source,principal)));
    Ok(crate::source_lookup::capsule_for(routes,aliases,instances,views,(source,principal)))
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
