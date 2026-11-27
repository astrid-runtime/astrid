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
}
