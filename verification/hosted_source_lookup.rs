//! A source UUID names an artifact. Resolution depends on the current indexes.
use crate::{generation::RuntimeId, instance_swap::Entry, source_lookup::{capsule_for,eligible}};
use std::{collections::HashMap,sync::Arc};
use vstd::prelude::*;
use vstd::{laws_eq::obeys_concrete_eq,std_specs::hash::{hash_map_inv,obeys_key_model}};

type Id = RuntimeId<u64,u64,u64>;

verus! {
fn resolve_source<C: ?Sized>(scoped: &HashMap<(u64,u64),Id>, aliases: &HashMap<u64,u64>,
    instances: &HashMap<Id,Entry<C,u64>>, views: &HashMap<u64,HashMap<u64,Id>>,
    uuid: u64, principal: u64) -> (out: Option<Arc<C>>)
    requires hash_map_inv(scoped), hash_map_inv(aliases), hash_map_inv(instances), hash_map_inv(views),
        obeys_key_model::<(u64,u64)>(), obeys_key_model::<Id>(), obeys_concrete_eq::<Id>(),
        forall|p:u64| views@.contains_key(p) ==> hash_map_inv(&views@[p]),
    ensures ({
        if scoped@.contains_key((uuid,principal)) {
            let runtime = scoped@[(uuid,principal)];
            out == if instances@.contains_key(runtime) { Some(instances@[runtime].capsule) } else { None }
        } else if aliases@.contains_key(uuid) && views@.contains_key(principal) {
            let view = views@[principal]@;
            let keys = view.dom().filter(|k:u64| eligible(view[k],aliases@[uuid],instances@));
            match out {
                Some(handle) => exists|k:u64| keys == Set::empty().insert(k) && handle == #[trigger] instances@[view[k]].capsule,
                None => forall|k:u64| keys != #[trigger] Set::empty().insert(k),
            }
        } else { out.is_none() }
    }),
{
    broadcast use vstd::std_specs::hash::group_hash_axioms;
    capsule_for(scoped,aliases,instances,views,(uuid,principal))
}
}
