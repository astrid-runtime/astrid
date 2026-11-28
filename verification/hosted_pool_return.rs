//! Compose the production checkout decision with its cleanup handoff.
use crate::pool_return::{finish, policy, Returned};
use std::collections::HashMap;
use vstd::prelude::*;

verus! {
fn checkout(healthy: bool, free: bool, empty: bool, responses: &HashMap<u64, u64>, store: u64) -> (result: Returned<(u64, bool)>)
    requires vstd::std_specs::hash::hash_map_inv(responses),
    ensures match result {
        Returned::Warm((id, reset)) => id == store && healthy && (!free || (empty && responses@.len() == 0)) && reset == free,
        Returned::Retired((id, reset)) => id == store && reset && (!healthy || (free && (!empty || responses@.len() != 0))),
    },
{
    let decision = policy(healthy, free, responses, || -> (r: bool) ensures r == empty, { empty });
    finish(decision, (store, false), |value: (u64, bool), reset: bool| -> (r: (u64, bool))
        ensures r == (value.0, reset), { (value.0, reset) })
}

struct Store {
    id: u64,
    table: u64,
    responses: HashMap<u64, u64>,
}

/// Compose occupancy, policy and the actual table/map reset on one leased value.
fn return_store(store: Store, healthy: bool, free: bool, occupied: bool, replacement: u64)
    -> (returned: Returned<Store>)
    requires vstd::std_specs::hash::hash_map_inv(&store.responses),
    ensures match returned {
        Returned::Warm(after) => {
            &&& after.id == store.id
            &&& healthy && (!free || (!occupied && store.responses@.len() == 0))
            &&& after.table == (if free { replacement } else { store.table })
            &&& after.responses@ == (if free { Map::empty() } else { store.responses@ })
        },
        Returned::Retired(after) => {
            &&& !healthy || (free && (occupied || store.responses@.len() != 0))
            &&& after.id == store.id && after.table == replacement && after.responses@ == Map::empty()
        },
    },
{
    let decision = policy(healthy, free, &store.responses,
        || -> (r: bool) ensures r == !occupied, { !occupied });
    finish(decision, store, |input: Store, reset: bool| -> (after: Store)
        requires vstd::std_specs::hash::hash_map_inv(&input.responses),
        ensures after.id == input.id,
            after.table == (if reset { replacement } else { input.table }),
            after.responses@ == (if reset { Map::empty() } else { input.responses@ }),
    {
        let mut value = input;
        crate::pool_return::reset_resources(&mut value.table, &mut value.responses, reset,
            || -> (r: u64) ensures r == replacement, { replacement });
        value
    })
}

}
