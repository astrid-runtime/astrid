//! Select a connected peer from the manager's current registry observation.
use std::collections::HashMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::hash::hash_map_inv;

verus! {
#[derive(Debug, PartialEq, Eq)]
pub(super) enum LookupError {
    Missing,
    Disconnected,
}

pub(super) fn select<S,P,F: Fn(&S) -> Option<P>>(
    servers: &HashMap<String,S>, requested: &str, peer: F,
) -> (result: Result<P,LookupError>)
    requires hash_map_inv(servers), forall|server:&S| #[trigger] peer.requires((server,)),
    ensures match result {
        Err(LookupError::Missing) => forall|k:String| #[trigger] servers@.contains_key(k) ==> k@ != requested@,
        Err(LookupError::Disconnected) => exists|k:String| #[trigger] servers@.contains_key(k)
            && k@ == requested@ && peer.ensures((&servers@[k],),None),
        Ok(handle) => exists|k:String| #[trigger] servers@.contains_key(k)
            && k@ == requested@ && peer.ensures((&servers@[k],),Some(handle)),
    },
{
    broadcast use vstd::std_specs::hash::group_hash_axioms;
    broadcast use vstd::std_specs::borrow::group_borrow_axioms;
    let Some(server) = servers.get(requested) else { return Err(LookupError::Missing); };
    match peer(server) {
        Some(handle) => Ok(handle),
        None => Err(LookupError::Disconnected),
    }
}
}
