//! Read the peer identity from the specific registration observed under the manager lock.
use crate::peer_selection::{select, LookupError};
use std::collections::HashMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::hash::hash_map_inv;

verus! {
fn registered_peer(servers: &HashMap<String,Option<u64>>, name: &str)
    -> (result: Result<u64,LookupError>)
    requires hash_map_inv(servers),
    ensures match result {
        Ok(id) => exists|k:String| #[trigger] servers@.contains_key(k) && k@ == name@ && servers@[k] == Some(id),
        Err(LookupError::Disconnected) => exists|k:String| #[trigger] servers@.contains_key(k) && k@ == name@ && servers@[k].is_none(),
        Err(LookupError::Missing) => forall|k:String| #[trigger] servers@.contains_key(k) ==> k@ != name@,
    },
{
    select(servers,name,|entry:&Option<u64>| -> (out:Option<u64>) ensures out == *entry { *entry })
}
}
