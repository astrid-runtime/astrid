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

proof fn different_incarnations(c1: Seq<char>, s1: Seq<char>, p1: Option<Seq<char>>, g1:u64,
    c2: Seq<char>, s2: Seq<char>, p2: Option<Seq<char>>, g2:u64)
    requires g1 != g2,
    ensures crate::mcp_registration::registration(c1,s1,p1,g1) != crate::mcp_registration::registration(c2,s2,p2,g2),
{
    use crate::mcp_registration::{registration,prefix,distinct_generations};
    if registration(c1,s1,p1,g1) == registration(c2,s2,p2,g2) {
        distinct_generations(prefix(c1,s1,p1),prefix(c2,s2,p2),g1,g2);
    }
}

/// Compose the native encoder with manager lookup for a registry-issued incarnation.
fn capsule_peer<'a>(servers: &HashMap<String,Option<u64>>,
    runtime: &'a crate::runtime_generation::RuntimeId<&'a str,u64,Option<&'a str>>, server: &str)
    -> (result: Result<u64,LookupError>)
    requires hash_map_inv(servers),
    ensures ({
        let (key, generation) = runtime.identity();
        let name = crate::mcp_registration::registration(key.0@, server@,
            match key.2 { Some(uid) => Some(uid@), None => None }, generation);
        match result {
            Ok(id) => exists|k:String| #[trigger] servers@.contains_key(k) && k@ == name && servers@[k] == Some(id),
            Err(LookupError::Disconnected) => exists|k:String| #[trigger] servers@.contains_key(k) && k@ == name && servers@[k].is_none(),
            Err(LookupError::Missing) => forall|k:String| #[trigger] servers@.contains_key(k) ==> k@ != name,
        }
    }),
{
    let name = crate::mcp_registration::runtime_name(runtime, server,
        |value: &&'a str| -> (text: &'a str) ensures text == *value { *value },
        |scope: Option<&'a str>| -> (text: Option<String>)
            ensures match scope {
                Some(uid) => text matches Some(t) && t@ == uid@,
                None => text.is_none(),
            }
        { match scope { Some(uid) => Some(uid.to_owned()), None => None } });

    registered_peer(servers, name.as_str())
}
}
