//! Read the peer identity from the specific registration observed under the manager lock.
use crate::peer_selection::{select, LookupError};
use std::collections::HashMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::hash::hash_map_inv;

verus! {
/// Compose manifest admission with the two authority fields read by stdio
/// command preparation. The native ServerConfig assembly transfers the fields.
fn native_capsule_command<D,P,C,T,E,B:crate::stdio_policy::Builder<C,T,E>>(
    builder:&mut B, domains:&[D], peers:&[P], program:&str, config:&C,
) -> (out:Option<Result<T,E>>)
    ensures if domains.len() > 0 || peers.len() > 0 {
        out.is_none() && final(builder).calls() == old(builder).calls()
    } else {
        out matches Some(result) && final(builder).calls() == old(builder).calls().push(
            crate::stdio_policy::Build::Sandboxed(program@,*config,false,result))
    },
{
    let settings = crate::capsule_stdio_network::admit(domains,peers)?;
    Some(crate::stdio_policy::prepare(builder,program,config,settings.trusted,settings.allow_network))
}

/// Compose platform path validation and wrapper selection with native command
/// assembly. Config is the prepared sandbox configuration and child is the
/// resolved executable plus its arguments. The host translates native errors.
fn sandbox_child<C,P,E,H,T,B:crate::prefix_policy::Platform<C,P,E>,A:crate::stdio_policy::Assembler<P,H,T>>(
    platform:&mut B, assembler:&mut A, config:&C, child:&H, policy:crate::prefix_policy::SandboxPolicy,
) -> (out:Result<T,E>)
    ensures ({
        let checks = old(platform).checks();
        let commands = old(assembler).commands();
        let valid = checks.push(crate::prefix_policy::Check::Paths(*config,None));
        let observed = final(platform).checks();
        let built = final(assembler).commands();
        match out {
            Err(e) => built == commands && (
                observed == checks.push(crate::prefix_policy::Check::Paths(*config,Some(e))) ||
                (policy is Required && observed == valid.push(crate::prefix_policy::Check::Platform(*config,Err(e))))),
            Ok(cmd) => match policy {
                crate::prefix_policy::SandboxPolicy::Required => {
                    observed.last() matches crate::prefix_policy::Check::Platform(c,Ok(p)) &&
                    c == *config && observed == valid.push(crate::prefix_policy::Check::Platform(*config,Ok(p))) &&
                    built == commands.push(crate::stdio_policy::Assembly::Wrapped(p,*child,cmd))
                },
                crate::prefix_policy::SandboxPolicy::Off => observed == valid &&
                    built == commands.push(crate::stdio_policy::Assembly::Bare(*child,cmd)),
            },
        }
    }),
{
    let prefix = crate::prefix_policy::select(platform,config,policy);
    crate::stdio_policy::assemble(assembler,prefix,child)
}

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

/// A teardown worker and every observer retain the encoded target until completion.
fn retirement_target(capsule: &str, server: &str, scope: Option<&str>, generation: u64,
    replacement: String) -> (target: String)
    ensures target@ == crate::mcp_registration::registration(capsule@,server@,
        match scope { Some(s) => Some(s@), None => None },generation),
{
    use crate::mcp_cleanup::Phase;
    let mut phase = Phase::Open(None);
    let encoded = crate::mcp_registration::name(capsule, server, scope, generation);
    let ghost expected = encoded@;
    let accepted = phase.register(encoded);
    assert(accepted);
    let worker = phase.begin().unwrap();
    let replaced = phase.register(replacement);
    assert(!replaced);
    let duplicate = phase.begin();
    assert(duplicate.is_none());
    let observed = phase.target().unwrap();
    let target = worker.target().unwrap();
    assert(target@ == expected && observed@ == target@);
    let done = phase.finish(worker);
    assert(done && phase is Done);
    let after = phase.target();
    assert(after.is_none());
    observed
}

/// Even a completed worker for another generation cannot retire this one.
fn foreign_cleanup(capsule: &str, server: &str, generation: u64, other: u64)
    requires generation != other,
{
    use crate::mcp_cleanup::Phase;
    let mut current = Phase::Open(None);
    let mut foreign = Phase::Open(None);
    current.register(crate::mcp_registration::name(capsule, server, None, generation));
    foreign.register(crate::mcp_registration::name(capsule, server, None, other));
    let own_worker = current.begin().unwrap();
    let other_worker = foreign.begin().unwrap();
    proof { different_incarnations(capsule@,server@,None,generation,capsule@,server@,None,other); }
    let wrong = current.finish(other_worker);
    assert(!wrong && current is Draining);
    let right = current.finish(own_worker);
    assert(right && current is Done);
}

/// Every successful hook send carries the selected handle, fixed tool and caller-supplied arguments.
fn registered_hook<'a>(servers: &HashMap<String,Option<u64>>, capsule: &str, server: &str,
    scope: Option<&str>, generation:u64, action: &'a str, payload:u64)
    -> (result: Result<(u64,&'static str,(&'a str,u64)),LookupError>)
    requires hash_map_inv(servers),
    ensures ({
        let key = crate::mcp_registration::registration(capsule@,server@,
            match scope { Some(uid) => Some(uid@), None => None },generation);
        match result {
            Ok((handle,tool,args)) => tool@ == "astrid_hook_intercept"@ && args == (action,payload)
                && exists|k:String| #[trigger] servers@.contains_key(k)
                    && k@ == key && servers@[k] == Some(handle),
            Err(LookupError::Disconnected) => exists|k:String| #[trigger] servers@.contains_key(k)
                && k@ == key && servers@[k].is_none(),
            Err(LookupError::Missing) => forall|k:String| #[trigger] servers@.contains_key(k) ==> k@ != key,
        }
    }),
{
    let key = crate::mcp_registration::name(capsule,server,scope,generation);
    let call = crate::tool_call::ToolCall::hook(action,payload,
        |name: &'a str, value:u64| -> (args:(&'a str,u64)) ensures args == (name,value) { (name,value) });
    let bound = crate::tool_call::bind(servers,key.as_str(),call,
        |entry: &Option<u64>| -> (p:Option<u64>) ensures p == *entry { *entry })?;
    Ok(bound.send(|peer:u64, tool:&'static str, args:(&'a str,u64)| -> (sent:(u64,&'static str,(&'a str,u64)))
        ensures sent == (peer,tool,args) { (peer,tool,args) }))
}
}
