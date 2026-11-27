//! A captured native target survives closure and rebinding of its public handle.
use crate::host_address::{close,install,retain,Address};
use std::{collections::HashMap,sync::Arc};
use vstd::prelude::*;

verus! {
broadcast use vstd::std_specs::hash::group_hash_axioms;
fn after_rebind<'a>(table:&mut HashMap<u64,Arc<u64>>, key:u64, replacement:Arc<u64>, path:&'a str)
    -> (out:Option<((u64,&'a str),u64)>)
    requires vstd::std_specs::hash::hash_map_inv(old(table)),
    ensures out.is_some() == old(table)@.contains_key(key),
        out matches Some((work,now)) ==> work == (*old(table)@[key],path) && now == *replacement,
        final(table)@ == if old(table)@.contains_key(key) { old(table)@.insert(key,replacement) } else { old(table)@ },
{
    let Some(original) = retain(table,&key) else { return None; };
    let target = Address::new(original,path,|p:&'a str| -> (r:&'a str) ensures r == p, { p });
    let observed = target.path();
    assert(*observed == path);
    let closed = close(table,&key);
    assert(closed);
    let duplicate = close(table,&key);
    assert(!duplicate);
    let absent = retain(table,&key);
    assert(absent.is_none());
    install(table,key,replacement);
    let current = retain(table,&key).unwrap();
    let result = target.run(|d:Arc<u64>,p:&'a str| -> (r:(u64,&'a str)) ensures r == (*d,p), { (*d,p) });
    assert(table@ =~= old(table)@.insert(key,replacement));
    Some((result,*current))
}

/// Carry the guard, handle and relative operand through mount choice, directory
/// lookup and worker dispatch; another mount can contain the very same handle.
fn admitted_worker<'a>(tables:[&HashMap<u64,Arc<u64>>;3], handles:[u64;3],
    target:crate::mount_selection::VfsTarget, spelling:&'a str, relative:&'a str, allowed:bool)
    -> (out:Option<(&'a str,u64,&'a str)>)
    requires forall|i:int| 0 <= i < 3 ==> vstd::std_specs::hash::hash_map_inv(#[trigger] tables@[i]),
    ensures ({
        let i:int = match target { crate::mount_selection::VfsTarget::Workspace => 0,
            crate::mount_selection::VfsTarget::Home => 1, crate::mount_selection::VfsTarget::Tmp => 2 };
        let table = tables@[i]@;
        let key = handles@[i];
        &&& out.is_some() == (allowed && table.contains_key(key))
        &&& out matches Some((guard,dir,path)) ==> guard == spelling && dir == *table[key] && path == relative
    }),
{
    let mounts = (Some((tables[0],handles[0])),Some((tables[1],handles[1])),Some((tables[2],handles[2])));
    let Ok((guard,(table,key),path)) = target.admitted(spelling,relative,mounts,(),
        |g:&'a str| -> (r:Result<&'a str,()>) ensures r == if allowed { Ok(g) } else { Err(()) },
        { if allowed { Ok(g) } else { Err(()) } }) else { return None; };
    let dir = retain(table,&key)?;
    let address = Address::new(dir,path,|p:&'a str| -> (r:&'a str) ensures r == p, { p });
    Some(address.run(|d:Arc<u64>,p:&'a str| -> (r:(&'a str,u64,&'a str))
        ensures r == (guard,*d,p), { (guard,*d,p) }))
}
}
