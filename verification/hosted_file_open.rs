//! Compose the guest file policy, retained access and native open options.
use crate::file_access::{Access,Policy};
use crate::open_options::{Options,open_with};
use crate::host_address::{retain,Address};
use crate::mount_selection::VfsTarget;
use std::{collections::HashMap,sync::Arc};
use vstd::prelude::*;

verus! {
struct Flags(bool,bool,bool,bool);
impl Options for Flags {
    closed spec fn flags(&self) -> (bool,bool,bool,bool) { (self.0,self.1,self.2,self.3) }
    fn new() -> Self { Self(false,false,false,false) }
    fn read(&mut self, v:bool) { self.0 = v; }
    fn write(&mut self, v:bool) { self.1 = v; }
    fn create(&mut self, v:bool) { self.2 = v; }
    fn truncate(&mut self, v:bool) { self.3 = v; }
}

fn native<'a>(dir:u64,path:&'a str,write:bool,truncate:bool) -> (r:(u64,&'a str,Flags))
    ensures r.0 == dir, r.1 == path, r.2.flags() == (true,write,write,truncate),
{
    open_with(dir,path,write,truncate,
        |d:u64,p:&'a str,b:Flags| -> (result:(u64,&'a str,Flags)) ensures result == (d,p,b), { (d,p,b) })
}

type Table = HashMap<u64,Arc<u64>>;
type Mount<'a> = (&'a Table,u64);

fn in_table<'a>(table:&Table,key:u64,path:&'a str,w:bool,t:bool) -> (out:Option<(u64,&'a str,Flags)>)
    requires vstd::std_specs::hash::hash_map_inv(table),
    ensures out.is_some() == table@.contains_key(key),
        out matches Some(r) ==> r.0 == *table@[key] && r.1 == path && r.2.flags() == (true,w,w,t),
{
    let owner = retain(table,&key)?;
    let address = Address::new(owner,path,|p:&'a str| -> (r:&'a str) ensures r == p, { p });
    Some(address.run(|d:Arc<u64>,p:&'a str| -> (r:(u64,&'a str,Flags))
        ensures r.0 == *d && r.1 == p && r.2.flags() == (true,w,w,t), { native(*d,p,w,t) }))
}

spec fn permits(p:Policy,read:bool,write:bool,delete:bool) -> bool {
    match p { Policy::Read => read, Policy::Write => write, Policy::Delete => delete }
}

fn guest<'a>(access:Access<u64>,gate:&'a str,target:VfsTarget,mounts:[Option<Mount<'a>>;3],
    path:&'a str,read_ok:bool,write_ok:bool,delete_ok:bool)
    -> (out:Option<((Policy,&'a str),(u64,&'a str,Flags))>)
    requires forall|i:int| 0<=i<3 && (#[trigger] mounts@[i]).is_some() ==>
        vstd::std_specs::hash::hash_map_inv(mounts@[i].unwrap().0),
    ensures ({
        let i:int = match target { VfsTarget::Workspace => 0, VfsTarget::Home => 1, VfsTarget::Tmp => 2 };
        let mount = mounts@[i];
        let (table,key) = mount.unwrap();
        &&& out.is_some() == (mount.is_some() && table@.contains_key(key)
            && ((access is Read && read_ok) || (access is Write && write_ok)))
        &&& out matches Some((guard,call)) ==> guard == (if access is Write { Policy::Write } else { Policy::Read },gate)
            && call.0 == *table@[key] && call.1 == path
            && call.2.flags() == (true,access is Write,access is Write,access is Write)
    }),
{
    let check = |policy:Policy,g:&'a str| -> (v:Result<(Policy,&'a str),()>)
        ensures v == if permits(policy,read_ok,write_ok,delete_ok) { Ok((policy,g)) } else { Err(()) }, {
        if match policy { Policy::Read => read_ok, Policy::Write => write_ok, Policy::Delete => delete_ok } {
            Ok((policy,g))
        } else { Err(()) }
    };
    let Ok(((guard,retained),(table,key),relative)) = target.admitted(gate,path,(mounts[0],mounts[1],mounts[2]),(),
        |g:&'a str| -> (r:Result<((Policy,&'a str),Access<u64>),()>)
            ensures r == if permits(access.policy(),read_ok,write_ok,delete_ok) { Ok(((access.policy(),g),access)) } else { Err(()) },
        { access.authorize(g,check) }) else { return None; };
    let call = retained.open(key,relative,
        |h:u64,p:&'a str,w:bool,t:bool| -> (r:Option<(u64,&'a str,Flags)>)
            ensures r.is_some() == table@.contains_key(h),
                r matches Some(v) ==> v.0 == *table@[h] && v.1 == p && v.2.flags() == (true,w,w,t),
            { in_table(table,h,p,w,t) })??;
    Some((guard,call))
}
/// Follow a storage-backed replacement from guest dispatch to the close-time publication arguments.
/// The input path is the backend's resolved file path, after its directory lookup and join.
fn storage_replace<'a>(path:&'a str, existing:Option<u64>, content:&[u8], allowed:bool)
    -> (out:Option<(&'a str,Vec<u8>)>)
    ensures out.is_some() == allowed,
        out matches Some((target,data)) ==> target == path && data@ == content@,
{
    let access = Access::<u64>::Write(None);
    let (_,retained) = access.authorize(path,|policy:Policy,p:&'a str| -> (r:Result<(),()>)
        ensures r.is_ok() == (policy == Policy::Write && allowed), {
        if matches!(policy,Policy::Write) && allowed { Ok(()) } else { Err(()) }
    }).ok()?;
    let mut file = retained.open((),path,|_:(),p:&'a str,w:bool,t:bool| -> (r:Option<crate::storage_file::OpenFile<&'a str>>)
        ensures w && t ==> (r matches Some(f) && f.destination() == p && f.buffered().len() == 0
            && f.position() == 0 && f.can_write() && f.changed()), {
        crate::storage_file::open_at(p,existing,w,t,|_:&&str,_:u64,_:u64| -> Result<Vec<u8>,()> { Err(()) }).ok()
    })??;
    file.write_bytes(content);
    let (target,data) = file.publication()?;
    assert(data@ =~= content@);
    Some((*target,data.clone()))
}

/// Preserving opens read exactly the statted range of this path. Refusals retain their precedence.
fn storage_preserve(path:u64, existing:Option<u64>, write:bool, truncate:bool, bytes:Vec<u8>, readable:bool)
    -> (out:Result<crate::storage_file::OpenFile<u64>,crate::storage_file::OpenError<()>>)
    ensures match (existing,write,truncate) {
        (None,false,_) => out matches Err(crate::storage_file::OpenError::Missing),
        (Some(_),false,true) => out matches Err(crate::storage_file::OpenError::TruncateDenied),
        (None,true,_) | (Some(_),true,true) =>
            out matches Ok(f) && f.destination() == path && f.changed() && f.buffered().len() == 0,
        (Some(_),_,false) => if readable {
            out matches Ok(f) && f.destination() == path && f.buffered() == bytes@ && !f.changed() && f.can_write() == write
        } else { out matches Err(crate::storage_file::OpenError::Read(())) },
    },
{
    crate::storage_file::open_at(path,existing,write,truncate,
        |target:&u64,offset:u64,length:u64| -> (r:Result<Vec<u8>,()>)
            ensures r == if *target == path && offset == 0 && Some(length) == existing && readable { Ok(bytes) } else { Err(()) }, {
            if *target == path && offset == 0 && Some(length) == existing && readable { Ok(bytes) } else { Err(()) }
        })
}

/// Slot indices stand for mutex identities. The table chooses both the write and close targets.
fn storage_handles<'a>(first_key:String, other_key:String, path:&'a str, other_path:&'a str,
    bytes:&[u8]) -> (out:Option<(&'a str,Vec<u8>)>)
    requires first_key@ != other_key@,
    ensures out matches Some((target,data)) && target == path && data@ == bytes@,
{
    let mut table = crate::storage_handles::HandleTable::new();
    let mut files = [
        crate::storage_file::open_at(path,None,true,true,|_:&&str,_:u64,_:u64| -> Result<Vec<u8>,()> { Err(()) }).ok()?,
        crate::storage_file::open_at(other_path,None,true,true,|_:&&str,_:u64,_:u64| -> Result<Vec<u8>,()> { Err(()) }).ok()?,
    ];
    let first = first_key.clone();
    let other = other_key.clone();
    let ghost first_owned = first;
    let ghost other_owned = other;
    proof { table.membership(first_key@); }
    if !table.register(first,0usize) { return None; }
    proof { table.membership(other_key@); }
    if !table.register(other,1usize) { return None; }
    proof { table.registered_key(first_owned); }
    if table.register(first_key.clone(),1usize) { return None; }
    proof { table.registered_key(first_owned); }
    let slot = *table.lookup(first_key.as_str())?;
    proof { table.unique_binding(first_key@,0,slot); }
    files[slot].write_bytes(bytes);
    let ghost before = table;
    proof { table.registered_key(other_owned); }
    let other = table.retire(other_key.as_str())?;
    proof { before.retired_key(other_owned,other,&table); }
    assert(files[other as int].buffered().len() == 0);
    let ghost before = table;
    proof { table.registered_key(first_owned); }
    let slot = table.retire(first_key.as_str())?;
    proof { before.retired_key(first_owned,slot,&table); }
    if table.retire(first_key.as_str()).is_some() { return None; }
    let call = files[slot].publish(|p:&&'a str,b:&Vec<u8>| -> (r:(&'a str,Vec<u8>))
        ensures r.0 == *p && r.1@ == b@, { (*p,b.clone()) })?;
    assert(call.1@ =~= bytes@);
    Some(call)
}

/// At any table size, retiring a borrowed key returns the same slot selected for I/O.
fn retire_observed<V:Copy>(table:&mut crate::storage_handles::HandleTable<V>, key:&str)
    -> (out:(Option<V>,Option<V>))
    requires old(table).valid(),
    ensures out.0 == out.1, out.0.is_some() == old(table).has(key@),
        !final(table).has(key@), final(table).valid(),
        out.1 matches Some(v) ==> old(table).removed(key@,v,final(table)),
        out.1.is_none() ==> final(table).contents() == old(table).contents(),
{
    let observed = match table.lookup(key) { Some(slot) => Some(*slot), None => None };
    let ghost before = *table;
    let retired = table.retire(key);
    proof {
        if let (Some(a),Some(b)) = (observed,retired) { before.unique_binding(key@,a,b); }
    }
    (observed,retired)
}

}
