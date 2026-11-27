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
}
