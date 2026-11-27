//! The allowed pair, count and operation must reach the same table and guard.
use crate::io_splice::{Mode, Request};
use vstd::prelude::*;

verus! {
fn transfer(request: Request, dst: u32, src: u32, count: u64, owner: u64, table: u64, mode: Mode)
    -> (out: Result<(bool,u64,u64,u32,u32,u64),u8>)
    ensures out == if request.destination == dst && request.source == src && request.length == count {
        if mode == request.mode { Ok((mode == Mode::Blocking,owner,table,dst,src,count)) } else { Err(2u8) }
    } else { Err(1u8) },
{
    let operation = request.admit(|r: Request| -> (v: Result<u64,u8>)
        ensures v == if r.destination == dst && r.source == src && r.length == count {Ok(owner)} else {Err(1u8)},
    { if r.destination == dst && r.source == src && r.length == count {Ok(owner)} else {Err(1u8)} })?;
    let blocking = matches!(mode, Mode::Blocking);
    operation.start(mode, table,
        |g:&u64,t:u64,target:Request| -> (r:(bool,u64,u64,u32,u32,u64))
            ensures r == (blocking,*g,t,target.destination,target.source,target.length), { (blocking,*g,t,target.destination,target.source,target.length) })
        .ok_or(2u8)
}
fn bound_operands(alias: &[u8], uid: &[u8;32], forward: Option<&[u8;32]>, reverse: Option<&[u8]>,
    destination: u32, source:u32, count:u64) -> (out:Result<(u32,u32,u64),(u32,u32,u64)>)
    ensures out == if (forward matches Some(f) && f@ == uid@) && (reverse matches Some(r) && r@ == alias@) {
        Ok((destination,source,count))
    } else { Err((destination,source,count)) },
{
    crate::principal_binding::with_pair(alias,uid,forward,reverse,(destination,source,count),
        |args:(u32,u32,u64)| -> (r:(u32,u32,u64)) ensures r == args, { args })
}

}
