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

// Model the native table by its identity. The directory observations come from
// the lookup performed at start, which may differ from those at admission.
type Operands = (u64, u32, u32, u64);

fn rebound_transfer<'a>(request: Request, mode: Mode, admitted: bool, table: u64,
    alias: &'a [u8], uid: &'a [u8;32], forward: Option<&[u8;32]>, reverse: Option<&[u8]>)
    -> (out: Option<Operands>)
    ensures out == if admitted && request.mode == mode
        && (forward matches Some(f) && f@ == uid@) && (reverse matches Some(r) && r@ == alias@) {
        Some((table,request.destination,request.source,request.length))
    } else { None },
{
    let operation = request.admit(|_:Request| -> (v:Result<(&'a [u8], &'a [u8;32]),()>)
        ensures v == if admitted { Ok((alias,uid)) } else { Err(()) },
    { if admitted { Ok((alias,uid)) } else { Err(()) } }).ok()?;
    operation.start(mode,table,
        |guard:&(&'a [u8], &'a [u8;32]), t:u64, r:Request| -> (value:Option<Operands>)
            ensures value == if (forward matches Some(f) && f@ == guard.1@)
                    && (reverse matches Some(a) && a@ == guard.0@) {
                Some((t,r.destination,r.source,r.length))
            } else { None },
        {
            crate::principal_binding::with_pair(guard.0,guard.1,forward,reverse,
                (t,r.destination,r.source,r.length),
                |args:Operands| -> (result:Operands) ensures result == args, { args }).ok()
        })?
}

// Include the operation itself in the bound tuple. The operands and result can
// be any types, including a byte buffer or an error from the native table.
fn stream_access<T,S,A,R,F:FnOnce(T,S,A)->R>(
    alias:&[u8], uid:&[u8;32], forward:Option<&[u8;32]>, reverse:Option<&[u8]>,
    cancelled:bool, retired:bool, table:T, stream:S, args:A, op:F,
) -> (out:Option<R>)
    requires !cancelled && !retired ==> op.requires((table,stream,args)),
    ensures if !cancelled && !retired && (forward matches Some(f) && f@ == uid@)
        && (reverse matches Some(r) && r@ == alias@) {
        out matches Some(value) && op.ensures((table,stream,args),value)
    } else { out.is_none() },
{
    crate::principal_binding::with_pair(alias,uid,forward,reverse,(stream,args,op),
        |bound:(S,A,F)| -> (value:Option<R>)
            requires !cancelled && !retired ==> bound.2.requires((table,bound.0,bound.1)),
            ensures if cancelled || retired { value.is_none() }
                else { value matches Some(v) && bound.2.ensures((table,bound.0,bound.1),v) },
        { crate::io_dispatch::dispatch(cancelled,retired,table,bound) }).ok()?
}

// The completion snapshot may differ from both opening and start. Preserve the
// exact observed bytes or error only if the captured UID still owns the alias.
fn blocking_completion<R>(alias:&[u8],expected:Option<[u8;32]>, opening:[u8;32],
    forward:Option<&[u8;32]>,reverse:Option<&[u8]>,cancelled:bool,retired:bool,
    observed:R) -> (out:Option<R>)
    ensures out == if (expected matches Some(e) ==> e@ == opening@)
        && (forward matches Some(f) && f@ == opening@) && (reverse matches Some(r) && r@ == alias@)
        && !cancelled && !retired { Some(observed) } else { None },
{
    let uid = crate::principal_binding::select(expected,opening)?;
    crate::principal_binding::with_pair(alias,&uid,forward,reverse,observed,
        |result:R| -> (value:Option<R>) ensures value == if cancelled || retired { None } else { Some(result) },
        { crate::io_dispatch::disclose(cancelled,retired,result) }).ok()?
}

}
