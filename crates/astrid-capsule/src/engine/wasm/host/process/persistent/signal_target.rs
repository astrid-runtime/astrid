//! Unix signal delivery to a child group with a direct-child fallback.
use vstd::prelude::*;

verus! {
pub(super) enum DeliveryError<E> { Closed, InvalidPid, Send(E) }

pub(super) fn deliver<S: Copy,E,G: FnOnce(i32,S) -> bool,P: FnOnce(i32,S) -> Result<(),E>>(
    pid: u32, signal: S, group: G, process: P,
) -> (out: Result<(),DeliveryError<E>>)
    requires
        0 < pid <= i32::MAX ==> group.requires((pid as i32,signal)),
        0 < pid <= i32::MAX && group.ensures((pid as i32,signal),false)
            ==> process.requires((pid as i32,signal)),
    ensures
        if pid == 0 { out == Err(DeliveryError::Closed) }
        else if pid > i32::MAX { out == Err(DeliveryError::InvalidPid) }
        else {
            let args = (pid as i32,signal);
            match out {
                Ok(unit) => group.ensures(args,true) ||
                    (group.ensures(args,false) && process.ensures(args,Ok::<(),E>(unit))),
                Err(DeliveryError::Send(e)) => group.ensures(args,false) && process.ensures(args,Err(e)),
                _ => false,
            }
        },
{
    if pid == 0 { return Err(DeliveryError::Closed); }
    if pid > i32::MAX as u32 { return Err(DeliveryError::InvalidPid); }
    let target = pid as i32;
    assert(target as int == pid as int);
    let sent = group(target,signal);
    assert(group.ensures((target,signal),sent));
    if sent { return Ok(()); }
    let fallback = process(target,signal);
    assert(process.ensures((target,signal),fallback));
    match fallback {
        Ok(unit) => Ok(unit),
        Err(error) => Err(DeliveryError::Send(error)),
    }
}
}
