//! Consume the operation and operands released by the current directory binding.
use vstd::prelude::*;

verus! {
pub(super) fn dispatch<T,S,A,R,F: FnOnce(T,S,A) -> R>(
    cancelled: bool, retired: bool, table: T, input: (S,A,F),
) -> (out: Option<R>)
    requires !cancelled && !retired ==> input.2.requires((table,input.0,input.1)),
    ensures if cancelled || retired { out.is_none() }
        else { out matches Some(r) && input.2.ensures((table,input.0,input.1),r) },
{
    if cancelled || retired { return None; }
    let (stream,args,operation) = input;
    Some(operation(table,stream,args))
}
/// Release the original native result only while the caller remains live.
pub(super) fn disclose<R>(cancelled:bool, retired:bool, observed:R) -> (out:Option<R>)
    ensures out == if cancelled || retired { None } else { Some(observed) },
{
    if cancelled || retired { None } else { Some(observed) }
}

}
