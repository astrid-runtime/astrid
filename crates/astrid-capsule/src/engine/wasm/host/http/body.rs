//! Buffered response publication after device, invocation and transport completion.
use vstd::prelude::*;

verus! {

pub(super) fn finish<E>(body: Vec<u8>, read: Option<Option<Result<(), E>>>, closed: E)
    -> (result: Result<Vec<u8>, E>)
    ensures match read {
        Some(Some(Ok(()))) => result matches Ok(bytes) && bytes@ == body@,
        Some(Some(Err(error))) => result == Err(error),
        _ => result == Err(closed),
    },
{
    match read {
        Some(Some(Ok(()))) => Ok(body),
        Some(Some(Err(error))) => Err(error),
        _ => Err(closed),
    }
}

}
