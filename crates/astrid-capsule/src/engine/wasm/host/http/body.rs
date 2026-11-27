//! Publication of buffered and streaming responses after admission.
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

/// Compare the reader alias and pinned UID with the opening identity.
pub(super) fn same_owner(reader: &str, creator: &str, expected: Option<&[u8; 32]>, owner: &[u8; 32])
    -> (matches: bool)
    ensures matches == (reader@ == creator@ && match expected {
        Some(uid) => uid@ == owner@,
        None => true,
    }),
{
    if reader != creator { return false; }
    let Some(uid) = expected else { return true; };
    if uid.as_slice() != owner.as_slice() { return false; }
    assert(uid@ =~= owner@);
    true
}

/// Evaluate the disclosure callback only while the resource and its reader are admitted.
pub(super) fn disclose<H,T,F:FnOnce(H)->T>(owner:bool, opening:bool, reading:bool, handle:H, effect:F)
    -> (r:Option<T>)
    requires effect.requires((handle,)),
    ensures if owner && opening && reading {
        r matches Some(v) && effect.ensures((handle,),v)
    } else { r.is_none() },
{
    if owner && opening && reading { Some(effect(handle)) } else { None }
}

}
