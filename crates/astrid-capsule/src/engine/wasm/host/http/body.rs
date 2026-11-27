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

/// Prepare the guest result and any EOF audit record within the disclosure guard.
pub(super) fn stream_result<B, C, Data: FnOnce(B) -> Vec<u8>, End: FnOnce() -> Option<C>>(
    received: Option<B>, data: Data, end: End,
) -> (result: (Vec<u8>, Option<C>))
    requires match received { Some(bytes) => data.requires((bytes,)), None => end.requires(()) },
    ensures match received {
        Some(bytes) => data.ensures((bytes,), result.0) && result.1.is_none(),
        None => result.0@.len() == 0 && end.ensures((), result.1),
    },
{
    match received {
        Some(bytes) => (data(bytes), None),
        None => (Vec::new(), end()),
    }
}

/// An elapsed wait is retryable. A transport error selects its own audit record.
pub(super) fn read_outcome<B, W, E, C, Success: FnOnce(Option<B>) -> (Vec<u8>, Option<C>),
    Failure: FnOnce(W) -> (E, Option<C>)>(
    read: Option<Result<Option<B>, W>>, timeout: E, success: Success, failure: Failure,
) -> (out: (Result<Vec<u8>, E>, Option<C>))
    requires match read {
        Some(Ok(received)) => success.requires((received,)),
        Some(Err(error)) => failure.requires((error,)),
        None => true,
    },
    ensures match read {
        Some(Ok(received)) => out.0 matches Ok(bytes) && success.ensures((received,), (bytes, out.1)),
        Some(Err(error)) => out.0 matches Err(reason) && failure.ensures((error,), (reason, out.1)),
        None => out.0 == Err(timeout) && out.1.is_none(),
    },
{
    match read {
        Some(Ok(received)) => {
            let (bytes, record) = success(received);
            (Ok(bytes), record)
        },
        Some(Err(error)) => {
            let (reason, record) = failure(error);
            (Err(reason), record)
        },
        None => (Err(timeout), None),
    }
}

/// The outcome belongs to the transport on which the read was issued.
pub(super) struct Observation<H, T> { source: H, outcome: T }

impl<H, T> Observation<H, T> {
    pub(super) closed spec fn parts(&self) -> (H, T) { (self.source, self.outcome) }

    pub(super) fn new(source: H, outcome: T) -> (read: Self)
        ensures read.parts() == (source, outcome),
    { Self { source, outcome } }

    pub(super) fn release_for<F: FnOnce(&H, &H) -> bool>(self, selected: &H, same: F)
        -> (out: Option<T>)
        requires same.requires((&self.parts().0,selected)),
        ensures exists|matched: bool| #[trigger] same.ensures((&self.parts().0, selected), matched)
            && out == (if matched { Some(self.parts().1) } else { None }),
    {
        let matched = same(&self.source, selected);
        assert(same.ensures((&self.source, selected), matched));
        if matched { Some(self.outcome) } else { None }
    }
}

}
