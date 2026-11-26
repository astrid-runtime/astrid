//! Consume an ordered delivery with the reservation that accompanied its event.

use vstd::prelude::*;

verus! {

pub(super) fn dispatch<E, R, T, F>(event: E, reservation: Option<R>, deliver: F)
    -> (outcome: Result<T, E>)
    where F: FnOnce(R, E) -> T,
    requires reservation matches Some(r) ==> deliver.requires((r, event)),
    ensures
        match reservation {
            Some(r) => outcome matches Ok(receipt) && deliver.ensures((r, event), receipt),
            None => outcome == Err(event),
        },
{
    match reservation {
        Some(reserved) => Ok(deliver(reserved, event)),
        None => Err(event),
    }
}

}
