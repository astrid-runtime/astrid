//! Recheck captured delivery capacity under the publication-order lock.

use vstd::prelude::*;

verus! {

pub(crate) fn recheck<R, H>(
    delivery: Option<R>, observed_handoff: Option<(H, bool)>,
    delivery_required: bool, inbox_required: bool,
) -> (accepted: Option<(Option<R>, Option<H>)>)
    ensures
        accepted.is_some() == ((delivery.is_some() || !delivery_required)
            && match observed_handoff {
                Some((_, closed)) => !closed,
                None => !inbox_required,
            }),
        accepted matches Some(pair) ==> pair.0 == delivery
            && (match observed_handoff {
                Some((handoff, _)) => pair.1 == Some(handoff),
                None => pair.1.is_none(),
            }),
{
    if delivery.is_none() && delivery_required {
        return None;
    }
    let handoff = match observed_handoff {
        Some((_, true)) => return None,
        Some((handoff, false)) => Some(handoff),
        None if inbox_required => return None,
        None => None,
    };
    Some((delivery, handoff))
}

}
