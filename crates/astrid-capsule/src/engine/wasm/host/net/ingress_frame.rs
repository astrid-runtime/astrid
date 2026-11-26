//! Select the authenticated connection identity for one completed read.

use vstd::prelude::*;

verus! {

pub(super) fn select<T>(uplink: bool, data: bool, binding: Option<T>) -> (stamp: Option<T>)
    ensures stamp == if uplink && data { binding } else { None },
{
    if uplink && data { binding } else { None }
}

/// Move the captured operation out of the Store before admission or delivery.
pub(crate) fn take_publication<T>(slot: &mut Option<T>) -> (captured: Option<T>)
    ensures captured == *old(slot), final(slot).is_none(),
{
    slot.take()
}

/// Admit only the topic and normalized payload captured together from the frame.
pub(crate) fn matches_publication(topic: &[u8], body: &[u8], offered_topic: &[u8], offered_body: &[u8]) -> (accepted: bool)
    ensures accepted == (topic@ == offered_topic@ && body@ == offered_body@),
{
    if topic != offered_topic { return false; }
    if body != offered_body { return false; }
    assert(topic@ =~= offered_topic@);
    assert(body@ =~= offered_body@);
    true
}

}
