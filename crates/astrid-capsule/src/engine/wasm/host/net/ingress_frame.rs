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

pub(crate) enum PublicationGuard<T> {
    Unbound,
    Signed(T),
    Denied,
}

/// Select the actual lease the publisher must run under. A device credential
/// cannot fall through to an unguarded bus operation.
pub(crate) fn publication_guard<T>(
    socket: Option<(T, &str, Option<&str>, u128)>,
    principal: &str, key: Option<&str>, owner: Option<u128>,
) -> (guard: PublicationGuard<T>)
    ensures guard == match socket {
        None => if key.is_none() { PublicationGuard::Unbound } else { PublicationGuard::Denied },
        Some((lease, peer, device, connection)) => match (device, key) {
            (Some(a), Some(b)) if a@ == b@ && peer@ == principal@ && owner == Some(connection)
                => PublicationGuard::Signed(lease),
            _ => PublicationGuard::Denied,
        },
    },
{
    let Some((lease, peer, device, connection)) = socket else {
        return if key.is_none() { PublicationGuard::Unbound } else { PublicationGuard::Denied };
    };
    let (Some(a), Some(b)) = (device, key) else { return PublicationGuard::Denied; };
    if a != b || peer != principal || owner != Some(connection) { return PublicationGuard::Denied; }
    assert(a@ =~= b@);
    assert(peer@ =~= principal@);
    PublicationGuard::Signed(lease)
}

}
