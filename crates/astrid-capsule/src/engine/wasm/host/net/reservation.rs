//! TCP quota accounting and admission from the listener’s pending slot.
use vstd::prelude::*;

verus! {
pub(super) fn reserve(count: usize, limit: usize) -> (next: Option<usize>)
    ensures if count < limit {
        next matches Some(n) && n as int == count as int + 1 && n <= limit
    } else { next.is_none() },
{
    if count < limit { Some(count + 1) } else { None }
}

pub(super) enum TcpAcceptAdmission<T> {
    Reserved(T),
    Fresh,
    Full,
}

pub(super) fn admit<T, F: FnOnce() -> usize>(slot: &mut Option<T>, limit: usize, occupancy: F)
    -> (admission: TcpAcceptAdmission<T>)
    requires occupancy.requires(()),
    ensures
        final(slot).is_none(),
        match admission {
            TcpAcceptAdmission::Reserved(value) => *old(slot) == Some(value),
            TcpAcceptAdmission::Fresh => old(slot).is_none()
                && exists|n: usize| #[trigger] occupancy.ensures((), n) && n < limit,
            TcpAcceptAdmission::Full => old(slot).is_none()
                && exists|n: usize| #[trigger] occupancy.ensures((), n) && n >= limit,
        },
{
    if let Some(connection) = slot.take() {
        TcpAcceptAdmission::Reserved(connection)
    } else if occupancy() >= limit {
        TcpAcceptAdmission::Full
    } else {
        TcpAcceptAdmission::Fresh
    }
}
}
