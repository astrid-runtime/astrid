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

pub(super) enum StreamCharge { Reserved, Fresh }
pub(super) enum RegisterError<E> { Quota, Table(E) }

#[cfg(verus_keep_ghost)]
pub(super) ghost enum Event<S,H,E> {
    Claim, Reserve(bool), Publish(S,Result<H,E>), Release,
}

pub(super) trait StreamTable<S,H,E> {
    spec fn events(&self) -> Seq<Event<S,H,E>>;
    fn claim(&mut self)
        ensures final(self).events() == old(self).events().push(Event::Claim);
    fn reserve(&mut self) -> (ok: bool)
        ensures final(self).events() == old(self).events().push(Event::Reserve(ok));
    fn publish(&mut self, socket: S) -> (r: Result<H,E>)
        ensures final(self).events() == old(self).events().push(Event::Publish(socket,r));
    fn release(&mut self)
        ensures final(self).events() == old(self).events().push(Event::Release);
}

pub(super) fn register<S,H,E,B:StreamTable<S,H,E>>(table: &mut B, socket: S, charge: StreamCharge)
    -> (out: Result<H, RegisterError<E>>)
    ensures ({
        let before = old(table).events();
        let charged = before.push(match charge {
            StreamCharge::Reserved => Event::Claim, StreamCharge::Fresh => Event::Reserve(true),
        });
        final(table).events() == match out {
            Ok(handle) => charged.push(Event::Publish(socket,Ok(handle))),
            Err(RegisterError::Table(e)) => charged.push(Event::Publish(socket,Err(e))).push(Event::Release),
            Err(RegisterError::Quota) => before.push(Event::Reserve(false)),
        }
        && (out matches Err(RegisterError::Quota) ==> charge is Fresh)
    }),
{
    match charge {
        StreamCharge::Reserved => table.claim(),
        StreamCharge::Fresh => if !table.reserve() { return Err(RegisterError::Quota); },
    }
    match table.publish(socket) {
        Ok(handle) => Ok(handle),
        Err(error) => { table.release(); Err(RegisterError::Table(error)) },
    }
}
}
