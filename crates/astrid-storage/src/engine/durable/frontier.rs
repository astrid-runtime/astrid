//! Keep each accepted group and its persistence result together through publication.
use vstd::prelude::*;

verus! {

/// Select the new cached WAL arena position after the filesystem length is read.
/// Equal lengths preserve the existing tail even when pending locations exist.
pub(super) fn wal_position<L: Copy>(current: u64, tail: Option<L>, observed: u64, pending: Option<L>)
    -> (position: Option<(u64, Option<L>)>)
    ensures
        position == if observed < current { None }
            else if observed == current { Some((current, tail)) }
            else { Some((observed, if pending.is_some() { pending } else { tail })) },
{
    match observed.cmp(&current) {
        std::cmp::Ordering::Less => None,
        std::cmp::Ordering::Equal => Some((current, tail)),
        std::cmp::Ordering::Greater => Some((observed, match pending { Some(location) => Some(location), None => tail })),
    }
}

pub(super) enum PublicationError<E> { Active, Empty, Sync(E) }

/// Consume the pending count only after the actual writer sync succeeds.
pub(super) fn sync_pending<E,F>(active: bool, pending: &mut u64, poisoned: &mut bool, sync: F)
    -> (outcome: Result<u64, PublicationError<E>>)
    where F: FnOnce() -> Result<(), E>,
    requires sync.requires(()),
    ensures
        (outcome matches Err(PublicationError::Active)) == active,
        (outcome matches Err(PublicationError::Empty)) == (!active && *old(pending) == 0),
        outcome matches Ok(n) ==> n == *old(pending) && n > 0 && !active
            && exists|w: Result<(),E>| w.is_ok() && #[trigger] sync.ensures((),w),
        outcome matches Err(PublicationError::Sync(error)) ==> !active && *old(pending) > 0
            && sync.ensures((), Err(error)),
        *final(pending) == if outcome.is_ok() { 0 } else { *old(pending) },
        *final(poisoned) == (*old(poisoned) || outcome matches Err(PublicationError::Sync(_))),
{
    if active { return Err(PublicationError::Active); }
    if *pending == 0 { return Err(PublicationError::Empty); }
    let synced = sync();
    if let Err(error) = synced {
        *poisoned = true;
        return Err(PublicationError::Sync(error));
    }
    let count = *pending;
    *pending = 0;
    Ok(count)
}

pub(super) struct PersistedGroup<B, D> {
    batch: B,
    durable: D,
}

impl<B, D> PersistedGroup<B, D> {
    pub(super) closed spec fn binding(&self) -> (B, D) {
        (self.batch, self.durable)
    }

    pub(super) fn persist<E, F>(batch: B, persist: F) -> (result: Result<Self, (B, E)>)
        where F: FnOnce(&B) -> Result<D, E>,
        requires persist.requires((&batch,)),
        ensures
            result matches Ok(group) ==> group.binding().0 == batch
                && persist.ensures((&batch,), Ok(group.binding().1)),
            result matches Err((submitted, error)) ==> submitted == batch
                && persist.ensures((&batch,), Err(error)),
    {
        match persist(&batch) {
            Ok(durable) => Ok(Self { batch, durable }),
            Err(error) => Err((batch, error)),
        }
    }

    pub(super) fn publish<T, E, F>(self, advance: F) -> (result: Result<(B, T), (B, E)>)
        where F: FnOnce(D) -> Result<T, E>,
        requires advance.requires((self.binding().1,)),
        ensures
            result matches Ok((batch, frontier)) ==> batch == self.binding().0
                && advance.ensures((self.binding().1,), Ok(frontier)),
            result matches Err((submitted, error)) ==> submitted == self.binding().0
                && advance.ensures((self.binding().1,), Err(error)),
    {
        match advance(self.durable) {
            Ok(frontier) => Ok((self.batch, frontier)),
            Err(error) => Err((self.batch, error)),
        }
    }
}

}
