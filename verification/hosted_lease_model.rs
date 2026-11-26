//! Trace of a single kernel-issued native mount identity. A fresh issue starts a new trace.
use vstd::prelude::*;

use crate::mount_reservation::Reservation;
use crate::storage_callback::{self, Admission, Issued, Effect, OperationClass};
use crate::storage_filesystem::StorageFilesystemOperationV1;

verus! {

enum Phase { Preparing, Published, Closed }
enum Event { Publish, Retire { affected: bool }, Revoke, Restart, Callback }

spec fn step(phase: Phase, event: Event) -> Phase {
    match event {
        Event::Publish if phase == Phase::Preparing => Phase::Published,
        Event::Retire { affected: true } | Event::Revoke | Event::Restart => Phase::Closed,
        _ => phase,
    }
}

spec fn after(events: Seq<Event>, count: int) -> Phase
    recommends 0 <= count <= events.len(),
    decreases count,
{
    if count <= 0 { Phase::Preparing }
    else { step(after(events, count - 1), events[count - 1]) }
}

/// Closing an identity is irreversible even if late publications and callbacks follow.
proof fn closure_persists(events: Seq<Event>, closed_at: int, count: int)
    requires
        0 <= closed_at < count <= events.len(),
        step(after(events, closed_at), events[closed_at]) == Phase::Closed,
    ensures after(events, count) == Phase::Closed,
    decreases count - closed_at,
{
    if count > closed_at + 1 { closure_persists(events, closed_at, count - 1); }
}

/// Revoke, matching requester retirement and restart all close this identity.
proof fn no_admission_after_close(events: Seq<Event>, i: int, count: int)
    requires 0 <= i < count <= events.len(),
        events[i] == Event::Revoke || events[i] == Event::Restart ||
            events[i] == (Event::Retire { affected: true }),
    ensures after(events, count) == Phase::Closed,
{
    closure_persists(events, i, count);
}

proof fn publication_opens_a_fresh_identity()
    ensures step(Phase::Preparing, Event::Publish) == Phase::Published,
{}

// Interpret the issue map entry, listener publication and per-lease revoked bit.
// Their synchronization and the transport's process lifetime are adapter obligations.
struct RuntimeLease<T,B> {
    issued: Issued<T,B>,
    issue: Reservation<()>,
    published: bool,
    revoked: bool,
}

impl<T,B> RuntimeLease<T,B> {
    spec fn phase(self) -> Phase {
        if self.revoked { Phase::Closed }
        else if self.published { Phase::Published }
        else if self.issue is Preparing { Phase::Preparing }
        else { Phase::Closed }
    }

    fn publish(&mut self) -> (ok: bool)
        requires old(self).issue is Preparing ==> !old(self).published && !old(self).revoked,
        ensures
            ok == (old(self).phase() == Phase::Preparing),
            final(self).phase() == step(old(self).phase(), Event::Publish),
    {
        let ok = self.issue.claim_publication();
        if ok { self.published = true; }
        ok
    }

    fn retire(&mut self, affected: bool)
        ensures final(self).phase() == step(old(self).phase(), Event::Retire { affected }),
    {
        self.issue.retire(affected);
        if affected { self.revoked = true; }
    }

    fn callback<L>(&self, lease: L, now: u64, expires: u64, authenticated: bool,
        writable: bool, operation: StorageFilesystemOperationV1)
        -> (result: Admission<L, StorageFilesystemOperationV1>)
        ensures
            (result is Accepted) == (self.phase() == Phase::Published && now <= expires &&
                authenticated && (storage_callback::access_class(operation) != OperationClass::Write || writable)),
            result matches Admission::Accepted(value) ==>
                value.binding() == (lease, operation, storage_callback::access_class(operation)),
    {
        let active = self.published && storage_callback::live(self.revoked, now, expires);
        storage_callback::admit(lease, active, authenticated, writable, operation)
    }

    /// Compose lease phase, credential and access checks with final dispatch.
    fn effect<'a,L>(&'a self, lease_id: L, now: u64, expires: u64,
        authenticated: bool, writable: bool, operation: StorageFilesystemOperationV1)
        -> (result: Option<Effect<L,&'a T,&'a B>>)
        ensures
            result.is_some() == (self.phase() == Phase::Published && now <= expires &&
                authenticated && (storage_callback::access_class(operation) != OperationClass::Write || writable)),
            result matches Some(Effect::Volume(lease, scope, backing)) ==>
                operation is VolumeInfo && lease == lease_id && *scope == self.issued.scope && *backing == self.issued.backing,
            result matches Some(Effect::Filesystem(lease, target, backing, op, class)) ==>
                !(operation is VolumeInfo) && lease == lease_id && *target == self.issued.scope &&
                *backing == self.issued.backing && op == operation && class == storage_callback::access_class(operation),
    {
        match self.callback(self.issued.bind(lease_id), now, expires, authenticated, writable, operation) {
            Admission::Accepted(ticket) => Some(ticket.into_effect()),
            _ => None,
        }
    }

    /// Once the runtime phase refines this trace prefix, even an authenticated
    /// caller with write permission can obtain no effect after closure.
    fn effect_after_closure<'a,L>(&'a self, lease: L, now: u64, expires: u64,
        operation: StorageFilesystemOperationV1, Ghost(events): Ghost<Seq<Event>>,
        Ghost(closed): Ghost<int>, Ghost(count): Ghost<int>)
        -> (result: Option<Effect<L,&'a T,&'a B>>)
        requires 0 <= closed < count <= events.len(),
            events[closed] == Event::Revoke || events[closed] == Event::Restart ||
                events[closed] == (Event::Retire { affected: true }),
            self.phase() == after(events, count),
        ensures result.is_none(),
    {
        proof { no_admission_after_close(events, closed, count); }
        self.effect(lease, now, expires, true, true, operation)
    }
}

}
