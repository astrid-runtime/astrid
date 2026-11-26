//! Transitions of one registered challenge or signed connection.

use vstd::hash_set::StringHashSet;
use vstd::prelude::*;

verus! {

pub(super) enum Phase {
    Challenge(StringHashSet),
    Serving(String),
}

impl Phase {
    pub(super) closed spec fn excludes(&self, key: Seq<char>) -> bool {
        match self { Self::Challenge(keys) => keys@.contains(key), Self::Serving(_) => false }
    }

    pub(super) closed spec fn bound(&self) -> Option<Seq<char>> {
        match self { Self::Serving(key) => Some(key@), Self::Challenge(_) => None }
    }

    pub(super) closed spec fn consistent(&self) -> bool {
        match self { Self::Challenge(keys) => keys.well_formed(), Self::Serving(_) => true }
    }

    pub(super) fn challenge() -> (phase: Self)
        ensures phase.consistent(), phase.bound().is_none(), forall|key: Seq<char>| !phase.excludes(key),
    {
        Self::Challenge(StringHashSet::new())
    }

    pub(super) fn bind(&mut self, key: String) -> (ok: bool)
        requires old(self).consistent(),
        ensures
            final(self).consistent(),
            ok == (old(self).bound().is_none() && !old(self).excludes(key@)),
            ok ==> final(self).bound() == Some(key@),
            !ok ==> *final(self) == *old(self),
    {
        let Self::Challenge(retired) = self else { return false; };
        if retired.contains(&key) { return false; }
        *self = Self::Serving(key);
        true
    }

    /// Return whether the caller must signal and drain this entry.
    pub(super) fn retire(&mut self, owner: &str, requested: &str, key: &str) -> (drain: bool)
        requires old(self).consistent(),
        ensures
            final(self).consistent(),
            drain == (owner@ == requested@ && old(self).bound() == Some(key@)),
            final(self).bound() == old(self).bound(),
            forall|other: Seq<char>| final(self).excludes(other) ==
                (old(self).excludes(other) || (old(self).bound().is_none()
                    && owner@ == requested@ && other == key@)),
    {
        if owner != requested { return false; }
        assert(owner@ =~= requested@);
        match self {
            Self::Challenge(keys) => { keys.insert(key.to_owned()); false }
            Self::Serving(bound) => bound.as_str() == key,
        }
    }
}

#[derive(Debug)]
pub(super) struct Entry<S> {
    pub(super) owner: String,
    pub(super) phase: Phase,
    pub(super) signal: S,
}

pub(super) closed spec fn target<S>(entry: Entry<S>, owner: &str, key: &str) -> bool {
    entry.owner@ == owner@ && entry.phase.bound() == Some(key@)
}

pub(super) closed spec fn updated<S>(before: Entry<S>, after: Entry<S>, owner: &str, key: &str) -> bool {
    &&& before.owner == after.owner
    &&& before.signal == after.signal
    &&& after.phase.consistent()
    &&& after.phase.bound() == before.phase.bound()
    &&& forall|other: Seq<char>| after.phase.excludes(other) ==
        (before.phase.excludes(other) || (before.phase.bound().is_none() &&
            before.owner@ == owner@ && other == key@))
}

/// Update every outstanding challenge and collect precisely the serving
/// slots whose channels the caller must signal and await under this snapshot.
pub(super) fn retire_entries<S>(entries: &mut [Entry<S>], owner: &str, key: &str)
    -> (drains: Vec<usize>)
    requires forall|j: int| 0 <= j < old(entries).len() ==> old(entries)@[j].phase.consistent(),
    ensures
        final(entries).len() == old(entries).len(),
        forall|j: int| 0 <= j < old(entries).len() ==>
            updated(old(entries)@[j], final(entries)@[j], owner, key),
        forall|j: usize| #[trigger] drains@.contains(j) ==
            (j < old(entries).len() && target(old(entries)@[j as int], owner, key)),
        drains@.no_duplicates(),
{
    broadcast use vstd::seq_lib::lemma_seq_contains_after_push;
    let mut drains = Vec::new();
    let mut i = 0usize;
    while i < entries.len()
        invariant
            i <= entries.len() == old(entries).len(),
            forall|j: int| i <= j < entries.len() ==> entries@[j] == old(entries)@[j],
            forall|j: int| 0 <= j < old(entries).len() ==> old(entries)@[j].phase.consistent(),
            forall|j: int| 0 <= j < i ==> updated(old(entries)@[j], entries@[j], owner, key),
            forall|j: usize| #[trigger] drains@.contains(j) ==
                (j < i && target(old(entries)@[j as int], owner, key)),
            drains@.no_duplicates(),
        decreases entries.len() - i,
    {
        assert(!drains@.contains(i));
        let entry = &mut entries[i];
        let drain = entry.phase.retire(entry.owner.as_str(), owner, key);
        assert(drain == target(old(entries)@[i as int], owner, key));
        let ghost previous = drains@;
        if drain {
            drains.push(i);
            assert forall|a: int, b: int| 0 <= a < b < drains.len() implies drains@[a] != drains@[b] by {
                if b == previous.len() { assert(previous.contains(previous[a])); }
            };
        }
        assert forall|j: usize| #[trigger] drains@.contains(j) ==
            (j <= i && target(old(entries)@[j as int], owner, key)) by {
            assert(previous.contains(j) == (j < i && target(old(entries)@[j as int], owner, key)));
            if drain { vstd::seq_lib::lemma_seq_contains_after_push(previous, i, j); }
        }
        i = i.saturating_add(1);
    }
    drains
}

/// Capture channel handles while the registry is still locked. The returned
/// vector can be drained after the lock has been released.
pub(super) fn retire_and_capture<S, T, F: Fn(&S) -> T>(
    entries: &mut [Entry<S>], owner: &str, key: &str, capture: F,
) -> (signals: Vec<T>)
    requires
        forall|j: int| 0 <= j < old(entries).len() ==> old(entries)@[j].phase.consistent(),
        forall|s: &S| #[trigger] capture.requires((s,)),
    ensures
        final(entries).len() == old(entries).len(),
        forall|j: int| 0 <= j < old(entries).len() ==>
            updated(old(entries)@[j], final(entries)@[j], owner, key),
        exists|slots: Seq<usize>| slots.len() == signals.len() && slots.no_duplicates()
            && (forall|j: usize| #[trigger] slots.contains(j) ==
                (j < old(entries).len() && target(old(entries)@[j as int], owner, key)))
            && (forall|k: int| 0 <= k < slots.len() ==>
                capture.ensures((&old(entries)@[slots[k] as int].signal,), signals@[k])),
{
    let slots = retire_entries(entries, owner, key);
    let mut signals = Vec::with_capacity(slots.len());
    let mut i = 0usize;
    while i < slots.len()
        invariant
            i == signals.len() <= slots.len(),
            forall|j: usize| #[trigger] slots@.contains(j) ==
                (j < old(entries).len() && target(old(entries)@[j as int], owner, key)),
            entries.len() == old(entries).len(),
            forall|j: int| 0 <= j < entries.len() ==>
                updated(old(entries)@[j], entries@[j], owner, key),
            forall|s: &S| #[trigger] capture.requires((s,)),
            forall|k: int| 0 <= k < i ==>
                capture.ensures((&old(entries)@[slots@[k] as int].signal,), signals@[k]),
        decreases slots.len() - i,
    {
        let slot = slots[i];
        assert(slots@.contains(slot));
        signals.push(capture(&entries[slot].signal));
        i = i.saturating_add(1);
    }
    assert(slots@.no_duplicates());
    signals
}

}

impl std::fmt::Debug for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Challenge(_) => f.write_str("Challenge"),
            Self::Serving(key) => f.debug_tuple("Serving").field(key).finish(),
        }
    }
}

verus! {

/// The cursor keeps the actual notification handles in their captured order.
/// Only an affirmative observation on the current handle advances it.
pub(super) struct DrainBatch<S> {
    signals: Vec<S>,
    confirmed: usize,
}

impl<S> DrainBatch<S> {
    pub(super) closed spec fn handles(&self) -> Seq<S> { self.signals@ }
    pub(super) closed spec fn count(&self) -> nat { self.confirmed as nat }

    pub(super) fn new(signals: Vec<S>) -> (batch: Self)
        ensures batch.handles() == signals@, batch.count() == 0,
    {
        Self { signals, confirmed: 0 }
    }

    pub(super) fn pending(&self) -> (signal: Option<&S>)
        requires self.count() <= self.handles().len(),
        ensures match signal {
            None => self.count() == self.handles().len(),
            Some(s) => self.count() < self.handles().len() && *s == self.handles()[self.count() as int],
        },
    {
        self.signals.get(self.confirmed)
    }

    pub(super) fn confirm<F: Fn(&S) -> bool>(&mut self, closed: F) -> (advanced: bool)
        requires
            old(self).count() <= old(self).handles().len(),
            forall|s: &S| #[trigger] closed.requires((s,)),
        ensures
            final(self).handles() == old(self).handles(),
            final(self).count() == old(self).count() + if advanced { 1nat } else { 0nat },
            final(self).count() <= final(self).handles().len(),
            old(self).count() == old(self).handles().len() ==> !advanced,
            old(self).count() < old(self).handles().len() ==>
                closed.ensures((&old(self).handles()[old(self).count() as int],), advanced),
    {
        if self.confirmed >= self.signals.len() { return false; }
        let signal = &self.signals[self.confirmed];
        if !closed(signal) { return false; }
        self.confirmed = self.confirmed.saturating_add(1);
        true
    }
}

}
