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

pub(super) enum Binding {
    Missing,
    Retired,
    Bound,
}

/// Bind the registered challenge identified by its channel, preserving every
/// other entry (including concurrent challenges for the same principal).
pub(super) fn bind_registered<S, F: Fn(&S, &S) -> bool>(
    entries: &mut [Entry<S>], challenge: &S, key: String, same_channel: F,
) -> (result: Binding)
    requires
        forall|j: int| 0 <= j < old(entries).len() ==> old(entries)@[j].phase.consistent(),
        forall|s: &S| #[trigger] same_channel.requires((challenge, s)),
    ensures
        final(entries).len() == old(entries).len(),
        match result {
            Binding::Missing => final(entries)@ == old(entries)@ &&
                forall|j: int| 0 <= j < old(entries).len() ==>
                    same_channel.ensures((challenge, &old(entries)@[j].signal), false),
            Binding::Retired | Binding::Bound => exists|i: int| 0 <= i < old(entries).len()
                && same_channel.ensures((challenge, &old(entries)@[i].signal), true)
                && (forall|j: int| 0 <= j < i ==>
                    same_channel.ensures((challenge, &old(entries)@[j].signal), false))
                && (forall|j: int| 0 <= j < old(entries).len() && j != i ==>
                    final(entries)@[j] == old(entries)@[j])
                && final(entries)@[i].owner == old(entries)@[i].owner
                && final(entries)@[i].signal == old(entries)@[i].signal
                && match result {
                    Binding::Bound => old(entries)@[i].phase.bound().is_none()
                        && !old(entries)@[i].phase.excludes(key@)
                        && final(entries)@[i].phase.bound() == Some(key@)
                        && final(entries)@[i].phase.consistent(),
                    _ => final(entries)@ == old(entries)@ && (old(entries)@[i].phase.bound().is_some()
                        || old(entries)@[i].phase.excludes(key@)),
                },
        },
{
    let mut i = 0usize;
    while i < entries.len()
        invariant entries@ == old(entries)@, i <= entries.len(),
            forall|j: int| 0 <= j < old(entries).len() ==> old(entries)@[j].phase.consistent(),
            forall|s: &S| #[trigger] same_channel.requires((challenge, s)),
            forall|j: int| 0 <= j < i ==> same_channel.ensures((challenge, &old(entries)@[j].signal), false),
        decreases entries.len() - i,
    {
        if same_channel(challenge, &entries[i].signal) {
            if entries[i].phase.bind(key) {
                return Binding::Bound;
            }
            assert(entries@ =~= old(entries)@);
            return Binding::Retired;
        }
        i = i.saturating_add(1);
    }
    Binding::Missing
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
pub(super) fn retire_and_capture<'a, S, T, F: Fn(&S) -> T>(
    entries: &mut [Entry<S>], owner: &'a str, key: &'a str, capture: F,
) -> (batch: DrainBatch<'a, T>)
    requires
        forall|j: int| 0 <= j < old(entries).len() ==> old(entries)@[j].phase.consistent(),
        forall|s: &S| #[trigger] capture.requires((s,)),
    ensures
        final(entries).len() == old(entries).len(),
        forall|j: int| 0 <= j < old(entries).len() ==>
            updated(old(entries)@[j], final(entries)@[j], owner, key),
        batch.identity() == (owner, key),
        exists|slots: Seq<usize>| slots.len() == batch.handles().len() && slots.no_duplicates()
            && (forall|j: usize| #[trigger] slots.contains(j) ==
                (j < old(entries).len() && target(old(entries)@[j as int], owner, key)))
            && (forall|k: int| 0 <= k < slots.len() ==>
                capture.ensures((&old(entries)@[slots[k] as int].signal,), batch.handles()[k])),
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
    DrainBatch { owner, key, signals }
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

/// The registry snapshot and the exact operation that selected its channels.
pub(super) struct DrainBatch<'a, S> {
    owner: &'a str,
    key: &'a str,
    signals: Vec<S>,
}

/// Evidence that the native device registry observed all selected channels closed.
#[derive(Debug)]
pub struct DeviceRetirement<'a> {
    owner: &'a str,
    key: &'a str,
}

impl<'a> DeviceRetirement<'a> {
    pub closed spec fn identity(&self) -> (&'a str, &'a str) { (self.owner, self.key) }

    /// Principal whose device sessions were retired.
    #[must_use]
    pub fn principal(&self) -> (owner: &'a str)
        ensures owner == self.identity().0,
    { self.owner }

    /// Registered key whose device sessions were retired.
    #[must_use]
    pub fn key_id(&self) -> (key: &'a str)
        ensures key == self.identity().1,
    { self.key }
}

impl<'a, S> DrainBatch<'a, S> {
    pub(super) closed spec fn identity(&self) -> (&'a str, &'a str) { (self.owner, self.key) }

    pub(super) closed spec fn handles(&self) -> Seq<S> { self.signals@ }

    pub(super) fn signals(&self) -> (signals: &[S])
        ensures signals@ == self.handles(),
    { self.signals.as_slice() }

    /// A completed wait alone cannot mint a receipt. Observe closure on
    /// every selected channel before releasing either response identifier.
    pub(super) fn certify<F: Fn(&S) -> bool>(self, closed: F) -> (receipt: Option<DeviceRetirement<'a>>)
        requires forall|s: &S| #[trigger] closed.requires((s,)),
        ensures
            receipt matches Some(r) ==> r.identity() == self.identity(),
            receipt.is_some() ==> forall|j: int| 0 <= j < self.handles().len() ==>
                closed.ensures((&self.handles()[j],), true),
            receipt.is_none() ==> exists|j: int| 0 <= j < self.handles().len() &&
                closed.ensures((&self.handles()[j],), false),
    {
        let mut confirmed = 0usize;
        while confirmed < self.signals.len()
            invariant
                confirmed <= self.signals.len(),
                forall|s: &S| #[trigger] closed.requires((s,)),
                forall|j: int| 0 <= j < confirmed ==> closed.ensures((&self.handles()[j],), true),
            decreases self.signals.len() - confirmed,
        {
            let signal = &self.signals[confirmed];
            if !closed(signal) {
                assert(closed.ensures((&self.handles()[confirmed as int],), false));
                return None;
            }
            confirmed = confirmed.saturating_add(1);
        }
        Some(DeviceRetirement { owner: self.owner, key: self.key })
    }
}

}
