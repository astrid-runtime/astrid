//! Token authority derived from revocation and single-use records.

use std::{collections::HashMap, hash::Hash};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::hash::{hash_map_inv, obeys_key_model};

verus! {

broadcast use vstd::std_specs::hash::group_hash_axioms;

/// Read the live authority for the requested token, including never-marked tokens.
pub(super) fn status<K: Eq + Hash>(authority: &HashMap<K, TokenStatus>, id: &K) -> (out: TokenStatus)
    requires hash_map_inv(authority), obeys_key_model::<K>(), vstd::laws_eq::obeys_concrete_eq::<K>(),
    ensures if authority@.contains_key(*id) { out == authority@[*id] }
        else { !out.revoked() && !out.used() },
{
    match authority.get(id) {
        Some(existing) => *existing,
        None => TokenStatus::recover(false, false),
    }
}

/// Fence this token and return the same identity for the persistent write.
pub(super) fn fence_revocation<'a, K: Eq + Hash + Clone>(
    authority: &mut HashMap<K, TokenStatus>, id: &'a K,
) -> (address: (&'static str, &'a K))
    requires hash_map_inv(old(authority)), obeys_key_model::<K>(), vstd::laws_eq::obeys_concrete_eq::<K>(), vstd::pervasive::obeys_clone_eq::<K>(),
    ensures hash_map_inv(final(authority)), address.0@ == "caps:revoked"@, *address.1 == *id,
        final(authority)@.contains_key(*id), final(authority)@[*id].revoked(),
        final(authority)@[*id].used() == (old(authority)@.contains_key(*id) && old(authority)@[*id].used()),
        final(authority)@ == old(authority)@.insert(*id, final(authority)@[*id]),
{
    let mut live = status(authority, id);
    live.record_revocation();
    let key = id.clone();
    assert(vstd::pervasive::cloned(*id, key));
    authority.insert(key, live);
    Marker::Revoked.address(id)
}

/// Revocation and consumption can coexist. Each record is monotone.
#[derive(Clone, Copy)]
pub(super) struct TokenStatus {
    revoked: bool,
    used: bool,
}

#[derive(Clone, Copy)]
pub(super) enum Admission {
    Revoked,
    AlreadyUsed,
    Allowed,
}

/// Evidence loaded from one of the two durable token marker namespaces.
#[derive(Clone, Copy)]
pub(super) enum Marker {
    Revoked,
    Consumed,
}

impl Marker {
    /// Both durable namespaces must be replayed before publishing authority.
    pub(super) fn recovery_order() -> (markers: [Self; 2])
        ensures markers[0] is Revoked, markers[1] is Consumed,
    {
        [Self::Revoked, Self::Consumed]
    }

    pub(super) fn namespace(self) -> (name: &'static str)
        ensures name@ == match self {
            Self::Revoked => "caps:revoked"@,
            Self::Consumed => "caps:used"@,
        },
    {
        match self { Self::Revoked => "caps:revoked", Self::Consumed => "caps:used" }
    }

    /// Writes address the same namespace that recovery enumerates and keep the entire token key.
    pub(super) fn address<T>(self, token_key: T) -> (address: (&'static str, T))
        ensures address.1 == token_key,
            address.0@ == match self {
                Self::Revoked => "caps:revoked"@,
                Self::Consumed => "caps:used"@,
            },
    {
        (self.namespace(), token_key)
    }
}

impl TokenStatus {
    pub(super) closed spec fn revoked(&self) -> bool { self.revoked }
    pub(super) closed spec fn used(&self) -> bool { self.used }

    pub(super) fn recover(revoked: bool, used: bool) -> (status: Self)
        ensures status.revoked() == revoked, status.used() == used,
    {
        Self { revoked, used }
    }

    pub(super) fn is_revoked(self) -> (revoked: bool)
        ensures revoked == self.revoked(),
    {
        self.revoked
    }

    pub(super) fn is_used(self) -> (used: bool)
        ensures used == self.used(),
    {
        self.used
    }

    pub(super) fn record_revocation(&mut self)
        ensures final(self).revoked(), final(self).used() == old(self).used(),
    {
        self.revoked = true;
    }

    pub(super) fn record_consumption(&mut self)
        ensures final(self).revoked() == old(self).revoked(), final(self).used(),
    {
        self.used = true;
    }

    pub(super) fn restore(&mut self, marker: Marker)
        ensures
            final(self).revoked() == (old(self).revoked() || marker is Revoked),
            final(self).used() == (old(self).used() || marker is Consumed),
            forall|prefix: Seq<Marker>| (old(self).revoked(), old(self).used()) == replay(prefix)
                ==> (final(self).revoked(), final(self).used()) == #[trigger] replay(prefix.push(marker)),
    {
        let ghost before = *self;
        match marker {
            Marker::Revoked => self.record_revocation(),
            Marker::Consumed => self.record_consumption(),
        }
        proof {
            assert forall|prefix: Seq<Marker>| (before.revoked(), before.used()) == replay(prefix)
                implies (self.revoked(), self.used()) == #[trigger] replay(prefix.push(marker)) by {
                Self::restore_refines_replay(before, *self, prefix, marker);
            }
        };
    }

    /// Reflect the consume CAS result. A loser may observe a prior durable
    /// write, so it also leaves the token unavailable in the live store.
    pub(super) fn confirm_consumption(&mut self, won: bool) -> (admitted: bool)
        ensures
            final(self).revoked() == old(self).revoked(),
            final(self).used(),
            admitted == (won && !old(self).revoked() && !old(self).used()),
    {
        let admitted = won && !self.revoked && !self.used;
        self.record_consumption();
        admitted
    }

    /// Replay the durable markers recorded for one token. Startup calls this
    /// for each token it reads, so neither the order nor a duplicate record
    /// can reopen authority. A token has at most one marker in each of the
    /// two namespaces, so the list is short.
    pub(super) fn recover_markers(markers: &[Marker]) -> (status: Self)
        ensures
            (status.revoked(), status.used()) == replay(markers@),
        decreases markers.len(),
    {
        let Some(last) = markers.last() else {
            return Self::recover(false, false);
        };
        let (prefix, _) = markers.split_at(markers.len().saturating_sub(1));
        let mut status = Self::recover_markers(prefix);
        proof {
            markers@.lemma_add_last_back();
        }
        status.restore(*last);
        status
    }

    // Connect each production restore step to the abstract history for
    // this token. The adapter may encounter either namespace first.
    proof fn restore_refines_replay(before: Self, after: Self, prefix: Seq<Marker>, marker: Marker)
        requires
            (before.revoked(), before.used()) == replay(prefix),
            after.revoked() == (before.revoked() || marker is Revoked),
            after.used() == (before.used() || marker is Consumed),
        ensures
            (after.revoked(), after.used()) == replay(prefix.push(marker)),
    {
        assert(prefix.push(marker).drop_last() =~= prefix);
    }

    pub(super) fn admit(self, single_use: bool) -> (decision: Admission)
        ensures
            (decision is Revoked) == self.revoked(),
            (decision is AlreadyUsed) == (!self.revoked() && single_use && self.used()),
            (decision is Allowed) == (!self.revoked() && (!single_use || !self.used())),
    {
        if self.revoked {
            Admission::Revoked
        } else if single_use && self.used {
            Admission::AlreadyUsed
        } else {
            Admission::Allowed
        }
    }
}


// Project replay to the markers for one token. The store indexes tokens by
// ID and invokes restore only on that entry.
pub(super) closed spec fn replay(markers: Seq<Marker>) -> (bool, bool)
    decreases markers.len(),
{
    if markers.len() == 0 {
        (false, false)
    } else {
        let previous = replay(markers.drop_last());
        (previous.0 || markers.last() is Revoked, previous.1 || markers.last() is Consumed)
    }
}

// Ordering and duplication of durable records do not resurrect authority.
pub(super) proof fn replay_keeps_markers(markers: Seq<Marker>)
    ensures
        replay(markers).0 == markers.contains(Marker::Revoked),
        replay(markers).1 == markers.contains(Marker::Consumed),
    decreases markers.len(),
{
    if markers.len() == 0 {
        vstd::seq_lib::lemma_seq_empty_contains_nothing(Marker::Revoked);
        vstd::seq_lib::lemma_seq_empty_contains_nothing(Marker::Consumed);
    } else {
        let prefix = markers.drop_last();
        let last = markers.last();
        assert(markers =~= prefix.push(last));
        replay_keeps_markers(prefix);
        vstd::seq_lib::lemma_seq_contains_after_push(prefix, last, Marker::Revoked);
        vstd::seq_lib::lemma_seq_contains_after_push(prefix, last, Marker::Consumed);
    }
}

}
