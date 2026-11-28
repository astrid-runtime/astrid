//! Token authority derived from revocation and single-use records.

use std::{collections::HashMap, hash::Hash};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::hash::{hash_map_inv, obeys_key_model};
#[cfg(verus_keep_ghost)]
use vstd::std_specs::iter::IteratorSpec;

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

/// Bind a single-use marker address to the live entry updated after the CAS.
pub(super) struct Consumption<'a,K> {
    id: &'a K,
}

impl<'a,K: Eq + Hash + Clone> Consumption<'a,K> {
    pub(super) closed spec fn target(&self) -> K { *self.id }

    pub(super) fn new(id:&'a K) -> (out:Self)
        ensures out.target() == *id,
    { Self { id } }

    pub(super) fn address(&self) -> (out:(&'static str,&'a K))
        ensures out.0@ == "caps:used"@, *out.1 == self.target(),
    { Marker::Consumed.address(self.id) }

    pub(super) fn finish(self,authority:&mut HashMap<K,TokenStatus>,won:bool) -> (admitted:bool)
        requires hash_map_inv(old(authority)),obeys_key_model::<K>(),vstd::laws_eq::obeys_concrete_eq::<K>(),
            vstd::pervasive::obeys_clone_eq::<K>(),
        ensures hash_map_inv(final(authority)), ({
            let id = self.target();
            let revoked = old(authority)@.contains_key(id) && old(authority)@[id].revoked();
            let used = old(authority)@.contains_key(id) && old(authority)@[id].used();
            &&& admitted == (won && !revoked && !used)
            &&& final(authority)@.contains_key(id) && final(authority)@[id].used()
            &&& final(authority)@[id].revoked() == revoked
            &&& final(authority)@ == old(authority)@.insert(id,final(authority)@[id])
        }),
    {
        let key = self.id.clone();
        assert(vstd::pervasive::cloned(*self.id,key));
        let slot = authority.entry(key).or_insert(TokenStatus::recover(false,false));
        slot.confirm_consumption(won)
    }
}

/// Rebuild the complete live map before the store becomes available.
pub(super) fn recover_authority<K: Eq + Hash>(
    recorded: HashMap<K, Vec<Marker>>,
) -> (live: HashMap<K, TokenStatus>)
    requires hash_map_inv(&recorded), obeys_key_model::<K>(), vstd::laws_eq::obeys_concrete_eq::<K>(),
    ensures hash_map_inv(&live), live@.dom() == recorded@.dom(),
        forall|id: K| recorded@.contains_key(id) ==> (#[trigger] live@[id].revoked(), live@[id].used())
            == replay(recorded@[id]@),
{
    let ghost source = recorded@;
    let mut live = HashMap::<K, TokenStatus>::with_capacity(recorded.len());
    let mut rows = recorded.into_iter();
    proof {
        let entries = rows.remaining();
        assert(entries.to_set() == source.kv_pairs());
        assert forall|k: K| #[trigger] source.contains_key(k) implies entries.contains((k,source[k])) by {
            assert(source.kv_pairs().contains((k,source[k])));
            assert(entries.to_set().contains((k,source[k])));
        }
        assert forall|i: int| 0 <= i < entries.len() implies ({
            let row = #[trigger] entries[i];
            source.contains_key(row.0) && row.1 == source[row.0]
        }) by {
            let row = entries[i];
            assert(entries.contains(row));
            assert(source.kv_pairs().contains(row));
            let k = choose|k: K| source.dom().contains(k) && (k,source[k]) == row;
        }
    }
    let ghost mut left = vstd::std_specs::hash::into_iter_entries(rows).len() as int;
    loop
        invariant source == recorded@, left == rows.remaining().len(), hash_map_inv(&live), obeys_key_model::<K>(), vstd::laws_eq::obeys_concrete_eq::<K>(),
            forall|id: K| #[trigger] source.contains_key(id) ==> live@.contains_key(id)
                || rows.remaining().contains((id,source[id])),
            forall|i: int| 0 <= i < rows.remaining().len() ==> ({
                let row = #[trigger] rows.remaining()[i];
                source.contains_key(row.0) && row.1 == source[row.0]
            }),
            forall|id: K| #[trigger] live@.contains_key(id) ==> source.contains_key(id)
                && (live@[id].revoked(), live@[id].used()) == replay(source[id]@),
        decreases left,
    {
        let ghost before = rows.remaining();
        let Some((id,markers)) = rows.next() else {
            assert(live@.dom() =~= source.dom());
            return live;
        };
        assert(before[0] == (id,markers));
        assert(source.contains_key(id) && markers == source[id]);
        let status = TokenStatus::recover_markers(&markers);
        live.insert(id,status);
        assert forall|k: K| #[trigger] source.contains_key(k) implies live@.contains_key(k)
            || rows.remaining().contains((k,source[k])) by {
            if !live@.contains_key(k) {
                let i = choose|i:int| 0 <= i < before.len() && before[i] == (k,source[k]);
                assert(i > 0);
                assert(rows.remaining()[i-1] == before[i]);
            }
        }
        proof { left = left - 1; };
    }
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

    /// Restore every recorded marker, including duplicate legacy spellings.
    pub(super) fn recover_markers(markers: &[Marker]) -> (status: Self)
        ensures (status.revoked(), status.used()) == replay(markers@),
    {
        let mut status = Self::recover(false, false);
        let mut i = 0usize;
        while i < markers.len()
            invariant i <= markers.len(),
                (status.revoked(), status.used()) == replay(markers@.take(i as int)),
            decreases markers.len() - i,
        {
            status.restore(markers[i]);
            assert(markers@.take(i as int + 1) =~= markers@.take(i as int).push(markers@[i as int]));
            i += 1;
        }
        assert(markers@.take(i as int) =~= markers@);
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
