//! Atomic byte representation of a single runtime generation's route gate.

use vstd::atomic_ghost::{AtomicInvariantPredicate, AtomicU8};
use vstd::atomic_with_ghost;
use vstd::prelude::*;
use vstd::resource::{
    Loc,
    set::{GhostPersistentSingleton, GhostSetAuth},
};

verus! {

pub(super) const STAGED: u8 = 0;
pub(super) const PUBLISHED: u8 = 1;
pub(super) const RETIRED: u8 = 2;

struct GateInvariant;

pub(super) type Retirement = GhostPersistentSingleton<()>;

#[cfg_attr(not(verus_keep_ghost), allow(dead_code, reason = "atomic ghost state is erased in native builds"))]
tracked struct History {
    tracked authority: GhostSetAuth<()>,
    tracked receipt: Option<Retirement>,
}

impl AtomicInvariantPredicate<Loc, u8, History> for GateInvariant {
    closed spec fn atomic_inv(location: Loc, byte: u8, history: History) -> bool {
        &&& byte == STAGED || byte == PUBLISHED || byte == RETIRED
        &&& history.authority.id() == location
        &&& history.authority@.contains(()) == (byte == RETIRED)
        &&& history.receipt.is_some() == (byte == RETIRED)
        &&& history.receipt matches Some(r) ==> r.id() == location
    }
}

/// Atomic gate with an erased, generation-specific retirement witness.
pub(super) struct GateState {
    byte: AtomicU8<Loc, History, GateInvariant>,
}

impl GateState {
    #[verifier::type_invariant]
    spec fn valid(&self) -> bool { self.byte.well_formed() }

    pub(super) closed spec fn location(&self) -> Loc { self.byte.constant() }

    pub(super) fn new(published: bool) -> Self {
        let initial = if published { PUBLISHED } else { STAGED };
        assert(initial == PUBLISHED <==> published);
        assert(initial == STAGED <==> !published);
        let tracked (authority, _) = GhostSetAuth::new(Set::empty());
        let ghost location = authority.id();
        let tracked history = History { authority, receipt: None };
        Self { byte: AtomicU8::new(Ghost(location), initial, Tracked(history)) }
    }

    pub(super) fn publish(&self) {
        proof { use_type_invariant(self); }
        let _ = atomic_with_ghost!(self.byte => compare_exchange(STAGED, PUBLISHED);
            update before -> after;
            ghost history => {
                assert(after == if before == STAGED { PUBLISHED } else { before });
                assert(history.receipt.is_some() ==> after == RETIRED);
            }
        );
    }

    pub(super) fn retire(&self) -> (retired: Tracked<Retirement>)
        ensures retired@.id() == self.location(),
    {
        proof { use_type_invariant(self); }
        let tracked receipt;
        atomic_with_ghost!(self.byte => store(RETIRED);
            ghost history => {
                if let Some(issued) = &history.receipt {
                    receipt = issued.duplicate();
                } else {
                    receipt = history.authority.insert(()).persist();
                    history.receipt = Some(receipt.duplicate());
                }
            }
        );
        Tracked(receipt)
    }

    // Both ordinary runtime reads and the retirement consumer perform this load.
    pub(super) fn read(&self, Tracked(witness): Tracked<Option<&Retirement>>) -> (byte: u8)
        requires witness matches Some(r) ==> r.id() == self.location(),
        ensures byte == STAGED || byte == PUBLISHED || byte == RETIRED,
            witness.is_some() ==> byte == RETIRED,
    {
        proof { use_type_invariant(self); }
        atomic_with_ghost!(self.byte => load();
            returning observed;
            ghost history => {
                if let Some(issued) = witness {
                    issued.agree(&history.authority);
                    assert(observed == RETIRED);
                }
            }
        )
    }

    pub(super) fn observe(&self) -> (byte: u8)
        ensures byte == STAGED || byte == PUBLISHED || byte == RETIRED,
    {
        self.read(Tracked(None))
    }

}

pub(super) fn admits(current: u8) -> (open: bool)
    ensures open == (current == PUBLISHED),
{
    current == PUBLISHED
}

pub(super) fn release<T>(current: u8, pending: T) -> (delivery: Option<T>)
    ensures delivery == (if current == PUBLISHED { Some(pending) } else { None }),
{
    if admits(current) { Some(pending) } else { None }
}

}
