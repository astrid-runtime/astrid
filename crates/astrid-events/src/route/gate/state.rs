//! Atomic byte representation of a single runtime generation's route gate.

use vstd::atomic_ghost::{AtomicInvariantPredicate, AtomicU8};
use vstd::atomic_with_ghost;
use vstd::prelude::*;

verus! {

pub(super) const STAGED: u8 = 0;
pub(super) const PUBLISHED: u8 = 1;
pub(super) const RETIRED: u8 = 2;

struct GateInvariant;

impl AtomicInvariantPredicate<(), u8, bool> for GateInvariant {
    closed spec fn atomic_inv(_: (), byte: u8, retired: bool) -> bool {
        (byte == STAGED || byte == PUBLISHED || byte == RETIRED) && (retired == (byte == RETIRED))
    }
}

/// One atomic location per generation. The erased flag records retirement
/// and is never cleared by publication or observation.
pub(super) struct GateState {
    byte: AtomicU8<(), bool, GateInvariant>,
}

impl GateState {
    #[verifier::type_invariant]
    spec fn valid(&self) -> bool { self.byte.well_formed() }

    pub(super) fn new(published: bool) -> Self {
        let initial = if published { PUBLISHED } else { STAGED };
        assert(initial == PUBLISHED <==> published);
        assert(initial == STAGED <==> !published);
        Self { byte: AtomicU8::new(Ghost(()), initial, Tracked(false)) }
    }

    pub(super) fn publish(&self) {
        proof { use_type_invariant(self); }
        let _ = atomic_with_ghost!(self.byte => compare_exchange(STAGED, PUBLISHED);
            update before -> after;
            ghost retired => {
                assert(after == if before == STAGED { PUBLISHED } else { before });
                assert(retired ==> after == RETIRED);
            }
        );
    }

    pub(super) fn retire(&self) {
        proof { use_type_invariant(self); }
        atomic_with_ghost!(self.byte => store(RETIRED);
            ghost retired => { retired = true; }
        );
    }

    pub(super) fn observe(&self) -> (byte: u8)
        ensures byte == STAGED || byte == PUBLISHED || byte == RETIRED,
    {
        proof { use_type_invariant(self); }
        atomic_with_ghost!(self.byte => load();
            returning observed;
            ghost retired => { assert(retired == (observed == RETIRED)); }
        )
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
