//! Atomic byte representation of a single runtime generation's route gate.

use vstd::prelude::*;

verus! {

pub(super) const STAGED: u8 = 0;
pub(super) const PUBLISHED: u8 = 1;
pub(super) const RETIRED: u8 = 2;

pub(super) fn publish(current: u8) -> (next: u8)
    ensures
        next == PUBLISHED <==> current == STAGED || current == PUBLISHED,
        current != STAGED && current != PUBLISHED ==> next == RETIRED,
{
    match current {
        STAGED | PUBLISHED => PUBLISHED,
        _ => RETIRED,
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
