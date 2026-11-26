//! Compare durable roots by their generation and the full commit identity.
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy)]
pub(super) struct Version {
    pub(super) generation: u64,
    pub(super) commit: [u8; 32],
}

#[derive(Clone, Copy)]
pub(super) enum Advance { Conflict, Overflow, Next(u64) }

pub(super) open spec fn matches_root(a: Option<Version>, b: Option<Version>) -> bool {
    match (a,b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.generation == b.generation && a.commit@ == b.commit@,
        _ => false,
    }
}

fn same_root(a: Option<Version>, b: Option<Version>) -> (same: bool)
    ensures same == matches_root(a,b),
{
    match (a,b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            if a.generation != b.generation || a.commit.as_slice() != b.commit.as_slice() { return false; }
            assert(a.commit@ =~= b.commit@);
            true
        },
        _ => false,
    }
}

pub(super) fn advance(actual: Option<Version>, expected: Option<Version>) -> (decision: Advance)
    ensures
        (decision is Conflict) == !matches_root(actual,expected),
        (decision is Overflow) == (matches_root(actual,expected) && (actual matches Some(v) && v.generation == u64::MAX)),
        decision matches Advance::Next(next) ==> matches_root(actual,expected) && match actual {
            None => next == 0,
            Some(v) => next as int == v.generation as int + 1,
        },
{
    if !same_root(actual, expected) { return Advance::Conflict; }
    match actual {
        None => Advance::Next(0),
        Some(v) => match v.generation.checked_add(1) {
            Some(next) => Advance::Next(next),
            None => Advance::Overflow,
        },
    }
}

/// A previously published WAL transition can be replayed idempotently.
pub(super) enum Replay { AlreadyPublished, Apply, Conflict }

pub(super) fn replay(actual: Option<Version>, expected: Option<Version>, replacement: Version)
    -> (decision: Replay)
    ensures
        (decision is AlreadyPublished) == matches_root(actual, Some(replacement)),
        (decision is Apply) == (!matches_root(actual, Some(replacement)) && matches_root(actual, expected)),
        (decision is Conflict) == (!matches_root(actual, Some(replacement)) && !matches_root(actual, expected)),
{
    if same_root(actual, Some(replacement)) { Replay::AlreadyPublished }
    else if same_root(actual, expected) { Replay::Apply }
    else { Replay::Conflict }
}

}
