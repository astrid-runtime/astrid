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

/// The journal payload and the root publication it describes travel together.
#[derive(Debug)]
pub(super) struct PreparedRoot<P, R> {
    owner: P,
    expected: Option<R>,
    replacement: R,
    journal: Vec<u8>,
}

impl<P,R: Copy> PreparedRoot<P,R> {
    pub(super) closed spec fn binding(&self) -> (P, Option<R>, R, Vec<u8>) {
        (self.owner, self.expected, self.replacement, self.journal)
    }

    pub(super) fn encode<E,F>(owner: P, expected: Option<R>, replacement: R, encode: F)
        -> (result: Result<Self,E>) where F: FnOnce(&P,Option<R>,R) -> Result<Vec<u8>,E>,
        requires encode.requires((&owner, expected, replacement)),
        ensures
            result matches Ok(prepared) ==> {
                let (p,e,r,bytes) = prepared.binding();
                &&& (p,e,r) == (owner,expected,replacement)
                &&& encode.ensures((&owner,expected,replacement), Ok(bytes))
            },
            result matches Err(error) ==> encode.ensures((&owner,expected,replacement), Err(error)),
    {
        let journal = encode(&owner,expected,replacement)?;
        Ok(Self {owner,expected,replacement,journal})
    }

    pub(super) fn owner(&self) -> (p: &P) ensures *p == self.binding().0 { &self.owner }
    pub(super) fn replacement(&self) -> (r: R) ensures r == self.binding().2 { self.replacement }
    pub(super) fn journal(&self) -> (j: &Vec<u8>) ensures *j == self.binding().3 { &self.journal }

    /// Stage or append this owner's prepared transition in the WAL.
    pub(super) fn write_wal<T,F>(&self, write: F) -> (result: T)
        where F: FnOnce(&P,Option<R>,R,&Vec<u8>) -> T,
        requires write.requires((&self.binding().0,self.binding().1,self.binding().2,&self.binding().3)),
        ensures write.ensures((&self.binding().0,self.binding().1,self.binding().2,&self.binding().3),result),
    {
        write(&self.owner,self.expected,self.replacement,&self.journal)
    }

    /// Return the acknowledged root after passing this entry's owner and
    /// replacement to the engine's publication operation.
    pub(super) fn publish<T,F>(&self, publish: F) -> (result: (R,T)) where F: FnOnce(&P,R) -> T,
        requires publish.requires((&self.binding().0,self.binding().2)),
        ensures result.0 == self.binding().2,
            publish.ensures((&self.binding().0,self.binding().2),result.1),
    {
        let outcome = publish(&self.owner,self.replacement);
        (self.replacement,outcome)
    }
}

}
