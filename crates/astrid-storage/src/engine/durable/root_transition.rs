//! Compare durable roots by their generation and the full commit identity.
use super::RootState;
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    pervasive::obeys_clone_eq,
    std_specs::btree::btree_map_inv,
};

verus! {

#[derive(Clone, Copy)]
pub(super) struct Version {
    pub(super) generation: u64,
    pub(super) commit: [u8; 32],
}

pub(super) open spec fn represents(v:Version,r:RootState) -> bool {
    v.generation == r.generation.value() && v.commit@ == r.commit.digest()
}

pub(super) fn version(r:RootState) -> (v:Version)
    ensures represents(v,r),
{
    Version { generation:r.generation.get(), commit:*r.commit.as_bytes() }
}

fn optional(root:Option<RootState>) -> (v:Option<Version>)
    ensures match root {
        Some(r) => v matches Some(v) && represents(v,r),
        None => v.is_none(),
    },
{
    root.map(|r:RootState| -> (v:Version) ensures represents(v,r) { version(r) })
}

pub(super) enum SelectionError {
    Conflict { expected:Option<RootState>, actual:Option<RootState> },
    Overflow,
}

/// CAS selection retains the complete root transition during object validation.
pub(super) struct SelectedRoot<P> {
    owner:P,
    expected:Option<RootState>,
    replacement:RootState,
}

impl<P> SelectedRoot<P> {
    pub(super) closed spec fn binding(&self) -> (P,Option<RootState>,RootState) {
        (self.owner,self.expected,self.replacement)
    }

    pub(super) fn replacement(&self) -> (r:RootState)
        ensures r == self.binding().2,
    { self.replacement }

    pub(super) fn encode<E,F:FnOnce(&P,Option<RootState>,RootState)->Result<Vec<u8>,E>>(self,encoder:F)
        -> (out:Result<PreparedRoot<P,RootState>,E>)
        requires encoder.requires((&self.binding().0,self.binding().1,self.binding().2)),
        ensures match out {
            Ok(prepared) => {
                let (owner,expected,root,bytes) = prepared.binding();
                &&& (owner,expected,root) == self.binding()
                &&& encoder.ensures((&owner,expected,root),Ok(bytes))
            },
            Err(e) => encoder.ensures((&self.binding().0,self.binding().1,self.binding().2),Err(e)),
        },
    {
        PreparedRoot::encode(self.owner,self.expected,self.replacement,encoder)
    }
}

type DeclaredRows = Vec<(super::ObjectId,super::ObjectRecord)>;

pub(super) fn select_update<P:Ord>(pending:&BTreeMap<P,RootState>,published:&BTreeMap<P,RootState>,
    update:super::root_declaration::Update<P>) -> (out:Result<(SelectedRoot<P>,DeclaredRows),SelectionError>)
    requires obeys_cmp::<P>(), obeys_cmp_concrete_eq::<P>(), btree_map_inv(pending), btree_map_inv(published),
    ensures ({
        let owner = update.principal;
        let actual = if pending@.contains_key(owner) {Some(pending@[owner])}
            else if published@.contains_key(owner) {Some(published@[owner])} else {None};
        match out {
            Err(SelectionError::Conflict {expected,actual:a}) => expected == update.expected && a == actual && expected != a,
            Err(SelectionError::Overflow) => actual == update.expected && (actual matches Some(r) && r.generation.value() == u64::MAX),
            Ok((selected,rows)) => {
                let (p,e,root) = selected.binding();
                &&& p == owner && e == update.expected && rows == update.records
                &&& actual == update.expected && root.commit == update.commit
                &&& match actual {
                None => root.generation.value() == 0,
                Some(old) => root.generation.value() == old.generation.value() + 1,
                }
            },
        }
    }),
{
    let (actual,decision) = admit_current(pending,published,&update.principal,update.expected);
    match decision {
        Advance::Conflict => Err(SelectionError::Conflict {expected:update.expected,actual}),
        Advance::Overflow => Err(SelectionError::Overflow),
        Advance::Next(n) => Ok((SelectedRoot { owner:update.principal,expected:update.expected,
            replacement:RootState {generation:super::RootGeneration::new(n),commit:update.commit} },update.records)),
    }
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

/// Read the entry for this principal from the published root map.
pub(super) fn published<P:Ord,R:Copy>(roots:&BTreeMap<P,R>, owner:&P) -> (root:Option<R>)
    requires obeys_cmp::<P>(), obeys_cmp_concrete_eq::<P>(), btree_map_inv(roots),
    ensures root == if roots@.contains_key(*owner) { Some(roots@[*owner]) } else { None },
{
    roots.get(owner).copied()
}

/// Group preparation observes the latest accepted entry for this owner.
pub(super) fn current<P:Ord,R:Copy>(pending:&BTreeMap<P,R>, published:&BTreeMap<P,R>, owner:&P)
    -> (root:Option<R>)
    requires obeys_cmp::<P>(), obeys_cmp_concrete_eq::<P>(), btree_map_inv(pending), btree_map_inv(published),
    ensures root == if pending@.contains_key(*owner) { Some(pending@[*owner]) }
        else if published@.contains_key(*owner) { Some(published@[*owner]) } else { None },
{
    if let Some(root) = pending.get(owner) { Some(*root) } else { self::published(published,owner) }
}

/// Compare the full root selected for this owner with the caller's sampled root.
pub(super) fn admit_current<P:Ord>(pending:&BTreeMap<P,RootState>,published:&BTreeMap<P,RootState>,
    owner:&P, expected:Option<RootState>) -> (out:(Option<RootState>,Advance))
    requires obeys_cmp::<P>(), obeys_cmp_concrete_eq::<P>(), btree_map_inv(pending), btree_map_inv(published),
    ensures out.0 == if pending@.contains_key(*owner) {Some(pending@[*owner])}
        else if published@.contains_key(*owner) {Some(published@[*owner])} else {None},
        (out.1 is Conflict) == (out.0 != expected),
        (out.1 is Overflow) == (out.0 == expected && (expected matches Some(r) && r.generation.value() == u64::MAX)),
        out.1 matches Advance::Next(n) ==> out.0 == expected && match expected {
            None => n == 0, Some(r) => n as int == r.generation.value() as int + 1,
        },
{
    let actual = current(pending,published,owner);
    (actual,compare(actual,expected))
}

pub(super) fn compare(actual:Option<RootState>,expected:Option<RootState>) -> (decision:Advance)
    ensures (decision is Conflict) == (actual != expected),
        (decision is Overflow) == (actual == expected && (expected matches Some(r) && r.generation.value() == u64::MAX)),
        decision matches Advance::Next(next) ==> actual == expected && match expected {
            None => next == 0, Some(r) => next as int == r.generation.value() as int + 1,
        },
{
    let a = optional(actual);
    let e = optional(expected);
    let decision = advance(a,e);
    proof {
        if let (Some(x),Some(y)) = (actual,expected) {
            if matches_root(a,e) {
                super::ObjectId::same_digest(x.commit,y.commit);
                x.generation.same_value(y.generation);
            }
        }
    }
    decision
}

/// A WAL descriptor must name the successor permitted at preparation.
pub(super) fn valid_generation(expected: Option<Version>, replacement: u64) -> (valid: bool)
    ensures valid == match expected {
        None => replacement == 0,
        Some(v) => replacement as int == v.generation as int + 1,
    },
{
    match advance(expected, expected) {
        Advance::Next(next) => next == replacement,
        Advance::Conflict | Advance::Overflow => false,
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
    pub(super) fn journal(&self) -> (j: &Vec<u8>) ensures *j == self.binding().3 { &self.journal }

    /// Make this accepted replacement visible to subsequent preparations in the batch.
    pub(super) fn stage(&self, pending:&mut BTreeMap<P,R>) where P:Ord+Clone,
        requires obeys_cmp::<P>(), obeys_cmp_concrete_eq::<P>(), obeys_clone_eq::<P>(), btree_map_inv(old(pending)),
        ensures btree_map_inv(final(pending)),
            final(pending)@ == old(pending)@.insert(self.binding().0,self.binding().2),
    {
        proof { reveal(obeys_clone_eq); }
        let owner = P::clone(&self.owner);
        assert(vstd::pervasive::cloned(self.owner,owner));
        assert(owner == self.owner);
        pending.insert(owner,self.replacement);
    }

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

impl From<RootState> for Version {
    fn from(root: RootState) -> Self {
        version(root)
    }
}
