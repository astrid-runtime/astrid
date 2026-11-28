//! Admission and dispatch of a durable workspace attachment operation.
use std::{collections::HashMap, hash::Hash};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_eq::obeys_concrete_eq,
    std_specs::hash::{hash_map_inv, obeys_key_model},
};

verus! {
/// Operation applied to one authenticated workspace branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceCommitOp {
    /// Publish the branch's selected attachment into the owner catalog.
    Promote,
    /// Discard the branch's selected attachment.
    Rollback,
}

pub(super) enum LeaseError { Missing, Mismatch }

/// Return the authoritative record selected by the UID before opening storage.
pub(super) fn lease<K: Eq + Hash,T: Copy + Eq>(bindings: &HashMap<K,T>, uid: &K, expected: &T)
    -> (out: Result<T,LeaseError>)
    requires hash_map_inv(bindings), obeys_key_model::<K>(), obeys_concrete_eq::<K>(), obeys_concrete_eq::<T>(),
    ensures if bindings@.contains_key(*uid) {
        let observed = bindings@[*uid];
        out == if observed == *expected { Ok(observed) } else { Err(LeaseError::Mismatch) }
    } else { out == Err(LeaseError::Missing) },
{
    broadcast use vstd::std_specs::hash::group_hash_axioms;
    proof { reveal(obeys_concrete_eq); }
    let Some(observed) = bindings.get(uid) else { return Err(LeaseError::Missing); };
    if T::eq(observed,expected) { Ok(*observed) } else { Err(LeaseError::Mismatch) }
}

pub(super) struct Attachment<'a> {
    pub(super) live: bool,
    pub(super) uid: Option<[u8;32]>,
    pub(super) prefix: Option<&'a [u8]>,
}

impl Attachment<'_> {
    pub(super) open spec fn admits(self, uid: [u8;32], prefix: &[u8]) -> bool {
        self.live && self.uid == Some(uid) && self.prefix == Some(prefix)
    }

    pub(super) fn matches(self, uid: [u8;32], prefix: &[u8]) -> (yes: bool)
        ensures yes == self.admits(uid,prefix),
    {
        if !self.live { return false; }
        let Some(recorded) = self.uid else { return false; };
        if recorded != uid { return false; }
        assert(recorded@ =~= uid@);
        assert(recorded == uid);
        let Some(bound) = self.prefix else { return false; };
        if bound != prefix { return false; }
        assert(bound@ =~= prefix@);
        assert(bound == prefix);
        true
    }
}

pub(super) trait Writer<O,B> {
    type Error;
    spec fn calls(&self) -> Seq<(WorkspaceCommitOp,O,B)>;
    spec fn outcome(&self, op: WorkspaceCommitOp, owner: O, branch: B, result: Result<(),Self::Error>) -> bool;

    fn promote(&mut self, owner: O, branch: B) -> (r: Result<(),Self::Error>)
        ensures final(self).calls() == old(self).calls().push((WorkspaceCommitOp::Promote,owner,branch)),
            old(self).outcome(WorkspaceCommitOp::Promote,owner,branch,r);

    fn rollback(&mut self, owner: O, branch: B) -> (r: Result<(),Self::Error>)
        ensures final(self).calls() == old(self).calls().push((WorkspaceCommitOp::Rollback,owner,branch)),
            old(self).outcome(WorkspaceCommitOp::Rollback,owner,branch,r);
}

/// A mismatch refuses the operation before reaching either storage method.
pub(super) fn finish<O,B,W: Writer<O,B>>(attachment: Attachment<'_>, uid: [u8;32],
    prefix: &[u8], op: WorkspaceCommitOp, owner: O, branch: B, writer: &mut W)
    -> (out: Option<Result<(),W::Error>>)
    ensures if attachment.admits(uid,prefix) {
        match out {
            Some(r) => final(writer).calls() == old(writer).calls().push((op,owner,branch))
                && old(writer).outcome(op,owner,branch,r),
            None => false,
        }
    } else { out.is_none() && final(writer).calls() == old(writer).calls() },
{
    if !attachment.matches(uid,prefix) { return None; }
    Some(match op {
        WorkspaceCommitOp::Promote => writer.promote(owner,branch),
        WorkspaceCommitOp::Rollback => writer.rollback(owner,branch),
    })
}
}
